package http

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"sync"
	"text/template"
	"strings"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/bytespool"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/retry"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/net/http2"
)

type Client struct {
	serverPicker  protocol.ServerPicker
	policyManager policy.Manager
	header        []*Header
}

type h2Conn struct {
	rawConn net.Conn
	h2Conn  *http2.ClientConn
}

var (
	cachedH2Mutex sync.Mutex
	cachedH2Conns map[net.Destination]h2Conn
)

// NewClient create a new http client based on the given config.
func NewClient(ctx context.Context, config *ClientConfig) (*Client, error) {
	serverList := protocol.NewServerList()
	for _, rec := range config.Server {
		s, err := protocol.NewServerSpecFromPB(rec)
		if err != nil {
			return nil, newError("failed to get server spec").Base(err)
		}
		serverList.AddServer(s)
	}
	if serverList.Size() == 0 {
		return nil, newError("0 target server")
	}

	v := core.MustFromContext(ctx)
	return &Client{
		serverPicker:  protocol.NewRoundRobinServerPicker(serverList),
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
		header:        config.Header,
	}, nil
}

// Process implements proxy.Outbound.Process. We first create a socket tunnel via HTTP CONNECT method, then redirect all inbound traffic to that tunnel.
func (c *Client) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbound := session.OutboundFromContext(ctx)
	if outbound == nil || !outbound.Target.IsValid() {
		return newError("target not specified.")
	}
	target := outbound.Target
	targetAddr := target.NetAddr()

	if target.Network == net.Network_UDP {
		return newError("UDP is not supported by HTTP outbound")
	}

	var user *protocol.MemoryUser
	var conn stat.Connection

	mbuf, _ := link.Reader.ReadMultiBuffer()
	len := mbuf.Len()
	firstPayload := bytespool.Alloc(len)
	mbuf, _ = buf.SplitBytes(mbuf, firstPayload)
	firstPayload = firstPayload[:len]

	buf.ReleaseMulti(mbuf)
	defer bytespool.Free(firstPayload)

	header, err := fillRequestHeader(ctx, c.header)
	if err != nil {
		return newError("failed to fill out header").Base(err)
	}

	if err := retry.ExponentialBackoff(5, 100).On(func() error {
		server := c.serverPicker.PickServer()
		dest := server.Destination()
		user = server.PickUser()

		netConn, err := setUpHTTPTunnel(ctx, dest, targetAddr, user, dialer, header, firstPayload)
		if netConn != nil {
			if _, ok := netConn.(*http2Conn); !ok {
				if _, err := netConn.Write(firstPayload); err != nil {
					netConn.Close()
					return err
				}
			}
			conn = stat.Connection(netConn)
		}
		return err
	}); err != nil {
		return newError("failed to find an available destination").Base(err)
	}

	defer func() {
		if err := conn.Close(); err != nil {
			newError("failed to closed connection").Base(err).WriteToLog(session.ExportIDToError(ctx))
		}
	}()

	p := c.policyManager.ForLevel(0)
	if user != nil {
		p = c.policyManager.ForLevel(user.Level)
	}

	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, p.Timeouts.ConnectionIdle)

	requestFunc := func() error {
		defer timer.SetTimeout(p.Timeouts.DownlinkOnly)
		return buf.Copy(link.Reader, buf.NewWriter(conn), buf.UpdateActivity(timer))
	}
	responseFunc := func() error {
		defer timer.SetTimeout(p.Timeouts.UplinkOnly)
		return buf.Copy(buf.NewReader(conn), link.Writer, buf.UpdateActivity(timer))
	}

	responseDonePost := task.OnSuccess(responseFunc, task.Close(link.Writer))
	if err := task.Run(ctx, requestFunc, responseDonePost); err != nil {
		return newError("connection ends").Base(err)
	}

	return nil
}

// fillRequestHeader will fill out the template of the headers
func fillRequestHeader(ctx context.Context, header []*Header) ([]*Header, error) {
	if len(header) == 0 {
		return header, nil
	}

	inbound := session.InboundFromContext(ctx)
	outbound := session.OutboundFromContext(ctx)

	data := struct {
		Source net.Destination
		Target net.Destination
	}{
		Source: inbound.Source,
		Target: outbound.Target,
	}

	filled := make([]*Header, len(header))
	for i, h := range header {
		tmpl, err := template.New(h.Key).Parse(h.Value)
		if err != nil {
			return nil, err
		}
		var buf bytes.Buffer

		if err = tmpl.Execute(&buf, data); err != nil {
			return nil, err
		}
		filled[i] = &Header{Key: h.Key, Value: buf.String()}
	}

	return filled, nil
}

// setUpHTTPTunnel will create a socket tunnel via HTTP CONNECT method
func setUpHTTPTunnel(ctx context.Context, dest net.Destination, target string, user *protocol.MemoryUser, dialer internet.Dialer, header []*Header, firstPayload []byte) (net.Conn, error) {
	req := &http.Request{
		Method: http.MethodConnect,
		// URL:    &url.URL{Host: target},
		URL:    &url.URL{Opaque: target},
		// https://github.com/6Kmfi6HP/x-tunnel/blob/main/internal/app/front_proxy.go#L161
		// https://pkg.go.dev/net/http#Request.Write
		// https://cs.opensource.google/go/go/+/refs/tags/go1.20:src/net/http/request.go;l=598;bpv=1
		// https://pkg.go.dev/net/url#URL
		Header: make(http.Header),
		Host:   target,
	}

	if user != nil && user.Account != nil {
		account := user.Account.(*Account)
		auth := account.GetUsername() + ":" + account.GetPassword()
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))
	}

	for _, h := range header {
		req.Header.Set(h.Key, h.Value)
	}

	// ★ 新增：Header 里显式带了 Host 时，优先采用它，不再用 target。
	// 注意：CONNECT 的 Host 与请求行 authority 必须是同一个值，
	// 所以 req.Host 和 req.URL.Host 要一起改，否则合规代理会忽略/拒绝。
	// https://github.com/MetaCubeX/mihomo/issues/534
	// https://github.com/MetaCubeX/mihomo/pull/535
	// 但百度直连 HTTP CONNECT cloudnproxy.com:443 notls 不是标准的 RFC 实现，它不会拒绝 req.Host 和 req.URL.Host 不一致的请求。
	// 另外注意标准的 Host 是由（域名/IP）地址和端口组成的，即 Host: name:port，如 Host: example.com:443，并非只有地址。
	if v := req.Header.Get("Host"); v != "" {
		v = strings.TrimSpace(v)  // import ( "strings" )
		// CONNECT 要求 host:port，自定义 Host 缺端口时从原 target 继承端口
		// if _, _, err := net.SplitHostPort(v); err != nil {
		// 	if _, origPort, _ := net.SplitHostPort(target); origPort != "" {  // import ( "net" )
		// 		v = net.JoinHostPort(v, origPort)
		// 	} else {
		// 		v = net.JoinHostPort(v, "443")
		// 	}
		// }
		req.Host = v        // Host 头
		// req.URL.Host = v    // 请求行 CONNECT v ... （隧道目标随之改变）
		req.Header.Del("Host") // 防止 H2 路径出现多余的 host 字段
	}

	connectHTTP1 := func(rawConn net.Conn) (net.Conn, error) {
		req.Header.Set("Proxy-Connection", "Keep-Alive")

		err := req.Write(rawConn)
		if err != nil {
			rawConn.Close()
			return nil, err
		}

		resp, err := http.ReadResponse(bufio.NewReader(rawConn), req)
		if err != nil {
			rawConn.Close()
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			rawConn.Close()
			return nil, newError("Proxy responded with non 200 code: " + resp.Status)
		}
		return rawConn, nil
	}

	connectHTTP2 := func(rawConn net.Conn, h2clientConn *http2.ClientConn) (net.Conn, error) {
		pr, pw := io.Pipe()
		req.Body = pr

		var pErr error
		var wg sync.WaitGroup
		wg.Add(1)

		go func() {
			_, pErr = pw.Write(firstPayload)
			wg.Done()
		}()

		resp, err := h2clientConn.RoundTrip(req)
		if err != nil {
			rawConn.Close()
			return nil, err
		}

		wg.Wait()
		if pErr != nil {
			rawConn.Close()
			return nil, pErr
		}

		if resp.StatusCode != http.StatusOK {
			rawConn.Close()
			return nil, newError("Proxy responded with non 200 code: " + resp.Status)
		}
		return newHTTP2Conn(rawConn, pw, resp.Body), nil
	}

	cachedH2Mutex.Lock()
	cachedConn, cachedConnFound := cachedH2Conns[dest]
	cachedH2Mutex.Unlock()

	if cachedConnFound {
		rc, cc := cachedConn.rawConn, cachedConn.h2Conn
		if cc.CanTakeNewRequest() {
			proxyConn, err := connectHTTP2(rc, cc)
			if err != nil {
				return nil, err
			}

			return proxyConn, nil
		}
	}

	rawConn, err := dialer.Dial(ctx, dest)
	if err != nil {
		return nil, err
	}

	iConn := rawConn
	if statConn, ok := iConn.(*stat.CounterConnection); ok {
		iConn = statConn.Connection
	}

	nextProto := ""
	if tlsConn, ok := iConn.(*tls.Conn); ok {
		if err := tlsConn.Handshake(); err != nil {
			rawConn.Close()
			return nil, err
		}
		nextProto = tlsConn.ConnectionState().NegotiatedProtocol
	}

	switch nextProto {
	case "", "http/1.1":
		return connectHTTP1(rawConn)
	case "h2":
		t := http2.Transport{}
		h2clientConn, err := t.NewClientConn(rawConn)
		if err != nil {
			rawConn.Close()
			return nil, err
		}

		proxyConn, err := connectHTTP2(rawConn, h2clientConn)
		if err != nil {
			rawConn.Close()
			return nil, err
		}

		cachedH2Mutex.Lock()
		if cachedH2Conns == nil {
			cachedH2Conns = make(map[net.Destination]h2Conn)
		}

		cachedH2Conns[dest] = h2Conn{
			rawConn: rawConn,
			h2Conn:  h2clientConn,
		}
		cachedH2Mutex.Unlock()

		return proxyConn, err
	default:
		return nil, newError("negotiated unsupported application layer protocol: " + nextProto)
	}
}

func newHTTP2Conn(c net.Conn, pipedReqBody *io.PipeWriter, respBody io.ReadCloser) net.Conn {
	return &http2Conn{Conn: c, in: pipedReqBody, out: respBody}
}

type http2Conn struct {
	net.Conn
	in  *io.PipeWriter
	out io.ReadCloser
}

func (h *http2Conn) Read(p []byte) (n int, err error) {
	return h.out.Read(p)
}

func (h *http2Conn) Write(p []byte) (n int, err error) {
	return h.in.Write(p)
}

func (h *http2Conn) Close() error {
	h.in.Close()
	return h.out.Close()
}

func init() {
	common.Must(common.RegisterConfig((*ClientConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewClient(ctx, config.(*ClientConfig))
	}))
}
