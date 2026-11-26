package nickserv

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	nethttp "net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// maxRPCResponse bounds an RPC response body.
const maxRPCResponse = 1 << 20

// RPCError is an error the services returned (JSON-RPC error object or
// XML-RPC fault).
type RPCError struct {
	Code    int
	Message string
}

func (e *RPCError) Error() string { return fmt.Sprintf("rpc error %d: %s", e.Code, e.Message) }

// Caller calls one RPC method with string parameters. The result is JSON
// (XML-RPC results come back as a JSON string).
type Caller interface {
	Call(ctx context.Context, method string, params ...string) (json.RawMessage, error)
}

func newHTTPClient(tlsConf *tls.Config, timeout time.Duration) *nethttp.Client {
	return &nethttp.Client{
		Timeout: timeout,
		Transport: &nethttp.Transport{
			// Never through an environment proxy: the body holds a password.
			Proxy:               nil,
			DialContext:         (&net.Dialer{Timeout: timeout}).DialContext,
			TLSClientConfig:     tlsConf.Clone(),
			TLSHandshakeTimeout: timeout,
			MaxIdleConns:        4,
			IdleConnTimeout:     30 * time.Second,
			// Anope's and Atheme's httpd close or misbehave on reuse.
			DisableKeepAlives:     true,
			ResponseHeaderTimeout: timeout,
		},
		// A redirect would resend the request (and password) elsewhere.
		CheckRedirect: func(*nethttp.Request, []*nethttp.Request) error { return nethttp.ErrUseLastResponse },
	}
}

// post sends body and returns the response body. Transport problems are
// ErrUnavailable; the error never contains the request body.
func post(ctx context.Context, c *nethttp.Client, url, contentType, auth string, body []byte) ([]byte, error) {
	req, err := nethttp.NewRequestWithContext(ctx, nethttp.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "boson-auth")
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrUnavailable, redactURLError(err))
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxRPCResponse+1))
	if err != nil {
		return nil, fmt.Errorf("%w: reading response: %v", ErrUnavailable, err)
	}
	if len(data) > maxRPCResponse {
		return nil, fmt.Errorf("%w: response too large", ErrUnavailable)
	}
	if resp.StatusCode != nethttp.StatusOK {
		return nil, fmt.Errorf("%w: HTTP %d from the services RPC endpoint", ErrUnavailable, resp.StatusCode)
	}
	return data, nil
}

// redactURLError keeps the operation and cause of a *url.Error (the URL
// carries no secrets; the body is never part of it).
func redactURLError(err error) string {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	return err.Error()
}

// JSONRPC is a JSON-RPC 2.0 client (Anope jsonrpc, Atheme transport/jsonrpc).
type JSONRPC struct {
	URL string
	// Token, if set, is sent as "Authorization: Bearer base64(token)",
	// the form Anope's jsonrpc expects.
	Token  string
	client *nethttp.Client
	ids    atomic.Uint64
}

// NewJSONRPC makes a JSON-RPC client.
func NewJSONRPC(url, token string, tlsConf *tls.Config, timeout time.Duration) *JSONRPC {
	return &JSONRPC{URL: url, Token: token, client: newHTTPClient(tlsConf, timeout)}
}

type jsonRPCResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func (c *JSONRPC) Call(ctx context.Context, method string, params ...string) (json.RawMessage, error) {
	if params == nil {
		params = []string{}
	}
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": strconv.FormatUint(c.ids.Add(1), 10), "method": method, "params": params,
	})
	if err != nil {
		return nil, err
	}
	auth := ""
	if c.Token != "" {
		auth = "Bearer " + base64.StdEncoding.EncodeToString([]byte(c.Token))
	}
	data, err := post(ctx, c.client, c.URL, "application/json", auth, body)
	if err != nil {
		return nil, err
	}
	var r jsonRPCResponse
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("%w: invalid JSON-RPC response", ErrUnavailable)
	}
	if r.Error != nil {
		return nil, &RPCError{Code: r.Error.Code, Message: r.Error.Message}
	}
	if len(r.Result) == 0 {
		return nil, fmt.Errorf("%w: JSON-RPC response without a result", ErrUnavailable)
	}
	return r.Result, nil
}

// XMLRPC is an XML-RPC client for Atheme's transport/xmlrpc.
type XMLRPC struct {
	URL    string
	client *nethttp.Client
}

// NewXMLRPC makes an XML-RPC client.
func NewXMLRPC(url string, tlsConf *tls.Config, timeout time.Duration) *XMLRPC {
	return &XMLRPC{URL: url, client: newHTTPClient(tlsConf, timeout)}
}

// xmlValue is an XML-RPC <value>: a typed scalar, a struct (faults), or
// untyped text (a string).
type xmlValue struct {
	String *string    `xml:"string"`
	Int    *string    `xml:"int"`
	I4     *string    `xml:"i4"`
	Bool   *string    `xml:"boolean"`
	Struct *xmlStruct `xml:"struct"`
	Inner  string     `xml:",chardata"`
}

type xmlStruct struct {
	Members []struct {
		Name  string   `xml:"name"`
		Value xmlValue `xml:"value"`
	} `xml:"member"`
}

type xmlMethodResponse struct {
	Params []struct {
		Value xmlValue `xml:"value"`
	} `xml:"params>param"`
	Fault *struct {
		Value xmlValue `xml:"value"`
	} `xml:"fault"`
}

// text is a scalar value as a string (untyped values are strings).
func (v xmlValue) text() string {
	switch {
	case v.String != nil:
		return *v.String
	case v.Int != nil:
		return strings.TrimSpace(*v.Int)
	case v.I4 != nil:
		return strings.TrimSpace(*v.I4)
	case v.Bool != nil:
		return strings.TrimSpace(*v.Bool)
	}
	return v.Inner
}

func (c *XMLRPC) Call(ctx context.Context, method string, params ...string) (json.RawMessage, error) {
	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0"?><methodCall><methodName>`)
	if err := xml.EscapeText(&b, []byte(method)); err != nil {
		return nil, err
	}
	b.WriteString(`</methodName><params>`)
	for _, p := range params {
		b.WriteString(`<param><value><string>`)
		if err := xml.EscapeText(&b, []byte(p)); err != nil {
			return nil, err
		}
		b.WriteString(`</string></value></param>`)
	}
	b.WriteString(`</params></methodCall>`)
	data, err := post(ctx, c.client, c.URL, "text/xml", "", b.Bytes())
	if err != nil {
		return nil, err
	}
	var r xmlMethodResponse
	if err := xml.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("%w: invalid XML-RPC response", ErrUnavailable)
	}
	if r.Fault != nil {
		e := &RPCError{}
		if s := r.Fault.Value.Struct; s != nil {
			for _, m := range s.Members {
				switch m.Name {
				case "faultCode":
					e.Code, _ = strconv.Atoi(m.Value.text())
				case "faultString":
					e.Message = m.Value.text()
				}
			}
		}
		return nil, e
	}
	if len(r.Params) == 0 {
		return nil, fmt.Errorf("%w: XML-RPC response without a result", ErrUnavailable)
	}
	return json.Marshal(r.Params[0].Value.text())
}
