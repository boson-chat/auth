package nickserv

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeIRC is a scripted IRC server: each connection runs script.
type fakeIRC struct {
	ln    net.Listener
	mu    sync.Mutex
	lines []string // everything clients sent, in order
	wg    sync.WaitGroup
}

type fakeClient struct {
	t    *testing.T
	srv  *fakeIRC
	conn net.Conn
	r    *bufio.Reader
	nick string
}

func newFakeIRC(t *testing.T, tlsConf *tls.Config, script func(c *fakeClient)) *fakeIRC {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if tlsConf != nil {
		ln = tls.NewListener(ln, tlsConf)
	}
	f := &fakeIRC{ln: ln}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			f.wg.Add(1)
			go func() {
				defer f.wg.Done()
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				script(&fakeClient{t: t, srv: f, conn: conn, r: bufio.NewReader(conn)})
			}()
		}
	}()
	t.Cleanup(func() { _ = ln.Close(); f.wg.Wait() })
	return f
}

func (f *fakeIRC) addr() string { return f.ln.Addr().String() }

func (f *fakeIRC) sent() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.lines...)
}

// read returns the next line from the client ("" on EOF).
func (c *fakeClient) read() string {
	line, err := c.r.ReadString('\n')
	if err != nil {
		return ""
	}
	line = strings.TrimRight(line, "\r\n")
	c.srv.mu.Lock()
	c.srv.lines = append(c.srv.lines, line)
	c.srv.mu.Unlock()
	if m := parseIRC(line); m.Command == "NICK" {
		c.nick = m.Param(0)
	}
	return line
}

// until reads lines until one starts with prefix and returns it.
func (c *fakeClient) until(prefix string) string {
	for {
		l := c.read()
		if l == "" || strings.HasPrefix(l, prefix) {
			return l
		}
	}
}

func (c *fakeClient) send(lines ...string) {
	for _, l := range lines {
		l = strings.ReplaceAll(l, "$NICK", c.nick)
		_, _ = c.conn.Write([]byte(l + "\r\n"))
	}
}

// welcome reads NICK/USER and sends 001.
func (c *fakeClient) welcome() {
	c.until("USER ")
	c.send(":irc.test 001 $NICK :Welcome", ":irc.test 376 $NICK :End of MOTD")
}

func testDialer(addr string) IRCDialer {
	return IRCDialer{Addr: addr, NickPrefix: "bsn"}
}

func ctxTimeout(t *testing.T, d time.Duration) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

// selfSigned makes a TLS server config with a fresh self-signed cert for
// 127.0.0.1 / localhost, signed by a fresh CA (returned PEM).
func selfSigned(t *testing.T) (*tls.Config, *x509.Certificate, []byte) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	conf := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}}}
	return conf, leaf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
}
