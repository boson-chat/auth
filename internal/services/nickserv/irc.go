package nickserv

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// maxIRCLine bounds one received line (512 + IRCv3 tags).
const maxIRCLine = 16 * 1024

// IRCDialer opens the short-lived check connections.
type IRCDialer struct {
	Addr   string
	UseTLS bool
	TLS    *tls.Config
	// ServerPassword is sent with PASS when set.
	ServerPassword string
	NickPrefix     string
	// Dial replaces the network dial (tests).
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// ircMessage is one parsed IRC line.
type ircMessage struct {
	Prefix  string
	Command string
	Params  []string
}

// Nick is the prefix's nick (before '!').
func (m *ircMessage) Nick() string {
	n, _, _ := strings.Cut(m.Prefix, "!")
	return n
}

// Host is the prefix's host (after '@'), "" if none.
func (m *ircMessage) Host() string {
	_, h, _ := strings.Cut(m.Prefix, "@")
	return h
}

// Param is the i-th parameter or "".
func (m *ircMessage) Param(i int) string {
	if i < len(m.Params) {
		return m.Params[i]
	}
	return ""
}

// Last is the last parameter or "".
func (m *ircMessage) Last() string {
	if len(m.Params) == 0 {
		return ""
	}
	return m.Params[len(m.Params)-1]
}

func parseIRC(line string) *ircMessage {
	m := &ircMessage{}
	if strings.HasPrefix(line, "@") { // IRCv3 tags: not needed
		_, line, _ = strings.Cut(line, " ")
	}
	line = strings.TrimLeft(line, " ")
	if strings.HasPrefix(line, ":") {
		m.Prefix, line, _ = strings.Cut(line[1:], " ")
	}
	for line != "" {
		line = strings.TrimLeft(line, " ")
		if line == "" {
			break
		}
		if strings.HasPrefix(line, ":") {
			m.Params = append(m.Params, line[1:])
			break
		}
		var p string
		p, line, _ = strings.Cut(line, " ")
		if m.Command == "" {
			m.Command = strings.ToUpper(p)
		} else {
			m.Params = append(m.Params, p)
		}
	}
	return m
}

// ircConn is one check connection. Every read and write is bounded by the
// context's deadline. Nothing it sends is ever logged or put in an error.
type ircConn struct {
	conn net.Conn
	r    *bufio.Reader
	nick string
	pfx  string
	// stop unregisters the context watcher that aborts I/O on cancel.
	stop func() bool
}

func randomNick(prefix string) string {
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

func (d IRCDialer) open(ctx context.Context) (*ircConn, error) {
	dial := d.Dial
	if dial == nil {
		var nd net.Dialer
		dial = nd.DialContext
	}
	conn, err := dial(ctx, "tcp", d.Addr)
	if err != nil {
		return nil, fmt.Errorf("%w: connecting to %s: %s", ErrUnavailable, d.Addr, redactURLError(err))
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if d.UseTLS {
		conf := d.TLS.Clone()
		if conf == nil {
			conf = &tls.Config{MinVersion: tls.VersionTLS12}
		}
		if conf.ServerName == "" {
			host, _, _ := net.SplitHostPort(d.Addr)
			conf.ServerName = host
		}
		tc := tls.Client(conn, conf)
		if err := tc.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("%w: TLS with %s: %v", ErrUnavailable, d.Addr, err)
		}
		conn = tc
	}
	prefix := d.NickPrefix
	if prefix == "" {
		prefix = "bsn"
	}
	c := &ircConn{conn: conn, r: bufio.NewReaderSize(conn, maxIRCLine), nick: randomNick(prefix), pfx: prefix}
	// A cancelled request aborts blocked reads and writes at once.
	c.stop = context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	return c, nil
}

var errBadParam = errors.New("nickserv: parameter contains CR, LF or NUL")

// send writes one line. A line with CR/LF/NUL in it is refused (it would
// inject a second command). The error never contains the line.
func (c *ircConn) send(line string) error {
	if strings.ContainsAny(line, "\r\n\x00") {
		return errBadParam
	}
	if len(line) > 510 {
		return fmt.Errorf("%w: line too long for IRC", ErrUnsupported)
	}
	if _, err := c.conn.Write([]byte(line + "\r\n")); err != nil {
		return fmt.Errorf("%w: writing to the IRC server: %s", ErrUnavailable, redactURLError(err))
	}
	return nil
}

// read returns the next message, answering PINGs on the way.
func (c *ircConn) read() (*ircMessage, error) {
	for {
		line, err := c.r.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			return nil, fmt.Errorf("%w: IRC line too long", ErrUnavailable)
		}
		if err != nil {
			return nil, fmt.Errorf("%w: reading from the IRC server: %s", ErrUnavailable, redactURLError(err))
		}
		s := strings.TrimRight(string(line), "\r\n")
		if s == "" {
			continue
		}
		m := parseIRC(s)
		switch m.Command {
		case "PING":
			if err := c.send("PONG :" + m.Last()); err != nil {
				return nil, err
			}
			continue
		case "ERROR":
			return nil, fmt.Errorf("%w: the IRC server closed the connection: %s", ErrUnavailable, StripFormatting(m.Last()))
		}
		return m, nil
	}
}

// renick picks a new nick after 432/433/436 during registration.
func (c *ircConn) renick() error {
	c.nick = randomNick(c.pfx)
	return c.send("NICK " + c.nick)
}

// hello sends PASS (if any), optionally CAP LS, NICK and USER.
func (c *ircConn) hello(serverPassword string, capLS bool) error {
	if capLS {
		if err := c.send("CAP LS 302"); err != nil {
			return err
		}
	}
	if serverPassword != "" {
		if err := c.send("PASS :" + serverPassword); err != nil {
			return err
		}
	}
	if err := c.send("NICK " + c.nick); err != nil {
		return err
	}
	return c.send("USER boson 0 * :Boson account check")
}

func (c *ircConn) close() {
	c.stop()
	_ = c.conn.SetWriteDeadline(time.Now().Add(time.Second))
	_ = c.send("QUIT :Boson account check done")
	_ = c.conn.Close()
}

// nickErrors are the registration numerics that mean "pick another nick".
func nickError(cmd string) bool { return cmd == "432" || cmd == "433" || cmd == "436" || cmd == "437" }

// Numerics that end a connection attempt before registration.
func fatalRegistration(m *ircMessage) error {
	switch m.Command {
	case "465", "463", "464": // banned / no permission / wrong server password
		return fmt.Errorf("%w: the IRC server refused the check connection (%s %s)", ErrUnavailable, m.Command, StripFormatting(m.Last()))
	}
	return nil
}

// shortTimeout bounds a wait for an optional message after the result.
func shortTimeout(ctx context.Context, conn net.Conn, d time.Duration) func() {
	_ = conn.SetReadDeadline(time.Now().Add(d))
	return func() {
		if dl, ok := ctx.Deadline(); ok {
			_ = conn.SetReadDeadline(dl)
		} else {
			_ = conn.SetReadDeadline(time.Time{})
		}
	}
}
