package nickserv

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/boson-chat/auth/config"
)

const secret = "s3cret pass:word"

// noSecret fails if err's text contains the password.
func noSecret(t *testing.T, err error) {
	t.Helper()
	if err != nil && strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaks the password: %v", err)
	}
}

// saslServer answers like InspIRCd + services: sasl=PLAIN,EXTERNAL, then
// 900+903 for alice/secret, 904 otherwise.
func saslServer(c *fakeClient) {
	switch l := c.read(); l {
	case "CAP LS 302":
	case "": // the client gave up (e.g. a refused TLS handshake)
		return
	default:
		c.t.Errorf("first line %q, want CAP LS 302", l)
		return
	}
	c.until("USER ")
	c.send(":irc.test CAP * LS * :multi-prefix account-tag", ":irc.test CAP * LS :cap-notify sasl=PLAIN,EXTERNAL")
	if l := c.read(); l != "CAP REQ :sasl" {
		c.t.Errorf("got %q, want CAP REQ :sasl", l)
		return
	}
	c.send(":irc.test CAP * ACK :sasl")
	if l := c.read(); l != "AUTHENTICATE PLAIN" {
		c.t.Errorf("got %q", l)
		return
	}
	c.send("AUTHENTICATE +")
	payload := strings.TrimPrefix(c.read(), "AUTHENTICATE ")
	raw, _ := base64.StdEncoding.DecodeString(payload)
	parts := strings.Split(string(raw), "\x00")
	if len(parts) == 3 && strings.EqualFold(parts[1], "alice") && parts[2] == secret {
		c.send(":irc.test 900 * * Alice :You are now logged in as Alice", ":irc.test 903 * :SASL authentication successful")
	} else {
		c.send(":irc.test 904 * :SASL authentication failed")
	}
	c.until("QUIT")
}

func TestSASLSuccessAndFailure(t *testing.T) {
	srv := newFakeIRC(t, nil, saslServer)
	s := &SASL{Dialer: testDialer(srv.addr())}
	acct, err := s.Verify(ctxTimeout(t, 5*time.Second), Credentials{Account: "alice", Password: secret})
	if err != nil {
		t.Fatal(err)
	}
	if acct.Name != "Alice" {
		t.Fatalf("account %q, want the 900 spelling Alice", acct.Name)
	}
	_, err = s.Verify(ctxTimeout(t, 5*time.Second), Credentials{Account: "alice", Password: "wrong"})
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password: %v", err)
	}
	for _, l := range srv.sent() {
		if strings.HasPrefix(l, "CAP END") {
			t.Fatal("the check must never finish registration (CAP END)")
		}
	}
}

func TestSASLUnsupported(t *testing.T) {
	cases := map[string]func(c *fakeClient){
		"no sasl cap": func(c *fakeClient) {
			c.until("USER ")
			c.send(":irc.test CAP * LS :multi-prefix")
			c.until("QUIT")
		},
		"external only": func(c *fakeClient) {
			c.until("USER ")
			c.send(":irc.test CAP * LS :sasl=EXTERNAL")
			c.until("QUIT")
		},
		"no CAP at all (ngircd-style registration)": func(c *fakeClient) {
			c.until("USER ")
			c.send(":irc.test 421 * CAP :Unknown command")
			c.until("QUIT")
		},
		"registers straight away": func(c *fakeClient) {
			c.welcome()
			c.until("QUIT")
		},
	}
	for name, script := range cases {
		t.Run(name, func(t *testing.T) {
			srv := newFakeIRC(t, nil, script)
			s := &SASL{Dialer: testDialer(srv.addr())}
			_, err := s.Verify(ctxTimeout(t, 5*time.Second), Credentials{Account: "alice", Password: secret})
			if !errors.Is(err, ErrUnsupported) {
				t.Fatalf("got %v, want ErrUnsupported", err)
			}
			for _, l := range srv.sent() {
				if strings.Contains(l, "AUTHENTICATE") {
					t.Fatal("sent AUTHENTICATE without SASL PLAIN on offer")
				}
			}
		})
	}
}

func TestSASLLongPayloadIsChunked(t *testing.T) {
	long := strings.Repeat("p", 450)
	var chunks []string
	srv := newFakeIRC(t, nil, func(c *fakeClient) {
		c.until("USER ")
		c.send(":irc.test CAP * LS :sasl")
		c.read()
		c.send(":irc.test CAP * ACK :sasl")
		c.read()
		c.send("AUTHENTICATE +")
		for {
			l := strings.TrimPrefix(c.read(), "AUTHENTICATE ")
			chunks = append(chunks, l)
			if len(l) < 400 {
				break
			}
		}
		c.send(":irc.test 903 * :ok")
		c.until("QUIT")
	})
	s := &SASL{Dialer: testDialer(srv.addr())}
	if _, err := s.Verify(ctxTimeout(t, 5*time.Second), Credentials{Account: "alice", Password: long}); err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(strings.Join(chunks, ""))
	if len(chunks) < 2 || len(chunks[0]) != 400 || !strings.HasSuffix(string(raw), long) {
		t.Fatalf("chunks %d (first %d bytes), payload ok=%v", len(chunks), len(chunks[0]), strings.HasSuffix(string(raw), long))
	}
}

func TestSASLTimeout(t *testing.T) {
	srv := newFakeIRC(t, nil, func(c *fakeClient) {
		c.until("USER ")
		time.Sleep(2 * time.Second) // never answers in time
	})
	s := &SASL{Dialer: testDialer(srv.addr())}
	start := time.Now()
	_, err := s.Verify(ctxTimeout(t, 300*time.Millisecond), Credentials{Account: "alice", Password: secret})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("got %v, want ErrUnavailable", err)
	}
	if time.Since(start) > time.Second {
		t.Fatalf("timeout not enforced: %v", time.Since(start))
	}
	noSecret(t, err)
}

func TestSASLServerDown(t *testing.T) {
	s := &SASL{Dialer: testDialer("127.0.0.1:1")}
	_, err := s.Verify(ctxTimeout(t, 2*time.Second), Credentials{Account: "alice", Password: secret})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("got %v", err)
	}
}

func anopePatterns(t *testing.T) Patterns {
	p, err := PatternsFor(config.NickServConfig{Services: config.ServicesAnope})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func athemePatterns(t *testing.T) Patterns {
	p, err := PatternsFor(config.NickServConfig{Services: config.ServicesAtheme})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// identifyServer is NickServ answering IDENTIFY with reply(account, password).
func identifyServer(reply func(account, password string) []string) func(c *fakeClient) {
	return func(c *fakeClient) {
		c.welcome()
		l := c.until("PRIVMSG ")
		msg := l[strings.Index(l, " :")+2:]
		fields := strings.SplitN(msg, " ", 3)
		if len(fields) != 3 || fields[0] != "IDENTIFY" {
			c.t.Errorf("unexpected %q", l)
			return
		}
		c.send(reply(fields[1], fields[2])...)
		c.until("QUIT")
	}
}

func TestIdentifyAnope(t *testing.T) {
	srv := newFakeIRC(t, nil, identifyServer(func(a, p string) []string {
		switch {
		case a == "nobody":
			return []string{":NickServ!services@services.test NOTICE $NICK :Nick \x02nobody\x02 isn't registered."}
		case p == secret:
			// Noise from another nick first: it must be ignored.
			return []string{
				":Mallory!m@evil NOTICE $NICK :Password accepted - you are now recognized.",
				":NickServ!services@services.test NOTICE $NICK :Password accepted - you are now recognized.",
				":irc.test 900 $NICK $NICK!boson@host Alice :You are now logged in as Alice",
			}
		case p == "suspended":
			return []string{":NickServ!services@services.test NOTICE $NICK :Nick alice is currently suspended."}
		}
		return []string{":NickServ!services@services.test NOTICE $NICK :Password incorrect."}
	}))
	s := &Identify{Dialer: testDialer(srv.addr()), ServiceNick: "NickServ", Target: "NickServ", Patterns: anopePatterns(t)}
	ctx := ctxTimeout(t, 5*time.Second)
	acct, err := s.Verify(ctx, Credentials{Account: "alice", Password: secret})
	if err != nil || acct.Name != "Alice" {
		t.Fatalf("success: %+v %v", acct, err)
	}
	if _, err := s.Verify(ctx, Credentials{Account: "alice", Password: "nope"}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password: %v", err)
	}
	if _, err := s.Verify(ctx, Credentials{Account: "nobody", Password: secret}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("unknown account: %v", err)
	}
	_, err = s.Verify(ctx, Credentials{Account: "alice", Password: "suspended"})
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("suspended: %v", err)
	}
	if !strings.Contains(err.Error(), "suspended") {
		t.Fatalf("refusal should carry the services' text: %v", err)
	}
}

func TestIdentifyAtheme(t *testing.T) {
	srv := newFakeIRC(t, nil, identifyServer(func(a, p string) []string {
		if p == secret {
			return []string{":NickServ!NickServ@services.test NOTICE $NICK :You are now logged in as \x02Alice\x02."}
		}
		if p == "frozen" {
			return []string{":NickServ!NickServ@services.test NOTICE $NICK :You cannot log in as \x02alice\x02 because the account has been frozen."}
		}
		return []string{":NickServ!NickServ@services.test NOTICE $NICK :Invalid password for \x02alice\x02."}
	}))
	s := &Identify{Dialer: testDialer(srv.addr()), ServiceNick: "NickServ", Target: "NickServ", Patterns: athemePatterns(t)}
	ctx := ctxTimeout(t, 5*time.Second)
	acct, err := s.Verify(ctx, Credentials{Account: "alice", Password: secret})
	if err != nil || acct.Name != "Alice" {
		t.Fatalf("success: %+v %v", acct, err)
	}
	if _, err := s.Verify(ctx, Credentials{Account: "alice", Password: "x"}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password: %v", err)
	}
	if _, err := s.Verify(ctx, Credentials{Account: "alice", Password: "frozen"}); !errors.Is(err, ErrRefused) {
		t.Fatalf("frozen: %v", err)
	}
}

func TestIdentifyNoNickServ(t *testing.T) {
	srv := newFakeIRC(t, nil, func(c *fakeClient) {
		c.welcome()
		c.until("PRIVMSG ")
		c.send(":irc.test 401 $NICK NickServ :No such nick or channel name")
		c.until("QUIT")
	})
	s := &Identify{Dialer: testDialer(srv.addr()), ServiceNick: "NickServ", Target: "NickServ", Patterns: anopePatterns(t)}
	_, err := s.Verify(ctxTimeout(t, 5*time.Second), Credentials{Account: "alice", Password: secret})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("got %v", err)
	}
	noSecret(t, err)
}

func TestIdentifyServicesServerCheck(t *testing.T) {
	impostor := newFakeIRC(t, nil, func(c *fakeClient) {
		c.welcome()
		c.until("WHOIS ")
		c.send(":irc.test 311 $NICK NickServ evil host * :x", ":irc.test 312 $NICK NickServ irc.test :a normal server", ":irc.test 318 $NICK NickServ :End")
		c.until("QUIT")
	})
	s := &Identify{Dialer: testDialer(impostor.addr()), ServiceNick: "NickServ", Target: "NickServ",
		ServicesServer: "services.test", Patterns: anopePatterns(t)}
	_, err := s.Verify(ctxTimeout(t, 5*time.Second), Credentials{Account: "alice", Password: secret})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("got %v", err)
	}
	for _, l := range impostor.sent() {
		if strings.Contains(l, secret) || strings.Contains(l, "IDENTIFY") {
			t.Fatalf("password sent to an impostor NickServ: %q", l)
		}
	}

	real := newFakeIRC(t, nil, func(c *fakeClient) {
		c.welcome()
		c.until("WHOIS ")
		c.send(":irc.test 312 $NICK NickServ services.test :Services", ":irc.test 318 $NICK NickServ :End")
		c.until("PRIVMSG ")
		c.send(":NickServ!s@services.test NOTICE $NICK :Password accepted - you are now recognized.")
		c.until("QUIT")
	})
	s.Dialer = testDialer(real.addr())
	if _, err := s.Verify(ctxTimeout(t, 5*time.Second), Credentials{Account: "alice", Password: secret}); err != nil {
		t.Fatal(err)
	}
}

func TestIdentifyNickInUseAndPing(t *testing.T) {
	srv := newFakeIRC(t, nil, func(c *fakeClient) {
		c.until("USER ")
		c.send(":irc.test 433 * $NICK :Nickname is already in use")
		c.until("NICK ")
		c.send("PING :abc")
		if l := c.read(); l != "PONG :abc" {
			c.t.Errorf("got %q, want PONG", l)
		}
		c.send(":irc.test 001 $NICK :Welcome")
		c.until("PRIVMSG NickServ :IDENTIFY")
		c.send(":NickServ!s@services NOTICE $NICK :Password accepted - you are now recognized.")
		c.until("QUIT")
	})
	s := &Identify{Dialer: testDialer(srv.addr()), ServiceNick: "NickServ", Target: "NickServ", Patterns: anopePatterns(t)}
	if _, err := s.Verify(ctxTimeout(t, 5*time.Second), Credentials{Account: "alice", Password: secret}); err != nil {
		t.Fatal(err)
	}
}

func TestIdentifyCustomPatterns(t *testing.T) {
	p, err := PatternsFor(config.NickServConfig{
		Services:        config.ServicesAnope,
		IdentifySuccess: `["^OK as (?P<account>\\S+)$"]`,
		IdentifyFailure: "^NO$\n^BAD$",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Refused) == 0 {
		t.Fatal("unset refused patterns should keep the defaults")
	}
	srv := newFakeIRC(t, nil, identifyServer(func(a, pw string) []string {
		if pw == secret {
			return []string{":NickServ!s@x NOTICE $NICK :OK as Alice"}
		}
		return []string{":NickServ!s@x NOTICE $NICK :BAD"}
	}))
	s := &Identify{Dialer: testDialer(srv.addr()), ServiceNick: "NickServ", Target: "NickServ", Patterns: p}
	ctx := ctxTimeout(t, 5*time.Second)
	if acct, err := s.Verify(ctx, Credentials{Account: "alice", Password: secret}); err != nil || acct.Name != "Alice" {
		t.Fatalf("%+v %v", acct, err)
	}
	if _, err := s.Verify(ctx, Credentials{Account: "alice", Password: "x"}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatal(err)
	}
}

func TestLineInjectionRefused(t *testing.T) {
	srv := newFakeIRC(t, nil, func(c *fakeClient) {
		c.welcome()
		c.until("QUIT")
	})
	s := &Identify{Dialer: testDialer(srv.addr()), ServiceNick: "NickServ", Target: "NickServ", Patterns: anopePatterns(t)}
	_, err := s.Verify(ctxTimeout(t, 5*time.Second), Credentials{Account: "alice", Password: "x\r\nPRIVMSG #chan :spam"})
	if err == nil {
		t.Fatal("a password with CR/LF must not be sent")
	}
	noSecret(t, err)
	for _, l := range srv.sent() {
		if strings.Contains(l, "spam") {
			t.Fatalf("injected line reached the server: %q", l)
		}
	}
	if ValidPassword("a\nb") || ValidPassword("") || !ValidPassword(secret) {
		t.Fatal("ValidPassword")
	}
	for _, bad := range []string{"", "a b", ":x", "#chan", "a@b.c", "a\x00", strings.Repeat("a", 65)} {
		if ValidAccount(bad) {
			t.Errorf("ValidAccount(%q) = true", bad)
		}
	}
	if !ValidAccount("[Alice]_|") {
		t.Error("ValidAccount rejects a normal nick")
	}
}

func TestTLSPinsAndCA(t *testing.T) {
	serverConf, leaf, caPEM := selfSigned(t)
	srv := newFakeIRC(t, serverConf, saslServer)
	host, port := "127.0.0.1", srv.addr()[strings.LastIndex(srv.addr(), ":")+1:]
	addr := host + ":" + port
	verify := func(cfg config.NickServConfig) error {
		tc, err := TLSConfig(cfg)
		if err != nil {
			t.Fatal(err)
		}
		d := testDialer(addr)
		d.UseTLS, d.TLS = true, tc
		_, err = (&SASL{Dialer: d}).Verify(ctxTimeout(t, 5*time.Second), Credentials{Account: "alice", Password: secret})
		noSecret(t, err)
		return err
	}
	// System roots: the test CA is unknown.
	if err := verify(config.NickServConfig{}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("untrusted cert accepted: %v", err)
	}
	// The right pin alone.
	pin := hex.EncodeToString(SPKIPin(leaf))
	if err := verify(config.NickServConfig{TLSPins: pin}); err != nil {
		t.Fatalf("pinned: %v", err)
	}
	// A wrong pin.
	if err := verify(config.NickServConfig{TLSPins: strings.Repeat("ab", 32)}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("wrong pin accepted: %v", err)
	}
	// The CA file.
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verify(config.NickServConfig{TLSCAFile: caFile}); err != nil {
		t.Fatalf("CA file: %v", err)
	}
	// CA file + right pin (base64 form) / wrong name.
	if err := verify(config.NickServConfig{TLSCAFile: caFile, TLSPins: base64.StdEncoding.EncodeToString(SPKIPin(leaf))}); err != nil {
		t.Fatalf("CA + pin: %v", err)
	}
	if err := verify(config.NickServConfig{TLSCAFile: caFile, TLSServerName: "irc.example.org"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("wrong name accepted: %v", err)
	}
}

func TestStripFormatting(t *testing.T) {
	cases := map[string]string{
		"\x02bold\x02 text":               "bold text",
		"\x0304,12red\x03 plain":          "red plain",
		"\x03 3 not a colour":             "3 not a colour",
		"\x04ff0000hex\x0f done":          "hex done",
		"  \x1ditalic\x1d \x1funder\x1f ": "italic under",
	}
	for in, want := range cases {
		if got := StripFormatting(in); got != want {
			t.Errorf("StripFormatting(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseIRC(t *testing.T) {
	m := parseIRC("@time=x :nick!user@host PRIVMSG #chan :hello there")
	if m.Nick() != "nick" || m.Host() != "host" || m.Command != "PRIVMSG" || m.Param(0) != "#chan" || m.Last() != "hello there" {
		t.Fatalf("%+v", m)
	}
	if m := parseIRC("ping :x"); m.Command != "PING" || m.Last() != "x" {
		t.Fatalf("%+v", m)
	}
}
