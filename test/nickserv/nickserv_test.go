// Package nickservit checks the NickServ strategies against real services
// and IRC servers: Anope 2.1 behind InspIRCd 4, Atheme 7.2 behind ngircd 27
// (compose.yaml next to this file).
//
//	make test-nickserv          # up, go test, down
//
// Skipped unless TEST_NICKSERV=1.
package nickservit

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/boson-chat/auth/config"
	"github.com/boson-chat/auth/internal/services/nickserv"
)

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

var (
	anopeRPC       = env("TEST_NICKSERV_ANOPE_RPC", "http://127.0.0.1:38080/jsonrpc")
	anopeToken     = env("TEST_NICKSERV_ANOPE_TOKEN", "anope-rpc-token")
	anopeIRC       = env("TEST_NICKSERV_ANOPE_IRC", "127.0.0.1:36667")
	anopeIRCTLS    = env("TEST_NICKSERV_ANOPE_IRC_TLS", "127.0.0.1:36697")
	athemeJSON     = env("TEST_NICKSERV_ATHEME_JSONRPC", "http://127.0.0.1:38081/jsonrpc")
	athemeXML      = env("TEST_NICKSERV_ATHEME_XMLRPC", "http://127.0.0.1:38081/xmlrpc")
	athemeIRC      = env("TEST_NICKSERV_ATHEME_IRC", "127.0.0.1:37667")
	athemeIRCTLS   = env("TEST_NICKSERV_ATHEME_IRC_TLS", "127.0.0.1:37697")
	athemeMailbox  = env("TEST_NICKSERV_ATHEME_CONTAINER", "auth-nickserv-test-atheme-1")
	certsDir       = env("TEST_NICKSERV_CERTS", ".certs")
	anopeServices  = "services.anope.test"
	athemeServices = "services.atheme.test"
)

func skipUnlessEnabled(t *testing.T) {
	t.Helper()
	if os.Getenv("TEST_NICKSERV") != "1" {
		t.Skip("TEST_NICKSERV=1 not set (make test-nickserv)")
	}
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return c
}

func randName(prefix string) string {
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

func backend(t *testing.T, cfg config.NickServConfig) *nickserv.Backend {
	t.Helper()
	if cfg.Timeout == 0 {
		cfg.Timeout = 15 * time.Second
	}
	if cfg.IRCNickPrefix == "" {
		cfg.IRCNickPrefix = "bsn"
	}
	if cfg.ServiceNick == "" {
		cfg.ServiceNick = "NickServ"
	}
	cfg.Registration, cfg.StoreSession, cfg.MaxConcurrent, cfg.LinkExisting = true, false, 4, config.LinkExistingUnclaimed
	cfg.RateAccountBurst, cfg.RateAccountPerMinute, cfg.RateIPBurst, cfg.RateIPPerMinute = 1, 1, 1, 1
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	b, err := nickserv.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// ircSession is a plain IRC client for setting up accounts.
type ircSession struct {
	t    *testing.T
	conn net.Conn
	r    *bufio.Reader
	nick string
}

func dialIRC(t *testing.T, addr, nick string) *ircSession {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	s := &ircSession{t: t, conn: conn, r: bufio.NewReader(conn), nick: nick}
	s.send("NICK " + nick)
	s.send("USER " + nick + " 0 * :fixture")
	s.waitFor(func(l string) bool { return strings.Contains(l, " 001 ") })
	return s
}

func (s *ircSession) send(l string) { _, _ = s.conn.Write([]byte(l + "\r\n")) }

func (s *ircSession) waitFor(match func(string) bool) string {
	s.t.Helper()
	for {
		l, err := s.r.ReadString('\n')
		if err != nil {
			s.t.Fatalf("IRC read: %v", err)
		}
		l = strings.TrimRight(l, "\r\n")
		if strings.HasPrefix(l, "PING ") {
			s.send("PONG " + l[5:])
			continue
		}
		if match(l) {
			return l
		}
	}
}

func (s *ircSession) close() { s.send("QUIT"); _ = s.conn.Close() }

// registerAnope registers nick on the Anope network like a user would.
func registerAnope(t *testing.T, nick, password string) {
	t.Helper()
	s := dialIRC(t, anopeIRC, nick)
	defer s.close()
	s.send("PRIVMSG NickServ :REGISTER " + password + " " + nick + "@example.org")
	l := s.waitFor(func(l string) bool {
		return strings.Contains(l, "NOTICE "+nick+" :") && strings.HasPrefix(l, ":NickServ!")
	})
	if !strings.Contains(l, "registered") {
		t.Fatalf("Anope REGISTER: %s", l)
	}
}

func caFile(t *testing.T) string {
	p, err := filepath.Abs(filepath.Join(certsDir, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func ircPin(t *testing.T) string {
	raw, err := os.ReadFile(filepath.Join(certsDir, "irc.pem"))
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(raw)
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(nickserv.SPKIPin(cert))
}

// checkVerifier runs the standard right / wrong / unknown checks.
func checkVerifier(t *testing.T, v nickserv.Verifier, account, password string) *nickserv.Account {
	t.Helper()
	acct, err := v.Verify(ctx(t), nickserv.Credentials{Account: account, Password: password, ClientIP: "192.0.2.10"})
	if err != nil {
		t.Fatalf("right password: %v", err)
	}
	if !strings.EqualFold(acct.Name, account) {
		t.Fatalf("account %q, want %q", acct.Name, account)
	}
	_, err = v.Verify(ctx(t), nickserv.Credentials{Account: account, Password: password + "x"})
	if !errors.Is(err, nickserv.ErrInvalidCredentials) {
		t.Fatalf("wrong password: %v", err)
	}
	if err != nil && strings.Contains(err.Error(), password) {
		t.Fatalf("error leaks the password: %v", err)
	}
	_, err = v.Verify(ctx(t), nickserv.Credentials{Account: randName("nobody"), Password: password})
	if !errors.Is(err, nickserv.ErrInvalidCredentials) {
		t.Fatalf("unknown account: %v", err)
	}
	return acct
}

func TestAnope(t *testing.T) {
	skipUnlessEnabled(t)
	nick, password := randName("alice"), "anope-pass-"+randName("")
	registerAnope(t, nick, password)

	t.Run("anope_rpc", func(t *testing.T) {
		b := backend(t, config.NickServConfig{Strategy: config.StrategyAnopeRPC, RPCURL: anopeRPC, RPCToken: anopeToken})
		acct := checkVerifier(t, b.Verifier, nick, password)
		if acct.Email != nick+"@example.org" || acct.ID == "" || acct.Confirmed == nil || !*acct.Confirmed {
			t.Fatalf("account info: %+v", acct)
		}
		if b.Registrar != nil {
			t.Fatal("Anope's RPC can't register; sign-up must be off")
		}
		bad := backend(t, config.NickServConfig{Strategy: config.StrategyAnopeRPC, RPCURL: anopeRPC, RPCToken: "wrong-token"})
		if _, err := bad.Verifier.Verify(ctx(t), nickserv.Credentials{Account: nick, Password: password}); !errors.Is(err, nickserv.ErrUnavailable) {
			t.Fatalf("wrong RPC token: %v", err)
		}
	})
	t.Run("sasl/inspircd tls+ca", func(t *testing.T) {
		b := backend(t, config.NickServConfig{Strategy: config.StrategySASL, IRCAddr: anopeIRCTLS, IRCTLS: true,
			TLSCAFile: caFile(t), TLSServerName: "localhost"})
		checkVerifier(t, b.Verifier, nick, password)
	})
	t.Run("sasl/inspircd tls+pin", func(t *testing.T) {
		b := backend(t, config.NickServConfig{Strategy: config.StrategySASL, IRCAddr: anopeIRCTLS, IRCTLS: true, TLSPins: ircPin(t)})
		checkVerifier(t, b.Verifier, nick, password)
		wrong := backend(t, config.NickServConfig{Strategy: config.StrategySASL, IRCAddr: anopeIRCTLS, IRCTLS: true, TLSPins: strings.Repeat("00", 32)})
		if _, err := wrong.Verifier.Verify(ctx(t), nickserv.Credentials{Account: nick, Password: password}); !errors.Is(err, nickserv.ErrUnavailable) {
			t.Fatalf("wrong pin: %v", err)
		}
	})
	t.Run("sasl/inspircd system roots refuse the test CA", func(t *testing.T) {
		b := backend(t, config.NickServConfig{Strategy: config.StrategySASL, IRCAddr: anopeIRCTLS, IRCTLS: true})
		_, err := b.Verifier.Verify(ctx(t), nickserv.Credentials{Account: nick, Password: password})
		var ue x509.UnknownAuthorityError
		if !errors.Is(err, nickserv.ErrUnavailable) || !(errors.As(err, &ue) || strings.Contains(err.Error(), "certificate")) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("identify/inspircd", func(t *testing.T) {
		b := backend(t, config.NickServConfig{Strategy: config.StrategyIdentify, Services: config.ServicesAnope,
			IRCAddr: anopeIRC, IRCTLS: false, ServicesServer: anopeServices})
		checkVerifier(t, b.Verifier, nick, password)
	})
	t.Run("identify/inspircd wrong services server", func(t *testing.T) {
		b := backend(t, config.NickServConfig{Strategy: config.StrategyIdentify, Services: config.ServicesAnope,
			IRCAddr: anopeIRC, IRCTLS: false, ServicesServer: "irc.anope.test"})
		if _, err := b.Verifier.Verify(ctx(t), nickserv.Credentials{Account: nick, Password: password}); !errors.Is(err, nickserv.ErrUnavailable) {
			t.Fatalf("got %v", err)
		}
	})
}

// athemeKey reads the verification key Atheme mailed for account.
func athemeKey(t *testing.T, account string) string {
	t.Helper()
	re := regexp.MustCompile(`(?i)VERIFY REGISTER ` + regexp.QuoteMeta(account) + ` (\S+)`)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		out, err := exec.Command("docker", "exec", athemeMailbox, "sh", "-c", "cat /mail/*.eml 2>/dev/null").Output()
		if err == nil {
			if m := re.FindStringSubmatch(string(out)); m != nil {
				return m[1]
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("no verification email for %s in %s:/mail", account, athemeMailbox)
	return ""
}

func TestAtheme(t *testing.T) {
	skipUnlessEnabled(t)
	for _, tc := range []struct{ strategy, url string }{
		{config.StrategyAthemeJSONRPC, athemeJSON},
		{config.StrategyAthemeXMLRPC, athemeXML},
	} {
		t.Run(tc.strategy, func(t *testing.T) {
			b := backend(t, config.NickServConfig{Strategy: tc.strategy, RPCURL: tc.url})
			account, password := randName("bob"), "atheme-pass-"+randName("")
			reg, err := b.Registrar.Register(ctx(t), account, password, account+"@example.org", "192.0.2.10")
			if err != nil {
				t.Fatal(err)
			}
			if !reg.VerificationRequired {
				t.Fatalf("auth = email, but no verification required: %+v", reg)
			}
			if _, err := b.Registrar.Register(ctx(t), account, password, account+"@example.org", ""); !errors.Is(err, nickserv.ErrAccountExists) {
				t.Fatalf("registering twice: %v", err)
			}
			var rej *nickserv.RejectedError
			if _, err := b.Registrar.Register(ctx(t), randName("c"), password, "not-an-email", ""); !errors.As(err, &rej) {
				t.Fatalf("bad email: %v", err)
			}
			acct, err := b.Verifier.Verify(ctx(t), nickserv.Credentials{Account: account, Password: password})
			if err != nil || acct.Confirmed == nil || *acct.Confirmed {
				t.Fatalf("before VERIFY: %+v %v", acct, err)
			}
			if err := b.Registrar.ConfirmRegistration(ctx(t), account, "wrongkey", ""); !errors.Is(err, nickserv.ErrInvalidCode) {
				t.Fatalf("wrong key: %v", err)
			}
			if err := b.Registrar.ConfirmRegistration(ctx(t), account, athemeKey(t, account), ""); err != nil {
				t.Fatal(err)
			}
			acct = checkVerifier(t, b.Verifier, account, password)
			if acct.Email != account+"@example.org" || acct.ID == "" || !*acct.Confirmed {
				t.Fatalf("account info: %+v", acct)
			}
			// The authcookie can be kept and ended.
			keep := &nickserv.Atheme{RPC: nickserv.NewJSONRPC(athemeJSON, "", nil, 10*time.Second), KeepSession: true}
			if tc.strategy == config.StrategyAthemeXMLRPC {
				keep.RPC = nickserv.NewXMLRPC(athemeXML, nil, 10*time.Second)
			}
			acct, err = keep.Verify(ctx(t), nickserv.Credentials{Account: account, Password: password})
			if err != nil || acct.Session == nil || acct.Session.Token == "" {
				t.Fatalf("session: %+v %v", acct, err)
			}
			if err := keep.EndSession(ctx(t), account, *acct.Session); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAthemeOverIRC(t *testing.T) {
	skipUnlessEnabled(t)
	rpc := backend(t, config.NickServConfig{Strategy: config.StrategyAthemeJSONRPC, RPCURL: athemeJSON})
	account, password := randName("dan"), "atheme-pass-"+randName("")
	if _, err := rpc.Registrar.Register(ctx(t), account, password, account+"@example.org", ""); err != nil {
		t.Fatal(err)
	}
	if err := rpc.Registrar.ConfirmRegistration(ctx(t), account, athemeKey(t, account), ""); err != nil {
		t.Fatal(err)
	}
	t.Run("identify/ngircd", func(t *testing.T) {
		b := backend(t, config.NickServConfig{Strategy: config.StrategyIdentify, Services: config.ServicesAtheme,
			IRCAddr: athemeIRC, IRCTLS: false, ServicesServer: athemeServices})
		checkVerifier(t, b.Verifier, account, password)
	})
	t.Run("identify/ngircd tls+ca", func(t *testing.T) {
		b := backend(t, config.NickServConfig{Strategy: config.StrategyIdentify, Services: config.ServicesAtheme,
			IRCAddr: athemeIRCTLS, IRCTLS: true, TLSCAFile: caFile(t), TLSServerName: "localhost"})
		checkVerifier(t, b.Verifier, account, password)
	})
	t.Run("sasl/ngircd is unsupported", func(t *testing.T) {
		b := backend(t, config.NickServConfig{Strategy: config.StrategySASL, IRCAddr: athemeIRC, IRCTLS: false})
		_, err := b.Verifier.Verify(ctx(t), nickserv.Credentials{Account: account, Password: password})
		if !errors.Is(err, nickserv.ErrUnsupported) {
			t.Fatalf("got %v, want ErrUnsupported", err)
		}
	})
}
