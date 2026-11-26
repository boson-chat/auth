package nickservit

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/boson-chat/auth/internal/services/nickserv"
)

// TestMain waits (up to TEST_NICKSERV_WAIT, 3m) until the services answer
// RPC and NickServ is on both networks: the containers start in seconds,
// but services link and burst a little later.
func TestMain(m *testing.M) {
	if os.Getenv("TEST_NICKSERV") == "1" {
		wait, err := time.ParseDuration(env("TEST_NICKSERV_WAIT", "3m"))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		if err := waitReady(wait); err != nil {
			fmt.Fprintln(os.Stderr, "nickserv fixtures not ready:", err)
			os.Exit(1)
		}
	}
	os.Exit(m.Run())
}

func waitReady(total time.Duration) error {
	deadline := time.Now().Add(total)
	checks := map[string]func() error{
		"anope rpc": func() error {
			_, err := (&nickserv.Anope{RPC: nickserv.NewJSONRPC(anopeRPC, anopeToken, nil, 3*time.Second)}).
				Verify(context.Background(), nickserv.Credentials{Account: "readiness", Password: "x"})
			return rpcReady(err)
		},
		"atheme rpc": func() error {
			_, err := (&nickserv.Atheme{RPC: nickserv.NewJSONRPC(athemeJSON, "", nil, 3*time.Second)}).
				Verify(context.Background(), nickserv.Credentials{Account: "readiness", Password: "x"})
			return rpcReady(err)
		},
		"NickServ on the anope network":  func() error { return nickServOnline(anopeIRC, anopeServices) },
		"NickServ on the atheme network": func() error { return nickServOnline(athemeIRC, athemeServices) },
	}
	for name, check := range checks {
		var err error
		for {
			if err = check(); err == nil {
				break
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("%s: %w", name, err)
			}
			time.Sleep(time.Second)
		}
	}
	return nil
}

// rpcReady: an "invalid credentials" answer means the RPC works.
func rpcReady(err error) error {
	if errors.Is(err, nickserv.ErrInvalidCredentials) {
		return nil
	}
	if err == nil {
		return errors.New("unexpected success")
	}
	return err
}

// nickServOnline WHOISes NickServ and wants it on the services server.
func nickServOnline(addr, server string) error {
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(conn, "NICK rdy%d\r\nUSER rdy 0 * :ready\r\n", time.Now().UnixNano()%100000)
	r := bufio.NewReader(conn)
	whoised := false
	for {
		l, err := r.ReadString('\n')
		if err != nil {
			return err
		}
		f := strings.Fields(l)
		switch {
		case len(f) > 1 && f[0] == "PING":
			fmt.Fprintf(conn, "PONG %s\r\n", f[1])
		case len(f) > 1 && f[1] == "001" && !whoised:
			whoised = true
			fmt.Fprintf(conn, "WHOIS NickServ\r\n")
		case len(f) > 4 && f[1] == "312" && strings.EqualFold(f[3], "NickServ"):
			if strings.EqualFold(f[4], server) {
				fmt.Fprintf(conn, "QUIT\r\n")
				return nil
			}
		case len(f) > 1 && (f[1] == "401" || f[1] == "318"):
			return fmt.Errorf("NickServ not on %s yet", server)
		}
	}
}
