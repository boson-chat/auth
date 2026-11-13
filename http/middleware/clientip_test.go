package middleware

import (
	nethttp "net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestResolveClientIP(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("::1/128")}
	isTrusted := func(a netip.Addr) bool {
		for _, p := range trusted {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}
	cases := []struct {
		name, remote string
		xff          []string
		want         string
	}{
		{"untrusted peer ignores XFF", "203.0.113.9:1234", []string{"1.2.3.4"}, "203.0.113.9"},
		{"trusted peer uses XFF", "10.0.0.5:1234", []string{"198.51.100.7"}, "198.51.100.7"},
		{"spoofed left entries ignored", "10.0.0.5:1234", []string{"6.6.6.6, 198.51.100.7"}, "198.51.100.7"},
		{"chain of trusted proxies", "10.0.0.5:1234", []string{"198.51.100.7, 10.1.1.1"}, "198.51.100.7"},
		{"multiple headers", "10.0.0.5:1234", []string{"6.6.6.6", "198.51.100.7"}, "198.51.100.7"},
		{"no XFF", "10.0.0.5:1234", nil, "10.0.0.5"},
		{"garbage XFF", "10.0.0.5:1234", []string{"nonsense"}, "10.0.0.5"},
		{"ipv6 peer", "[::1]:80", []string{"2001:db8::1"}, "2001:db8::1"},
		{"v4-mapped", "[::ffff:203.0.113.9]:80", nil, "203.0.113.9"},
	}
	for _, c := range cases {
		r := httptest.NewRequest(nethttp.MethodGet, "/", nil)
		r.RemoteAddr = c.remote
		for _, v := range c.xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		if got := ResolveClientIP(r, isTrusted); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
}
