package federation

import (
	"crypto/rand"
	"math/big"
	"strconv"
	"strings"

	"github.com/boson-chat/auth/internal/nick"
)

// maxDomainLabel bounds the domain part of a suffixed handle.
const maxDomainLabel = 16

// domainLabel is the short form of a home domain used in handles:
// boson.chat → bosonchat (letters and digits only, at most 16).
func domainLabel(domain string) string {
	var b strings.Builder
	for i := 0; i < len(domain) && b.Len() < maxDomainLabel; i++ {
		c := domain[i]
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' {
			b.WriteByte(c)
		} else if c >= 'A' && c <= 'Z' {
			b.WriteByte(c + 'a' - 'A')
		}
	}
	return b.String()
}

// handleBase is the IRC-valid form of a home username.
func handleBase(preferred string) string {
	if b := nick.Sanitize(preferred); b != "" {
		return b
	}
	return "user"
}

// fit truncates base so base+suffix fits an IRC account name.
func fit(base, suffix string) string {
	if len(base)+len(suffix) > nick.MaxLen {
		base = base[:nick.MaxLen-len(suffix)]
	}
	return base + suffix
}

// handleCandidates lists local handles to try, in order: the home username
// (alice), then with the home domain's label (alice-bosonchat), then that
// with a number (alice-bosonchat2 … alice-bosonchat20). With suffixed,
// the bare home username isn't tried: next to an existing IRC network
// (the bridge) it may be a nick someone registered there, which Boson
// can't see. Every candidate is a valid IRC account name.
func handleCandidates(preferred, domain string, suffixed bool) []string {
	base := handleBase(preferred)
	label := domainLabel(domain)
	out := []string{base}
	if suffixed && label != "" {
		out = nil
	}
	if label != "" {
		withDomain := fit(base, "-"+label)
		out = append(out, withDomain)
		for n := 2; n <= 20; n++ {
			out = append(out, fit(base, "-"+label+strconv.Itoa(n)))
		}
	} else {
		for n := 2; n <= 20; n++ {
			out = append(out, fit(base, strconv.Itoa(n)))
		}
	}
	return dedupeValid(out)
}

// randomHandle is the last resort: base plus a random 5-digit number.
func randomHandle(preferred string) (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(90000))
	if err != nil {
		return "", err
	}
	return fit(handleBase(preferred), strconv.Itoa(10000+int(n.Int64()))), nil
}

func dedupeValid(in []string) []string {
	seen := map[string]bool{}
	out := in[:0]
	for _, c := range in {
		f := nick.Fold(c)
		if seen[f] || nick.Validate(c) != nil {
			continue
		}
		seen[f] = true
		out = append(out, c)
	}
	return out
}
