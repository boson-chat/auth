package nickserv

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"github.com/boson-chat/auth/config"
)

// TLSConfig builds the client TLS config for the IRC / RPC connections:
//
//   - NICKSERV_TLS_CA_FILE: the chain must lead to one of these CAs
//     (instead of the system roots), and the name must match;
//   - NICKSERV_TLS_PIN_SHA256: the leaf's public key must match a pin. With
//     pins and no CA file the chain and name aren't checked (self-signed
//     IRC certificates); with both, everything is;
//   - neither: normal verification against the system roots.
//
// ServerName is NICKSERV_TLS_SERVER_NAME, else Go's default (the dialled host).
func TLSConfig(cfg config.NickServConfig) (*tls.Config, error) {
	pins, err := config.ParsePins(cfg.TLSPins)
	if err != nil {
		return nil, err
	}
	c := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: cfg.TLSServerName}
	if cfg.TLSCAFile != "" {
		pem, err := os.ReadFile(cfg.TLSCAFile)
		if err != nil {
			return nil, fmt.Errorf("NICKSERV_TLS_CA_FILE: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("NICKSERV_TLS_CA_FILE %s has no PEM certificates", cfg.TLSCAFile)
		}
		c.RootCAs = pool
	}
	if len(pins) > 0 {
		if cfg.TLSCAFile == "" {
			// Pin only: the pin is the trust anchor (VerifyConnection still runs).
			c.InsecureSkipVerify = true
		}
		c.VerifyConnection = func(cs tls.ConnectionState) error { return checkPins(cs, pins) }
	}
	return c, nil
}

var errPinMismatch = errors.New("nickserv: server certificate does not match NICKSERV_TLS_PIN_SHA256")

func checkPins(cs tls.ConnectionState, pins [][]byte) error {
	if len(cs.PeerCertificates) == 0 {
		return errPinMismatch
	}
	sum := SPKIPin(cs.PeerCertificates[0])
	for _, p := range pins {
		if subtle.ConstantTimeCompare(sum, p) == 1 {
			return nil
		}
	}
	return errPinMismatch
}

// SPKIPin is the SHA-256 of a certificate's SubjectPublicKeyInfo, the value
// NICKSERV_TLS_PIN_SHA256 takes. Get it with:
//
//	openssl s_client -connect irc.example.org:6697 </dev/null 2>/dev/null | openssl x509 -pubkey -noout |
//	  openssl pkey -pubin -outform der | openssl dgst -sha256
func SPKIPin(cert *x509.Certificate) []byte {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return sum[:]
}
