package handlers

import (
	"encoding/json"
	"errors"
	nethttp "net/http"

	"github.com/boson-chat/auth/internal/apperr"
	"github.com/boson-chat/auth/internal/services/workload"
)

// WorkloadTokenHeader carries a workload's own secret, WORKLOAD_TOKEN_<NAME>.
const WorkloadTokenHeader = "X-Workload-Token"

// WorkloadTokenField is the JSON field holding the JWT in
// GET /internal/v1/workload/token (Google credential_source.format
// subject_token_field_name).
const WorkloadTokenField = "id_token"

// registerWorkloadPublic mounts the workload issuer's discovery document and
// JWKS. Without WORKLOAD_IDENTITIES nothing is mounted (404).
func (h *Handlers) registerWorkloadPublic(mux *nethttp.ServeMux) {
	if h.Workload == nil {
		return
	}
	mux.HandleFunc("GET "+workload.PathPrefix+"/.well-known/openid-configuration", h.workloadDiscovery)
	mux.HandleFunc("GET "+workload.PathPrefix+"/jwks.json", h.workloadJWKS)
}

// registerWorkloadInternal mounts the token endpoint on the internal
// listener. Without WORKLOAD_IDENTITIES nothing is mounted (404).
func (h *Handlers) registerWorkloadInternal(mux *nethttp.ServeMux) {
	if h.Workload == nil {
		return
	}
	mux.HandleFunc("GET /internal/v1/workload/token", h.workloadToken)
}

// workloadDiscovery: what Google Workload Identity Federation (and any OIDC
// verifier) reads from <issuer>/.well-known/openid-configuration.
func (h *Handlers) workloadDiscovery(w nethttp.ResponseWriter, _ *nethttp.Request) {
	iss := h.Workload.Issuer()
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, nethttp.StatusOK, map[string]any{
		"issuer":                                iss,
		"jwks_uri":                              iss + "/jwks.json",
		"response_types_supported":              []string{"id_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{workload.AlgES256},
		"claims_supported":                      []string{"iss", "sub", "aud", "iat", "exp", "jti"},
	})
}

func (h *Handlers) workloadJWKS(w nethttp.ResponseWriter, _ *nethttp.Request) {
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("Content-Type", "application/jwk-set+json")
	w.WriteHeader(nethttp.StatusOK)
	_ = json.NewEncoder(w).Encode(h.Workload.Keys.JWKS())
}

// workloadToken: GET /internal/v1/workload/token[?audience=][&format=text]
// with X-Workload-Token. Mints a token for the workload that secret
// belongs to. audience may be left out when the workload has only one.
//
// Default response (Google credential_source format {type: json,
// subject_token_field_name: id_token}):
//
//	{"id_token": "<jwt>", "token_type": "urn:ietf:params:oauth:token-type:id_token",
//	 "expires_in": 300, "expires_at": 1767225600}
//
// format=text: the bare JWT, Content-Type application/jwt (format type text).
func (h *Handlers) workloadToken(w nethttp.ResponseWriter, r *nethttp.Request) {
	w.Header().Set("Cache-Control", "no-store")
	q := r.URL.Query()
	format := q.Get("format")
	if format != "" && format != "json" && format != "text" {
		writeError(w, r, apperr.InvalidField("format", "must be json or text"))
		return
	}
	id, err := h.Workload.Authenticate(r.Header.Get(WorkloadTokenHeader))
	if err != nil {
		writeError(w, r, apperr.ErrUnauthenticated)
		return
	}
	tok, err := h.Workload.Mint(r.Context(), id, q.Get("audience"))
	if errors.Is(err, workload.ErrAudience) {
		writeError(w, r, apperr.New(nethttp.StatusForbidden, "audience_not_allowed",
			"audience is not configured for this workload in WORKLOAD_IDENTITIES"))
		return
	}
	if err != nil {
		writeError(w, r, err)
		return
	}
	if format == "text" {
		w.Header().Set("Content-Type", "application/jwt")
		w.WriteHeader(nethttp.StatusOK)
		_, _ = w.Write([]byte(tok.JWT))
		return
	}
	writeJSON(w, nethttp.StatusOK, map[string]any{
		WorkloadTokenField: tok.JWT,
		"token_type":       "urn:ietf:params:oauth:token-type:id_token",
		"expires_in":       int(tok.ExpiresAt.Sub(tok.IssuedAt).Seconds()),
		"expires_at":       tok.ExpiresAt.Unix(),
	})
}
