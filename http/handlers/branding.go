package handlers

import (
	"bytes"
	nethttp "net/http"
	"strings"
	"time"

	"github.com/boson-chat/auth/internal/apperr"
	"github.com/boson-chat/auth/internal/theme"
)

// Cache lifetimes of the branding endpoints.
const (
	brandingDocMaxAge  = "public, max-age=60"
	brandingAssetFresh = "public, max-age=31536000, immutable" // ?v= matches the content
	brandingAssetStale = "public, max-age=300"
	// svgCSP keeps an SVG opened directly (not as an <img>) inert.
	svgCSP = "default-src 'none'; style-src 'unsafe-inline'"
)

var errNoBranding = apperr.New(nethttp.StatusNotFound, "no_branding", "this network has no branding configured")

func (h *Handlers) registerBranding(mux *nethttp.ServeMux) {
	mux.HandleFunc("GET /v1/branding", h.brandingDocument)
	mux.HandleFunc("GET /v1/branding/assets/{file}", h.brandingAsset)
}

// brandingDocument: GET /v1/branding → the boson-theme/1 document (public,
// CORS *, ETag / If-None-Match → 304). 404 no_branding when the stack
// config file has no branding: section.
func (h *Handlers) brandingDocument(w nethttp.ResponseWriter, r *nethttp.Request) {
	if h.Branding == nil {
		writeError(w, r, errNoBranding)
		return
	}
	doc, ok := h.Branding.Document(r.Context())
	if !ok {
		writeError(w, r, errNoBranding)
		return
	}
	hdr := w.Header()
	hdr.Set("ETag", doc.ETag)
	hdr.Set("Cache-Control", brandingDocMaxAge)
	if etagMatch(r.Header.Get("If-None-Match"), doc.ETag) {
		w.WriteHeader(nethttp.StatusNotModified)
		return
	}
	hdr.Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(nethttp.StatusOK)
	if r.Method != nethttp.MethodHead {
		_, _ = w.Write(doc.JSON)
	}
}

// etagMatch implements If-None-Match (weak comparison, lists and *).
func etagMatch(header, etag string) bool {
	for _, t := range strings.Split(header, ",") {
		t = strings.TrimPrefix(strings.TrimSpace(t), "W/")
		if t == "*" || (t != "" && t == strings.TrimPrefix(etag, "W/")) {
			return true
		}
	}
	return false
}

// brandingAsset: GET /v1/branding/assets/{file}. Only the files the current
// branding references are served, from memory (they were read and checked
// when the config was loaded), so nothing else in the branding directory,
// and nothing outside it, is reachable.
func (h *Handlers) brandingAsset(w nethttp.ResponseWriter, r *nethttp.Request) {
	name := r.PathValue("file")
	if _, err := theme.CheckFileName(name); err != nil || h.Branding == nil {
		writeError(w, r, apperr.ErrNotFound)
		return
	}
	a, ok := h.Branding.Asset(r.Context(), name)
	if !ok {
		writeError(w, r, apperr.ErrNotFound)
		return
	}
	hdr := w.Header()
	hdr.Set("Content-Type", a.MediaType)
	hdr.Set("X-Content-Type-Options", "nosniff")
	hdr.Set("Cross-Origin-Resource-Policy", "cross-origin")
	hdr.Set("ETag", `"`+a.Hash+`"`)
	if a.MediaType == "image/svg+xml" {
		hdr.Set("Content-Security-Policy", svgCSP)
	}
	if r.URL.Query().Get("v") == a.Hash {
		hdr.Set("Cache-Control", brandingAssetFresh)
	} else {
		hdr.Set("Cache-Control", brandingAssetStale)
	}
	nethttp.ServeContent(w, r, "", time.Time{}, bytes.NewReader(a.Data))
}
