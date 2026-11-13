package handlers

import (
	"embed"
	nethttp "net/http"
)

// Minimal built-in pages for the links in emails, so verification and reset
// work before (or without) a web app. Point APP_URL at your web app to use
// its own pages instead; they receive the token in the URL fragment.
//
//go:embed pages/*
var pages embed.FS

const pageCSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; " +
	"form-action 'self'; base-uri 'none'; frame-ancestors 'none'"

func (h *Handlers) registerPages(mux *nethttp.ServeMux) {
	serve := func(name, ctype string) nethttp.HandlerFunc {
		return func(w nethttp.ResponseWriter, r *nethttp.Request) {
			b, err := pages.ReadFile("pages/" + name)
			if err != nil {
				nethttp.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", ctype)
			w.Header().Set("Content-Security-Policy", pageCSP)
			if ctype != "text/html; charset=utf-8" {
				w.Header().Set("Cache-Control", "public, max-age=3600")
			}
			_, _ = w.Write(b)
		}
	}
	mux.HandleFunc("GET /verify-email", serve("verify-email.html", "text/html; charset=utf-8"))
	mux.HandleFunc("GET /reset-password", serve("reset-password.html", "text/html; charset=utf-8"))
	mux.HandleFunc("GET /assets/pages.js", serve("pages.js", "text/javascript; charset=utf-8"))
	mux.HandleFunc("GET /assets/pages.css", serve("pages.css", "text/css; charset=utf-8"))
}
