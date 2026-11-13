// Package reqmeta carries the client IP and user agent of the current
// request through the context, for sessions and the audit log.
package reqmeta

import "context"

type Meta struct {
	IP        string
	UserAgent string
}

type ctxKey struct{}

func With(ctx context.Context, m Meta) context.Context { return context.WithValue(ctx, ctxKey{}, m) }

func From(ctx context.Context) Meta {
	m, _ := ctx.Value(ctxKey{}).(Meta)
	return m
}
