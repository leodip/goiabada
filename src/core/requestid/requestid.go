// Package requestid is the id each request carries through both servers: adopted from the
// X-Request-Id a client or proxy sent, or minted, then read off the context by the log handler,
// the audit log, the error pages and the 500's error_description. It makes ids exactly as chi's
// RequestID middleware made them, which the deploy docs promise operators (#462 decision 6).
package requestid

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"sync"
	"sync/atomic"

	"github.com/leodip/goiabada/core/securerandom"
)

// Header is the request header an incoming id is adopted from.
const Header = "X-Request-Id"

// base62 is the alphabet of the random part of a minted id: chi's base64 with + and / dropped.
const base62 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// contextKey is unexported, so FromContext and NewContext are the only way to the id.
type contextKey struct{}

// prefix is the part every id this process mints shares, <hostname>/<10 base62 characters>, drawn
// once, when the first id is minted.
var prefix = sync.OnceValue(func() string {
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = "localhost"
	}
	return hostname + "/" + securerandom.StringFromAlphabet(10, base62)
})

// counter numbers the ids this process mints, from 1.
var counter atomic.Uint64

// Middleware puts the request's id on its context: the X-Request-Id it arrived with, verbatim, or
// one minted as <hostname>/<10 base62 characters>-<counter of at least six digits>. It writes no
// response header.
//
// An adopted id is client-chosen and is not checked here. Every place one lands bounds or escapes
// it: logging.FieldForLog's clip in records and audit rows, the templates' escaping, and the auth
// server renderer's header guard (#159).
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(Header)
		if id == "" {
			id = fmt.Sprintf("%s-%06d", prefix(), counter.Add(1))
		}
		next.ServeHTTP(w, r.WithContext(NewContext(r.Context(), id)))
	})
}

// FromContext answers the request id ctx carries, or "" when it carries none.
func FromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	id, _ := ctx.Value(contextKey{}).(string)
	return id
}

// NewContext answers ctx carrying id as its request id. Middleware is the one production writer;
// tests plant an id with it.
func NewContext(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, contextKey{}, id)
}
