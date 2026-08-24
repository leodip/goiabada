package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Seam B: MiddlewareNoStore as a plain http.Handler decorator (#247).
//
// Every assertion below reads w.Result().Header rather than w.Header(). The two disagree:
// httptest.ResponseRecorder.Header() returns the live map, which keeps accepting writes long
// after the response has committed, while Result().Header returns the snapshot taken at
// WriteHeader, which is what a client actually receives. Asserting through the live map is how a
// header that never ships stays green, and this repository already carries one such assertion.
func TestMiddlewareNoStore(t *testing.T) {
	tests := []struct {
		name string
		// handler is what the middleware wraps. The two differ in when they commit the
		// status, which is the whole point of the second case.
		handler http.HandlerFunc
	}{
		{
			name: "handler writes a body without committing a status",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"ok":true}`))
			},
		},
		{
			// The arrangement 47 of the API's JSON call sites use: WriteHeader first, then
			// encode. A header set after that point is dropped, which is why the pair is
			// written by a middleware ahead of the handler rather than inside the encoder.
			// If this middleware were ever moved behind the handler, or reimplemented as a
			// wrapped ResponseWriter that writes on first flush, this case is the one that
			// would notice.
			name: "handler commits its status before writing",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error_code":"ACCESS_TOKEN_REQUIRED"}`))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			handler := MiddlewareNoStore()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				tt.handler(w, r)
			}))

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/account/otp/enrollment", nil))

			if !called {
				t.Fatal("expected next handler to be called")
			}

			got := rr.Result().Header
			if v := got.Get("Cache-Control"); v != "no-store" {
				t.Errorf("Cache-Control = %q, want %q", v, "no-store")
			}
			if v := got.Get("Pragma"); v != "no-cache" {
				t.Errorf("Pragma = %q, want %q", v, "no-cache")
			}
		})
	}
}

// TestMiddlewareNoStore_HandlerCanOverrideCacheControl pins the escape hatch the design relies on:
// Header().Set replaces, so a handler that has a legitimate reason to be cacheable can say so and
// win. Nothing under /api/v1 does today, and the sweep in the authserver's routes_no_store_test.go
// is what would catch it if one started to. This case exists so that the escape hatch is a stated
// property rather than an accident of ordering, since a future rewrite as a wrapped
// ResponseWriter that forced the value on flush would silently take it away.
func TestMiddlewareNoStore_HandlerCanOverrideCacheControl(t *testing.T) {
	handler := MiddlewareNoStore()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.WriteHeader(http.StatusOK)
	}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))

	if v := rr.Result().Header.Get("Cache-Control"); v != "public, max-age=300" {
		t.Errorf("Cache-Control = %q, want the handler's own value to have replaced the middleware's", v)
	}
}
