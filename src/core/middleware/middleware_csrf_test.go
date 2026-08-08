package middleware

import (
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/gorilla/securecookie"
)

const skipCheckKey string = "gorilla.csrf.Skip"

func TestMiddlewareSkipCsrf(t *testing.T) {
	tests := []struct {
		name string
		// method defaults to GET, which is what every path-only row wants: the exemption those rows
		// describe does not depend on the method.
		method string
		path   string
		// body is sent as application/x-www-form-urlencoded when set, which is how a relying party
		// serializes logout parameters into a POST per OpenID Connect Core's Form Serialization.
		body string
		skip bool
	}{
		// Exempt: exact-match endpoints (bearer/client-authenticated, no cookie).
		{"Authorize exact", "", "/auth/authorize", "", true},
		{"Token exact", "", "/auth/token", "", true},
		{"Callback exact", "", "/auth/callback", "", true},
		{"Userinfo exact", "", "/userinfo", "", true},
		{"DCR register exact", "", "/connect/register", "", true},

		// Exempt: intentional subtree prefixes.
		{"API admin subtree", "", "/api/v1/admin/users", "", true},
		{"API account subtree", "", "/api/v1/account/profile", "", true},
		{"API public settings", "", "/api/public/settings", "", true},
		{"Static css", "", "/static/file.css", "", true},
		{"Static nested js", "", "/static/js/app.js", "", true},

		// Drift guards: sibling routes under a formerly-prefixed path must NOT
		// inherit the exemption now that single endpoints are matched exactly.
		{"Token introspect not skipped", "", "/auth/token-introspect", "", false},
		{"Tokeninfo not skipped", "", "/auth/tokeninfo", "", false},
		{"Tokens not skipped", "", "/auth/tokens", "", false},
		{"Userinfo export not skipped", "", "/userinfo-export", "", false},
		{"Userinfo typo not skipped", "", "/userinfoo", "", false},
		{"Connect register status not skipped", "", "/connect/register-status", "", false},
		{"Connect bare not skipped", "", "/connect/", "", false},
		{"Static without slash not skipped", "", "/static-secret", "", false},
		{"Authorize-extra not skipped", "", "/auth/authorize-extra", "", false},

		// Cookie-authenticated routes must keep CSRF protection.
		{"Auth pwd protected", "", "/auth/pwd", "", false},
		{"Auth otp protected", "", "/auth/otp", "", false},
		{"Auth consent protected", "", "/auth/consent", "", false},
		{"Auth logout protected", "", "/auth/logout", "", false},
		{"Account register protected", "", "/account/register", "", false},
		{"Account profile protected", "", "/account/profile", "", false},
		{"Admin console page protected", "", "/admin/clients", "", false},
		{"Forgot password protected", "", "/forgot-password", "", false},
		{"Reset password protected", "", "/reset-password", "", false},
		{"Root protected", "", "/", "", false},
		{"Other path", "", "/other", "", false},

		// The one conditional exemption: POST /auth/logout carrying an id_token_hint, which
		// RP-Initiated Logout 1.0 section 2 makes a MUST ("OpenID Providers MUST support the use of
		// the HTTP GET and POST methods defined in RFC 7231") and which gorilla/csrf otherwise
		// refuses from every foreign origin (#109 decision 9).
		//
		// Both arrival routes, because a relying party may put the parameter in the query or
		// serialize it into the body, and the handler reads both.
		{"Logout POST with a hint in the query", http.MethodPost, "/auth/logout?id_token_hint=abc", "", true},
		{"Logout POST with a hint in the body", http.MethodPost, "/auth/logout", "id_token_hint=abc", true},

		// PRESENCE, not a value, and this pair is the reason the shared extractor exists. The
		// handler classifies "id_token_hint=" as a hint that was supplied and cannot be confirmed,
		// so it asks the End-User. Were this predicate to read the same parameter as no hint at all,
		// the exempted POST would take the hintless branch instead, which is the confirmation of the
		// consent page and tears the whole session down without asking anybody (#109 decision 13).
		{"Logout POST with an empty hint in the query", http.MethodPost, "/auth/logout?id_token_hint=", "", true},
		{"Logout POST with an empty hint in the body", http.MethodPost, "/auth/logout", "id_token_hint=", true},

		// And the hintless POST keeps full protection, which is the whole reason the exemption is
		// conditional: an unconditional entry would let any site force a logout with no token at all.
		{"Logout POST with no hint", http.MethodPost, "/auth/logout", "", false},
		{"Logout POST with only other parameters", http.MethodPost, "/auth/logout", "state=abc&client_id=x", false},
		{"Logout POST with a lookalike parameter", http.MethodPost, "/auth/logout?id_token_hintx=abc", "", false},
		{"Logout POST with a lookalike parameter in the body", http.MethodPost, "/auth/logout", "id_token_hint_x=abc", false},

		// Methods other than POST are not exempted even with a hint. GET is never checked by
		// gorilla/csrf anyway; PUT and DELETE are, and neither is routed here, so exempting them
		// would widen the hole for a route that would have to be added deliberately.
		{"Logout GET with a hint", http.MethodGet, "/auth/logout?id_token_hint=abc", "", false},
		{"Logout PUT with a hint", http.MethodPut, "/auth/logout?id_token_hint=abc", "", false},
		{"Logout DELETE with a hint", http.MethodDelete, "/auth/logout?id_token_hint=abc", "", false},

		// The predicate is bound to its exact path, like the exact-match table above and for the same
		// drift reason: an id_token_hint on any other endpoint exempts nothing.
		{"Auth pwd POST with a hint", http.MethodPost, "/auth/pwd?id_token_hint=abc", "", false},
		{"Logout sibling route with a hint", http.MethodPost, "/auth/logout-extra?id_token_hint=abc", "", false},
		{"Logout prefix route with a hint", http.MethodPost, "/auth/logout/confirm?id_token_hint=abc", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			method := tt.method
			if method == "" {
				method = http.MethodGet
			}
			var body io.Reader
			if tt.body != "" {
				body = strings.NewReader(tt.body)
			}
			req := httptest.NewRequest(method, tt.path, body)
			if tt.body != "" {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
			rr := httptest.NewRecorder()

			handler := MiddlewareSkipCsrf()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				skipValue := r.Context().Value(skipCheckKey)
				if tt.skip {
					if skipValue != true {
						t.Errorf("MiddlewareSkipCsrf() for path %s: expected CSRF check to be skipped, but it wasn't", tt.path)
					}
				} else {
					if skipValue == true {
						t.Errorf("MiddlewareSkipCsrf() for path %s: expected CSRF check not to be skipped, but it was", tt.path)
					}
				}
			}))

			handler.ServeHTTP(rr, req)
		})
	}
}

// TestMiddlewareSkipCsrf_LogoutBodySurvivesTheHintCheck is the case decision 9 names as the thing
// that has to be pinned: looking for the hint in a POST body means parsing the form in middleware,
// and a form parse consumes the request body.
//
// It survives because Go caches the parse in r.PostForm and r.Form, and the handler's r.FormValue
// reads the cache rather than the socket. If it ever stopped surviving, the logout handler would see
// a request with no ui_locales, no state and no post_logout_redirect_uri, which is a page in the
// wrong language and a redirect that silently does not happen, so this asserts the siblings and not
// only the hint itself.
func TestMiddlewareSkipCsrf_LogoutBodySurvivesTheHintCheck(t *testing.T) {
	body := url.Values{
		"id_token_hint":            {"a.b.c"},
		"post_logout_redirect_uri": {"https://rp.example/bye"},
		"state":                    {"opaque+value/=="},
		"ui_locales":               {"pt-BR"},
	}

	var seen url.Values
	var skipped bool
	handler := MiddlewareSkipCsrf()(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		skipped, _ = r.Context().Value(skipCheckKey).(bool)
		seen = url.Values{}
		for _, key := range []string{"id_token_hint", "post_logout_redirect_uri", "state", "ui_locales"} {
			seen.Set(key, r.FormValue(key))
		}
	}))

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if !skipped {
		t.Fatal("a POST carrying an id_token_hint in its body must be exempted")
	}
	for key, want := range body {
		if got := seen.Get(key); got != want[0] {
			t.Errorf("handler read %s = %q after the middleware parsed the body, want %q", key, got, want[0])
		}
	}
}

// TestMiddlewareSkipCsrf_OtherPathsKeepAnUnreadBody is the boundary on the test above: the body is
// read for the one path that has a predicate and for nothing else.
//
// It matters because the exempt prefixes include the whole /api/ subtree, whose handlers decode JSON
// straight off r.Body. A predicate table that grew a prefix entry, or a parse hoisted out of the
// predicate and up into the middleware, would leave those handlers reading an empty body and the
// failure would look nothing like a CSRF change.
func TestMiddlewareSkipCsrf_OtherPathsKeepAnUnreadBody(t *testing.T) {
	const payload = `{"name":"unread"}`

	for _, path := range []string{"/api/v1/admin/users", "/auth/token", "/auth/pwd", "/auth/logout-extra"} {
		t.Run(path, func(t *testing.T) {
			var got string
			handler := MiddlewareSkipCsrf()(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				raw, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatalf("reading the body: %v", err)
				}
				got = string(raw)
			}))

			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(payload))
			req.Header.Set("Content-Type", "application/json")
			handler.ServeHTTP(httptest.NewRecorder(), req)

			if got != payload {
				t.Errorf("handler read %q from the body, want %q: the middleware consumed it", got, payload)
			}
		})
	}
}

// TestMiddlewareSkipCsrf_CombinedChain mounts the production middleware chain
// (StripSlashes -> MiddlewareSkipCsrf -> MiddlewareCsrf) onto a chi router and
// issues real cross-origin POSTs. This proves the actual `403 Forbidden -
// origin invalid` regression is fixed end-to-end, beyond the context-flag check
// in TestMiddlewareSkipCsrf.
func TestMiddlewareSkipCsrf_CombinedChain(t *testing.T) {
	testKey := securecookie.GenerateRandomKey(64)
	testKeyHex := hex.EncodeToString(testKey)

	const foreignOrigin = "https://www.certification.openid.net"

	newRouter := func() *chi.Mux {
		r := chi.NewRouter()
		r.Use(chimiddleware.StripSlashes)
		r.Use(MiddlewareSkipCsrf())
		r.Use(MiddlewareCsrf(testKeyHex, "http://localhost:9091", "http://localhost:9090", false))

		inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		r.Post("/auth/authorize", inner)
		r.Post("/auth/authorize-extra", inner)
		r.Post("/auth/pwd", inner)
		r.Post("/auth/token", inner)
		r.Post("/auth/token-introspect", inner)
		r.Post("/userinfo", inner)
		r.Post("/userinfo-export", inner)
		r.Post("/api/v1/admin/users", inner)
		r.Post("/auth/logout", inner)
		r.Post("/auth/logout-extra", inner)
		return r
	}

	tests := []struct {
		name       string
		path       string
		body       string
		wantStatus int
	}{
		// Exempt endpoints let the foreign-origin POST through.
		{"POST /auth/authorize foreign origin reaches handler", "/auth/authorize", "", http.StatusOK},
		{"POST /auth/authorize/ trailing slash reaches handler", "/auth/authorize/", "", http.StatusOK},
		{"POST /auth/token reaches handler", "/auth/token", "", http.StatusOK},
		{"POST /userinfo reaches handler", "/userinfo", "", http.StatusOK},
		{"POST /api/v1/admin/users reaches handler", "/api/v1/admin/users", "", http.StatusOK},

		// Non-exempt routes are still blocked (403 origin invalid).
		{"POST /auth/pwd foreign origin still blocked", "/auth/pwd", "", http.StatusForbidden},
		{"POST /auth/authorize-extra not skipped", "/auth/authorize-extra", "", http.StatusForbidden},
		{"POST /auth/token-introspect not skipped", "/auth/token-introspect", "", http.StatusForbidden},
		{"POST /userinfo-export not skipped", "/userinfo-export", "", http.StatusForbidden},

		// The logout binding, which is what the exemption is for: a relying party POSTs a hint from
		// its own origin and must reach the handler. Both arrival routes and the trailing-slash form,
		// since the path the predicate is matched against comes from chi's StripSlashes.
		{"POST /auth/logout with a hint in the query reaches handler", "/auth/logout?id_token_hint=abc", "", http.StatusOK},
		{"POST /auth/logout with a hint in the body reaches handler", "/auth/logout", "id_token_hint=abc", http.StatusOK},
		{"POST /auth/logout/ trailing slash with a hint reaches handler", "/auth/logout/?id_token_hint=abc", "", http.StatusOK},
		{"POST /auth/logout with an empty hint reaches handler", "/auth/logout?id_token_hint=", "", http.StatusOK},

		// And the shape the exemption must never cover. This is the case that makes the conditional
		// table worth its complexity: an unconditional /auth/logout entry would answer this 200 and
		// any site could force a logout (#109 decision 9).
		{"POST /auth/logout with no hint is still blocked", "/auth/logout", "", http.StatusForbidden},
		{"POST /auth/logout with only other parameters is still blocked", "/auth/logout", "state=abc", http.StatusForbidden},
		{"POST /auth/logout-extra with a hint is still blocked", "/auth/logout-extra?id_token_hint=abc", "", http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := newRouter()
			var body io.Reader
			if tt.body != "" {
				body = strings.NewReader(tt.body)
			}
			req := httptest.NewRequest(http.MethodPost, tt.path, body)
			if tt.body != "" {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
			req.Header.Set("Origin", foreignOrigin)
			rr := httptest.NewRecorder()

			router.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("path %s: got status %d, want %d", tt.path, rr.Code, tt.wantStatus)
			}
		})
	}
}

func TestMiddlewareCsrf(t *testing.T) {
	// Generate a test session key and hex-encode it
	testKey := securecookie.GenerateRandomKey(64)
	testKeyHex := hex.EncodeToString(testKey)

	handler := MiddlewareCsrf(testKeyHex, "http://localhost:9091", "http://localhost:9090", false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("CSRF middleware applied", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Header().Get("Set-Cookie") == "" || !strings.Contains(rr.Header().Get("Set-Cookie"), "_gorilla_csrf=") {
			t.Error("Expected CSRF cookie to be set")
		}
	})
}

// TestMiddlewareCsrf_CookieMaxAge verifies the CSRF cookie uses our one-year
// MaxAge rather than gorilla/csrf's 12h default, so it never expires mid-session.
func TestMiddlewareCsrf_CookieMaxAge(t *testing.T) {
	testKey := securecookie.GenerateRandomKey(64)
	testKeyHex := hex.EncodeToString(testKey)

	handler := MiddlewareCsrf(testKeyHex, "http://localhost:9091", "http://localhost:9090", false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req, _ := http.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	found := false
	for _, c := range rr.Result().Cookies() {
		if c.Name == "_gorilla_csrf" {
			found = true
			if c.MaxAge != csrfCookieMaxAgeSeconds {
				t.Errorf("CSRF cookie MaxAge = %d, want %d", c.MaxAge, csrfCookieMaxAgeSeconds)
			}
		}
	}
	if !found {
		t.Fatal("expected _gorilla_csrf cookie to be set")
	}
}
