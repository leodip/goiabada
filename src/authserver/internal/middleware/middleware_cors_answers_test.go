package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// The CORS answers on every branch, pinned as go-chi/cors v1.2.2 gave them before the middleware
// became this repository's own (#462 decision 8, #280). Every CORS header is asserted, present or
// absent, and Vary always: a Vary missing from an answer that depends on the request's Origin lets
// a shared cache hand one origin's answer to another.
//
// A preflight is an OPTIONS carrying Origin and a non-empty Access-Control-Request-Method. It is
// answered 200 here, never passed on, and always varies on the three request fields it reads; it
// carries the origin, the one requested method, the requested headers and a ten-minute Max-Age
// only when origin, method and headers are all allowed. Any other request is passed on, varies on
// Origin, and carries the origin only when it is allowed and its method is GET, HEAD, POST, DELETE
// or OPTIONS. No answer carries Access-Control-Allow-Credentials.

const (
	corsAnyOrigin        = "https://anywhere.example"
	corsRegisteredOrigin = "https://registered.example"
	corsUnknownOrigin    = "https://unknown.example"

	// The status the next handler answers with, which no CORS answer uses, so a preflight answered
	// by the middleware is told apart from one passed on.
	corsNextStatus = http.StatusTeapot
)

var (
	corsPreflightVary = []string{"Origin", "Access-Control-Request-Method", "Access-Control-Request-Headers"}
	corsActualVary    = []string{"Origin"}
)

// corsAnswer is what a response says about CORS: its status, whether the next handler ran, and the
// values of every CORS header field, nil where the field is absent.
type corsAnswer struct {
	Status        int
	NextRan       bool
	Vary          []string
	AllowOrigin   []string
	AllowMethods  []string
	AllowHeaders  []string
	MaxAge        []string
	Credentials   []string
	ExposeHeaders []string
}

// serveCORS sends one request through CORS over database, to a next handler that answers
// corsNextStatus, and reads the answer off the response as sent rather than the recorder's live
// header map.
func serveCORS(database *datamocks.Database, method, path string, header http.Header) corsAnswer {
	var answer corsAnswer
	handler := CORS(database)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		answer.NextRan = true
		w.WriteHeader(corsNextStatus)
	}))

	req := httptest.NewRequest(method, path, nil)
	for name, values := range header {
		req.Header[name] = values
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	sent := rr.Result().Header
	answer.Status = rr.Code
	answer.Vary = sent.Values("Vary")
	answer.AllowOrigin = sent.Values("Access-Control-Allow-Origin")
	answer.AllowMethods = sent.Values("Access-Control-Allow-Methods")
	answer.AllowHeaders = sent.Values("Access-Control-Allow-Headers")
	answer.MaxAge = sent.Values("Access-Control-Max-Age")
	answer.Credentials = sent.Values("Access-Control-Allow-Credentials")
	answer.ExposeHeaders = sent.Values("Access-Control-Expose-Headers")
	return answer
}

// preflight is the header of a preflight from origin for method, asking for requestHeaders when it
// is not empty.
func preflight(origin, method, requestHeaders string) http.Header {
	header := http.Header{
		"Origin":                        {origin},
		"Access-Control-Request-Method": {method},
	}
	if requestHeaders != "" {
		header["Access-Control-Request-Headers"] = []string{requestHeaders}
	}
	return header
}

func fromOrigin(origin string) http.Header {
	return http.Header{"Origin": {origin}}
}

// corsOriginDatabase answers the origin lookup: corsRegisteredOrigin is registered, every other
// origin is not. Maybe, because a branch that never reaches the lookup must not need it, and a
// strict mock refuses any lookup nobody stubbed.
func corsOriginDatabase(t *testing.T) *datamocks.Database {
	t.Helper()
	database := datamocks.NewDatabase(t)
	database.On("WebOriginExists", mock.Anything, mock.Anything, corsRegisteredOrigin).Return(true, nil).Maybe()
	database.On("WebOriginExists", mock.Anything, mock.Anything, mock.MatchedBy(func(origin string) bool {
		return origin != corsRegisteredOrigin
	})).Return(false, nil).Maybe()
	return database
}

// The preflight branch, allowed: the answer names the origin, the one method asked for, upper-cased,
// the headers asked for, in their canonical spelling and the order asked, and a Max-Age of 600.
func TestCORS_AnAllowedPreflightIsAnsweredWithTheGrant(t *testing.T) {
	tests := []struct {
		name           string
		path           string
		origin         string
		method         string
		requestHeaders string
		wantMethods    []string
		wantHeaders    []string
	}{
		{name: "OIDC discovery from any origin", path: "/.well-known/openid-configuration", origin: corsAnyOrigin, method: "GET"},
		{name: "OIDC discovery with a trailing slash", path: "/.well-known/openid-configuration/", origin: corsAnyOrigin, method: "GET"},
		{name: "RFC 8414 discovery from any origin", path: "/.well-known/oauth-authorization-server", origin: corsAnyOrigin, method: "GET"},
		{name: "RFC 8414 discovery with a trailing slash", path: "/.well-known/oauth-authorization-server/", origin: corsAnyOrigin, method: "GET"},
		{name: "the JWKS from any origin", path: "/certs", origin: corsAnyOrigin, method: "GET"},
		{name: "the JWKS with a trailing slash", path: "/certs/", origin: corsAnyOrigin, method: "GET"},
		{name: "the token endpoint from a registered origin", path: "/auth/token", origin: corsRegisteredOrigin, method: "POST",
			requestHeaders: "content-type", wantHeaders: []string{"Content-Type"}},
		{name: "the token endpoint with a trailing slash", path: "/auth/token/", origin: corsRegisteredOrigin, method: "POST"},
		{name: "logout from a registered origin", path: "/auth/logout", origin: corsRegisteredOrigin, method: "POST"},
		{name: "userinfo from a registered origin, with every allowed header", path: "/userinfo", origin: corsRegisteredOrigin, method: "GET",
			requestHeaders: "authorization,accept, x-csrf-token,content-type,origin",
			wantHeaders:    []string{"Authorization, Accept, X-Csrf-Token, Content-Type, Origin"}},
		// RFC 9110 section 5.6.1 lets a list put optional whitespace, SP or HTAB, around each comma,
		// and the library granted all three spellings.
		{name: "a tab after a comma", path: "/certs", origin: corsAnyOrigin, method: "GET",
			requestHeaders: "authorization,\tcontent-type", wantHeaders: []string{"Authorization, Content-Type"}},
		{name: "a tab before a comma", path: "/certs", origin: corsAnyOrigin, method: "GET",
			requestHeaders: "authorization\t,content-type", wantHeaders: []string{"Authorization, Content-Type"}},
		{name: "a space and a tab after a comma", path: "/certs", origin: corsAnyOrigin, method: "GET",
			requestHeaders: "authorization, \tcontent-type", wantHeaders: []string{"Authorization, Content-Type"}},
		{name: "a lower-case method is granted upper-cased", path: "/userinfo", origin: corsRegisteredOrigin, method: "get", wantMethods: []string{"GET"}},
		{name: "HEAD", path: "/certs", origin: corsAnyOrigin, method: "HEAD"},
		{name: "DELETE", path: "/auth/logout", origin: corsRegisteredOrigin, method: "DELETE"},
		{name: "OPTIONS", path: "/certs", origin: corsAnyOrigin, method: "OPTIONS"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := serveCORS(corsOriginDatabase(t), http.MethodOptions, tt.path, preflight(tt.origin, tt.method, tt.requestHeaders))

			wantMethods := tt.wantMethods
			if wantMethods == nil {
				wantMethods = []string{tt.method}
			}
			assert.Equal(t, corsAnswer{
				Status:       http.StatusOK,
				Vary:         corsPreflightVary,
				AllowOrigin:  []string{tt.origin},
				AllowMethods: wantMethods,
				AllowHeaders: tt.wantHeaders,
				MaxAge:       []string{"600"},
			}, got)
		})
	}
}

// The preflight branch, refused: still answered 200 by the middleware with the three Vary values,
// and nothing that grants anything. The origin is decided first, so a refused origin is refused
// whatever it asks for; an allowed origin asking for a method or a header outside the lists is
// refused too.
func TestCORS_ARefusedPreflightIsAnsweredWithNoGrant(t *testing.T) {
	tests := []struct {
		name           string
		path           string
		origin         string
		method         string
		requestHeaders string
	}{
		{name: "an unregistered origin at the token endpoint", path: "/auth/token", origin: corsUnknownOrigin, method: "POST"},
		{name: "an unregistered origin at logout", path: "/auth/logout", origin: corsUnknownOrigin, method: "POST"},
		{name: "an unregistered origin at userinfo", path: "/userinfo", origin: corsUnknownOrigin, method: "GET"},
		{name: "a path no origin is allowed at", path: "/auth/authorize", origin: corsRegisteredOrigin, method: "GET"},
		{name: "the root", path: "/", origin: corsAnyOrigin, method: "GET"},
		{name: "a path below the token endpoint", path: "/auth/token/more", origin: corsRegisteredOrigin, method: "POST"},
		{name: "a path below RFC 8414 discovery", path: "/.well-known/oauth-authorization-server/tenant", origin: corsAnyOrigin, method: "GET"},
		{name: "two trailing slashes", path: "/certs//", origin: corsAnyOrigin, method: "GET"},
		{name: "PUT from an allowed origin", path: "/certs", origin: corsAnyOrigin, method: "PUT"},
		{name: "PATCH from a registered origin", path: "/userinfo", origin: corsRegisteredOrigin, method: "PATCH"},
		{name: "a header outside the list", path: "/userinfo", origin: corsRegisteredOrigin, method: "GET", requestHeaders: "authorization, x-requested-with"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := serveCORS(corsOriginDatabase(t), http.MethodOptions, tt.path, preflight(tt.origin, tt.method, tt.requestHeaders))

			assert.Equal(t, corsAnswer{Status: http.StatusOK, Vary: corsPreflightVary}, got)
		})
	}
}

// What makes a request a preflight: OPTIONS, an Origin field, present even when empty, and a
// non-empty Access-Control-Request-Method. An OPTIONS missing either is an ordinary request and is
// passed on, varying on Origin alone.
func TestCORS_OnlyAnOptionsWithOriginAndRequestMethodIsAPreflight(t *testing.T) {
	t.Run("an empty Origin is still an Origin", func(t *testing.T) {
		// The discovery document allows every origin, the empty one included, and the grant echoes
		// it as sent.
		got := serveCORS(corsOriginDatabase(t), http.MethodOptions, "/certs", preflight("", "GET", ""))

		assert.Equal(t, corsAnswer{
			Status:       http.StatusOK,
			Vary:         corsPreflightVary,
			AllowOrigin:  []string{""},
			AllowMethods: []string{"GET"},
			MaxAge:       []string{"600"},
		}, got)
	})

	t.Run("no Origin", func(t *testing.T) {
		got := serveCORS(datamocks.NewDatabase(t), http.MethodOptions, "/certs",
			http.Header{"Access-Control-Request-Method": {"GET"}})

		assert.Equal(t, corsAnswer{Status: corsNextStatus, NextRan: true, Vary: corsActualVary}, got)
	})

	t.Run("an empty Access-Control-Request-Method", func(t *testing.T) {
		got := serveCORS(corsOriginDatabase(t), http.MethodOptions, "/certs",
			http.Header{"Origin": {corsAnyOrigin}, "Access-Control-Request-Method": {""}})

		assert.Equal(t, corsAnswer{Status: corsNextStatus, NextRan: true, Vary: corsActualVary, AllowOrigin: []string{corsAnyOrigin}}, got)
	})

	t.Run("no Access-Control-Request-Method", func(t *testing.T) {
		got := serveCORS(corsOriginDatabase(t), http.MethodOptions, "/auth/token", fromOrigin(corsRegisteredOrigin))

		assert.Equal(t, corsAnswer{Status: corsNextStatus, NextRan: true, Vary: corsActualVary, AllowOrigin: []string{corsRegisteredOrigin}}, got)
	})

	t.Run("not OPTIONS", func(t *testing.T) {
		got := serveCORS(corsOriginDatabase(t), http.MethodPost, "/auth/token", preflight(corsRegisteredOrigin, "POST", "content-type"))

		assert.Equal(t, corsAnswer{Status: corsNextStatus, NextRan: true, Vary: corsActualVary, AllowOrigin: []string{corsRegisteredOrigin}}, got)
	})
}

// The ordinary request branch: passed on, varying on Origin, and naming the origin only when it is
// allowed and the method is one of the five listed, whatever its case. Nothing else is granted.
func TestCORS_AnOrdinaryRequestNamesAnAllowedOriginOnly(t *testing.T) {
	tests := []struct {
		name      string
		method    string
		path      string
		origin    string
		wantAllow bool
	}{
		{name: "GET of OIDC discovery", method: "GET", path: "/.well-known/openid-configuration", origin: corsAnyOrigin, wantAllow: true},
		{name: "HEAD of RFC 8414 discovery", method: "HEAD", path: "/.well-known/oauth-authorization-server", origin: corsAnyOrigin, wantAllow: true},
		{name: "GET of the JWKS with a trailing slash", method: "GET", path: "/certs/", origin: corsAnyOrigin, wantAllow: true},
		{name: "POST to the token endpoint from a registered origin", method: "POST", path: "/auth/token", origin: corsRegisteredOrigin, wantAllow: true},
		{name: "DELETE at logout from a registered origin", method: "DELETE", path: "/auth/logout", origin: corsRegisteredOrigin, wantAllow: true},
		{name: "GET of userinfo from a registered origin", method: "GET", path: "/userinfo", origin: corsRegisteredOrigin, wantAllow: true},
		{name: "a lower-case method", method: "get", path: "/userinfo", origin: corsRegisteredOrigin, wantAllow: true},
		{name: "PUT from an allowed origin", method: "PUT", path: "/certs", origin: corsAnyOrigin},
		{name: "PATCH from a registered origin", method: "PATCH", path: "/userinfo", origin: corsRegisteredOrigin},
		{name: "POST to the token endpoint from an unregistered origin", method: "POST", path: "/auth/token", origin: corsUnknownOrigin},
		{name: "GET of userinfo from an unregistered origin", method: "GET", path: "/userinfo", origin: corsUnknownOrigin},
		{name: "a path no origin is allowed at", method: "GET", path: "/auth/authorize", origin: corsRegisteredOrigin},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := serveCORS(corsOriginDatabase(t), tt.method, tt.path, fromOrigin(tt.origin))

			want := corsAnswer{Status: corsNextStatus, NextRan: true, Vary: corsActualVary}
			if tt.wantAllow {
				want.AllowOrigin = []string{tt.origin}
			}
			assert.Equal(t, want, got)
		})
	}
}

// A request with no Origin is not a cross-origin one: it varies on Origin, so a cache keeps it apart
// from the answers that name one, and the origin lookup is never made, on a gated path either.
func TestCORS_ARequestWithNoOriginVariesOnOriginAndLooksNothingUp(t *testing.T) {
	for _, method := range []string{"GET", "POST", "OPTIONS"} {
		for _, path := range []string{"/auth/token", "/userinfo", "/certs", "/"} {
			t.Run(method+" "+path, func(t *testing.T) {
				database := datamocks.NewDatabase(t)

				got := serveCORS(database, method, path, nil)

				assert.Equal(t, corsAnswer{Status: corsNextStatus, NextRan: true, Vary: corsActualVary}, got)
				database.AssertNotCalled(t, "WebOriginExists", mock.Anything, mock.Anything, mock.Anything)
			})
		}
	}
}

// Vary is added to, never replaced: a Vary the next handler adds stays beside Origin, and a Vary
// already on the response before CORS stays before the ones it adds.
func TestCORS_VaryIsAddedToWhatTheResponseCarries(t *testing.T) {
	database := corsOriginDatabase(t)
	handler := CORS(database)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Vary", "Accept-Encoding")
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("an ordinary request", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/certs", nil)
		req.Header.Set("Origin", corsAnyOrigin)
		rr := httptest.NewRecorder()
		rr.Header().Add("Vary", "Cookie")
		handler.ServeHTTP(rr, req)

		assert.Equal(t, []string{"Cookie", "Origin", "Accept-Encoding"}, rr.Result().Header.Values("Vary"))
	})

	t.Run("a preflight", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/certs", nil)
		req.Header = preflight(corsAnyOrigin, "GET", "")
		rr := httptest.NewRecorder()
		rr.Header().Add("Vary", "Cookie")
		handler.ServeHTTP(rr, req)

		assert.Equal(t, append([]string{"Cookie"}, corsPreflightVary...), rr.Result().Header.Values("Vary"))
	})
}

// The origin lookup is made for a request carrying Origin on a gated path whatever its method,
// before the method is weighed: a preflight asking for a method outside the list and an ordinary
// PUT both consult it once. Pinned because the lookup's count is what a browser's preflight costs.
func TestCORS_TheOriginIsLookedUpBeforeTheMethodIsWeighed(t *testing.T) {
	for _, tt := range []struct {
		name   string
		method string
		header http.Header
	}{
		{name: "a preflight for PUT", method: http.MethodOptions, header: preflight(corsRegisteredOrigin, "PUT", "")},
		{name: "an ordinary PUT", method: http.MethodPut, header: fromOrigin(corsRegisteredOrigin)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			database.On("WebOriginExists", mock.Anything, mock.Anything, corsRegisteredOrigin).Return(true, nil).Once()

			serveCORS(database, tt.method, "/auth/token", tt.header)

			database.AssertExpectations(t)
		})
	}
}
