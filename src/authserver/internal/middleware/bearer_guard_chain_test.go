package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	chimiddleware "github.com/go-chi/chi/v5/middleware"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/render"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// This file is the bearer guard set's seam: the real chain routes.go mounts on /userinfo (parse,
// scope "openid", user-bound), driven through httptest with a stub parser, on both surfaces, with
// the real JSON writer behind the /userinfo refusals. It owns every row of RFC 6750's table for
// this server: the status, the exact WWW-Authenticate value and the exact body, per surface. The
// guard-level tests beside it pin their own branches and leave the wire to this table (#435).

// chainParser stands in for the signed-token parser: it knows four tokens by name and refuses
// everything else as a token that does not verify.
type chainParser struct{}

func (chainParser) DecodeAndValidateTokenString(_ context.Context, token string, _ bool) (*oauth.JwtToken, error) {
	claims := map[string]interface{}{"typ": "Bearer", "aud": "authserver", "sub": "u1", "auth_time": float64(1)}
	switch token {
	case "good":
		claims["scope"] = "openid profile"
	case "noopenid":
		claims["scope"] = "authserver:manage-account"
	case "client":
		// A client credentials token: no auth_time, which is what RequireUserBoundToken reads.
		delete(claims, "auth_time")
		claims["scope"] = "openid"
	case "refresh":
		claims["typ"] = "Refresh"
		claims["scope"] = "openid"
	default:
		return nil, errors.New("the token does not verify")
	}
	return &oauth.JwtToken{TokenBase64: token, Claims: claims}, nil
}

// chainSurface is one of the two guard sets routes.go builds.
type chainSurface struct {
	name  string
	build func() *BearerToken
}

func chainSurfaces() []chainSurface {
	return []chainSurface{
		{name: "api", build: func() *BearerToken { return NewBearerTokenForAPI(chainParser{}) }},
		{name: "userinfo", build: func() *BearerToken {
			// The real writer, so the /userinfo body is the bytes on the wire and not a recorded call.
			return NewBearerTokenForUserInfo(chainParser{}, render.New(nil))
		}},
	}
}

// chainAnswer is what one surface answers one request.
type chainAnswer struct {
	status    int
	challenge string
	body      string // exact JSON, or "" for no body
}

const (
	challengeMissing        = `Bearer realm="goiabada"`
	challengeInvalidToken   = `Bearer realm="goiabada", error="invalid_token", error_description="The access token is invalid."`
	challengeInvalidRequest = `Bearer realm="goiabada", error="invalid_request", error_description="The access token must be sent by one method only."`
	challengeRepeated       = `Bearer realm="goiabada", error="invalid_request", error_description="The access_token parameter must be sent once."`
	challengeUnparseable    = `Bearer realm="goiabada", error="invalid_request", error_description="The request body could not be parsed."`
	challengeHeaderRepeated = `Bearer realm="goiabada", error="invalid_request", error_description="The Authorization header must be sent once."`
	challengeScope          = `Bearer realm="goiabada", error="insufficient_scope", error_description="Insufficient scope."`
	challengeUserContext    = `Bearer realm="goiabada", error="insufficient_scope", error_description="This endpoint requires an access token issued for a user. Tokens obtained through the client credentials grant are not accepted."`
	userContextDescription  = "This endpoint requires an access token issued for a user. Tokens obtained through the client credentials grant are not accepted."
)

var (
	answerAdmitted = chainAnswer{status: http.StatusOK}

	apiMissing        = chainAnswer{http.StatusUnauthorized, challengeMissing, `{"error_code":"ACCESS_TOKEN_REQUIRED","error_description":"Access token required."}`}
	apiInvalidToken   = chainAnswer{http.StatusUnauthorized, challengeInvalidToken, `{"error_code":"INVALID_TOKEN","error_description":"The access token is invalid."}`}
	apiInvalidRequest = chainAnswer{http.StatusBadRequest, challengeInvalidRequest, `{"error_code":"INVALID_REQUEST","error_description":"The access token must be sent by one method only."}`}
	apiRepeated       = chainAnswer{http.StatusBadRequest, challengeRepeated, `{"error_code":"INVALID_REQUEST","error_description":"The access_token parameter must be sent once."}`}
	apiUnparseable    = chainAnswer{http.StatusBadRequest, challengeUnparseable, `{"error_code":"INVALID_REQUEST","error_description":"The request body could not be parsed."}`}
	apiHeaderRepeated = chainAnswer{http.StatusBadRequest, challengeHeaderRepeated, `{"error_code":"INVALID_REQUEST","error_description":"The Authorization header must be sent once."}`}
	apiScope          = chainAnswer{http.StatusForbidden, challengeScope, `{"error_code":"INSUFFICIENT_SCOPE","error_description":"Insufficient scope."}`}
	apiUserContext    = chainAnswer{http.StatusForbidden, challengeUserContext, `{"error_code":"USER_CONTEXT_REQUIRED","error_description":"` + userContextDescription + `"}`}

	userinfoMissing        = chainAnswer{http.StatusUnauthorized, challengeMissing, ""}
	userinfoInvalidToken   = chainAnswer{http.StatusUnauthorized, challengeInvalidToken, `{"error":"invalid_token","error_description":"The access token is invalid."}`}
	userinfoInvalidRequest = chainAnswer{http.StatusBadRequest, challengeInvalidRequest, `{"error":"invalid_request","error_description":"The access token must be sent by one method only."}`}
	userinfoRepeated       = chainAnswer{http.StatusBadRequest, challengeRepeated, `{"error":"invalid_request","error_description":"The access_token parameter must be sent once."}`}
	userinfoUnparseable    = chainAnswer{http.StatusBadRequest, challengeUnparseable, `{"error":"invalid_request","error_description":"The request body could not be parsed."}`}
	userinfoHeaderRepeated = chainAnswer{http.StatusBadRequest, challengeHeaderRepeated, `{"error":"invalid_request","error_description":"The Authorization header must be sent once."}`}
	userinfoScope          = chainAnswer{http.StatusForbidden, challengeScope, `{"error":"insufficient_scope","error_description":"Insufficient scope."}`}
	userinfoUserContext    = chainAnswer{http.StatusForbidden, challengeUserContext, `{"error":"insufficient_scope","error_description":"` + userContextDescription + `"}`}
)

// assertChainAnswer compares a recorded response with want, byte for byte on the challenge and as
// JSON on the body.
func assertChainAnswer(t *testing.T, want chainAnswer, rr *httptest.ResponseRecorder) {
	t.Helper()
	require.Equal(t, want.status, rr.Code, rr.Body.String())
	assert.Equal(t, want.challenge, rr.Header().Get("WWW-Authenticate"), "challenge")
	switch {
	case want.status == http.StatusOK:
		assert.Equal(t, "admitted", rr.Body.String())
	case want.body == "":
		assert.Empty(t, rr.Body.String(), "RFC 6750 section 3.1: no error information in the body")
	default:
		assert.JSONEq(t, want.body, rr.Body.String())
		assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
	}
}

// TestBearerGuardChain_RFC6750OnEachSurface is section 1's table of RFC 6750 rows, answered by each
// surface in its own format.
func TestBearerGuardChain_RFC6750OnEachSurface(t *testing.T) {
	tests := []struct {
		name          string
		method        string
		target        string
		authorization string
		// secondAuthorization, when set, is sent as a second Authorization field line.
		secondAuthorization string
		body                string
		// contentType is the body's media type, application/x-www-form-urlencoded when empty.
		contentType string
		api         chainAnswer
		userinfo    chainAnswer
	}{
		// RFC 6750 section 3.1: lacking any authentication information, no error code.
		{name: "no credentials at all", method: "GET", target: "/userinfo",
			api: apiMissing, userinfo: userinfoMissing},
		// 3.1's own example of lacking information: an unsupported authentication method.
		{name: "unsupported scheme (Basic)", method: "GET", target: "/userinfo", authorization: "Basic dXNlcjpwYXNz",
			api: apiMissing, userinfo: userinfoMissing},
		// Section 2.3's method, which this server does not support, is the same case.
		{name: "token in the query only", method: "GET", target: "/userinfo?access_token=good",
			api: apiMissing, userinfo: userinfoMissing},
		{name: "token in a POST's query only", method: "POST", target: "/userinfo?access_token=good", body: "other=1",
			api: apiMissing, userinfo: userinfoMissing},

		// A presented token that is refused: 401 invalid_token, never read as absent.
		{name: "Bearer with a token that fails validation", method: "GET", target: "/userinfo", authorization: "Bearer garbage",
			api: apiInvalidToken, userinfo: userinfoInvalidToken},
		{name: "Bearer with a refresh token (#401)", method: "GET", target: "/userinfo", authorization: "Bearer refresh",
			api: apiInvalidToken, userinfo: userinfoInvalidToken},
		{name: "Bearer with an empty token", method: "GET", target: "/userinfo", authorization: "Bearer ",
			api: apiInvalidToken, userinfo: userinfoInvalidToken},
		{name: "form body token that fails validation", method: "POST", target: "/userinfo", body: "access_token=garbage",
			api: apiInvalidToken, userinfo: userinfoInvalidToken},
		{name: "form body token empty", method: "POST", target: "/userinfo", body: "access_token=",
			api: apiInvalidToken, userinfo: userinfoInvalidToken},

		// RFC 6750 section 2.1 MUST, with RFC 5234 section 2.3's case-insensitive ABNF strings.
		{name: "lowercase scheme, valid token", method: "GET", target: "/userinfo", authorization: "bearer good",
			api: answerAdmitted, userinfo: answerAdmitted},
		{name: "uppercase scheme, valid token", method: "GET", target: "/userinfo", authorization: "BEARER good",
			api: answerAdmitted, userinfo: answerAdmitted},

		// RFC 6750 section 2 MUST NOT use more than one method; 3.1 invalid_request SHOULD 400.
		{name: "header and form body both", method: "POST", target: "/userinfo", authorization: "Bearer good", body: "access_token=good",
			api: apiInvalidRequest, userinfo: userinfoInvalidRequest},
		// RFC 9110 section 8.3.1: a media type is case-insensitive, and net/http reads this body as a form.
		{name: "header and form body both, the media type in capitals", method: "POST", target: "/userinfo", authorization: "Bearer good",
			body: "access_token=good", contentType: "APPLICATION/X-WWW-FORM-URLENCODED",
			api: apiInvalidRequest, userinfo: userinfoInvalidRequest},

		// RFC 9110 section 5.3: Authorization is no list, so a second field line makes the request
		// "otherwise malformed", RFC 6750 section 3.1's invalid_request.
		{name: "the Authorization header sent twice", method: "GET", target: "/userinfo", authorization: "Bearer good", secondAuthorization: "Bearer good",
			api: apiHeaderRepeated, userinfo: userinfoHeaderRepeated},
		{name: "a Basic line, then a Bearer line", method: "GET", target: "/userinfo", authorization: "Basic dXNlcjpwYXNz", secondAuthorization: "Bearer good",
			api: apiHeaderRepeated, userinfo: userinfoHeaderRepeated},

		// RFC 6750 section 3.1 invalid_request: a request that "repeats the same parameter".
		{name: "access_token repeated in the form body", method: "POST", target: "/userinfo", body: "access_token=good&access_token=good",
			api: apiRepeated, userinfo: userinfoRepeated},

		// RFC 6750 section 3.1 invalid_request: a request that "is otherwise malformed". A body that
		// does not parse cannot say whether it carries a second token, so neither the valid header
		// beside it nor the readable token inside it is admitted.
		{name: "valid header beside a form body that does not parse", method: "POST", target: "/userinfo", authorization: "Bearer good", body: "access_token=good&junk=%GG",
			api: apiUnparseable, userinfo: userinfoUnparseable},
		{name: "valid form body token beside a pair that does not parse", method: "POST", target: "/userinfo", body: "access_token=good&junk=%GG",
			api: apiUnparseable, userinfo: userinfoUnparseable},

		// RFC 6750 section 3.1 insufficient_scope SHOULD 403.
		{name: "valid token lacking openid", method: "GET", target: "/userinfo", authorization: "Bearer noopenid",
			api: apiScope, userinfo: userinfoScope},
		{name: "client credentials token", method: "GET", target: "/userinfo", authorization: "Bearer client",
			api: apiUserContext, userinfo: userinfoUserContext},

		{name: "valid token in the header", method: "GET", target: "/userinfo", authorization: "Bearer good",
			api: answerAdmitted, userinfo: answerAdmitted},
		// RFC 6750 section 2.2 MAY; OIDC Core 1.0 section 5.3.1 allows POST.
		{name: "valid token in a POST form body only", method: "POST", target: "/userinfo", body: "access_token=good",
			api: answerAdmitted, userinfo: answerAdmitted},
		{name: "valid token in a POST form body only, the media type in capitals", method: "POST", target: "/userinfo",
			body: "access_token=good", contentType: "APPLICATION/X-WWW-FORM-URLENCODED",
			api: answerAdmitted, userinfo: answerAdmitted},
	}

	for _, surface := range chainSurfaces() {
		for _, tc := range tests {
			t.Run(surface.name+"/"+tc.name, func(t *testing.T) {
				guards := surface.build()
				chain := guards.JwtAuthorizationHeaderToContext()(
					guards.RequireBearerTokenScope("openid")(guards.RequireUserBoundToken()(http.HandlerFunc(
						func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("admitted")) }))))

				var body *strings.Reader
				if tc.body != "" {
					body = strings.NewReader(tc.body)
				}
				var req *http.Request
				if body != nil {
					req = httptest.NewRequest(tc.method, tc.target, body)
					contentType := tc.contentType
					if contentType == "" {
						contentType = "application/x-www-form-urlencoded"
					}
					req.Header.Set("Content-Type", contentType)
				} else {
					req = httptest.NewRequest(tc.method, tc.target, nil)
				}
				if tc.authorization != "" {
					req.Header.Set("Authorization", tc.authorization)
				}
				if tc.secondAuthorization != "" {
					req.Header.Add("Authorization", tc.secondAuthorization)
				}

				rr := httptest.NewRecorder()
				chain.ServeHTTP(rr, req)

				want := tc.api
				if surface.name == "userinfo" {
					want = tc.userinfo
				}
				assertChainAnswer(t, want, rr)
			})
		}
	}
}

// userSessionToken is a user token the session guard reads: auth_time present and a sid.
func userSessionToken() oauth.JwtToken {
	return oauth.JwtToken{Claims: map[string]interface{}{
		"sub": "u1", "auth_time": float64(1), "sid": "sid-1", "scope": "openid",
	}}
}

// TestBearerGuardChain_SessionRefusalsOnEachSurface: RequireValidSession's refusals reach each
// surface's format. Which session states it refuses is TestRequireValidSession_Table's; this pins
// one 401 and the 500 on each surface, which is deliberately thin.
func TestBearerGuardChain_SessionRefusalsOnEachSurface(t *testing.T) {
	t.Run("a terminated session is 401 invalid_token", func(t *testing.T) {
		want := map[string]chainAnswer{
			"api": {http.StatusUnauthorized,
				`Bearer realm="goiabada", error="invalid_token", error_description="Session has been terminated"`,
				`{"error_code":"INVALID_TOKEN","error_description":"Session has been terminated"}`},
			"userinfo": {http.StatusUnauthorized,
				`Bearer realm="goiabada", error="invalid_token", error_description="Session has been terminated"`,
				`{"error":"invalid_token","error_description":"Session has been terminated"}`},
		}
		for _, surface := range chainSurfaces() {
			t.Run(surface.name, func(t *testing.T) {
				mockDB := mocks_data.NewDatabase(t)
				mockDB.On("GetUserBySubject", mock.Anything, mock.Anything, "u1").Return(nil, nil)

				req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
				req = req.WithContext(reqctx.WithBearerToken(req.Context(), userSessionToken()))
				rr := httptest.NewRecorder()
				surface.build().RequireValidSession(mockDB)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
					t.Error("a refused session must not reach the handler")
				})).ServeHTTP(rr, req)

				assertChainAnswer(t, want[surface.name], rr)
			})
		}
	})

	t.Run("a failed session lookup is 500 in the surface's format, logged once with the sid", func(t *testing.T) {
		for _, surface := range chainSurfaces() {
			t.Run(surface.name, func(t *testing.T) {
				logs := logtest.CaptureSlog(t)
				mockDB := mocks_data.NewDatabase(t)
				mockDB.On("GetUserBySubject", mock.Anything, mock.Anything, "u1").
					Return(&record.User{Id: 7, Enabled: true}, nil)
				mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, "sid-1").
					Return(nil, errors.New("the database is down"))

				req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
				ctx := context.WithValue(req.Context(), chimiddleware.RequestIDKey, "req-chain-1")
				req = req.WithContext(reqctx.WithBearerToken(ctx, userSessionToken()))
				rr := httptest.NewRecorder()
				surface.build().RequireValidSession(mockDB)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
					t.Error("a failed lookup must not reach the handler")
				})).ServeHTTP(rr, req)

				require.Equal(t, http.StatusInternalServerError, rr.Code, rr.Body.String())
				assert.Empty(t, rr.Header().Get("WWW-Authenticate"), "a server fault is not a challenge")
				assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
				if surface.name == "api" {
					assert.JSONEq(t, `{"error_code":"INTERNAL_SERVER_ERROR","error_description":"An unexpected server error has occurred. For additional information, refer to the server logs. Request Id: req-chain-1"}`, rr.Body.String())
				} else {
					assert.JSONEq(t, `{"error":"server_error","error_description":"An unexpected server error has occurred. For additional information, refer to the server logs. Request Id: req-chain-1"}`, rr.Body.String())
				}

				records := logs.Records()
				require.Len(t, records, 1, "one record per 500")
				assert.Equal(t, "internal server error", records[0].Message)
				assert.Contains(t, logs.Text(), "sid-1", "the session identifier reaches the one record")
				assert.Contains(t, logs.Text(), "the database is down")
			})
		}
	})
}
