package middleware

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const (
	// guardIssuer is the configured issuer of every guard test, and the iss of every token they
	// present unless a row says otherwise.
	guardIssuer = "https://auth.example.com"
	// guardClientIdentifier is the client every token the guard tests present was issued to.
	guardClientIdentifier = "client-1"
)

// issuedAccessToken is an access token as issuance mints it since #676: the at+jwt header, the
// configured issuer and the client it was issued to, with claims on top, which may replace any of
// them.
func issuedAccessToken(claims map[string]interface{}) oauth.JwtToken {
	all := map[string]interface{}{"iss": guardIssuer, "client_id": guardClientIdentifier}
	for name, value := range claims {
		all[name] = value
	}
	return oauth.JwtToken{Header: map[string]interface{}{"alg": "RS256", "typ": "at+jwt"}, Claims: all}
}

// guardSettings are the settings every guard test puts on the request: the issuer, an hour's idle
// timeout and a day's lifetime.
func guardSettings() *record.Settings {
	return &record.Settings{
		Issuer:                          guardIssuer,
		UserSessionIdleTimeoutInSeconds: 3600,
		UserSessionMaxLifetimeInSeconds: 86400,
	}
}

// armGuardClient has the session guard's client lookup find guardClientIdentifier enabled. Maybe,
// since a row refused before the client is read never reads it.
func armGuardClient(mockDB *datamocks.Database) {
	mockDB.On("GetClientByClientIdentifier", mock.Anything, (*sql.Tx)(nil), guardClientIdentifier).
		Return(&record.Client{Id: 7, ClientIdentifier: guardClientIdentifier, Enabled: true}, nil).Maybe()
}

// The session guard refuses what RFC 9068 section 4 says a resource server MUST refuse, and a token
// of a client that is gone or disabled (#676 decisions 2, 4 and 6), as 401 invalid_token with the
// sentence a token that does not parse gets, so none of them says which check refused it. Each is
// logged once, as a warning.
func TestRequireValidSession_RFC9068(t *testing.T) {
	userToken := map[string]interface{}{"auth_time": float64(1), "sub": "user-1"}
	clientToken := map[string]interface{}{"sub": guardClientIdentifier}

	tests := []struct {
		label  string
		header map[string]interface{}
		claims map[string]interface{}
		// client is what the client lookup finds; nil with clientGone finds none, nil without it
		// is never read.
		client     *record.Client
		clientGone bool
		readsUser  bool
		wantStatus int
		wantLog    string
	}{
		{label: "a user's token as issued", claims: userToken,
			client: &record.Client{ClientIdentifier: guardClientIdentifier, Enabled: true}, readsUser: true, wantStatus: http.StatusOK},
		{label: "a client's token as issued", claims: clientToken,
			client: &record.Client{ClientIdentifier: guardClientIdentifier, Enabled: true}, wantStatus: http.StatusOK},
		{label: "a token from before the upgrade, whose header says JWT", header: map[string]interface{}{"alg": "RS256", "typ": "JWT"},
			claims: userToken, wantStatus: http.StatusUnauthorized, wantLog: "rejecting bearer token: the header's typ is not at+jwt"},
		{label: "a client's token from before the upgrade", header: map[string]interface{}{"alg": "RS256", "typ": "JWT"},
			claims: clientToken, wantStatus: http.StatusUnauthorized, wantLog: "rejecting bearer token: the header's typ is not at+jwt"},
		{label: "a token from another issuer", claims: map[string]interface{}{"auth_time": float64(1), "sub": "user-1", "iss": "https://old.example.com"},
			wantStatus: http.StatusUnauthorized, wantLog: "rejecting bearer token: iss is not the configured issuer"},
		{label: "a token of a deleted client", claims: userToken, clientGone: true,
			wantStatus: http.StatusUnauthorized, wantLog: "rejecting bearer token: client_id does not resolve to a client"},
		{label: "a user's token of a disabled client", claims: userToken,
			client:     &record.Client{ClientIdentifier: guardClientIdentifier, Enabled: false},
			wantStatus: http.StatusUnauthorized, wantLog: "rejecting bearer token: client is disabled"},
		{label: "a client's token of a disabled client", claims: clientToken,
			client:     &record.Client{ClientIdentifier: guardClientIdentifier, Enabled: false},
			wantStatus: http.StatusUnauthorized, wantLog: "rejecting bearer token: client is disabled"},
	}

	for _, tc := range tests {
		t.Run(tc.label, func(t *testing.T) {
			logs := logtest.CaptureSlog(t)
			mockDB := datamocks.NewDatabase(t)
			switch {
			case tc.client != nil:
				mockDB.On("GetClientByClientIdentifier", mock.Anything, (*sql.Tx)(nil), guardClientIdentifier).Return(tc.client, nil).Once()
			case tc.clientGone:
				mockDB.On("GetClientByClientIdentifier", mock.Anything, (*sql.Tx)(nil), guardClientIdentifier).Return(nil, nil).Once()
			}
			if tc.readsUser {
				mockDB.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), "user-1").
					Return(&record.User{Id: 1, Subject: "user-1", Enabled: true}, nil).Once()
			}

			token := issuedAccessToken(tc.claims)
			if tc.header != nil {
				token.Header = tc.header
			}
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			ctx := reqctx.WithBearerToken(req.Context(), token)
			req = req.WithContext(reqctx.WithSettings(ctx, guardSettings()))
			rr := httptest.NewRecorder()
			nextCalled := false

			apiBearerForTest.RequireValidSession(mockDB)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				nextCalled = true
			})).ServeHTTP(rr, req)

			assert.Equal(t, tc.wantStatus, rr.Code, "status")
			assert.Equal(t, tc.wantStatus == http.StatusOK, nextCalled, "next handler called")
			if tc.wantStatus == http.StatusOK {
				assert.Empty(t, logs.Records(), "a token let through writes no rejection")
				return
			}
			assert.Equal(t, `Bearer realm="goiabada", error="invalid_token", error_description="The access token is invalid."`,
				rr.Header().Get("WWW-Authenticate"))
			var body api.ErrorResponse
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
			assert.Equal(t, api.ErrorResponse{ErrorCode: "INVALID_TOKEN", ErrorDescription: "The access token is invalid."}, body)
			records := logs.Records()
			require.Len(t, records, 1, "one record per refusal")
			assert.Equal(t, slog.LevelWarn, records[0].Level)
			assert.Equal(t, tc.wantLog, records[0].Message)
		})
	}
}

// Without settings a token whose header is not at+jwt is still refused, since that check needs
// none; any other token is the wiring fault reqctx names, answered 500, since its issuer cannot be
// checked.
func TestRequireValidSession_RFC9068WithoutSettings(t *testing.T) {
	t.Run("a JWT header is refused", func(t *testing.T) {
		token := issuedAccessToken(map[string]interface{}{"auth_time": float64(1), "sub": "user-1"})
		token.Header = map[string]interface{}{"alg": "RS256", "typ": "JWT"}
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req = req.WithContext(reqctx.WithBearerToken(req.Context(), token))
		rr := httptest.NewRecorder()

		apiBearerForTest.RequireValidSession(datamocks.NewDatabase(t))(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Error("a refused token must not reach the handler")
		})).ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("a client's token is a 500", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req = req.WithContext(reqctx.WithBearerToken(req.Context(), issuedAccessToken(map[string]interface{}{"sub": guardClientIdentifier})))
		rr := httptest.NewRecorder()

		apiBearerForTest.RequireValidSession(datamocks.NewDatabase(t))(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Error("an unchecked token must not reach the handler")
		})).ServeHTTP(rr, req)

		assert.Equal(t, http.StatusInternalServerError, rr.Code)
	})
}
