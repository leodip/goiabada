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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The session guard refuses an access token whose grant was revoked (#676 decision 1) as 401
// invalid_token with the sentence a token that does not parse gets, and logs it once as a warning
// naming the grant. A token of a live grant goes through and logs nothing.
func TestRequireValidSession_Grant(t *testing.T) {
	const grantId = "grant-1"

	for _, tc := range []struct {
		label     string
		grantLive bool
	}{
		{label: "a live grant", grantLive: true},
		{label: "a revoked grant", grantLive: false},
	} {
		t.Run(tc.label, func(t *testing.T) {
			logs := logtest.CaptureSlog(t)
			mockDB := datamocks.NewDatabase(t)
			armGuardClient(mockDB)
			mockDB.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), "user-1").
				Return(&record.User{Id: 1, Subject: "user-1", Enabled: true}, nil).Once()
			mockDB.On("IsRefreshTokenFamilyLive", mock.Anything, (*sql.Tx)(nil), grantId).Return(tc.grantLive, nil).Once()

			token := issuedAccessToken(map[string]interface{}{"auth_time": float64(1), "sub": "user-1", "grant_id": grantId})
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			ctx := reqctx.WithBearerToken(req.Context(), token)
			req = req.WithContext(reqctx.WithSettings(ctx, guardSettings()))
			rr := httptest.NewRecorder()
			nextCalled := false

			apiBearerForTest.RequireValidSession(mockDB)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				nextCalled = true
			})).ServeHTTP(rr, req)

			if tc.grantLive {
				assert.Equal(t, http.StatusOK, rr.Code)
				assert.True(t, nextCalled, "a token of a live grant reaches the handler")
				assert.Empty(t, logs.Records(), "a token let through writes no rejection")
				return
			}
			assert.Equal(t, http.StatusUnauthorized, rr.Code)
			assert.False(t, nextCalled, "a refused token must not reach the handler")
			assert.Equal(t, `Bearer realm="goiabada", error="invalid_token", error_description="The access token is invalid."`,
				rr.Header().Get("WWW-Authenticate"))
			var body api.ErrorResponse
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
			assert.Equal(t, api.ErrorResponse{ErrorCode: "INVALID_TOKEN", ErrorDescription: "The access token is invalid."}, body)
			records := logs.Records()
			require.Len(t, records, 1, "one record per refusal")
			assert.Equal(t, slog.LevelWarn, records[0].Level)
			assert.Equal(t, "rejecting bearer token: its grant has been revoked", records[0].Message)
			assert.Equal(t, grantId, records[0].Attrs["grant_id"])
		})
	}
}

// The session guard refuses an access token without a grant whose jti is stored as revoked (#676
// decision 1), a client's or one from the implicit flow, as 401 invalid_token with the sentence a
// token that does not parse gets, and logs it once as a warning naming the jti. Such a token whose
// jti is not stored goes through and logs nothing.
func TestRequireValidSession_RevokedJti(t *testing.T) {
	const jti = "at-1"

	for _, tc := range []struct {
		label   string
		claims  map[string]interface{}
		revoked bool
	}{
		{label: "a client's token, not revoked", claims: map[string]interface{}{"sub": guardClientIdentifier, "jti": jti}},
		{label: "a client's token, revoked", claims: map[string]interface{}{"sub": guardClientIdentifier, "jti": jti}, revoked: true},
		{label: "an implicit-flow token, not revoked", claims: map[string]interface{}{"auth_time": float64(1), "sub": "user-1", "jti": jti}},
		{label: "an implicit-flow token, revoked", claims: map[string]interface{}{"auth_time": float64(1), "sub": "user-1", "jti": jti}, revoked: true},
	} {
		t.Run(tc.label, func(t *testing.T) {
			logs := logtest.CaptureSlog(t)
			mockDB := datamocks.NewDatabase(t)
			mockDB.On("GetClientByClientIdentifier", mock.Anything, (*sql.Tx)(nil), guardClientIdentifier).
				Return(&record.Client{Id: 7, ClientIdentifier: guardClientIdentifier, Enabled: true}, nil).Once()
			if _, isUsers := tc.claims["auth_time"]; isUsers {
				mockDB.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), "user-1").
					Return(&record.User{Id: 1, Subject: "user-1", Enabled: true}, nil).Once()
			}
			mockDB.On("IsAccessTokenRevoked", mock.Anything, (*sql.Tx)(nil), jti).Return(tc.revoked, nil).Once()

			token := issuedAccessToken(tc.claims)
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			ctx := reqctx.WithBearerToken(req.Context(), token)
			req = req.WithContext(reqctx.WithSettings(ctx, guardSettings()))
			rr := httptest.NewRecorder()
			nextCalled := false

			apiBearerForTest.RequireValidSession(mockDB)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				nextCalled = true
			})).ServeHTTP(rr, req)

			if !tc.revoked {
				assert.Equal(t, http.StatusOK, rr.Code)
				assert.True(t, nextCalled, "a token not revoked reaches the handler")
				assert.Empty(t, logs.Records(), "a token let through writes no rejection")
				return
			}
			assert.Equal(t, http.StatusUnauthorized, rr.Code)
			assert.False(t, nextCalled, "a revoked token must not reach the handler")
			assert.Equal(t, `Bearer realm="goiabada", error="invalid_token", error_description="The access token is invalid."`,
				rr.Header().Get("WWW-Authenticate"))
			var body api.ErrorResponse
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
			assert.Equal(t, api.ErrorResponse{ErrorCode: "INVALID_TOKEN", ErrorDescription: "The access token is invalid."}, body)
			records := logs.Records()
			require.Len(t, records, 1, "one record per refusal")
			assert.Equal(t, slog.LevelWarn, records[0].Level)
			assert.Equal(t, "rejecting bearer token: it has been revoked", records[0].Message)
			assert.Equal(t, jti, records[0].Attrs["jti"])
		})
	}
}
