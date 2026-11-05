package middleware

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The session guard puts the user its liveness check found on the request's context, once the
// token is found live, so the audit logger can record who acted without reading the user again
// (#780 decision 2). A client credentials token has no user, and a request without a token has no
// check, so neither carries one.
func TestRequireValidSession_PutsTheActingUserOnTheContext(t *testing.T) {
	const actingUserId = int64(42)

	tests := []struct {
		label string
		// arm sets up what the check reads for this token.
		arm   func(mockDB *datamocks.Database)
		token map[string]interface{}
		// noToken presents no bearer token at all.
		noToken  bool
		wantUser bool
	}{
		{
			label: "a user's token with a live session",
			arm: func(mockDB *datamocks.Database) {
				now := time.Now().UTC()
				mockDB.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), "user-42").
					Return(&record.User{Id: actingUserId, Subject: "user-42", Enabled: true}, nil).Once()
				mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, (*sql.Tx)(nil), "sid-42").
					Return(&record.UserSession{
						SessionIdentifier: "sid-42",
						UserId:            actingUserId,
						Started:           now.Add(-time.Hour),
						LastAccessed:      now.Add(-time.Minute),
					}, nil).Once()
			},
			token:    map[string]interface{}{"auth_time": float64(1), "sub": "user-42", "sid": "sid-42"},
			wantUser: true,
		},
		{
			label: "a user's token of a live grant, with no session",
			arm: func(mockDB *datamocks.Database) {
				mockDB.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), "user-42").
					Return(&record.User{Id: actingUserId, Subject: "user-42", Enabled: true}, nil).Once()
				mockDB.On("IsRefreshTokenFamilyLive", mock.Anything, (*sql.Tx)(nil), "grant-42").Return(true, nil).Once()
			},
			token:    map[string]interface{}{"auth_time": float64(1), "sub": "user-42", "grant_id": "grant-42"},
			wantUser: true,
		},
		{
			label:    "a client credentials token",
			arm:      func(mockDB *datamocks.Database) {},
			token:    map[string]interface{}{"sub": guardClientIdentifier, "scope": "authserver:manage"},
			wantUser: false,
		},
		{
			label:    "no token",
			arm:      func(mockDB *datamocks.Database) {},
			noToken:  true,
			wantUser: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.label, func(t *testing.T) {
			mockDB := datamocks.NewDatabase(t)
			if !tc.noToken {
				armGuardClient(mockDB)
			}
			tc.arm(mockDB)

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			ctx := reqctx.WithSettings(req.Context(), guardSettings())
			if !tc.noToken {
				ctx = reqctx.WithBearerToken(ctx, issuedAccessToken(tc.token))
			}
			req = req.WithContext(ctx)
			rr := httptest.NewRecorder()

			var reached context.Context
			apiBearerForTest.RequireValidSession(mockDB)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				reached = r.Context()
			})).ServeHTTP(rr, req)

			require.Equal(t, http.StatusOK, rr.Code)
			require.NotNil(t, reached, "the request reaches the handler")

			got, ok := reqctx.ActingUserIdFrom(reached)
			assert.Equal(t, tc.wantUser, ok, "whether the handler's context names an acting user")
			if tc.wantUser {
				assert.Equal(t, actingUserId, got, "the acting user is the user the check found")
			}

			// The audit logger's port reads the same value off the same context.
			portId, portOk := ActingUser{}.ActingUserId(reached)
			assert.Equal(t, ok, portOk)
			assert.Equal(t, got, portId)
		})
	}
}

// The port answers nothing off a context the session guard never ran for: the browser sign-in
// flows, the rate limiter's root tiers and the recover command.
func TestActingUser_AnswersNothingWithoutTheSessionGuard(t *testing.T) {
	id, ok := ActingUser{}.ActingUserId(context.Background())
	assert.False(t, ok)
	assert.Zero(t, id)
}
