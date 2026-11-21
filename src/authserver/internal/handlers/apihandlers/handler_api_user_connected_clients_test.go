package apihandlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The Admin list marks a row isCurrent only when the listed user is the caller and the row's client
// is the one the calling token was issued to (#135 decision 5). A token issued for a user carries
// auth_time; a client credentials token carries none, and its sub is its client identifier, which a
// user's subject can equal as a string. Such a caller is no user, so no row is its own.

// The listed user's subject, chosen to equal the identifier of the client the token names, so a
// comparison of sub alone would take a client credentials caller for the user.
const sharedSubject = "portal"

// expectConnectedClientsOfUser42 registers the list's reads: user 42, holding a live grant with the
// portal client (5) and with another client (6).
func expectConnectedClientsOfUser42(database *datamocks.Database) {
	database.On("GetUserByID", mock.Anything, (*sql.Tx)(nil), int64(42)).
		Return(&record.User{ID: 42, Subject: sharedSubject}, nil).Once()
	database.On("GetConsentsByUserID", mock.Anything, (*sql.Tx)(nil), int64(42)).
		Return([]record.UserConsent{}, nil).Once()
	database.On("GetLiveGrantsByUserID", mock.Anything, (*sql.Tx)(nil), int64(42), mock.Anything).
		Return([]record.LiveGrant{
			{RefreshTokenID: 1, ClientID: 5, Scope: "openid"},
			{RefreshTokenID: 2, ClientID: 6, Scope: "openid"},
		}, nil).Once()
	database.On("GetClientsByIDs", mock.Anything, (*sql.Tx)(nil), []int64{5, 6}).
		Return([]record.Client{
			{ID: 5, ClientIdentifier: "portal"},
			{ID: 6, ClientIdentifier: "calendar"},
		}, nil).Once()
}

func TestHandleUserConnectedClientsGet_IsCurrent(t *testing.T) {
	for _, tc := range []struct {
		name   string
		claims map[string]interface{}
		want   map[string]bool
	}{
		{
			name:   "the listed user's own token marks the client it was issued to",
			claims: map[string]interface{}{"sub": sharedSubject, "client_id": "portal", "auth_time": float64(1)},
			want:   map[string]bool{"portal": true, "calendar": false},
		},
		{
			name:   "a client credentials token whose sub equals the user's subject marks nothing",
			claims: map[string]interface{}{"sub": sharedSubject, "client_id": "portal"},
			want:   map[string]bool{"portal": false, "calendar": false},
		},
		{
			name:   "another user's token marks nothing",
			claims: map[string]interface{}{"sub": "someone-else", "client_id": "portal", "auth_time": float64(1)},
			want:   map[string]bool{"portal": false, "calendar": false},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			expectConnectedClientsOfUser42(database)

			req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users/42/connected-clients", nil)
			req.SetPathValue("id", "42")
			req = setTokenContextWithClaims(req, tc.claims)
			rr := httptest.NewRecorder()
			HandleUserConnectedClientsGet(database).ServeHTTP(rr, req)

			require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
			var out api.GetConnectedClientsResponse
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &out))
			got := map[string]bool{}
			for _, row := range out.Clients {
				got[row.ClientIdentifier] = row.IsCurrent
			}
			assert.Equal(t, tc.want, got)
		})
	}
}
