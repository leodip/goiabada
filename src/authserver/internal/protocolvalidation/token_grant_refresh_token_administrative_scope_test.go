package protocolvalidation

import (
	"context"
	"net/http"
	"testing"

	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The refresh token grant refuses an administrative scope for a client that may not request one, on
// both shapes of refresh token: descended from a code, and issued by the password grant. It answers
// invalid_grant in the shape of the other per-scope re-checks, and before the token is spent, so a
// refresh whose scope leaves the administrative scope out still succeeds (#499 decisions 6 and 7).
// A token issued before the upgrade, or before an operator withdrew the allowance, is exactly such a
// grant: the client's allowance is read now, not when the token was issued.
//
// The refused rows pass reachesUser false, so the strict mock fails a case that reads the subject
// or the consent row, and the permission checker has no expectation, so the refusal is shown to
// come before both.
func TestValidateTokenRequest_RefreshToken_AdministrativeScope(t *testing.T) {
	testCases := []struct {
		name           string
		grant          storedGrant
		requestedScope string // empty means omitted, so the arm judges the whole stored grant
		// wantRefused is the administrative scopes refused, nil when the refresh is accepted.
		wantRefused []string
		wantDesc    string
		// permissionScope, when set, is the one resource scope the checker is asked about on an
		// accepted refresh, and it answers held.
		permissionScope string
	}{
		{
			name:        "authorization code grant, scope omitted",
			grant:       storedGrant{scope: "openid profile authserver:manage"},
			wantRefused: []string{"authserver:manage"},
			wantDesc:    "Scope 'authserver:manage' is not recognized. The client is not allowed to request the administrative scope 'authserver:manage'.",
		},
		{
			name:        "ROPC grant, scope omitted",
			grant:       storedGrant{ropc: true, scope: "openid authserver:manage"},
			wantRefused: []string{"authserver:manage"},
			wantDesc:    "Scope 'authserver:manage' is not recognized. The client is not allowed to request the administrative scope 'authserver:manage'.",
		},
		{
			// Every administrative scope asked for is recorded; the answer names the first.
			name:           "two administrative scopes requested explicitly",
			grant:          storedGrant{scope: "openid authserver:admin-read authserver:manage-users"},
			requestedScope: "openid authserver:admin-read authserver:manage-users",
			wantRefused:    []string{"authserver:admin-read", "authserver:manage-users"},
			wantDesc:       "Scope 'authserver:admin-read' is not recognized. The client is not allowed to request the administrative scope 'authserver:admin-read'.",
		},
		{
			// Refused before the consent comparison, so a client requiring consent, whose stored
			// consent holds the scope, gets the same answer.
			name:        "a client requiring consent gets the same answer",
			grant:       storedGrant{scope: "openid authserver:manage-clients", consentScope: "openid authserver:manage-clients"},
			wantRefused: []string{"authserver:manage-clients"},
			wantDesc:    "Scope 'authserver:manage-clients' is not recognized. The client is not allowed to request the administrative scope 'authserver:manage-clients'.",
		},
		{
			// The way out RFC 6749 section 6 gives the client: a refresh narrowed to leave the
			// administrative scope out.
			name:           "authorization code grant, narrowed to leave it out",
			grant:          storedGrant{scope: "openid profile authserver:manage"},
			requestedScope: "openid profile",
		},
		{
			name:           "ROPC grant, narrowed to leave it out",
			grant:          storedGrant{ropc: true, scope: "openid authserver:manage"},
			requestedScope: "openid",
		},
		{
			name:            "an allowed client refreshes it",
			grant:           storedGrant{scope: "openid authserver:manage", administrativeScopesAllowed: true},
			permissionScope: "authserver:manage",
		},
		{
			name:            "an allowed client refreshes it, ROPC grant",
			grant:           storedGrant{ropc: true, scope: "openid authserver:manage", administrativeScopesAllowed: true},
			permissionScope: "authserver:manage",
		},
		{
			// manage-account is not administrative (decision 2), so it reaches the permission
			// re-check as any resource scope does.
			name:            "manage-account is not refused",
			grant:           storedGrant{scope: "openid authserver:manage-account"},
			permissionScope: "authserver:manage-account",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			validator, mockPermissionChecker, settings, input := newStoredGrantRefresh(t, tc.grant, tc.requestedScope, tc.wantRefused == nil)
			if tc.permissionScope != "" {
				mockPermissionChecker.On("UserHasScopePermission", mock.Anything, int64(1), tc.permissionScope).
					Return(true, nil).Once()
			}

			result, err := validator.ValidateTokenRequest(context.Background(), settings, input)

			if tc.wantRefused == nil {
				require.NoError(t, err)
				assert.NotNil(t, result)
				return
			}

			assert.Nil(t, result)
			var refused *AdministrativeScopeRefusedError
			require.ErrorAs(t, err, &refused)
			assert.Equal(t, tc.wantRefused, refused.Scopes)
			assert.Equal(t, int64(1), refused.Client.Id)
			assert.Equal(t, "client1", refused.Client.ClientIdentifier)
			assert.Equal(t, int64(1), refused.UserId)

			var customErr *oauth.ErrorDetail
			require.ErrorAs(t, err, &customErr)
			assert.Equal(t, "invalid_grant", customErr.Code())
			assert.Equal(t, tc.wantDesc, customErr.Description())
			assert.Equal(t, http.StatusBadRequest, customErr.HTTPStatus())
			mockPermissionChecker.AssertNotCalled(t, "UserHasScopePermission", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}
