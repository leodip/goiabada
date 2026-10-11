package protocolvalidation

import (
	"context"
	"net/http"
	"testing"

	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The refresh token grant renews authserver:manage-account for a client other than the admin
// console's only while the user's stored consent to it covers that scope, whatever the client's
// Consent required says (#509 decision 3). It is judged on the scope this refresh would issue, so a
// refresh narrowed to leave manage-account out still succeeds, and refused with invalid_grant and
// the sentences a client requiring consent already gets. A token issued before the upgrade is
// exactly such a grant: nothing in it says how it was obtained. A password grant's token is not
// asked, and neither is the admin console's client.
//
// Every row's client has Consent required off. A row that passes readsConsent false has no consent
// row stubbed, so the strict mock fails it if the arm reads one.
func TestValidateTokenRequest_RefreshToken_ManageAccountConsent(t *testing.T) {
	const noConsent = "The user has either not given consent to this client or the previously granted consent has been revoked."
	const notConsented = "Scope 'authserver:manage-account' is not recognized. The user has not consented to the 'authserver:manage-account' permission."

	testCases := []struct {
		name           string
		grant          storedGrant
		requestedScope string // empty means omitted, so the arm judges the whole stored grant
		// wantDesc is the invalid_grant description, empty when the refresh is accepted.
		wantDesc string
		// permissionScope, when set, is the one resource scope the checker is asked about on an
		// accepted refresh, and it answers held.
		permissionScope string
	}{
		{
			// The crafted link's token, or one issued before the upgrade.
			name:     "no stored consent, scope omitted",
			grant:    storedGrant{scope: "openid authserver:manage-account", readsConsent: true},
			wantDesc: noConsent,
		},
		{
			name:           "no stored consent, scope requested explicitly",
			grant:          storedGrant{scope: "openid profile authserver:manage-account", readsConsent: true},
			requestedScope: "openid authserver:manage-account",
			wantDesc:       noConsent,
		},
		{
			// The user unticked manage-account on the screen, or the consent was rewritten without it.
			name:     "the stored consent leaves manage-account out",
			grant:    storedGrant{scope: "openid authserver:manage-account", readsConsent: true, consentScope: "openid"},
			wantDesc: notConsented,
		},
		{
			// The #499 allowance means only that (decision 2).
			name: "a client allowed the administrative scopes is refused like any other",
			grant: storedGrant{scope: "openid authserver:manage-account", readsConsent: true,
				administrativeScopesAllowed: true},
			wantDesc: noConsent,
		},
		{
			name: "the stored consent covers it",
			grant: storedGrant{scope: "openid authserver:manage-account", readsConsent: true,
				consentScope: "openid authserver:manage-account"},
			permissionScope: "authserver:manage-account",
		},
		{
			// Only manage-account is owed whatever the client says; the client's other scopes keep
			// following its Consent required, which is off.
			name: "a consent covering manage-account but not profile is enough",
			grant: storedGrant{scope: "openid profile authserver:manage-account", readsConsent: true,
				consentScope: "openid authserver:manage-account"},
			permissionScope: "authserver:manage-account",
		},
		{
			// RFC 6749 section 6 lets the client narrow the grant, and the token was not spent.
			name:           "narrowed to leave manage-account out, no consent is read",
			grant:          storedGrant{scope: "openid profile authserver:manage-account"},
			requestedScope: "openid profile",
		},
		{
			name:  "a grant without manage-account reads no consent",
			grant: storedGrant{scope: "openid profile"},
		},
		{
			name: "the admin console's client is not asked",
			grant: storedGrant{scope: "openid authserver:manage-account",
				clientIdentifier: builtin.AdminConsoleClientIdentifier},
			permissionScope: "authserver:manage-account",
		},
		{
			// A replay of a rotated token. Refused here, it would never reach the containment that
			// revokes its live successor, which would then refresh on narrowed to leave
			// manage-account out. Containment refuses it instead.
			name:            "a revoked token is handed on to replay containment, no consent is read",
			grant:           storedGrant{scope: "openid authserver:manage-account", revoked: true},
			permissionScope: "authserver:manage-account",
		},
		{
			// The user typed the password into the client, which skips consent today (decision 3).
			name:            "a password grant's token is not asked",
			grant:           storedGrant{ropc: true, scope: "openid authserver:manage-account"},
			permissionScope: "authserver:manage-account",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			validator, mockPermissionChecker, settings, input := newStoredGrantRefresh(t, tc.grant, tc.requestedScope, true)
			if tc.permissionScope != "" {
				mockPermissionChecker.On("UserHasScopePermission", mock.Anything, int64(1), tc.permissionScope).
					Return(true, nil).Once()
			}

			result, err := validator.ValidateTokenRequest(context.Background(), settings, input)

			if tc.wantDesc == "" {
				require.NoError(t, err)
				assert.NotNil(t, result)
				return
			}

			assert.Nil(t, result)
			var customErr *oauth.ErrorDetail
			require.ErrorAs(t, err, &customErr)
			assert.Equal(t, "invalid_grant", customErr.Code())
			assert.Equal(t, tc.wantDesc, customErr.Description())
			assert.Equal(t, http.StatusBadRequest, customErr.HTTPStatus())
			mockPermissionChecker.AssertNotCalled(t, "UserHasScopePermission", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}
