package protocolvalidation

import (
	"net/http"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Only a client allowed to request the administrative scopes may obtain one on a user's behalf:
// the admin console's client whatever its row says, or a client whose stored allowance is on. Any
// other client is refused every administrative scope it names, and nothing else (#499 decisions 2
// and 5).
func TestRefusedAdministrativeScopes(t *testing.T) {
	ordinary := &record.Client{ClientIdentifier: "my-reporting-tool"}
	allowed := &record.Client{ClientIdentifier: "my-reporting-tool", AdministrativeScopesAllowed: true}
	adminConsole := &record.Client{ClientIdentifier: "admin-console-client"}

	testCases := []struct {
		name   string
		client *record.Client
		scope  string
		want   []string
	}{
		{
			name:   "an ordinary client asking for manage",
			client: ordinary, scope: "openid authserver:manage",
			want: []string{"authserver:manage"},
		},
		{
			name:   "every administrative scope is named, in the order asked",
			client: ordinary,
			scope: "authserver:browser-sessions openid authserver:manage-settings authserver:manage-clients " +
				"authserver:manage-users authserver:admin-read authserver:manage",
			want: []string{"authserver:browser-sessions", "authserver:manage-settings", "authserver:manage-clients",
				"authserver:manage-users", "authserver:admin-read", "authserver:manage"},
		},
		{
			name:   "manage-account is not administrative",
			client: ordinary, scope: "openid authserver:manage-account",
			want: nil,
		},
		{
			name:   "a custom permission on authserver is not administrative",
			client: ordinary, scope: "openid authserver:custom-report",
			want: nil,
		},
		{
			name:   "another resource's manage is not administrative",
			client: ordinary, scope: "openid backend:manage offline_access",
			want: nil,
		},
		{
			name:   "an allowed client is refused nothing",
			client: allowed, scope: "openid authserver:manage authserver:admin-read",
			want: nil,
		},
		{
			name:   "the admin console's client is refused nothing, whatever its row says",
			client: adminConsole, scope: "openid email profile authserver:manage authserver:manage-account",
			want: nil,
		},
		{
			name:   "an empty scope",
			client: ordinary, scope: "",
			want: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, RefusedAdministrativeScopes(tc.client, tc.scope))
		})
	}
}

// The refusal is invalid_scope, RFC 6749 4.1.2.1's code for a requested scope the server will not
// grant, and its one English description names the first refused scope (#499 decision 7).
func TestAdministrativeScopeRefusal(t *testing.T) {
	refusal := AdministrativeScopeRefusal([]string{"authserver:manage", "authserver:admin-read"})
	require.NotNil(t, refusal)
	assert.Equal(t, "invalid_scope", refusal.Code())
	assert.Equal(t, "The client is not allowed to request the administrative scope 'authserver:manage'.",
		refusal.Description())
	assert.Equal(t, http.StatusBadRequest, refusal.HTTPStatus())
}
