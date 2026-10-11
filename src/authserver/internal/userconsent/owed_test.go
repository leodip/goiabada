package userconsent

import (
	"testing"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
)

// The scopes a client gets only once the user's stored consent covers them, whatever its Consent
// required says: authserver:manage-account, to every client but the admin console's, matched by its
// built-in identifier (#509 decisions 1 and 2). The literals are the issue's, not the constants the
// rule is written with.
func TestAlwaysOwed(t *testing.T) {
	testCases := []struct {
		name             string
		clientIdentifier string
		scope            string
		want             []string
	}{
		{name: "the crafted link", clientIdentifier: "crafted-link-client",
			scope: "openid authserver:manage-account", want: []string{"authserver:manage-account"}},
		{name: "alone", clientIdentifier: "an-application",
			scope: "authserver:manage-account", want: []string{"authserver:manage-account"}},
		{name: "beside offline_access and an administrative scope", clientIdentifier: "an-application",
			scope: "openid offline_access authserver:manage authserver:manage-account",
			want:  []string{"authserver:manage-account"}},
		{name: "the admin console's client skips it", clientIdentifier: "admin-console-client",
			scope: "authserver:manage authserver:manage-account email openid profile"},
		{name: "an identifier only resembling the admin console's does not",
			clientIdentifier: "Admin-Console-Client", scope: "openid authserver:manage-account",
			want: []string{"authserver:manage-account"}},
		{name: "no manage-account in the scope", clientIdentifier: "an-application",
			scope: "openid profile authserver:manage"},
		{name: "an empty scope", clientIdentifier: "an-application", scope: ""},
		{name: "a custom authserver permission is not covered", clientIdentifier: "an-application",
			scope: "openid authserver:manage-accounts authserver:account"},
		{name: "another resource's manage-account is not covered", clientIdentifier: "an-application",
			scope: "openid billing:manage-account"},
		{name: "the scope is compared exactly", clientIdentifier: "an-application",
			scope: "openid AUTHSERVER:MANAGE-ACCOUNT"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, AlwaysOwed(tc.clientIdentifier, tc.scope))
		})
	}
}

func TestCovers(t *testing.T) {
	owed := []string{"authserver:manage-account"}
	consent := func(scope string) *record.UserConsent { return &record.UserConsent{Scope: scope} }

	assert.False(t, Covers(nil, owed), "no stored consent covers nothing")
	assert.False(t, Covers(consent("openid profile"), owed), "a consent leaving manage-account out")
	assert.False(t, Covers(consent(""), owed), "an empty consent")
	assert.True(t, Covers(consent("openid authserver:manage-account"), owed))
	assert.True(t, Covers(consent("authserver:manage-account"), owed))
	assert.True(t, Covers(nil, nil), "nothing owed is covered by anything, no consent included")
	assert.True(t, Covers(consent("openid"), nil))
}
