package oauthclient_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/core/oauth"
)

// Decision 12: the granted scope is read from the token response, matched exactly.
func TestJwtInfo_HasScope(t *testing.T) {
	testCases := []struct {
		name    string
		granted string
		scope   string
		want    bool
	}{
		{"exact match", "openid authserver:manage profile", "authserver:manage", true},
		{"absent", "openid profile", "authserver:manage", false},
		{"a prefix of a granted scope", "authserver:manage-account", "authserver:manage", false},
		{"a scope extending a granted one", "authserver:manage", "authserver:manage-account", false},
		{"a substring", "authserver:manage", "server:man", false},
		{"empty argument", "openid profile", "", false},
		{"empty argument against a doubled space", "openid  profile", "", false},
		{"empty grant", "", "openid", false},
		{"doubled space, first token", "openid  authserver:manage", "openid", true},
		{"doubled space, second token", "openid  authserver:manage", "authserver:manage", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			info := oauthclient.JwtInfo{TokenResponse: oauth.TokenResponse{Scope: tc.granted}}

			assert.Equal(t, tc.want, info.HasScope(tc.scope))
		})
	}
}
