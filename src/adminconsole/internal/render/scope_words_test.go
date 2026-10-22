package render

import (
	"context"
	"testing"

	"github.com/leodip/goiabada/core/i18n"
	"github.com/stretchr/testify/assert"
)

// Each scope is worded as the consent screen words it, in the request's language, and a scope the
// catalog has no words for keeps its name alone.
func TestScopeList(t *testing.T) {
	en := context.Background()
	assert.Equal(t, []ScopeWord{
		{Scope: "openid", Description: i18n.T(en, "consent.scope.openid.description")},
		{Scope: "offline_access", Description: i18n.T(en, "consent.scope.offline_access.description")},
		{Scope: "authserver:manage-account", Description: i18n.T(en, "consent.scope.authserver_manage_account.description")},
		{Scope: "billing:read", Description: "Permission read on resource billing"},
		{Scope: "custom-scope", Description: ""},
	}, scopeList(en, "openid  offline_access authserver:manage-account billing:read custom-scope"))

	pt := i18n.WithLocale(context.Background(), true, "pt-BR")
	words := scopeList(pt, "email")
	assert.Equal(t, i18n.T(pt, "consent.scope.email.description"), words[0].Description)
	assert.NotEqual(t, i18n.T(en, "consent.scope.email.description"), words[0].Description, "worded in the request's language")

	assert.Empty(t, scopeList(en, ""))
}
