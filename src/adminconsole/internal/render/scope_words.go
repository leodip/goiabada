package render

import (
	"context"
	"strings"

	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/i18n"
)

// ScopeWord is one scope of a consent with its plain wording, empty when the catalog has none.
type ScopeWord struct {
	Scope       string
	Description string
}

// scopeList words each scope of a consent's space-separated scope as the auth server's consent
// screen does, in the request's language: a claim scope or offline_access by its
// consent.scope.<scope>.description entry, authserver:manage-account by its own, and any other
// resource permission by the permission template. A scope the catalog words nowhere keeps an empty
// description, which a page shows by its name alone. The consent screen decides the claim scopes
// from the auth server's own roster; here the catalog entry is the roster, since T answers a key
// it has no entry for with the key itself.
func scopeList(ctx context.Context, scope string) []ScopeWord {
	manageAccount := builtin.AuthServerResourceIdentifier + ":" + builtin.ManageAccountPermissionIdentifier
	var words []ScopeWord
	for _, s := range strings.Fields(scope) {
		word := ScopeWord{Scope: s}
		switch resource, permission, isPermission := strings.Cut(s, ":"); {
		case s == manageAccount:
			word.Description = i18n.T(ctx, "consent.scope.authserver_manage_account.description")
		case isPermission:
			word.Description = i18n.T(ctx, "consent.scope.permission_template",
				map[string]any{"permission": permission, "resource": resource})
		default:
			key := "consent.scope." + s + ".description"
			if text := i18n.T(ctx, key); text != key {
				word.Description = text
			}
		}
		words = append(words, word)
	}
	return words
}
