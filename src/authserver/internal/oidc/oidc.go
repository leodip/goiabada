package oidc

import (
	"slices"
	"strings"
)

const OfflineAccessScope = "offline_access"

func IsIdTokenScope(scope string) bool {
	oidcScopes := []string{"openid", "profile", "email", "address", "phone", "groups", "attributes"}
	return slices.Contains(oidcScopes, scope)
}

func IsOfflineAccessScope(scope string) bool {
	return strings.EqualFold(strings.TrimSpace(scope), "offline_access")
}

// GetIdTokenScopeDescriptionKey returns the i18n catalog key for a built-in
// OIDC / offline_access scope's description (consent.scope.<scope>.description).
// Returns "" for unknown scopes (the caller handles resource-permission scopes).
//
// This returns a key rather than the localized string so oidc stays free of an
// i18n dependency (i18n → oauth → oidc would otherwise cycle); the caller, which
// has a request context, renders it via i18n.T.
func GetIdTokenScopeDescriptionKey(scope string) string {
	switch scope {
	case "openid", "profile", "email", "address", "phone", "groups", "attributes", "offline_access":
		return "consent.scope." + scope + ".description"
	default:
		return ""
	}
}
