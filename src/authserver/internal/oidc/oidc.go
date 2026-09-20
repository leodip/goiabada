// Package oidc holds the OpenID Connect vocabulary the auth server publishes: which
// scopes are OIDC's own rather than a resource permission, and the shape of the
// discovery document served at /.well-known/openid-configuration.
//
// It belongs to the auth server rather than to the shared kernel because that is the
// process that publishes both. WellKnownConfig is a contract with arbitrary OIDC
// clients, not a contract between this server and the admin console, and the admin
// console consumes nothing here (#360).
//
// dcr.go is here on that same test. RFC 7591 registration is OAuth rather than OIDC
// proper, but both ends this server exposes are the OIDC-flavoured ones: /connect/register,
// announced as registration_endpoint in the discovery document above (#385).
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
