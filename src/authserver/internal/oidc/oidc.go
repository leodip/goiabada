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

// claimScopes is openid and the claim scopes: the set that is answered from the user's own
// profile rather than a resource permission, and that puts the userinfo audience in an access
// token. It is the one definition the predicate, the consent descriptions and the discovery
// document's scopes_supported all read, where each used to carry its own copy (#425).
var claimScopes = []string{"openid", "profile", "email", "address", "phone", "groups", "attributes"}

func IsClaimScope(scope string) bool {
	return slices.Contains(claimScopes, scope)
}

// IsOfflineAccessScope matches offline_access exactly. RFC 6749 section 3.3 makes scope values
// case-sensitive strings, so OFFLINE_ACCESS is not this scope, and every site now agrees on that:
// the validators used to accept it case-folded and trimmed while consent and issuance matched it
// exactly, and the prompt=none path matched it as a substring (#425).
func IsOfflineAccessScope(scope string) bool {
	return scope == OfflineAccessScope
}

// HasOfflineAccessScope reports whether a whole scope string, space-delimited per RFC 6749
// section 3.3, carries offline_access as one of its values. A resource scope that merely contains
// the text, such as res:offline_access_read, is not offline access.
func HasOfflineAccessScope(scope string) bool {
	return slices.ContainsFunc(strings.Split(scope, " "), IsOfflineAccessScope)
}

// SupportedScopes is the scopes_supported the discovery document publishes: the claim scopes and
// offline_access. It returns a fresh slice, so a caller appending to it cannot reach the roster.
func SupportedScopes() []string {
	return append(slices.Clone(claimScopes), OfflineAccessScope)
}

// ScopeDescriptionKey returns the i18n catalog key for a built-in scope's description
// (consent.scope.<scope>.description): a claim scope or offline_access. It returns "" for any
// other scope; the caller describes resource-permission scopes itself.
//
// It returns a key rather than the localized string because the locale is the request's, and
// the caller holds the request context that i18n.T reads it from.
func ScopeDescriptionKey(scope string) string {
	if IsClaimScope(scope) || IsOfflineAccessScope(scope) {
		return "consent.scope." + scope + ".description"
	}
	return ""
}
