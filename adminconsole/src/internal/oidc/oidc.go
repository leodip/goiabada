package oidc

import "slices"

func IsIdTokenScope(scope string) bool {
	oidcScopes := []string{"openid", "profile", "email", "address", "phone", "groups", "attributes", "offline_access"}
	return slices.Contains(oidcScopes, scope)
}
