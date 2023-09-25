package core

import "slices"

func IsOIDCScope(scope string) bool {
	oidcScopes := []string{"openid", "profile", "email", "address", "phone", "offline_access"}
	return slices.Contains(oidcScopes, scope)
}

func GetOIDCScopeDescription(scope string) string {
	if scope == "openid" {
		return "Authenticate your user and allow access to the subject identifier (sub claim)"
	} else if scope == "profile" {
		return "Access to claims: name, family_name, given_name, middle_name, nickname, preferred_username, profile, website, gender, birthdate, zoneinfo, locale, and updated_at"
	} else if scope == "email" {
		return "Access to claims: email, email_verified"
	} else if scope == "address" {
		return "Access to the address claim"
	} else if scope == "phone" {
		return "Access to claims: phone_number and phone_number_verified"
	} else if scope == "offline_access" {
		return "Access to a refresh token, allowing the client to obtain a new access token without requiring your immediate interaction"
	} else {
		return ""
	}
}
