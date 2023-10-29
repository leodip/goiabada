package core

import "slices"

func IsIdTokenScope(scope string) bool {
	oidcScopes := []string{"openid", "profile", "email", "address", "phone", "groups", "attributes", "offline_access"}
	return slices.Contains(oidcScopes, scope)
}

func GetIdTokenScopeDescription(scope string) string {
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
	} else if scope == "groups" {
		return "Access to the groups that you belong to"
	} else if scope == "attributes" {
		return "Access to the attributes assigned to you by an admin, stored as key-value pairs"
	} else if scope == "offline_access" {
		return "Access to a refresh token, allowing the client to obtain a new access token without requiring your immediate interaction"
	} else {
		return ""
	}
}
