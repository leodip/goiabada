package oauth

import "strings"

// ResponseTypeInfo contains parsed information about an OAuth2 response_type parameter.
// The response_type can be space-separated for OIDC (e.g., "id_token token").
type ResponseTypeInfo struct {
	HasCode    bool
	HasToken   bool
	HasIdToken bool
}

// ParseResponseType parses a response_type string and returns information about
// which response types are requested. The response_type can contain multiple
// space-separated values per OIDC Core specification.
func ParseResponseType(responseType string) ResponseTypeInfo {
	responseTypes := strings.Fields(responseType)
	info := ResponseTypeInfo{}
	for _, rt := range responseTypes {
		switch rt {
		case "code":
			info.HasCode = true
		case "token":
			info.HasToken = true
		case "id_token":
			info.HasIdToken = true
		}
	}
	return info
}

// IsImplicitFlow returns true if the response type indicates an implicit flow.
// Implicit flow response types: "token", "id_token", "id_token token" (or "token id_token").
// A response type with "code" is NOT implicit flow (it's authorization code or hybrid flow).
func (r ResponseTypeInfo) IsImplicitFlow() bool {
	return (r.HasToken || r.HasIdToken) && !r.HasCode
}
