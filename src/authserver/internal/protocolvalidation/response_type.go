package protocolvalidation

import (
	"strings"

	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/core/oauth"
)

// ResponseTypeInfo contains parsed information about an OAuth2 response_type parameter.
// The response_type can be space-separated for OIDC (e.g., "id_token token").
type ResponseTypeInfo struct {
	HasCode    bool
	HasToken   bool
	HasIdToken bool

	// Unrecognised is set when a value is none of code, token and id_token. RFC 6749 3.1.1 makes
	// response_type a space-delimited list of values and 3.1.2.4 an unsupported one an error, so the
	// parser reports what it did not understand instead of dropping it: "code foo" is not "code"
	// (#244).
	Unrecognised bool

	// Repeated is set when a recognised value appears twice. "code code" names one type, and the
	// parser used to collapse it into that, so a request repeating a value was accepted as the
	// request it repeated (#244).
	Repeated bool

	// Malformed is set when the values are not separated by single spaces, or a space comes before
	// the first or after the last (oauth.IsWellFormedSpaceDelimited). "code " is not "code": RFC
	// 6749 3.1.1's grammar is response-name *( SP response-name ) (#244).
	Malformed bool
}

// ParseResponseType parses a response_type string and returns information about
// which response types are requested. The response_type can contain multiple
// space-separated values per OIDC Core specification, split as every other space-delimited
// parameter is (oauth.SplitSpaceDelimited). A value it does not recognise, a recognised one it
// sees twice, or separators the grammar does not allow are reported on the result, and
// ValidateRequest refuses the request for each. The values are still read from a malformed one, so
// the response mode an error is answered in follows what the client asked for.
func ParseResponseType(responseType string) ResponseTypeInfo {
	info := ResponseTypeInfo{Malformed: !oauth.IsWellFormedSpaceDelimited(responseType)}
	for _, rt := range oauth.SplitSpaceDelimited(responseType) {
		var seen *bool
		switch rt {
		case "code":
			seen = &info.HasCode
		case "token":
			seen = &info.HasToken
		case "id_token":
			seen = &info.HasIdToken
		default:
			info.Unrecognised = true
			continue
		}
		if *seen {
			info.Repeated = true
		}
		*seen = true
	}
	return info
}

// IsImplicitFlow returns true if the response type indicates an implicit flow.
// Implicit flow response types: "token", "id_token", "id_token token" (or "token id_token").
// A response type with "code" is NOT implicit flow (it's authorization code or hybrid flow).
func (r ResponseTypeInfo) IsImplicitFlow() bool {
	return (r.HasToken || r.HasIdToken) && !r.HasCode
}

// IsCodeOnly reports whether the response type is exactly "code": the code was asked for and
// nothing else was, recognised or not, nothing was asked for twice, and no space came with it.
//
// It is what scopes RFC 8252 section 7.3's loopback port flexibility to the authorization code
// flow, at the three places that decide it (ValidateClientAndRedirectURI, redirectWillBeEmitted and
// /auth/issue's registration gate). They used to recover this from the raw token sequence, because
// the parser ignored unrecognised values and collapsed duplicates, which made HasCode && !HasToken
// && !HasIdToken true for "code foo" and "code code". The parser reports both now, so the parsed
// result carries the whole answer. And not !IsImplicitFlow(), which is true for "code token" and
// for garbage such as "foo": only the exact type buys an arbitrary loopback port (#41, #244).
func (r ResponseTypeInfo) IsCodeOnly() bool {
	return r.HasCode && !r.HasToken && !r.HasIdToken && !r.Unrecognised && !r.Repeated && !r.Malformed
}

// ScopeHonoured is scope as this response type can use it: offline_access is dropped when the
// response type does not return an authorization code, and the scope is otherwise returned as given,
// normalized.
//
// OpenID Connect Core 1.0 section 11: "The Authorization Server MUST ignore the offline_access
// request unless the Client is using a response_type value that would result in an Authorization
// Code being returned." A refresh token is only ever issued from a code, so on an implicit response
// the value could do nothing but ride on the scope claim of the tokens and force a consent screen
// for a grant that will not be offline (#244).
func (r ResponseTypeInfo) ScopeHonoured(scope string) string {
	normalized := oidc.NormalizeScope(scope)
	if r.HasCode {
		return normalized
	}

	kept := []string{}
	for _, value := range oidc.SplitScope(normalized) {
		if !oidc.IsOfflineAccessScope(value) {
			kept = append(kept, value)
		}
	}
	return strings.Join(kept, " ")
}
