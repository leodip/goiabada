package urlmatch

import (
	"net/url"
	"strings"
)

// BackchannelLogoutURIProblem is what CheckBackchannelLogoutURI found wrong with a back-channel
// logout URI, or BackchannelLogoutURIAcceptable. Each intake names its own refusal for each.
type BackchannelLogoutURIProblem int

const (
	// BackchannelLogoutURIAcceptable is a URI the rule admits.
	BackchannelLogoutURIAcceptable BackchannelLogoutURIProblem = iota
	// BackchannelLogoutURITooLong is a URI longer than BackchannelLogoutURIMaxBytes.
	BackchannelLogoutURITooLong
	// BackchannelLogoutURIMalformed is a value that is not an absolute URI naming a host, with no
	// fragment, well-formed percent-escapes and none of the characters a URI excludes.
	BackchannelLogoutURIMalformed
	// BackchannelLogoutURISchemeNotHTTP is an absolute URI whose scheme is neither http nor https.
	BackchannelLogoutURISchemeNotHTTP
	// BackchannelLogoutURIUserinfo is a URI carrying a user name or password.
	BackchannelLogoutURIUserinfo
	// BackchannelLogoutURIPlainHTTP is an http URI where only https is allowed.
	BackchannelLogoutURIPlainHTTP
)

// BackchannelLogoutURIMaxBytes bounds a back-channel logout URI at a redirect URI's width, the
// column's (#784 decision 14).
const BackchannelLogoutURIMaxBytes = 2048

// uriExcludedChars are the characters RFC 3986 excludes from a URI, which must be percent-encoded
// to appear at all: the set dynamic client registration refuses in a redirect URI.
const uriExcludedChars = "<>\"{}|\\^` "

// CheckBackchannelLogoutURI holds a back-channel logout URI to OpenID Connect Back-Channel Logout
// 1.0 section 2.2 as #784 decision 6 settles it: an absolute http or https URI naming a host, with no
// userinfo (RFC 9110 section 4.2.4 forbids it in an http or https URI) and no fragment (section 2.2),
// well-formed percent-escapes, none of the characters RFC 3986 excludes, and at most
// BackchannelLogoutURIMaxBytes. A query is allowed, and the URI is kept exactly as given.
//
// Section 2.2 says the URI SHOULD use https and MAY use http for a confidential client when the OP
// allows it. allowHTTP is that permission, which the caller decides: an administrator's
// confidential client has it, and a public client and a self-registered client do not. There is no
// loopback exception: the rule is about the client, not the host.
//
// The rule is checked when a URI is stored and again before each delivery, so a URI stored before a
// client changed type is not sent to.
func CheckBackchannelLogoutURI(uri string, allowHTTP bool) BackchannelLogoutURIProblem {
	// Before the parse, so an overlong value is never parsed.
	if len(uri) > BackchannelLogoutURIMaxBytes {
		return BackchannelLogoutURITooLong
	}
	if uri == "" || strings.ContainsAny(uri, uriExcludedChars) {
		return BackchannelLogoutURIMalformed
	}
	u, err := url.Parse(uri)
	if err != nil || !u.IsAbs() {
		return BackchannelLogoutURIMalformed
	}
	// url.Parse lowercases the scheme it answers.
	if u.Scheme != "http" && u.Scheme != "https" {
		return BackchannelLogoutURISchemeNotHTTP
	}
	if u.Hostname() == "" || strings.Contains(uri, "#") {
		return BackchannelLogoutURIMalformed
	}
	// url.Parse leaves a malformed escape in the query alone; PathUnescape refuses exactly a "%" not
	// followed by two hex digits, which RFC 3986 section 2.1 says is not a URI.
	if _, err := url.PathUnescape(uri); err != nil {
		return BackchannelLogoutURIMalformed
	}
	if u.User != nil {
		return BackchannelLogoutURIUserinfo
	}
	if u.Scheme == "http" && !allowHTTP {
		return BackchannelLogoutURIPlainHTTP
	}
	return BackchannelLogoutURIAcceptable
}
