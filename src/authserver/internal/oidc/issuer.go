package oidc

import (
	"net/url"
	"strings"
	"unicode"
)

// IssuerIsAcceptable is the issuer rule, the one the general settings save applies to a changed
// issuer and the start applies to the stored one (#576 decisions 3 and 4). It accepts an https URL
// naming a host, with no query, fragment or user info, which is what RFC 8414 section 2, RFC 9207
// section 2 and OpenID Connect Discovery 1.0 section 3 require of an issuer, and it accepts exactly
// baseURL whatever its scheme: discovery is fetched under the base URL, which RFC 8414 section 3.3
// requires the issuer to equal, and a new install seeds it as the issuer, http on a deployment with
// no TLS.
//
// The comparison with baseURL is exact, as a client's comparison of iss is. A trailing "?" or "#"
// counts as a query or a fragment, and no URL holding a space or a control character is accepted,
// since a client compares the issuer as the string it is. The host is read without the port, so
// an authority that is a port alone, "https://:443", names no host, which RFC 9110 section 4.2.2
// forbids of an https URI.
func IssuerIsAcceptable(issuer, baseURL string) bool {
	if issuer == "" {
		return false
	}
	if issuer == baseURL {
		return true
	}
	if strings.ContainsAny(issuer, "?#") || strings.ContainsFunc(issuer, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	}) {
		return false
	}
	parsed, err := url.Parse(issuer)
	if err != nil {
		return false
	}
	return parsed.Scheme == "https" && parsed.Opaque == "" && parsed.Hostname() != "" && parsed.User == nil
}
