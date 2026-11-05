package urlmatch

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// CheckBackchannelLogoutURI is OpenID Connect Back-Channel Logout 1.0 section 2.2's rule for a
// back-channel logout URI as #784 decision 6 settles it: absolute, http or https, naming a host,
// with no userinfo (RFC 9110 section 4.2.4) and no fragment, well-formed percent-escapes, none of
// the characters RFC 3986 excludes, at most 2048 bytes, a query allowed; and http only where the
// caller allows it, which is an administrator's confidential client.
func TestCheckBackchannelLogoutURI(t *testing.T) {
	// 2048 bytes exactly, and one more.
	atBound := "https://app.example.com/" + strings.Repeat("a", 2048-len("https://app.example.com/"))
	overBound := atBound + "a"

	cases := []struct {
		uri       string
		allowHTTP bool
		want      BackchannelLogoutURIProblem
	}{
		{"https://app.example.com/backchannel-logout", false, BackchannelLogoutURIAcceptable},
		{"https://app.example.com/backchannel-logout", true, BackchannelLogoutURIAcceptable},
		{"https://app.example.com:8443/bcl?tenant=a&next=%2Fhome", false, BackchannelLogoutURIAcceptable},
		{"https://[2001:db8::1]/bcl", false, BackchannelLogoutURIAcceptable},
		{atBound, false, BackchannelLogoutURIAcceptable},
		{overBound, false, BackchannelLogoutURITooLong},

		{"http://app:3000/backchannel-logout", true, BackchannelLogoutURIAcceptable},
		{"HTTP://app:3000/backchannel-logout", true, BackchannelLogoutURIAcceptable},
		{"http://app:3000/backchannel-logout", false, BackchannelLogoutURIPlainHTTP},
		{"HTTP://app:3000/backchannel-logout", false, BackchannelLogoutURIPlainHTTP},
		// No loopback exception: decision 6's rule is the client type, not the host.
		{"http://127.0.0.1:8080/bcl", false, BackchannelLogoutURIPlainHTTP},
		{"http://localhost/bcl", false, BackchannelLogoutURIPlainHTTP},

		{"ftp://app.example.com/bcl", true, BackchannelLogoutURISchemeNotHTTP},
		{"wss://app.example.com/bcl", true, BackchannelLogoutURISchemeNotHTTP},
		{"com.example.app:/bcl", true, BackchannelLogoutURISchemeNotHTTP},
		{"javascript:alert(1)", true, BackchannelLogoutURISchemeNotHTTP},

		{"https://user:secret@app.example.com/bcl", true, BackchannelLogoutURIUserinfo},
		{"https://user@app.example.com/bcl", true, BackchannelLogoutURIUserinfo},
		{"http://user@app:3000/bcl", true, BackchannelLogoutURIUserinfo},

		{"https://app.example.com/bcl#fragment", true, BackchannelLogoutURIMalformed},
		{"https://app.example.com/bcl#", true, BackchannelLogoutURIMalformed},
		{"//app.example.com/bcl", true, BackchannelLogoutURIMalformed},
		{"/backchannel-logout", true, BackchannelLogoutURIMalformed},
		{"app.example.com/bcl", true, BackchannelLogoutURIMalformed},
		{"https:///bcl", true, BackchannelLogoutURIMalformed},
		{"https://:443/bcl", true, BackchannelLogoutURIMalformed},
		{"https://app.example.com/%zz", true, BackchannelLogoutURIMalformed},
		{"https://app.example.com/bcl?x=%2", true, BackchannelLogoutURIMalformed},
		{"https://app.example.com/a b", true, BackchannelLogoutURIMalformed},
		{"https://app.example.com/<script>", true, BackchannelLogoutURIMalformed},
		{"https://app.example.com/a\"b", true, BackchannelLogoutURIMalformed},
		{"https://app.example.com/a{b}", true, BackchannelLogoutURIMalformed},
		{"https://app.example.com/a|b", true, BackchannelLogoutURIMalformed},
		{"https://app.example.com/a\\b", true, BackchannelLogoutURIMalformed},
		{"https://app.example.com/a^b", true, BackchannelLogoutURIMalformed},
		{"https://app.example.com/a`b", true, BackchannelLogoutURIMalformed},
		{"https://app.example.com/a\x7fb", true, BackchannelLogoutURIMalformed},
		{"https://app.example.com/a\nb", true, BackchannelLogoutURIMalformed},
		{"not a uri", true, BackchannelLogoutURIMalformed},
		{"", true, BackchannelLogoutURIMalformed},
	}
	for _, tc := range cases {
		assert.Equalf(t, tc.want, CheckBackchannelLogoutURI(tc.uri, tc.allowHTTP),
			"CheckBackchannelLogoutURI(%q, allowHTTP %v)", tc.uri, tc.allowHTTP)
	}
}
