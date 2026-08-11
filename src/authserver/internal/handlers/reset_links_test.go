package handlers

import (
	"net/url"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/stringutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// codeAlphabet restates the alphabet GenerateSecurityRandomString draws from. It is
// unexported there, so this copy is checked against real output in
// TestLinkCodeAlphabetIsUnreserved rather than trusted.
const codeAlphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_."

func setAuthServerBaseURL(t *testing.T, baseURL string) {
	t.Helper()
	previous := config.GetAuthServer().BaseURL
	t.Cleanup(func() { config.GetAuthServer().BaseURL = previous })
	config.GetAuthServer().BaseURL = baseURL
}

// ResetPasswordLink and AccountActivateLink own the shape of the two links Goiabada
// emails. The link carries the verification code and nothing else, which is what
// closes #112: no address means no address to mangle.
func TestResetPasswordLink(t *testing.T) {
	testCases := []struct {
		name    string
		baseURL string
		code    string
		want    string
	}{
		{
			name:    "typical base URL",
			baseURL: "https://auth.example.com",
			code:    "abc123",
			want:    "https://auth.example.com/reset-password?code=abc123",
		},
		{
			name:    "base URL with a port",
			baseURL: "http://localhost:9090",
			code:    "abc123",
			want:    "http://localhost:9090/reset-password?code=abc123",
		},
		{
			// The base URL is concatenated as-is, the same way GetProfileURL does it,
			// so a trailing slash doubles up. Pinned because it produces a subtly
			// broken link rather than an obvious failure.
			name:    "trailing slash is not normalized",
			baseURL: "https://auth.example.com/",
			code:    "abc123",
			want:    "https://auth.example.com//reset-password?code=abc123",
		},
		{
			name:    "empty base URL yields a relative link",
			baseURL: "",
			code:    "abc123",
			want:    "/reset-password?code=abc123",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			setAuthServerBaseURL(t, tc.baseURL)

			got := ResetPasswordLink(tc.code)

			assert.Equal(t, tc.want, got)
			// Section 2's checkable statement: no link Goiabada builds carries an
			// address, so none of them contains an '@'.
			assert.NotContains(t, got, "@")
		})
	}
}

func TestAccountActivateLink(t *testing.T) {
	testCases := []struct {
		name    string
		baseURL string
		code    string
		want    string
	}{
		{
			name:    "typical base URL",
			baseURL: "https://auth.example.com",
			code:    "abc123",
			want:    "https://auth.example.com/account/activate?code=abc123",
		},
		{
			name:    "base URL with a port",
			baseURL: "http://localhost:9090",
			code:    "abc123",
			want:    "http://localhost:9090/account/activate?code=abc123",
		},
		{
			name:    "trailing slash is not normalized",
			baseURL: "https://auth.example.com/",
			code:    "abc123",
			want:    "https://auth.example.com//account/activate?code=abc123",
		},
		{
			name:    "empty base URL yields a relative link",
			baseURL: "",
			code:    "abc123",
			want:    "/account/activate?code=abc123",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			setAuthServerBaseURL(t, tc.baseURL)

			got := AccountActivateLink(tc.code)

			assert.Equal(t, tc.want, got)
			assert.NotContains(t, got, "@")
		})
	}
}

// Both links must land on the path constant the consuming handlers redirect to. The
// flows validate the code on the first request and then redirect to the same path
// with no query, so a drift between the emailed path and the constant would break
// the flow rather than fail visibly.
func TestLinkPathsMatchTheSharedConstants(t *testing.T) {
	setAuthServerBaseURL(t, "https://auth.example.com")

	testCases := []struct {
		name string
		link string
		want string
	}{
		{name: "reset", link: ResetPasswordLink("abc123"), want: ResetPasswordPath},
		{name: "activate", link: AccountActivateLink("abc123"), want: AccountActivatePath},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := url.Parse(tc.link)
			require.NoError(t, err)

			assert.Equal(t, tc.want, parsed.Path)
			// The code is the only parameter in either link.
			assert.Equal(t, []string{"code"}, queryKeys(parsed))
		})
	}
}

func queryKeys(u *url.URL) []string {
	keys := make([]string, 0, len(u.Query()))
	for k := range u.Query() {
		keys = append(keys, k)
	}
	return keys
}

// The property the whole design rests on: the code recovered from the link is the
// code that was put in it.
//
// Section 1 measured the old shape corrupting 1 of 14 email local-part characters,
// and it was '+'. This is that measurement pointed at the only value the link still
// carries. The adversarial codes are not values GenerateSecurityRandomString can
// produce; they are here because the helper is exported and a future caller could
// pass anything.
func TestLinkCodeSurvivesTheRoundTrip(t *testing.T) {
	setAuthServerBaseURL(t, "https://auth.example.com")

	codes := []string{
		codeAlphabet, // every character the generator can emit, at once
		stringutil.GenerateSecurityRandomString(32), // a real code, at the length both flows issue
		"a+b",          // the character #112 is about: a bare '+' decodes to a space
		"a%2b",         // a '%' that begins a valid escape, the second broken class
		"a%26code%3dX", // an attempt to smuggle a second parameter
		"a@b",          // would put an '@' back into a link
		"a b",          // a literal space
		"a&b=c",        // a bare separator
		"",             // no code at all
	}

	for _, code := range codes {
		for _, build := range []struct {
			name string
			fn   func(string) string
		}{
			{name: "reset", fn: ResetPasswordLink},
			{name: "activate", fn: AccountActivateLink},
		} {
			t.Run(build.name+"/"+code, func(t *testing.T) {
				link := build.fn(code)

				// No link ever carries a literal '@', whatever it was handed.
				assert.NotContains(t, link, "@")

				parsed, err := url.Parse(link)
				require.NoError(t, err)

				// Query() applies form-urlencoded parsing, which is exactly what the
				// consuming handlers do and exactly what broke the old links.
				assert.Equal(t, code, parsed.Query().Get("code"))
			})
		}
	}
}

// The alphabet restated at the top of this file is the one the generator actually
// uses, so the round-trip case above really does cover every character a code can
// contain. Every character is RFC 3986 unreserved, which is the reason section 4
// gives for the design being safe.
func TestLinkCodeAlphabetIsUnreserved(t *testing.T) {
	const unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"

	for _, c := range codeAlphabet {
		assert.True(t, strings.ContainsRune(unreserved, c),
			"code alphabet character %q is not RFC 3986 unreserved", c)
	}

	// Sampled rather than exhaustive: this is only guarding against the generator's
	// alphabet drifting away from the copy above, and 8000 characters covers all 65
	// with overwhelming probability.
	generated := stringutil.GenerateSecurityRandomString(8000)
	require.Len(t, generated, 8000)
	for _, c := range generated {
		assert.True(t, strings.ContainsRune(codeAlphabet, c),
			"generated code contains %q, which codeAlphabet does not list", c)
	}
}
