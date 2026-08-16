package handlers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Every assertion in this file compares the whole returned string rather than a parsed
// url.Values. Parsing is the step that hid the duplicate state in the first place: Get
// silently returns the first of two, so a test that parses passes against the very defect
// this construction exists to remove (#146).

func TestWriteResponseParams(t *testing.T) {
	codeAndState := []responseParam{{"code", "abc123"}, {"state", "st"}}

	tests := []struct {
		name        string
		redirectURI string
		params      []responseParam
		reserved    []string
		expected    string
		expectError bool
	}{
		// The registered query must survive byte for byte (RFC 6749 section 3.1.2). The
		// six rows below are the shapes that decoding into url.Values and re-encoding
		// damages, the last one being the control that round-trips even that way.
		{
			name:        "A semicolon-separated field is not deleted",
			redirectURI: "https://app.example.com/cb?lang=en;mode=dark",
			params:      codeAndState,
			expected:    "https://app.example.com/cb?lang=en;mode=dark&code=abc123&state=st",
		},
		{
			name:        "Registered field order is not sorted",
			redirectURI: "https://app.example.com/cb?z=1&a=2",
			params:      codeAndState,
			expected:    "https://app.example.com/cb?z=1&a=2&code=abc123&state=st",
		},
		{
			name:        "A valueless registered field does not gain an equals sign",
			redirectURI: "https://app.example.com/cb?flag",
			params:      codeAndState,
			expected:    "https://app.example.com/cb?flag&code=abc123&state=st",
		},
		{
			name:        "Registered percent-escapes are not normalised",
			redirectURI: "https://app.example.com/cb?path=%7Efoo",
			params:      codeAndState,
			expected:    "https://app.example.com/cb?path=%7Efoo&code=abc123&state=st",
		},
		{
			name:        "An empty registered field is not collapsed",
			redirectURI: "https://app.example.com/cb?a=1&&b=2",
			params:      codeAndState,
			expected:    "https://app.example.com/cb?a=1&&b=2&code=abc123&state=st",
		},
		{
			name:        "A registered escaped plus survives",
			redirectURI: "https://app.example.com/cb?sig=a%2Bb",
			params:      codeAndState,
			expected:    "https://app.example.com/cb?sig=a%2Bb&code=abc123&state=st",
		},
		// The duplicate the issue names, and its percent-encoded twin.
		{
			name:        "A registered state is replaced while a registered lang survives",
			redirectURI: "https://app.example.com/cb?state=fixed&lang=en",
			params:      []responseParam{{"state", "client-csrf-token"}},
			expected:    "https://app.example.com/cb?lang=en&state=client-csrf-token",
		},
		{
			name:        "A percent-encoded registered state name is replaced too",
			redirectURI: "https://app.example.com/cb?%73tate=fixed&lang=en",
			params:      []responseParam{{"state", "client-csrf-token"}},
			expected:    "https://app.example.com/cb?lang=en&state=client-csrf-token",
		},
		{
			name:        "An unescapable registered field name is kept, not dropped",
			redirectURI: "https://app.example.com/cb?%zz=1",
			params:      []responseParam{{"state", "st"}},
			expected:    "https://app.example.com/cb?%zz=1&state=st",
		},
		{
			name:        "A URI with no query gains one without a leading ampersand",
			redirectURI: "https://app.example.com/cb",
			params:      codeAndState,
			expected:    "https://app.example.com/cb?code=abc123&state=st",
		},
		// Empty params is what makes the logout refactor behaviour-preserving: the
		// registered query comes back untouched, bare "?" included.
		{
			name:        "Empty params returns the registered query byte-identical",
			redirectURI: "https://app.example.com/cb?a=1&&b=2",
			params:      nil,
			expected:    "https://app.example.com/cb?a=1&&b=2",
		},
		{
			name:        "Empty params keeps a registered bare question mark",
			redirectURI: "https://app.example.com/cb?",
			params:      nil,
			expected:    "https://app.example.com/cb?",
		},
		{
			name:        "A registered bare question mark takes the params",
			redirectURI: "https://app.example.com/cb?",
			params:      []responseParam{{"state", "st"}},
			expected:    "https://app.example.com/cb?state=st",
		},
		{
			name:        "An unparseable redirect URI is an error, not a panic",
			redirectURI: "://bad",
			params:      []responseParam{{"state", "st"}},
			expectError: true,
		},
		// Every row above leaves reserved nil, which is what buildPostLogoutRedirect passes:
		// a registered field is replaced only when the response actually writes that name.
		// The rows below are the authorization emitters' set, where the four names are the
		// response's whether or not this particular response emits them. Each is a row of
		// the table in decision 13 of #146, driven at the seam the emitters share.
		{
			name:        "An unsent state is dropped rather than answered from the registered query",
			redirectURI: "https://app.example.com/cb?state=fixed&lang=en",
			params:      []responseParam{{"code", "fresh-code"}},
			reserved:    authorizationResponseParamNames,
			expected:    "https://app.example.com/cb?lang=en&code=fresh-code",
		},
		{
			name:        "A registered error does not ride along with an authorization code",
			redirectURI: "https://app.example.com/cb?error=stale&error_description=stale-detail&lang=en",
			params:      []responseParam{{"code", "fresh-code"}, {"state", "client-csrf"}},
			reserved:    authorizationResponseParamNames,
			expected:    "https://app.example.com/cb?lang=en&code=fresh-code&state=client-csrf",
		},
		{
			name:        "A registered code does not ride along with an error",
			redirectURI: "https://app.example.com/cb?code=stale&lang=en",
			params:      []responseParam{{"error", "access_denied"}, {"error_description", "denied"}, {"state", "client-csrf"}},
			reserved:    authorizationResponseParamNames,
			expected:    "https://app.example.com/cb?lang=en&error=access_denied&error_description=denied&state=client-csrf",
		},
		{
			// error_uri is defined by RFC 6749 4.1.2.1 and is deliberately not in the set,
			// because this server never emits it: reserving it would delete a registered
			// field that no response of ours can collide with.
			name:        "A registered error_uri survives, because no response emits one",
			redirectURI: "https://app.example.com/cb?error_uri=https%3A%2F%2Fstale&lang=en",
			params:      []responseParam{{"error", "access_denied"}, {"error_description", "denied"}},
			reserved:    authorizationResponseParamNames,
			expected:    "https://app.example.com/cb?error_uri=https%3A%2F%2Fstale&lang=en&error=access_denied&error_description=denied",
		},
		{
			name:        "A percent-encoded reserved name is dropped even when unsent",
			redirectURI: "https://app.example.com/cb?%73tate=fixed&lang=en",
			params:      []responseParam{{"code", "fresh-code"}},
			reserved:    authorizationResponseParamNames,
			expected:    "https://app.example.com/cb?lang=en&code=fresh-code",
		},
		{
			// No authorization emitter reaches this, since every response it builds carries
			// at least one parameter. Pinned so the reserved filter is known to be
			// independent of params rather than accidentally coupled to it.
			name:        "Reserved names are dropped even with no params to write",
			redirectURI: "https://app.example.com/cb?state=fixed&code=stale",
			params:      nil,
			reserved:    authorizationResponseParamNames,
			expected:    "https://app.example.com/cb",
		},
		{
			name:        "A reserved name the response also emits is dropped exactly once",
			redirectURI: "https://app.example.com/cb?state=fixed&lang=en",
			params:      []responseParam{{"code", "fresh-code"}, {"state", "client-csrf"}},
			reserved:    authorizationResponseParamNames,
			expected:    "https://app.example.com/cb?lang=en&code=fresh-code&state=client-csrf",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := writeResponseParams(tt.redirectURI, tt.params, tt.reserved)

			if tt.expectError {
				assert.Error(t, err)
				assert.Empty(t, result)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// The value goes through url.QueryEscape and nothing else: no trimming, no substitution.
// RFC 6749 section 4.1.2 requires "the exact value received from the client", and space is
// VSCHAR (%x20), so a whitespace-only state is a valid state rather than a missing one.
func TestWriteResponseParams_ByteExactValues(t *testing.T) {
	tests := []struct {
		name     string
		state    string
		expected string
	}{
		{name: "Whitespace-only state is not trimmed away", state: "   ", expected: "https://app.example.com/cb?state=+++"},
		{name: "Empty state is written as given", state: "", expected: "https://app.example.com/cb?state="},
		{name: "A space becomes a plus", state: "a b", expected: "https://app.example.com/cb?state=a+b"},
		{name: "A literal plus is escaped", state: "a+b", expected: "https://app.example.com/cb?state=a%2Bb"},
		{name: "Base64 padding survives", state: "a/b=", expected: "https://app.example.com/cb?state=a%2Fb%3D"},
		{name: "A hash does not start a fragment", state: "a#b", expected: "https://app.example.com/cb?state=a%23b"},
		{name: "Field separators do not split the value", state: "a&b=c", expected: "https://app.example.com/cb?state=a%26b%3Dc"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The empty-value row stays live even though no authorize emitter can hand
			// the helper an empty state under RFC 6749 section 3.1: buildPostLogoutRedirect
			// still can, because RP-Initiated Logout 1.0 carries no valueless-parameter
			// rule and #109's presence flag is untouched.
			result, err := writeResponseParams("https://app.example.com/cb", []responseParam{{"state", tt.state}}, nil)

			assert.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEncodeResponseParams(t *testing.T) {
	t.Run("An empty slice encodes to the empty string", func(t *testing.T) {
		assert.Equal(t, "", encodeResponseParams(nil))
		assert.Equal(t, "", encodeResponseParams([]responseParam{}))
	})

	t.Run("Declaration order is preserved and is not alphabetical", func(t *testing.T) {
		// token_type before expires_in is the assertion that matters: url.Values.Encode
		// would put expires_in first, so the implicit flow's field order is a choice this
		// package makes rather than an accident of the encoder.
		result := encodeResponseParams([]responseParam{
			{"access_token", "tok"},
			{"token_type", "Bearer"},
			{"expires_in", "300"},
			{"state", "st"},
		})

		assert.Equal(t, "access_token=tok&token_type=Bearer&expires_in=300&state=st", result)
	})

	t.Run("Values are escaped byte for byte", func(t *testing.T) {
		result := encodeResponseParams([]responseParam{
			{"state", "a b+c/d=e#f&g"},
		})

		assert.Equal(t, "state=a+b%2Bc%2Fd%3De%23f%26g", result)
	})
}
