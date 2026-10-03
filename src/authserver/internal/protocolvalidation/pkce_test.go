package protocolvalidation

import (
	"context"
	"database/sql"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	mocks_protocolvalidation "github.com/leodip/goiabada/authserver/internal/protocolvalidation/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/oauth"
)

const (
	// testCodeVerifier is the example verifier of RFC 7636 appendix B: 43 characters of the set. The
	// fixtures that store a challenge derive it from this one, so a request presenting it proves
	// PKCE, and one presenting wrongCodeVerifier, which is also well formed, fails only the
	// comparison.
	testCodeVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	wrongCodeVerifier = "wrong_verifier_0123456789_abcdefghijklmnopqrst"
)

// pkceValueOf is a well-formed value of exactly n characters, drawn from all four classes RFC 7636
// 4.1 allows so that a rule keeping only some of them cannot pass.
func pkceValueOf(n int) string {
	const cycle = "aZ09-._~"
	return strings.Repeat(cycle, n/len(cycle)+1)[:n]
}

// with replaces the character at position i of value, so a row differs from a passing row by one
// character.
func with(value string, i int, replacement string) string {
	return value[:i] + replacement + value[i+1:]
}

// TestIsPKCEValue pins RFC 7636 4.1 and 4.2's one production, 43*128unreserved, on both edges of the
// length and on both sides of each class of the set (#244, decision 20).
func TestIsPKCEValue(t *testing.T) {
	testCases := []struct {
		name  string
		value string
		want  bool
	}{
		{"the RFC's own example verifier", testCodeVerifier, true},
		{"43 characters, the lower bound", pkceValueOf(43), true},
		{"128 characters, the upper bound", pkceValueOf(128), true},
		{"42 characters, one under", pkceValueOf(42), false},
		{"129 characters, one over", pkceValueOf(129), false},
		{"empty", "", false},
		{"only upper case letters", strings.Repeat("A", 43), true},
		{"only lower case letters", strings.Repeat("z", 43), true},
		{"only digits", strings.Repeat("0", 43), true},
		{"only hyphens", strings.Repeat("-", 43), true},
		{"only periods", strings.Repeat(".", 43), true},
		{"only underscores", strings.Repeat("_", 43), true},
		{"only tildes", strings.Repeat("~", 43), true},

		// One character outside the set, in a value that is otherwise the passing 43-character one.
		{"a plus, which standard base64 uses and base64url does not", with(pkceValueOf(43), 10, "+"), false},
		{"a slash", with(pkceValueOf(43), 10, "/"), false},
		{"an equals sign, the padding base64url leaves off", with(pkceValueOf(43), 42, "="), false},
		{"a space", with(pkceValueOf(43), 10, " "), false},
		{"a percent sign", with(pkceValueOf(43), 10, "%"), false},
		{"a colon", with(pkceValueOf(43), 10, ":"), false},
		{"a tab", with(pkceValueOf(43), 10, "\t"), false},
		{"a NUL byte", with(pkceValueOf(43), 10, "\x00"), false},
		{"a character just below the letters, '@'", with(pkceValueOf(43), 10, "@"), false},
		{"a character just above the lower case letters, '{'", with(pkceValueOf(43), 10, "{"), false},
		{"a character just below the digits, '/'", with(pkceValueOf(43), 10, "/"), false},
		{"a character just above the digits, ':'", with(pkceValueOf(43), 10, ":"), false},
		{"a character just above the upper case letters, '['", with(pkceValueOf(43), 10, "["), false},

		// Bytes are not characters: a two-byte character in 43 bytes is 42 characters, and one in 44
		// is 43, and neither is in the set whatever the count.
		{"a two-byte character among 41 ASCII, 43 bytes", pkceValueOf(41) + "é", false},
		{"a two-byte character among 42 ASCII, 44 bytes", pkceValueOf(42) + "é", false},
		{"43 two-byte characters", strings.Repeat("é", 43), false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isPKCEValue(tc.value))
		})
	}
}

// TestValidateRequest_CodeChallengeGrammar holds the authorization endpoint to RFC 7636 4.2 in both
// PKCE branches, the one a client that must use PKCE takes and the one a client that merely offers
// it takes. A challenge of the right length with one character outside the set is refused; the same
// length with every character inside it is not, so it is the character that decides. The length
// refusals keep their own text, which the suite and the integration tier pin (#244).
func TestValidateRequest_CodeChallengeGrammar(t *testing.T) {
	validator := NewAuthorizeValidator(nil)

	for _, pkceRequired := range []bool{true, false} {
		branch := "PKCE offered"
		if pkceRequired {
			branch = "PKCE required"
		}

		request := func(challenge string) *ValidateRequestInput {
			return &ValidateRequestInput{
				ResponseType:        "code",
				CodeChallengeMethod: "S256",
				CodeChallenge:       challenge,
				PKCERequired:        pkceRequired,
				Scope:               "openid",
			}
		}

		accepted := map[string]string{
			"43 characters":           pkceValueOf(43),
			"128 characters":          pkceValueOf(128),
			"a real S256 challenge":   oauth.GeneratePKCECodeChallenge(testCodeVerifier),
			"hyphen, period, tilde":   strings.Repeat("-.~", 15),
			"underscore and digits":   strings.Repeat("_0", 30),
			"upper and lower letters": strings.Repeat("aZ", 30),
		}
		for name, challenge := range accepted {
			t.Run(branch+", accepts "+name, func(t *testing.T) {
				assert.NoError(t, validator.ValidateRequest(request(challenge)))
			})
		}

		refused := map[string]string{
			"a plus":                with(pkceValueOf(43), 10, "+"),
			"a slash":               with(pkceValueOf(43), 10, "/"),
			"padding":               with(pkceValueOf(43), 42, "="),
			"a space":               with(pkceValueOf(43), 10, " "),
			"a two-byte character":  pkceValueOf(41) + "é",
			"the 128 upper bound+ ": with(pkceValueOf(128), 127, "+"),
		}
		for name, challenge := range refused {
			t.Run(branch+", refuses "+name, func(t *testing.T) {
				err := validator.ValidateRequest(request(challenge))

				var detail *oauth.ErrorDetail
				require.ErrorAs(t, err, &detail)
				assert.Equal(t, "invalid_request", detail.Code())
				assert.Equal(t, http.StatusBadRequest, detail.HTTPStatus())
				assert.Equal(t, "The code_challenge parameter is incorrect. It may only contain A-Z, a-z, 0-9, '-', '.', '_' and '~'.",
					detail.Description())
			})
		}

		t.Run(branch+", a challenge too short keeps the length text", func(t *testing.T) {
			err := validator.ValidateRequest(request(pkceValueOf(42)))

			var detail *oauth.ErrorDetail
			require.ErrorAs(t, err, &detail)
			assert.Equal(t, "invalid_request", detail.Code())
			assert.Contains(t, detail.Description(), "It should be 43 to 128 characters long.")
		})

		t.Run(branch+", a challenge too long keeps the length text", func(t *testing.T) {
			err := validator.ValidateRequest(request(pkceValueOf(129)))

			var detail *oauth.ErrorDetail
			require.ErrorAs(t, err, &detail)
			assert.Equal(t, "invalid_request", detail.Code())
			assert.Contains(t, detail.Description(), "It should be 43 to 128 characters long.")
		})
	}

	t.Run("no PKCE at all needs no challenge and is not judged", func(t *testing.T) {
		assert.NoError(t, validator.ValidateRequest(&ValidateRequestInput{
			ResponseType: "code",
			Scope:        "openid",
		}))
	})
}

// verifierGrammarWant is the refusal a malformed verifier gets: invalid_grant, RFC 7636 4.6's code
// for a verifier that cannot match, naming the rule.
var verifierGrammarWant = wantRefusal{
	code:        "invalid_grant",
	description: "The code_verifier parameter is incorrect. It should be 43 to 128 characters long and may only contain A-Z, a-z, 0-9, '-', '.', '_' and '~'.",
	status:      http.StatusBadRequest,
}

// TestValidateTokenRequest_CodeVerifierGrammar holds the token endpoint to RFC 7636 4.1: a verifier
// outside the grammar is refused invalid_grant before the comparison, below client authentication,
// and answers identically whatever became of the account (#137, #244). Each refused row differs from
// the accepted 43-character one by a single character or by its length.
func TestValidateTokenRequest_CodeVerifierGrammar(t *testing.T) {
	const (
		clientSecret = "client_secret"
		redirectURI  = "https://example.com/callback"
	)

	run := func(t *testing.T, secret string, verifier string, enabled bool) (any, error) {
		t.Helper()

		mockDB := mocks_data.NewDatabase(t)
		validator := NewTokenValidator(mockDB, mocks_protocolvalidation.NewTokenParser(t),
			mocks_protocolvalidation.NewPermissionChecker(t), testDataCipher)

		clientSecretEncrypted, err := testDataCipher.Encrypt(clientSecret)
		require.NoError(t, err)
		client := &record.Client{
			Id: 1, ClientIdentifier: "client1", Enabled: true, AuthorizationCodeEnabled: true,
			ClientSecretEncrypted: clientSecretEncrypted,
		}
		codeEntity := &record.Code{
			CodeHash:            "hash_of_valid_code",
			RedirectURI:         redirectURI,
			CodeChallenge:       sql.NullString{String: oauth.GeneratePKCECodeChallenge(testCodeVerifier), Valid: true},
			AuthStateGeneration: 3,
			UserId:              7,
			Client:              record.Client{ClientIdentifier: "client1"},
			User:                record.User{Id: 7, Enabled: enabled, AuthStateGeneration: 3},
			CreatedAt:           sql.NullTime{Time: time.Now().UTC(), Valid: true},
		}

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "client1").Return(client, nil).Once()
		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.AnythingOfType("string"), false).
			Return(codeEntity, nil).Once()
		mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()
		mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()
		expectRedirectURIStillRegistered(mockDB, redirectURI)

		return validator.ValidateTokenRequest(context.Background(), &record.Settings{}, &ValidateTokenRequestInput{
			GrantType:    "authorization_code",
			ClientId:     "client1",
			ClientSecret: secret,
			Code:         "valid_code",
			RedirectURI:  redirectURI,
			CodeVerifier: verifier,
		})
	}

	refused := map[string]string{
		"42 characters, one under":                      testCodeVerifier[:42],
		"129 characters, one over":                      pkceValueOf(129),
		"a plus in a verifier of the right length":      with(testCodeVerifier, 10, "+"),
		"a slash in a verifier of the right length":     with(testCodeVerifier, 10, "/"),
		"padding, which base64url leaves off":           with(testCodeVerifier, 42, "="),
		"a space in a verifier of the right length":     with(testCodeVerifier, 10, " "),
		"a two-byte character, 43 bytes, 42 characters": testCodeVerifier[:41] + "é",
	}
	for name, verifier := range refused {
		for _, enabled := range []bool{true, false} {
			user := "untouched user"
			if !enabled {
				user = "disabled user"
			}
			t.Run(name+", "+user, func(t *testing.T) {
				grant, err := run(t, clientSecret, verifier, enabled)

				assert.Nil(t, grant)
				// The disabled user gets exactly the untouched user's answer: the verifier is refused
				// before anything about the account is read, and not through the disabled-user wrapper.
				assertRefusal(t, err, verifierGrammarWant)
			})
		}
	}

	t.Run("the well-formed verifier the challenge came from is accepted", func(t *testing.T) {
		grant, err := run(t, clientSecret, testCodeVerifier, true)
		require.NoError(t, err)
		assert.NotNil(t, grant)
	})

	t.Run("a well-formed verifier that does not match keeps the comparison's own text", func(t *testing.T) {
		grant, err := run(t, clientSecret, wrongCodeVerifier, true)

		assert.Nil(t, grant)
		assertRefusal(t, err, wantRefusal{code: "invalid_grant", description: "Invalid code_verifier (PKCE).", status: http.StatusBadRequest})
	})

	t.Run("a malformed verifier with a wrong secret is invalid_client, so client authentication comes first", func(t *testing.T) {
		grant, err := run(t, "not_the_secret", testCodeVerifier[:42], true)

		assert.Nil(t, grant)
		assertRefusal(t, err, wantRefusal{
			code: "invalid_client", description: "Client authentication failed. Please review your client_secret.",
			status: http.StatusUnauthorized,
		})
	})

	t.Run("a missing verifier is still the missing-verifier refusal, not a grammar one", func(t *testing.T) {
		grant, err := run(t, clientSecret, "", true)

		assert.Nil(t, grant)
		assertRefusal(t, err, wantRefusal{
			code: "invalid_request", description: "Missing required code_verifier parameter.",
			status: http.StatusBadRequest,
		})
	})
}

// TestValidateTokenRequest_MalformedVerifierOnAReusedCodeDoesNotCascade: the grammar refusal sits
// above the reuse return, like the comparison it stands beside, so a caller that cannot present a
// verifier for a used code is refused as an ordinary bad request and does not trigger #77's
// revocation of everything the code descended into.
func TestValidateTokenRequest_MalformedVerifierOnAReusedCodeDoesNotCascade(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	validator := NewTokenValidator(mockDB, mocks_protocolvalidation.NewTokenParser(t),
		mocks_protocolvalidation.NewPermissionChecker(t), testDataCipher)

	client := &record.Client{Id: 1, ClientIdentifier: "client1", Enabled: true, AuthorizationCodeEnabled: true, IsPublic: true}
	// A code already redeemed, so the retry lookup with used=true finds it. It is older than the
	// expiry window, which shows the grammar refusal is read above that check too.
	codeEntity := &record.Code{
		Id:                42,
		CodeHash:          "hash_of_reused_code",
		RedirectURI:       "https://example.com/callback",
		ClientId:          client.Id,
		Client:            *client,
		UserId:            1,
		User:              record.User{Id: 1, Enabled: true},
		CodeChallenge:     sql.NullString{String: oauth.GeneratePKCECodeChallenge(testCodeVerifier), Valid: true},
		CreatedAt:         sql.NullTime{Time: time.Now().UTC().Add(-10 * time.Minute), Valid: true},
		SessionIdentifier: "session-abc",
	}

	mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "client1").Return(client, nil).Once()
	mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.AnythingOfType("string"), false).Return(nil, nil).Once()
	mockDB.On("GetCodeByCodeHash", mock.Anything, mock.Anything, mock.AnythingOfType("string"), true).Return(codeEntity, nil).Once()
	mockDB.On("CodeLoadClient", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()
	mockDB.On("CodeLoadUser", mock.Anything, mock.Anything, codeEntity).Return(nil).Once()

	_, err := validator.ValidateTokenRequest(context.Background(), &record.Settings{}, &ValidateTokenRequestInput{
		GrantType:    "authorization_code",
		ClientId:     "client1",
		Code:         "reused_code",
		RedirectURI:  "https://example.com/callback",
		CodeVerifier: testCodeVerifier[:42],
	})

	_, isSentinel := err.(*AuthCodeReusedError)
	assert.False(t, isSentinel, "a malformed code_verifier must not yield the revocation sentinel")
	assertRefusal(t, err, verifierGrammarWant)
}
