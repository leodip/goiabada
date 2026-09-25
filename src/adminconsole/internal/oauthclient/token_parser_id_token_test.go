package oauthclient_test

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient/oauthclienttest"
	"github.com/leodip/goiabada/core/oauth"
)

// The ID-token rules of #427, driven through the parser's three exported methods with real RS256
// tokens against a JWKS server, never through the unexported check they share: a method that
// skipped the check would pass a test of the check.

const rawNonce = "the-raw-nonce-the-session-keeps"

// sentNonce is what the authorize request sent for rawNonce, computed here with crypto/sha256
// rather than through the code under test.
func sentNonce(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// signedInAt and issuedAt are fixed once, so the stored and the refreshed ID token of one row carry
// equal auth_time and iat unless the row changes them, whichever second each is signed in.
var (
	signedInAt = time.Now().Add(-time.Hour).Unix()
	issuedAt   = time.Now().Add(-time.Minute).Unix()
)

type idTokenFixture struct {
	key      *rsa.PrivateKey
	attacker *rsa.PrivateKey
	server   string
	parser   *oauthclient.JWKSTokenParser
}

// newIDTokenFixture publishes the signing key under key-1 and builds a parser expecting issuer.
func newIDTokenFixture(t *testing.T, issuer string) *idTokenFixture {
	t.Helper()
	key, attacker := oauthclienttest.Keys(t)
	server, _ := oauthclienttest.NewJwksServer(t, oauthclienttest.JwkFromPublicKey("key-1", &key.PublicKey))
	return &idTokenFixture{
		key:      key,
		attacker: attacker,
		server:   server.URL,
		parser:   oauthclient.NewJWKSTokenParser(server.URL, server.Client(), oauthclienttest.ClientID, oauthclienttest.StaticIssuer(issuer)),
	}
}

// parserExpecting is a second parser over the same JWKS, expecting another issuer.
func (f *idTokenFixture) parserExpecting(issuer string) *oauthclient.JWKSTokenParser {
	return f.parserFor(oauthclienttest.ClientID, issuer)
}

func (f *idTokenFixture) parserFor(clientID, issuer string) *oauthclient.JWKSTokenParser {
	return oauthclient.NewJWKSTokenParser(f.server, nil, clientID, oauthclienttest.StaticIssuer(issuer))
}

func (f *idTokenFixture) sign(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	return oauthclienttest.SignRS256(t, f.key, "key-1", claims)
}

// idClaims is a sign-in ID token every check accepts: the valid claims plus this sign-in's nonce
// and an auth_time, with iat a minute back so a refreshed token can be issued at, after or before
// it.
func idClaims() jwt.MapClaims {
	claims := oauthclienttest.ValidClaims()
	claims["nonce"] = sentNonce(rawNonce)
	claims["auth_time"] = signedInAt
	claims["iat"] = issuedAt
	return claims
}

// previousToken is the stored ID token a refresh is compared with, obtained the way the middleware
// obtains it: verified, by a parser expecting the issuer it names and, when its aud is one string,
// that audience. Two tokens that both verify under one parser cannot differ in iss or aud, so a
// row breaking either comparison stores a token verified under the setting before it changed.
func (f *idTokenFixture) previousToken(t *testing.T, claims jwt.MapClaims) *oauth.JwtToken {
	t.Helper()
	issuer, _ := claims["iss"].(string)
	clientID, ok := claims["aud"].(string)
	if !ok {
		clientID = oauthclienttest.ClientID
	}
	previous, err := f.parserFor(clientID, issuer).DecodeAndValidateStoredIDToken(context.Background(), f.sign(t, claims))
	require.NoError(t, err)
	return previous
}

// idTokenMethod is one of the three exported ways an ID token is accepted, each given the same raw
// ID token.
type idTokenMethod struct {
	name string
	run  func(t *testing.T, f *idTokenFixture, parser *oauthclient.JWKSTokenParser, idToken string) error
}

func idTokenMethods() []idTokenMethod {
	return []idTokenMethod{
		{"sign-in", func(t *testing.T, f *idTokenFixture, parser *oauthclient.JWKSTokenParser, idToken string) error {
			_, err := parser.DecodeAndValidateSignInResponse(context.Background(),
				&oauth.TokenResponse{AccessToken: "opaque-access-token", IdToken: idToken}, rawNonce)
			return err
		}},
		{"refresh", func(t *testing.T, f *idTokenFixture, parser *oauthclient.JWKSTokenParser, idToken string) error {
			_, err := parser.DecodeAndValidateRefreshResponse(context.Background(),
				&oauth.TokenResponse{AccessToken: "opaque-access-token", IdToken: idToken}, f.previousToken(t, idClaims()))
			return err
		}},
		{"stored", func(t *testing.T, f *idTokenFixture, parser *oauthclient.JWKSTokenParser, idToken string) error {
			_, err := parser.DecodeAndValidateStoredIDToken(context.Background(), idToken)
			return err
		}},
	}
}

type outcome int

const (
	accepted outcome = iota
	foreign
	refusedNotForeign
)

func assertOutcome(t *testing.T, want outcome, err error) {
	t.Helper()
	switch want {
	case accepted:
		assert.NoError(t, err)
	case foreign:
		require.Error(t, err)
		assert.ErrorIs(t, err, oauthclient.ErrForeignToken)
	case refusedNotForeign:
		require.Error(t, err)
		assert.NotErrorIs(t, err, oauthclient.ErrForeignToken)
	}
}

// Decision 1: iss exactly the expected issuer and aud exactly the console's client identifier,
// through every method, so a method that skipped either check turns its rows red.
func TestIDToken_IssuerAndAudience(t *testing.T) {
	client := oauthclienttest.ClientID
	testCases := []struct {
		name           string
		mutate         func(jwt.MapClaims)
		expectedIssuer string
		want           outcome
	}{
		{"iss right", func(jwt.MapClaims) {}, oauthclienttest.Issuer, accepted},
		{"iss with a trailing slash", func(c jwt.MapClaims) { c["iss"] = oauthclienttest.Issuer + "/" }, oauthclienttest.Issuer, foreign},
		{"iss with an upper-cased host", func(c jwt.MapClaims) { c["iss"] = "https://AUTH.example.com" }, oauthclienttest.Issuer, foreign},
		{"iss another host", func(c jwt.MapClaims) { c["iss"] = "https://other.example.com" }, oauthclienttest.Issuer, foreign},
		{"iss absent", func(c jwt.MapClaims) { delete(c, "iss") }, oauthclienttest.Issuer, foreign},
		{"iss numeric", func(c jwt.MapClaims) { c["iss"] = 42 }, oauthclienttest.Issuer, foreign},
		{"empty expected issuer", func(jwt.MapClaims) {}, "", refusedNotForeign},
		{"aud the exact string", func(c jwt.MapClaims) { c["aud"] = client }, oauthclienttest.Issuer, accepted},
		{"aud [client]", func(c jwt.MapClaims) { c["aud"] = []string{client} }, oauthclienttest.Issuer, accepted},
		// The chosen leniency: decision 1 forbids another value beside the client, and a repeat
		// of the client is not another value.
		{"aud [client, client]", func(c jwt.MapClaims) { c["aud"] = []string{client, client} }, oauthclienttest.Issuer, accepted},
		// Decision 1's exactness, OIDC Core 3.1.3.7 step 3: golang-jwt's WithAudience accepts this.
		{"aud [client, other]", func(c jwt.MapClaims) { c["aud"] = []string{client, "other"} }, oauthclienttest.Issuer, foreign},
		{"aud other", func(c jwt.MapClaims) { c["aud"] = "other" }, oauthclienttest.Issuer, foreign},
		{"aud a case variant of the client", func(c jwt.MapClaims) { c["aud"] = strings.ToUpper(client) }, oauthclienttest.Issuer, foreign},
		{"aud absent", func(c jwt.MapClaims) { delete(c, "aud") }, oauthclienttest.Issuer, foreign},
		{"aud numeric", func(c jwt.MapClaims) { c["aud"] = 42 }, oauthclienttest.Issuer, foreign},
		{"aud [client, 42]", func(c jwt.MapClaims) { c["aud"] = []any{client, 42} }, oauthclienttest.Issuer, foreign},
		{"aud []", func(c jwt.MapClaims) { c["aud"] = []string{} }, oauthclienttest.Issuer, foreign},
	}

	for _, method := range idTokenMethods() {
		for _, tc := range testCases {
			t.Run(method.name+"/"+tc.name, func(t *testing.T) {
				f := newIDTokenFixture(t, oauthclienttest.Issuer)
				claims := idClaims()
				tc.mutate(claims)

				err := method.run(t, f, f.parserExpecting(tc.expectedIssuer), f.sign(t, claims))

				assertOutcome(t, tc.want, err)
			})
		}
	}
}

// OIDC Core 3.1.3.7 step 9 binds accepting an ID token from a token response, at sign-in and at
// refresh; the stored token is re-verified without it (decision 13).
func TestIDToken_Expiry(t *testing.T) {
	testCases := []struct {
		name     string
		mutate   func(jwt.MapClaims)
		sentinel error
		want     map[string]outcome
	}{
		{
			name:     "expired",
			mutate:   func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Hour).Unix() },
			sentinel: jwt.ErrTokenExpired,
			want:     map[string]outcome{"sign-in": refusedNotForeign, "refresh": refusedNotForeign, "stored": accepted},
		},
		{
			name:     "exp absent",
			mutate:   func(c jwt.MapClaims) { delete(c, "exp") },
			sentinel: jwt.ErrTokenRequiredClaimMissing,
			want:     map[string]outcome{"sign-in": refusedNotForeign, "refresh": refusedNotForeign, "stored": accepted},
		},
		{
			name:     "nbf in the future",
			mutate:   func(c jwt.MapClaims) { c["nbf"] = time.Now().Add(time.Hour).Unix() },
			sentinel: jwt.ErrTokenNotValidYet,
			want:     map[string]outcome{"sign-in": refusedNotForeign, "refresh": refusedNotForeign, "stored": accepted},
		},
		{
			// Decision 3's order: foreign is decided before expiry, so a token that is both is
			// reported foreign by every method. An expiry-first check turns this row red.
			name: "expired and foreign",
			mutate: func(c jwt.MapClaims) {
				c["exp"] = time.Now().Add(-time.Hour).Unix()
				c["iss"] = "https://other.example.com"
			},
			want: map[string]outcome{"sign-in": foreign, "refresh": foreign, "stored": foreign},
		},
	}

	for _, method := range idTokenMethods() {
		for _, tc := range testCases {
			t.Run(method.name+"/"+tc.name, func(t *testing.T) {
				f := newIDTokenFixture(t, oauthclienttest.Issuer)
				claims := idClaims()
				tc.mutate(claims)

				err := method.run(t, f, f.parser, f.sign(t, claims))

				want := tc.want[method.name]
				assertOutcome(t, want, err)
				if want == refusedNotForeign && tc.sentinel != nil {
					assert.ErrorIs(t, err, tc.sentinel)
				}
			})
		}
	}
}

// Foreign is decided only once the signature has verified: a token nobody can vouch for says
// nothing about who issued it.
func TestIDToken_SignatureAndAlg(t *testing.T) {
	testCases := []struct {
		name     string
		token    func(t *testing.T, f *idTokenFixture) string
		sentinel error
	}{
		{
			name: "signed by an unpublished key under a published kid, with a wrong iss",
			token: func(t *testing.T, f *idTokenFixture) string {
				claims := idClaims()
				claims["iss"] = "https://other.example.com"
				return oauthclienttest.SignRS256(t, f.attacker, "key-1", claims)
			},
			sentinel: jwt.ErrTokenSignatureInvalid,
		},
		{
			name: "HS256",
			token: func(t *testing.T, f *idTokenFixture) string {
				signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, idClaims()).SignedString([]byte("secret"))
				require.NoError(t, err)
				return signed
			},
			sentinel: jwt.ErrTokenSignatureInvalid,
		},
		{
			name: "an unknown kid",
			token: func(t *testing.T, f *idTokenFixture) string {
				return oauthclienttest.SignRS256(t, f.key, "key-unknown", idClaims())
			},
		},
		{
			name:  "not a JWT",
			token: func(*testing.T, *idTokenFixture) string { return "not-a-jwt" },
		},
	}

	for _, method := range idTokenMethods() {
		for _, tc := range testCases {
			t.Run(method.name+"/"+tc.name, func(t *testing.T) {
				f := newIDTokenFixture(t, oauthclienttest.Issuer)

				err := method.run(t, f, f.parser, tc.token(t, f))

				assertOutcome(t, refusedNotForeign, err)
				if tc.sentinel != nil {
					assert.ErrorIs(t, err, tc.sentinel)
				}
			})
		}
	}
}

// Decisions 4 and 9: the sign-in response must carry an access token and an ID token, and the ID
// token must carry back the hash of this sign-in's nonce. Each row differs from the accept case
// in one thing only.
func TestDecodeAndValidateSignInResponse(t *testing.T) {
	testCases := []struct {
		name     string
		response func(t *testing.T, f *idTokenFixture) *oauth.TokenResponse
		nonce    string
	}{
		{
			name:     "no token response",
			response: func(*testing.T, *idTokenFixture) *oauth.TokenResponse { return nil },
			nonce:    rawNonce,
		},
		{
			name: "no ID token",
			response: func(t *testing.T, f *idTokenFixture) *oauth.TokenResponse {
				return &oauth.TokenResponse{AccessToken: "opaque-access-token"}
			},
			nonce: rawNonce,
		},
		{
			name: "no access token",
			response: func(t *testing.T, f *idTokenFixture) *oauth.TokenResponse {
				return &oauth.TokenResponse{IdToken: f.sign(t, idClaims())}
			},
			nonce: rawNonce,
		},
		{
			name: "empty nonce",
			response: func(t *testing.T, f *idTokenFixture) *oauth.TokenResponse {
				return &oauth.TokenResponse{AccessToken: "opaque-access-token", IdToken: f.sign(t, idClaims())}
			},
			nonce: "",
		},
		{
			name: "nonce claim absent",
			response: func(t *testing.T, f *idTokenFixture) *oauth.TokenResponse {
				claims := idClaims()
				delete(claims, "nonce")
				return &oauth.TokenResponse{AccessToken: "opaque-access-token", IdToken: f.sign(t, claims)}
			},
			nonce: rawNonce,
		},
		{
			name: "nonce claim not a string",
			response: func(t *testing.T, f *idTokenFixture) *oauth.TokenResponse {
				claims := idClaims()
				claims["nonce"] = 42
				return &oauth.TokenResponse{AccessToken: "opaque-access-token", IdToken: f.sign(t, claims)}
			},
			nonce: rawNonce,
		},
		{
			name: "nonce claim hashing another value",
			response: func(t *testing.T, f *idTokenFixture) *oauth.TokenResponse {
				claims := idClaims()
				claims["nonce"] = sentNonce("another-sign-in's-nonce")
				return &oauth.TokenResponse{AccessToken: "opaque-access-token", IdToken: f.sign(t, claims)}
			},
			nonce: rawNonce,
		},
		{
			// The near miss that proves the hash is what is compared.
			name: "nonce claim equal to the raw nonce rather than its hash",
			response: func(t *testing.T, f *idTokenFixture) *oauth.TokenResponse {
				claims := idClaims()
				claims["nonce"] = rawNonce
				return &oauth.TokenResponse{AccessToken: "opaque-access-token", IdToken: f.sign(t, claims)}
			},
			nonce: rawNonce,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newIDTokenFixture(t, oauthclienttest.Issuer)

			result, err := f.parser.DecodeAndValidateSignInResponse(context.Background(), tc.response(t, f), tc.nonce)

			assertOutcome(t, refusedNotForeign, err)
			assert.Nil(t, result)
		})
	}

	t.Run("accept", func(t *testing.T) {
		f := newIDTokenFixture(t, oauthclienttest.Issuer)
		idToken := f.sign(t, idClaims())
		response := &oauth.TokenResponse{
			AccessToken:  "opaque-access-token",
			IdToken:      idToken,
			RefreshToken: "opaque-refresh-token",
			TokenType:    "Bearer",
			ExpiresIn:    300,
			Scope:        "openid profile",
		}

		result, err := f.parser.DecodeAndValidateSignInResponse(context.Background(), response, rawNonce)

		require.NoError(t, err)
		assert.Equal(t, *response, result.TokenResponse)
		require.NotNil(t, result.IdToken)
		assert.Equal(t, idToken, result.IdToken.TokenBase64)
		assert.Equal(t, "1234567890", result.IdToken.GetStringClaim("sub"))
		// The access and refresh tokens are carried, never decoded: JwtInfo has no field to
		// decode them into since #427, so the equality with the response above is the whole of it.
	})
}

// Decision 14: a refreshed ID token is verified as at sign-in and then compared with the stored one
// under OIDC Core 12.2.
func TestDecodeAndValidateRefreshResponse(t *testing.T) {
	t.Run("no ID token keeps the previous one", func(t *testing.T) {
		f := newIDTokenFixture(t, oauthclienttest.Issuer)
		previous := f.previousToken(t, idClaims())
		response := &oauth.TokenResponse{AccessToken: "new-access-token", RefreshToken: "new-refresh-token", ExpiresIn: 300}

		result, err := f.parser.DecodeAndValidateRefreshResponse(context.Background(), response, previous)

		require.NoError(t, err)
		assert.Same(t, previous, result.IdToken)
		assert.Equal(t, previous.TokenBase64, result.TokenResponse.IdToken)
		assert.Equal(t, "new-access-token", result.TokenResponse.AccessToken)
		assert.Equal(t, "new-refresh-token", result.TokenResponse.RefreshToken)
		assert.Empty(t, response.IdToken, "the argument is not mutated")
	})

	refusals := []struct {
		name     string
		response func(t *testing.T, f *idTokenFixture) *oauth.TokenResponse
		previous func(t *testing.T, f *idTokenFixture) *oauth.JwtToken
	}{
		{
			name:     "no token response",
			response: func(*testing.T, *idTokenFixture) *oauth.TokenResponse { return nil },
			previous: func(t *testing.T, f *idTokenFixture) *oauth.JwtToken { return f.previousToken(t, idClaims()) },
		},
		{
			name: "no previous ID token",
			response: func(t *testing.T, f *idTokenFixture) *oauth.TokenResponse {
				return &oauth.TokenResponse{AccessToken: "new-access-token", IdToken: f.sign(t, idClaims())}
			},
			previous: func(*testing.T, *idTokenFixture) *oauth.JwtToken { return nil },
		},
		{
			name: "no access token",
			response: func(t *testing.T, f *idTokenFixture) *oauth.TokenResponse {
				return &oauth.TokenResponse{IdToken: f.sign(t, idClaims())}
			},
			previous: func(t *testing.T, f *idTokenFixture) *oauth.JwtToken { return f.previousToken(t, idClaims()) },
		},
	}
	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			f := newIDTokenFixture(t, oauthclienttest.Issuer)

			result, err := f.parser.DecodeAndValidateRefreshResponse(context.Background(), tc.response(t, f), tc.previous(t, f))

			assertOutcome(t, refusedNotForeign, err)
			assert.Nil(t, result)
		})
	}

	// One row per comparison, each broken or relaxed on its own. mutatePrevious and mutateRefreshed
	// start from the same idClaims.
	comparisons := []struct {
		name            string
		mutatePrevious  func(jwt.MapClaims)
		mutateRefreshed func(jwt.MapClaims)
		want            outcome
	}{
		{
			// The stored token was issued under the issuer the setting named before it changed.
			name:            "iss differs from the previous token's",
			mutatePrevious:  func(c jwt.MapClaims) { c["iss"] = "https://old.example.com" },
			mutateRefreshed: func(jwt.MapClaims) {},
			want:            foreign,
		},
		{
			name:            "sub differs",
			mutatePrevious:  func(jwt.MapClaims) {},
			mutateRefreshed: func(c jwt.MapClaims) { c["sub"] = "another-user" },
			want:            refusedNotForeign,
		},
		{
			name:            "aud differs",
			mutatePrevious:  func(c jwt.MapClaims) { c["aud"] = "a-previous-client-identifier" },
			mutateRefreshed: func(jwt.MapClaims) {},
			want:            refusedNotForeign,
		},
		{
			name:            "auth_time differs",
			mutatePrevious:  func(jwt.MapClaims) {},
			mutateRefreshed: func(c jwt.MapClaims) { c["auth_time"] = signedInAt + 1 },
			want:            refusedNotForeign,
		},
		{
			name:            "auth_time unreadable on one side",
			mutatePrevious:  func(jwt.MapClaims) {},
			mutateRefreshed: func(c jwt.MapClaims) { c["auth_time"] = "yesterday" },
			want:            refusedNotForeign,
		},
		{
			name:            "nonce present and different",
			mutatePrevious:  func(jwt.MapClaims) {},
			mutateRefreshed: func(c jwt.MapClaims) { c["nonce"] = sentNonce("another-sign-in's-nonce") },
			want:            refusedNotForeign,
		},
		{
			name:            "iat earlier",
			mutatePrevious:  func(jwt.MapClaims) {},
			mutateRefreshed: func(c jwt.MapClaims) { c["iat"] = issuedAt - 1 },
			want:            refusedNotForeign,
		},
		{
			name:            "iat absent while the previous token carries one",
			mutatePrevious:  func(jwt.MapClaims) {},
			mutateRefreshed: func(c jwt.MapClaims) { delete(c, "iat") },
			want:            refusedNotForeign,
		},
		{
			name:            "expired",
			mutatePrevious:  func(jwt.MapClaims) {},
			mutateRefreshed: func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Hour).Unix() },
			want:            refusedNotForeign,
		},
		// The chosen leniencies.
		{
			name:            "auth_time on the previous token only",
			mutatePrevious:  func(jwt.MapClaims) {},
			mutateRefreshed: func(c jwt.MapClaims) { delete(c, "auth_time") },
			want:            accepted,
		},
		{
			name:            "auth_time on the refreshed token only",
			mutatePrevious:  func(c jwt.MapClaims) { delete(c, "auth_time") },
			mutateRefreshed: func(jwt.MapClaims) {},
			want:            accepted,
		},
		{
			// OIDC Core 12.2: a refreshed ID token "SHOULD NOT have a nonce Claim".
			name:            "nonce absent",
			mutatePrevious:  func(jwt.MapClaims) {},
			mutateRefreshed: func(c jwt.MapClaims) { delete(c, "nonce") },
			want:            accepted,
		},
		{
			name:            "nonce equal",
			mutatePrevious:  func(jwt.MapClaims) {},
			mutateRefreshed: func(jwt.MapClaims) {},
			want:            accepted,
		},
		{
			name:            "iat equal",
			mutatePrevious:  func(jwt.MapClaims) {},
			mutateRefreshed: func(jwt.MapClaims) {},
			want:            accepted,
		},
		{
			name:            "aud as the string and as a one-element array",
			mutatePrevious:  func(c jwt.MapClaims) { c["aud"] = oauthclienttest.ClientID },
			mutateRefreshed: func(c jwt.MapClaims) { c["aud"] = []string{oauthclienttest.ClientID} },
			want:            accepted,
		},
		{
			name:            "iat later",
			mutatePrevious:  func(jwt.MapClaims) {},
			mutateRefreshed: func(c jwt.MapClaims) { c["iat"] = issuedAt + 1 },
			want:            accepted,
		},
	}
	for _, tc := range comparisons {
		t.Run(tc.name, func(t *testing.T) {
			f := newIDTokenFixture(t, oauthclienttest.Issuer)
			previousClaims := idClaims()
			refreshedClaims := jwt.MapClaims{}
			for k, v := range previousClaims {
				refreshedClaims[k] = v
			}
			tc.mutatePrevious(previousClaims)
			tc.mutateRefreshed(refreshedClaims)
			previous := f.previousToken(t, previousClaims)
			refreshed := f.sign(t, refreshedClaims)

			result, err := f.parser.DecodeAndValidateRefreshResponse(context.Background(),
				&oauth.TokenResponse{AccessToken: "new-access-token", IdToken: refreshed}, previous)

			assertOutcome(t, tc.want, err)
			if tc.want == accepted {
				require.NotNil(t, result)
				assert.Equal(t, refreshed, result.IdToken.TokenBase64, "the refreshed ID token replaces the previous one")
				assert.Equal(t, refreshed, result.TokenResponse.IdToken)
			} else {
				assert.Nil(t, result)
			}
		})
	}
}

// Decision 13: the stored ID token is re-verified on every request, all but its expiry.
func TestDecodeAndValidateStoredIDToken(t *testing.T) {
	t.Run("expired is accepted", func(t *testing.T) {
		f := newIDTokenFixture(t, oauthclienttest.Issuer)
		claims := idClaims()
		claims["exp"] = time.Now().Add(-time.Hour).Unix()
		raw := f.sign(t, claims)

		token, err := f.parser.DecodeAndValidateStoredIDToken(context.Background(), raw)

		require.NoError(t, err)
		assert.Equal(t, raw, token.TokenBase64)
		assert.Equal(t, "1234567890", token.GetStringClaim("sub"))
	})

	t.Run("foreign is refused as foreign", func(t *testing.T) {
		f := newIDTokenFixture(t, "https://new-issuer.example.com")

		token, err := f.parser.DecodeAndValidateStoredIDToken(context.Background(), f.sign(t, idClaims()))

		assertOutcome(t, foreign, err)
		assert.Nil(t, token)
	})

	t.Run("forged is refused, not as foreign", func(t *testing.T) {
		f := newIDTokenFixture(t, oauthclienttest.Issuer)

		token, err := f.parser.DecodeAndValidateStoredIDToken(context.Background(),
			oauthclienttest.SignRS256(t, f.attacker, "key-1", idClaims()))

		assertOutcome(t, refusedNotForeign, err)
		assert.ErrorIs(t, err, jwt.ErrTokenSignatureInvalid)
		assert.Nil(t, token)
	})

	t.Run("empty is refused", func(t *testing.T) {
		f := newIDTokenFixture(t, oauthclienttest.Issuer)

		token, err := f.parser.DecodeAndValidateStoredIDToken(context.Background(), "")

		assertOutcome(t, refusedNotForeign, err)
		assert.Nil(t, token)
	})
}
