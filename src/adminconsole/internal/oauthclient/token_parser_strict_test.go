package oauthclient_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient/oauthclienttest"
	"github.com/leodip/goiabada/core/oauth"
)

// #709 at the admin console's ID-token reader: the shared structural check (findings 1 to 4), the
// ID token's sub and iat (finding 5), and the verification keys it takes from the JWKS (findings 6
// and 7). Every case runs through the three exported ways an ID token is accepted. Here the stored
// ID token a refresh is compared with carries the refreshed token's own claims, so OIDC Core 12.2's
// comparison passes and only the reader's checks of the refreshed token can refuse it.

// readerMethod is one exported way an ID token is accepted, given the token and the claims it was
// signed with.
type readerMethod struct {
	name string
	run  func(parser *oauthclient.JWKSTokenParser, claims jwt.MapClaims, idToken string) error
}

func readerMethods() []readerMethod {
	return []readerMethod{
		{"sign-in", func(parser *oauthclient.JWKSTokenParser, _ jwt.MapClaims, idToken string) error {
			_, err := parser.DecodeAndValidateSignInResponse(context.Background(),
				&oauth.TokenResponse{AccessToken: "opaque-access-token", IdToken: idToken}, rawNonce)
			return err
		}},
		{"refresh", func(parser *oauthclient.JWKSTokenParser, claims jwt.MapClaims, idToken string) error {
			previous := &oauth.JwtToken{TokenBase64: "the-stored-id-token", Claims: decoded(claims)}
			_, err := parser.DecodeAndValidateRefreshResponse(context.Background(),
				&oauth.TokenResponse{AccessToken: "opaque-access-token", IdToken: idToken}, previous)
			return err
		}},
		{"stored", func(parser *oauthclient.JWKSTokenParser, _ jwt.MapClaims, idToken string) error {
			_, err := parser.DecodeAndValidateStoredIDToken(context.Background(), idToken)
			return err
		}},
	}
}

// decoded is claims as a verified token holds them: read back from JSON, every number a float64.
func decoded(claims jwt.MapClaims) jwt.MapClaims {
	encoded, err := json.Marshal(claims)
	if err != nil {
		panic(err)
	}
	var read jwt.MapClaims
	if err := json.Unmarshal(encoded, &read); err != nil {
		panic(err)
	}
	return read
}

// parserOver builds a parser expecting oauthclienttest.Issuer and ClientID over a JWKS publishing
// keys, and answers how many times the JWKS was fetched.
func parserOver(t *testing.T, keys ...oauth.Jwk) (*oauthclient.JWKSTokenParser, *atomic.Int32) {
	t.Helper()
	server, hits := oauthclienttest.NewJwksServer(t, keys...)
	return oauthclient.NewJWKSTokenParser(server.URL, server.Client(), nil, oauthclienttest.ClientID,
		oauthclienttest.StaticIssuer(oauthclienttest.Issuer)), hits
}

func claimsJSON(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	encoded, err := json.Marshal(claims)
	require.NoError(t, err)
	return string(encoded)
}

// Findings 1 to 4: each token is signed by the published key, and the unaltered token is accepted,
// so only its structure can refuse it. A refused token is answered as a malformed one is: not
// foreign, and marked as golang-jwt marks a malformed token.
func TestIDToken_RefusesATokenOfInvalidStructure(t *testing.T) {
	key, _ := oauthclienttest.Keys(t)
	claims := idClaims()
	payload := claimsJSON(t, claims)
	const header = `{"alg":"RS256","kid":"key-1","typ":"JWT"}`
	valid := oauthclienttest.SignRawRS256(t, key, header, payload)

	segments := strings.Split(valid, ".")
	withSignature := func(signature string) string { return segments[0] + "." + segments[1] + "." + signature }
	withSegment := func(i int, text string) string {
		altered := append([]string(nil), segments...)
		altered[i] += text
		return strings.Join(altered, ".")
	}
	// An extra claim holding the invalid byte, so the claims the reader checks are untouched.
	invalidUTF8Payload := strings.Replace(payload, "{", "{\"name\":\"a\xffb\",", 1)

	tokens := []struct {
		name  string
		token string
	}{
		{"a crit header naming an unknown extension", oauthclienttest.SignRawRS256(t, key,
			`{"alg":"RS256","kid":"key-1","crit":["unhandled"],"unhandled":true}`, payload)},
		{"a crit header holding the empty list", oauthclienttest.SignRawRS256(t, key,
			`{"alg":"RS256","kid":"key-1","crit":[]}`, payload)},
		{"a cty of JWT", oauthclienttest.SignRawRS256(t, key, `{"alg":"RS256","kid":"key-1","cty":"JWT"}`, payload)},
		{"a cty of jwt", oauthclienttest.SignRawRS256(t, key, `{"alg":"RS256","kid":"key-1","cty":"jwt"}`, payload)},
		{"a cty of application/jwt", oauthclienttest.SignRawRS256(t, key,
			`{"alg":"RS256","kid":"key-1","cty":"application/jwt"}`, payload)},
		{"an invalid UTF-8 byte in the header", oauthclienttest.SignRawRS256(t, key,
			"{\"alg\":\"RS256\",\"kid\":\"key-1\",\"x\":\"a\xffb\"}", payload)},
		{"an invalid UTF-8 byte in the payload", oauthclienttest.SignRawRS256(t, key, header, invalidUTF8Payload)},
		{"a CR appended to the signature", withSignature(segments[2] + "\r")},
		{"an LF appended to the signature", withSignature(segments[2] + "\n")},
		{"a CRLF appended to the signature", withSignature(segments[2] + "\r\n")},
		{"an LF inside the signature", withSignature(segments[2][:40] + "\n" + segments[2][40:])},
		{"an LF inside the header", withSegment(0, "\n")},
		{"a CR inside the payload", segments[0] + "." + segments[1][:10] + "\r" + segments[1][10:] + "." + segments[2]},
		{"= padding appended to the header", withSegment(0, "=")},
		{"= padding appended to the payload", withSegment(1, "==")},
		{"= padding appended to the signature", withSegment(2, "==")},
	}

	for _, method := range readerMethods() {
		t.Run(method.name+"/the unaltered token", func(t *testing.T) {
			parser, _ := parserOver(t, oauthclienttest.JwkFromPublicKey("key-1", &key.PublicKey))

			require.NoError(t, method.run(parser, claims, valid))
		})
		for _, tc := range tokens {
			t.Run(method.name+"/"+tc.name, func(t *testing.T) {
				parser, _ := parserOver(t, oauthclienttest.JwkFromPublicKey("key-1", &key.PublicKey))

				err := method.run(parser, claims, tc.token)

				assertOutcome(t, refusedNotForeign, err)
				assert.ErrorIs(t, err, jwt.ErrTokenMalformed)
			})
		}
	}
}

// The structural check runs before the library's parse, so no key is fetched for a token it
// refuses, as for any other malformed token.
func TestIDToken_AStructurallyRefusedTokenFetchesNoKey(t *testing.T) {
	key, _ := oauthclienttest.Keys(t)
	claims := idClaims()
	token := oauthclienttest.SignRawRS256(t, key,
		`{"alg":"RS256","kid":"key-1","crit":["unhandled"],"unhandled":true}`, claimsJSON(t, claims))

	for _, method := range readerMethods() {
		t.Run(method.name, func(t *testing.T) {
			parser, hits := parserOver(t, oauthclienttest.JwkFromPublicKey("key-1", &key.PublicKey))

			err := method.run(parser, claims, token)

			assertOutcome(t, refusedNotForeign, err)
			assert.Zero(t, hits.Load(), "the JWKS is not fetched for a token refused by its structure")
		})
	}
}

// Finding 5, OIDC Core 1.0 section 2: sub is REQUIRED, a case-sensitive string that "MUST NOT exceed
// 255 ASCII characters in length", and iat is REQUIRED, a JSON number. Neither refusal is foreign.
func TestIDToken_SubAndIat(t *testing.T) {
	testCases := []struct {
		name   string
		mutate func(jwt.MapClaims)
		want   outcome
	}{
		{"sub and iat as issued", func(jwt.MapClaims) {}, accepted},
		{"sub absent", func(c jwt.MapClaims) { delete(c, "sub") }, refusedNotForeign},
		{"sub null", func(c jwt.MapClaims) { c["sub"] = nil }, refusedNotForeign},
		{"sub a number", func(c jwt.MapClaims) { c["sub"] = 1234567890 }, refusedNotForeign},
		{"sub an array", func(c jwt.MapClaims) { c["sub"] = []string{"1234567890"} }, refusedNotForeign},
		{"sub empty", func(c jwt.MapClaims) { c["sub"] = "" }, refusedNotForeign},
		{"sub one character", func(c jwt.MapClaims) { c["sub"] = "a" }, accepted},
		{"sub 255 characters", func(c jwt.MapClaims) { c["sub"] = strings.Repeat("a", 255) }, accepted},
		{"sub 256 characters", func(c jwt.MapClaims) { c["sub"] = strings.Repeat("a", 256) }, refusedNotForeign},
		{"iat absent", func(c jwt.MapClaims) { delete(c, "iat") }, refusedNotForeign},
		{"iat null", func(c jwt.MapClaims) { c["iat"] = nil }, refusedNotForeign},
		{"iat a string", func(c jwt.MapClaims) { c["iat"] = fmt.Sprint(issuedAt) }, refusedNotForeign},
		{"iat a boolean", func(c jwt.MapClaims) { c["iat"] = true }, refusedNotForeign},
		// RFC 7519 section 2: a NumericDate is a JSON number, and need not be an integer.
		{"iat a fractional number", func(c jwt.MapClaims) { c["iat"] = float64(issuedAt) + 0.5 }, accepted},
	}

	key, _ := oauthclienttest.Keys(t)
	for _, method := range readerMethods() {
		for _, tc := range testCases {
			t.Run(method.name+"/"+tc.name, func(t *testing.T) {
				parser, _ := parserOver(t, oauthclienttest.JwkFromPublicKey("key-1", &key.PublicKey))
				claims := idClaims()
				tc.mutate(claims)
				token := oauthclienttest.SignRawRS256(t, key, `{"alg":"RS256","kid":"key-1","typ":"JWT"}`, claimsJSON(t, claims))

				err := method.run(parser, claims, token)

				assertOutcome(t, tc.want, err)
			})
		}
	}
}

// weakKey is a 1024-bit RSA key, which crypto/rsa still signs and verifies with, and RFC 7518
// section 3.3 forbids: "A key of size 2048 bits or larger MUST be used with these algorithms."
func weakKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	return key
}

// exponentIn writes 65537 big-endian in n bytes, zero-padded on the left: the same exponent, in
// more bytes than it needs.
func exponentIn(n int) string {
	e := make([]byte, n)
	e[n-3], e[n-2], e[n-1] = 0x01, 0x00, 0x01
	return base64.RawURLEncoding.EncodeToString(e)
}

// Findings 6 and 7: a key under 2048 bits or with an exponent longer than four bytes is refused
// (RFC 7518 section 3.3), and a key whose use is present and not sig, or whose alg is present and
// not RS256, is not used (OIDC Core 1.0 section 10.1, RFC 7517 sections 4.2 and 4.4), the one-key
// fallback for a token without a kid included. Each token is signed by the private half of the key
// published, so the signature itself is good. Even and tiny exponents cannot sign a token; they are
// refused at the key's decoding, tested beside it.
func TestIDToken_VerificationKeys(t *testing.T) {
	key, _ := oauthclienttest.Keys(t)
	weak := weakKey(t)
	published := oauthclienttest.JwkFromPublicKey("key-1", &key.PublicKey)
	with := func(change func(*oauth.Jwk)) oauth.Jwk {
		jwk := published
		change(&jwk)
		return jwk
	}
	absent := func(names ...string) func(map[string]any) {
		return func(m map[string]any) {
			for _, name := range names {
				delete(m, name)
			}
		}
	}
	set := func(name string, value any) func(map[string]any) {
		return func(m map[string]any) { m[name] = value }
	}

	// members, when set, changes the key's members as the document carries them, for what oauth.Jwk
	// cannot say: a member absent, or present with a value that is not a string.
	testCases := []struct {
		name    string
		jwk     oauth.Jwk
		members func(map[string]any)
		signer  *rsa.PrivateKey
		kid     string
		want    outcome
	}{
		{"the key as the auth server publishes it", published, nil, key, "key-1", accepted},
		{"a 1024-bit key", oauthclienttest.JwkFromPublicKey("key-1", &weak.PublicKey), nil, weak, "key-1", refusedNotForeign},
		{"e in four bytes", with(func(j *oauth.Jwk) { j.E = exponentIn(4) }), nil, key, "key-1", accepted},
		{"e in five bytes", with(func(j *oauth.Jwk) { j.E = exponentIn(5) }), nil, key, "key-1", refusedNotForeign},
		{"e in nine bytes", with(func(j *oauth.Jwk) { j.E = exponentIn(9) }), nil, key, "key-1", refusedNotForeign},
		{"use absent", published, absent("use"), key, "key-1", accepted},
		{"use enc", with(func(j *oauth.Jwk) { j.Use = "enc" }), nil, key, "key-1", refusedNotForeign},
		{"use SIG, which is not sig", with(func(j *oauth.Jwk) { j.Use = "SIG" }), nil, key, "key-1", refusedNotForeign},
		{"use an empty string, which is not absent", published, set("use", ""), key, "key-1", refusedNotForeign},
		{"use null, which is not absent", published, set("use", nil), key, "key-1", refusedNotForeign},
		{"use a number", published, set("use", 1), key, "key-1", refusedNotForeign},
		{"alg absent", published, absent("alg"), key, "key-1", accepted},
		{"alg RS512", with(func(j *oauth.Jwk) { j.Alg = "RS512" }), nil, key, "key-1", refusedNotForeign},
		{"alg PS256", with(func(j *oauth.Jwk) { j.Alg = "PS256" }), nil, key, "key-1", refusedNotForeign},
		{"alg rs256, which is not RS256", with(func(j *oauth.Jwk) { j.Alg = "rs256" }), nil, key, "key-1", refusedNotForeign},
		{"alg an empty string, which is not absent", published, set("alg", ""), key, "key-1", refusedNotForeign},
		{"alg null, which is not absent", published, set("alg", nil), key, "key-1", refusedNotForeign},
		{"alg an array holding RS256", published, set("alg", []string{"RS256"}), key, "key-1", refusedNotForeign},
		{"no kid, the one key as published", published, nil, key, "", accepted},
		{"no kid, the one key without use or alg", published, absent("use", "alg"), key, "", accepted},
		{"no kid, the one key marked use enc", with(func(j *oauth.Jwk) { j.Use = "enc" }), nil, key, "", refusedNotForeign},
		{"no kid, the one key marked alg RS512", with(func(j *oauth.Jwk) { j.Alg = "RS512" }), nil, key, "", refusedNotForeign},
		{"no kid, the one key with use empty", published, set("use", ""), key, "", refusedNotForeign},
		{"no kid, the one key with alg null", published, set("alg", nil), key, "", refusedNotForeign},
		{"no kid, the one key 1024 bits", oauthclienttest.JwkFromPublicKey("key-1", &weak.PublicKey), nil, weak, "", refusedNotForeign},
	}

	for _, method := range readerMethods() {
		for _, tc := range testCases {
			t.Run(method.name+"/"+tc.name, func(t *testing.T) {
				parser := parserOverDocument(t, tc.jwk, tc.members)
				claims := idClaims()

				err := method.run(parser, claims, oauthclienttest.SignRS256(t, tc.signer, tc.kid, claims))

				assertOutcome(t, tc.want, err)
			})
		}
	}
}

// parserOverDocument builds a parser expecting oauthclienttest.Issuer and ClientID over a JWKS
// publishing jwk alone, its members as JSON changed by members when that is set, served as the raw
// document so a member can be absent or hold any JSON value.
func parserOverDocument(t *testing.T, jwk oauth.Jwk, members func(map[string]any)) *oauthclient.JWKSTokenParser {
	t.Helper()
	encoded, err := json.Marshal(jwk)
	require.NoError(t, err)
	var key map[string]any
	require.NoError(t, json.Unmarshal(encoded, &key))
	if members != nil {
		members(key)
	}
	document, err := json.Marshal(map[string]any{"keys": []any{key}})
	require.NoError(t, err)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(document)
	}))
	t.Cleanup(server.Close)
	return oauthclient.NewJWKSTokenParser(server.URL, server.Client(), nil, oauthclienttest.ClientID,
		oauthclienttest.StaticIssuer(oauthclienttest.Issuer))
}

// authServerJwk writes a key as the auth server's /certs serves it (rsakey's JWK: alg, kid, kty,
// use, n, e), with e written out as RFC 7518 section 6.3.1.2's example for 65537.
func authServerJwk(kid string, pub *rsa.PublicKey) string {
	if pub.E != 65537 {
		panic("authServerJwk writes e as AQAB")
	}
	return fmt.Sprintf(`{"alg":"RS256","kid":%q,"kty":"RSA","use":"sig","n":%q,"e":"AQAB"}`,
		kid, base64.RawURLEncoding.EncodeToString(pub.N.Bytes()))
}

// The auth server's JWKS, as /certs answers it: the next, current and previous keys, each an RS256
// signing key, the current one 4096 bits as signingkeys generates them. A token under any of them
// is accepted by every method.
func TestIDToken_AcceptsTheAuthServersJWKS(t *testing.T) {
	current, err := rsa.GenerateKey(rand.Reader, 4096)
	require.NoError(t, err)
	next, previous := oauthclienttest.Keys(t)
	document := `{"keys":[` + authServerJwk("next-kid", &next.PublicKey) + "," +
		authServerJwk("current-kid", &current.PublicKey) + "," +
		authServerJwk("previous-kid", &previous.PublicKey) + `]}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(document))
	}))
	t.Cleanup(server.Close)

	signers := []struct {
		kid string
		key *rsa.PrivateKey
	}{{"current-kid", current}, {"previous-kid", previous}, {"next-kid", next}}

	for _, method := range readerMethods() {
		for _, signer := range signers {
			t.Run(method.name+"/"+signer.kid, func(t *testing.T) {
				parser := oauthclient.NewJWKSTokenParser(server.URL, server.Client(), nil, oauthclienttest.ClientID,
					oauthclienttest.StaticIssuer(oauthclienttest.Issuer))
				claims := idClaims()

				err := method.run(parser, claims, oauthclienttest.SignRS256(t, signer.key, signer.kid, claims))

				require.NoError(t, err)
			})
		}
	}
}

// The reader takes only ID tokens for the console. An access token and a refresh token the auth
// server signs with the same published key, shaped as issuance writes them, carry this sign-in's
// nonce, sub and iat, and are refused as foreign: their aud is not the console's client identifier.
func TestIDToken_RefusesTheAuthServersOtherTokens(t *testing.T) {
	key, _ := oauthclienttest.Keys(t)
	now := time.Now()
	common := func() jwt.MapClaims {
		return jwt.MapClaims{
			"iss":   oauthclienttest.Issuer,
			"sub":   "1234567890",
			"iat":   now.Unix(),
			"nbf":   now.Unix(),
			"exp":   now.Add(time.Hour).Unix(),
			"jti":   "4f1c9a52-7d2e-4b8a-9c3f-2e6d8a1b5c7e",
			"nonce": sentNonce(rawNonce),
		}
	}
	accessClaims := common()
	accessClaims["aud"] = "authserver"
	accessClaims["typ"] = "Bearer"
	accessClaims["client_id"] = oauthclienttest.ClientID
	accessClaims["scope"] = "openid profile authserver:admin-api"
	accessClaims["auth_time"] = signedInAt
	accessClaims["sid"] = "session-1"
	accessWithSeveralAudiences := common()
	for k, v := range accessClaims {
		accessWithSeveralAudiences[k] = v
	}
	accessWithSeveralAudiences["aud"] = []string{"authserver", "backend"}
	refreshClaims := common()
	refreshClaims["aud"] = oauthclienttest.Issuer
	refreshClaims["typ"] = "Refresh"
	refreshClaims["sid"] = "session-1"

	tokens := []struct {
		name   string
		header string
		claims jwt.MapClaims
	}{
		{"an access token", `{"alg":"RS256","kid":"key-1","typ":"at+jwt"}`, accessClaims},
		{"an access token for several resources", `{"alg":"RS256","kid":"key-1","typ":"at+jwt"}`, accessWithSeveralAudiences},
		{"a refresh token", `{"alg":"RS256","kid":"key-1","typ":"JWT"}`, refreshClaims},
	}

	for _, method := range readerMethods() {
		for _, tc := range tokens {
			t.Run(method.name+"/"+tc.name, func(t *testing.T) {
				parser, _ := parserOver(t, oauthclienttest.JwkFromPublicKey("key-1", &key.PublicKey))
				err := method.run(parser, tc.claims, oauthclienttest.SignRawRS256(t, key, tc.header, claimsJSON(t, tc.claims)))

				assertOutcome(t, foreign, err)
			})
		}
	}
}
