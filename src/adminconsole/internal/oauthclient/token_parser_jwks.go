package oauthclient

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"sync"

	"github.com/golang-jwt/jwt/v5"
	"github.com/leodip/goiabada/adminconsole/internal/boundedread"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
)

// ErrForeignToken marks an ID token that verified against the auth server's published keys but
// names another issuer or another audience than this console's: its iss is not the expected
// issuer, or its aud is not exactly the console's client identifier. It is wrapped into every
// such failure and nothing else, and only once the signature has verified, since an unverifiable
// token says nothing about who issued it. Callers match it with errors.Is: a foreign session is
// ended rather than refreshed, which is how every other signed-in administrator leaves when the
// issuer setting changes (#427).
var ErrForeignToken = errors.New("the id token was issued by another issuer or for another audience")

// issuerReader answers the issuer the console expects, per request: the auth server's Issuer
// setting as the request's settings snapshot holds it.
type issuerReader interface {
	Issuer(ctx context.Context) string
}

// JWKSTokenParser validates tokens using the auth server JWKS endpoint.
// It does not rely on any database and is suitable for the admin console.
type JWKSTokenParser struct {
	jwksURL    string
	httpClient *http.Client
	clientID   string
	issuer     issuerReader

	mu         sync.RWMutex
	cachedJwks oauth.Jwks
}

// NewJWKSTokenParser creates a JWKS-based token parser. The baseURL should be the
// reachable base URL for the auth server (InternalBaseURL if set, otherwise BaseURL).
// clientID is the console's client identifier, the one audience an ID token may name, and
// issuer answers the issuer an ID token must name.
func NewJWKSTokenParser(baseURL string, httpClient *http.Client, clientID string, issuer issuerReader) *JWKSTokenParser {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: TokenExchangeTimeout}
	}
	return &JWKSTokenParser{
		jwksURL:    strings.TrimRight(baseURL, "/") + "/certs",
		httpClient: httpClient,
		clientID:   clientID,
		issuer:     issuer,
	}
}

// DecodeAndValidateSignInResponse accepts the token response that completes a sign-in. It
// requires an access token (RFC 6749 section 5.1: access_token "REQUIRED") and an ID token
// (OIDC Core 3.1.3.3), verifies the ID token as verifyIDToken does with its expiry, and then
// checks the nonce: OIDC Core 3.1.3.7 step 11, "If a nonce value was sent in the Authentication
// Request, a nonce Claim MUST be present and its value checked". The console always sends one,
// so an empty expected nonce is refused rather than skipping the check. The claim must be
// nonceHash of the raw value the session kept, the scheme OIDC Core 15.5.2 describes. Only the
// ID token is decoded; the access and refresh tokens are carried as the strings they arrived as.
func (tp *JWKSTokenParser) DecodeAndValidateSignInResponse(ctx context.Context, tokenResponse *oauth.TokenResponse, nonce string) (*JwtInfo, error) {
	if tokenResponse == nil {
		return nil, errs.New("there is no token response")
	}
	if tokenResponse.AccessToken == "" {
		return nil, errs.New("the token response carries no access token")
	}
	if tokenResponse.IdToken == "" {
		return nil, errs.New("the token response carries no id token")
	}

	idToken, err := tp.verifyIDToken(ctx, tokenResponse.IdToken, true)
	if err != nil {
		return nil, err
	}

	if nonce == "" {
		return nil, errs.New("there is no nonce to check the id token against")
	}
	claim, ok := idToken.Claims["nonce"].(string)
	if !ok {
		return nil, errs.New("the id token carries no nonce")
	}
	expected, err := nonceHash(nonce)
	if err != nil {
		return nil, err
	}
	// The claim travels in the authorize URL before it comes back here, so it is no secret
	// and plain equality is enough.
	if claim != expected {
		return nil, errs.New("the id token's nonce is not the one this sign-in sent")
	}

	return &JwtInfo{TokenResponse: *tokenResponse, IdToken: idToken}, nil
}

// DecodeAndValidateRefreshResponse accepts the token response to a refresh grant. previous is
// the stored ID token, which verified on this same request. A response with no ID token keeps
// previous, since OIDC Core 12.2 says a refresh response "might not contain an id_token"; the
// returned response then carries previous as its id_token and the argument is not changed.
// Otherwise the new ID token is verified with its expiry and compared with previous under OIDC
// Core 12.2, which requires the same iss, sub and aud and, when both carry one, the same
// auth_time; lets a refreshed ID token omit nonce, which it "SHOULD NOT have", but not change
// it; and requires iat not to go backwards. An iss that differs from previous is
// ErrForeignToken; every other mismatch is not, because a different user or sign-in time in a
// refresh is something someone must look at rather than a changed setting.
func (tp *JWKSTokenParser) DecodeAndValidateRefreshResponse(ctx context.Context, tokenResponse *oauth.TokenResponse, previous *oauth.JwtToken) (*JwtInfo, error) {
	if tokenResponse == nil {
		return nil, errs.New("there is no token response")
	}
	if previous == nil {
		return nil, errs.New("there is no previous id token to compare the refreshed one with")
	}
	if tokenResponse.AccessToken == "" {
		return nil, errs.New("the token response carries no access token")
	}

	if tokenResponse.IdToken == "" {
		kept := *tokenResponse
		kept.IdToken = previous.TokenBase64
		return &JwtInfo{TokenResponse: kept, IdToken: previous}, nil
	}

	idToken, err := tp.verifyIDToken(ctx, tokenResponse.IdToken, true)
	if err != nil {
		return nil, err
	}
	if err := sameAuthentication(previous, idToken); err != nil {
		return nil, err
	}

	return &JwtInfo{TokenResponse: *tokenResponse, IdToken: idToken}, nil
}

// DecodeAndValidateStoredIDToken re-verifies the ID token a session holds, on every request:
// everything verifyIDToken checks but its expiry. OIDC Core 3.1.3.7 step 9's expiry governs
// accepting the token from a token response, which happens at sign-in and on every refresh; the
// console session's length is the refresh cycle and the session store's own lifetimes, not the
// ID token's, which a refresh may leave unrenewed (OIDC Core 12.2).
func (tp *JWKSTokenParser) DecodeAndValidateStoredIDToken(ctx context.Context, raw string) (*oauth.JwtToken, error) {
	return tp.verifyIDToken(ctx, raw, false)
}

// verifyIDToken is the one check every ID token the console accepts goes through, in this
// order: RS256 and a signature under a published key; iss equal to the expected issuer (OIDC
// Core 3.1.3.7 step 2); aud exactly the console's client identifier (step 3); and, when
// acceptingFromResponse, exp required and exp and nbf honoured (step 9).
//
// The iss and aud checks are written here rather than asked of golang-jwt's WithIssuer and
// WithAudience: WithAudience accepts an aud that merely contains the client, which step 3
// forbids ("MUST be rejected if ... it contains additional audiences not trusted by the
// Client"), and a missing iss or aud there shares its sentinel with a missing exp, so a caller
// could not tell a foreign token from an expired one. Both are decided after the signature,
// because an unverifiable token is evidence of nothing, and before the expiry, because a token
// that is both foreign and expired must be reported as foreign: that is the answer callers
// branch on, and moving the expiry first would report such a token as merely expired (#427).
func (tp *JWKSTokenParser) verifyIDToken(ctx context.Context, raw string, acceptingFromResponse bool) (*oauth.JwtToken, error) {
	if raw == "" {
		return nil, errs.New("the id token is empty")
	}

	claims := jwt.MapClaims{}
	if _, err := jwt.ParseWithClaims(raw, claims, tp.keyFunc(ctx),
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		jwt.WithoutClaimsValidation(),
	); err != nil {
		return nil, errs.Wrap(err, "unable to verify the id token's signature")
	}

	expectedIssuer := tp.issuer.Issuer(ctx)
	if expectedIssuer == "" {
		// A configuration fault, not evidence about the token, so not foreign.
		return nil, errs.New("there is no expected issuer to check the id token against")
	}
	iss, err := claims.GetIssuer()
	if err != nil {
		return nil, errs.Wrapf(ErrForeignToken, "the id token's iss is unreadable (%v)", err)
	}
	if iss != expectedIssuer {
		return nil, errs.Wrapf(ErrForeignToken, "the id token's iss %q is not the expected %q", iss, expectedIssuer)
	}

	aud, err := claims.GetAudience()
	if err != nil {
		return nil, errs.Wrapf(ErrForeignToken, "the id token's aud is unreadable (%v)", err)
	}
	if len(aud) == 0 {
		return nil, errs.Wrap(ErrForeignToken, "the id token names no audience")
	}
	for _, a := range aud {
		if a != tp.clientID {
			return nil, errs.Wrapf(ErrForeignToken, "the id token's aud %q is not exactly %q", []string(aud), tp.clientID)
		}
	}

	if acceptingFromResponse {
		if err := jwt.NewValidator(jwt.WithExpirationRequired()).Validate(claims); err != nil {
			return nil, errs.Wrap(err, "the id token is outside its validity period")
		}
	}

	return &oauth.JwtToken{TokenBase64: raw, Claims: claims}, nil
}

// sameAuthentication is OIDC Core 12.2's comparison of a refreshed ID token with the one it
// replaces.
func sameAuthentication(previous, refreshed *oauth.JwtToken) error {
	if previous.GetStringClaim("iss") != refreshed.GetStringClaim("iss") {
		return errs.Wrap(ErrForeignToken, "the refreshed id token's iss differs from the previous one's")
	}
	if previous.GetStringClaim("sub") != refreshed.GetStringClaim("sub") {
		return errs.New("the refreshed id token's sub differs from the previous one's")
	}
	if !sameAudience(previous, refreshed) {
		return errs.New("the refreshed id token's aud differs from the previous one's")
	}

	_, previousHasAuthTime := previous.Claims["auth_time"]
	_, refreshedHasAuthTime := refreshed.Claims["auth_time"]
	if previousHasAuthTime && refreshedHasAuthTime {
		previousAuthTime, previousOk := previous.GetIntClaim("auth_time")
		refreshedAuthTime, refreshedOk := refreshed.GetIntClaim("auth_time")
		if !previousOk || !refreshedOk || previousAuthTime != refreshedAuthTime {
			return errs.New("the refreshed id token's auth_time differs from the previous one's")
		}
	}

	if _, refreshedHasNonce := refreshed.Claims["nonce"]; refreshedHasNonce {
		refreshedNonce, refreshedOk := refreshed.Claims["nonce"].(string)
		previousNonce, previousOk := previous.Claims["nonce"].(string)
		if !refreshedOk || !previousOk || refreshedNonce != previousNonce {
			return errs.New("the refreshed id token's nonce differs from the previous one's")
		}
	}

	if previousIat, ok := previous.GetIntClaim("iat"); ok {
		refreshedIat, refreshedOk := refreshed.GetIntClaim("iat")
		if !refreshedOk || refreshedIat < previousIat {
			return errs.New("the refreshed id token's iat is missing or earlier than the previous one's")
		}
	}

	return nil
}

// sameAudience compares the two tokens' aud values as sets, so the string and the one-element
// array spellings of one audience are equal.
func sameAudience(previous, refreshed *oauth.JwtToken) bool {
	previousAud, previousErr := previous.Claims.GetAudience()
	refreshedAud, refreshedErr := refreshed.Claims.GetAudience()
	if previousErr != nil || refreshedErr != nil {
		return false
	}
	previousSet := make(map[string]bool, len(previousAud))
	for _, a := range previousAud {
		previousSet[a] = true
	}
	refreshedSet := make(map[string]bool, len(refreshedAud))
	for _, a := range refreshedAud {
		if !previousSet[a] {
			return false
		}
		refreshedSet[a] = true
	}
	return len(previousSet) == len(refreshedSet)
}

func (tp *JWKSTokenParser) DecodeAndValidateTokenResponse(ctx context.Context, tokenResponse *oauth.TokenResponse) (*JwtInfo, error) {
	result := &JwtInfo{TokenResponse: *tokenResponse}

	var err error
	if len(tokenResponse.AccessToken) > 0 {
		result.AccessToken, err = tp.DecodeAndValidateTokenString(ctx, tokenResponse.AccessToken, nil, true)
		if err != nil {
			return nil, err
		}
	}

	if len(tokenResponse.IdToken) > 0 {
		result.IdToken, err = tp.DecodeAndValidateTokenString(ctx, tokenResponse.IdToken, nil, true)
		if err != nil {
			return nil, err
		}
	}

	if len(tokenResponse.RefreshToken) > 0 {
		result.RefreshToken, err = tp.DecodeAndValidateTokenString(ctx, tokenResponse.RefreshToken, nil, false)
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

func (tp *JWKSTokenParser) DecodeAndValidateTokenString(ctx context.Context, token string, _ *rsa.PublicKey, withExpirationCheck bool) (*oauth.JwtToken, error) {
	result := &oauth.JwtToken{TokenBase64: token}
	if len(token) == 0 {
		return result, nil
	}

	claims := jwt.MapClaims{}

	opts := []jwt.ParserOption{jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()})}
	if withExpirationCheck {
		opts = append(opts, jwt.WithExpirationRequired())
	} else {
		opts = append(opts, jwt.WithoutClaimsValidation())
	}

	if _, err := jwt.ParseWithClaims(token, claims, tp.keyFunc(ctx), opts...); err != nil {
		return nil, err
	}
	result.Claims = claims
	return result, nil
}

// keyFunc finds the published key a token's kid names, refreshing the cached JWKS once when
// the cache does not hold it.
func (tp *JWKSTokenParser) keyFunc(ctx context.Context) jwt.Keyfunc {
	return func(t *jwt.Token) (interface{}, error) {
		kid, _ := t.Header["kid"].(string)
		// Try cached first
		if pub := tp.getPublicKeyFromCache(kid); pub != nil {
			return pub, nil
		}
		// Refresh JWKS and try again
		if err := tp.refreshJwks(ctx); err != nil {
			return nil, err
		}
		if pub := tp.getPublicKeyFromCache(kid); pub != nil {
			return pub, nil
		}
		return nil, errs.New("public key not found for token kid")
	}
}

func (tp *JWKSTokenParser) getPublicKeyFromCache(kid string) *rsa.PublicKey {
	tp.mu.RLock()
	defer tp.mu.RUnlock()
	if kid == "" {
		// If no kid, attempt current key if single
		if len(tp.cachedJwks.Keys) == 1 {
			if pub, err := jwkToRSAPublicKey(tp.cachedJwks.Keys[0]); err == nil {
				return pub
			}
		}
		return nil
	}
	for _, k := range tp.cachedJwks.Keys {
		if k.Kid == kid {
			if pub, err := jwkToRSAPublicKey(k); err == nil {
				return pub
			}
		}
	}
	return nil
}

func (tp *JWKSTokenParser) refreshJwks(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tp.jwksURL, nil)
	if err != nil {
		return err
	}
	resp, err := tp.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		slog.ErrorContext(ctx, "unable to fetch the jwks document", "status", resp.StatusCode)
		return errs.New("failed to fetch JWKS")
	}
	// Bounded like every other read the admin console makes of the auth server. The request
	// keeps its own context rather than a detached one: fetching /certs is an idempotent read
	// of a document the server holds no state for, so abandoning it when the browser goes
	// away loses nothing (#338).
	//
	// Read whole and then unmarshalled, rather than decoded off the wire through a
	// LimitReader. json.Decoder stops at the first complete value, so a document cut at the
	// ceiling that happened to be balanced would decode with keys missing and this would
	// cache a JWKS short of the key the next token needs, with nothing saying so. An overrun
	// is refused instead, and the cache below is left as it was (#386 decision 4).
	body, err := boundedread.Read(resp.Body, MaxTokenResponseBytes)
	if err != nil {
		return err
	}
	var jwks oauth.Jwks
	if err := json.Unmarshal(body, &jwks); err != nil {
		return err
	}
	tp.mu.Lock()
	tp.cachedJwks = jwks
	tp.mu.Unlock()
	return nil
}

func jwkToRSAPublicKey(j oauth.Jwk) (*rsa.PublicKey, error) {
	if j.Kty != "RSA" {
		return nil, errs.New("unsupported JWK kty")
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(j.N)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(j.E)
	if err != nil {
		return nil, err
	}
	var eInt int
	for _, b := range eBytes {
		eInt = eInt<<8 + int(b)
	}
	pub := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: eInt,
	}
	return pub, nil
}
