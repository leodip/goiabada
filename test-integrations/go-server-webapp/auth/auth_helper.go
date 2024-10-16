package auth

import (
	"GoServerWebApp/config"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/jwk"
	"golang.org/x/oauth2"
)

type AuthHelper struct {
	oauth2Config    oauth2.Config
	idTokenVerifier *oidc.IDTokenVerifier
	cachedJWKS      jwk.Set
	cacheMutex      sync.RWMutex
	cacheExpiry     time.Time
}

func NewAuthHelper(ctx context.Context) (*AuthHelper, error) {
	provider, err := oidc.NewProvider(ctx, config.OidcProvider)
	if err != nil {
		return nil, err
	}

	oauth2Config := oauth2.Config{
		ClientID:     config.ClientId,
		ClientSecret: config.ClientSecret,
		RedirectURL:  config.RedirectURL,
		Endpoint:     provider.Endpoint(),
	}

	idTokenVerifier := provider.Verifier(&oidc.Config{ClientID: config.ClientId})

	return &AuthHelper{
		oauth2Config:    oauth2Config,
		idTokenVerifier: idTokenVerifier,
	}, nil
}

func (a *AuthHelper) GenerateVerifier() string {
	return oauth2.GenerateVerifier()
}

func (a *AuthHelper) GenerateAuthCodeURL(state string, nonce string, verifier string, scopes []string) string {
	a.oauth2Config.Scopes = scopes

	url := a.oauth2Config.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("response_mode", config.ResponseMode),
		oauth2.S256ChallengeOption(verifier))
	return url
}

func (a *AuthHelper) fetchJWKS() (jwk.Set, error) {
	a.cacheMutex.RLock()
	if a.cachedJWKS != nil && time.Now().Before(a.cacheExpiry) {
		defer a.cacheMutex.RUnlock()
		return a.cachedJWKS, nil
	}
	a.cacheMutex.RUnlock()

	// Acquire write lock
	a.cacheMutex.Lock()
	defer a.cacheMutex.Unlock()

	// Double-check if another goroutine has updated the cache while we were waiting
	if a.cachedJWKS != nil && time.Now().Before(a.cacheExpiry) {
		return a.cachedJWKS, nil
	}

	// Fetch the discovery document
	wellKnownURL := fmt.Sprintf("%s/.well-known/openid-configuration", config.OidcProvider)
	resp, err := http.Get(wellKnownURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch discovery document: %v", err)
	}
	defer resp.Body.Close()

	// Parse the discovery document
	var discovery struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		return nil, fmt.Errorf("failed to decode discovery document: %v", err)
	}

	// Fetch the JWKS
	jwksResp, err := http.Get(discovery.JWKSURI)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %v", err)
	}
	defer jwksResp.Body.Close()

	jwksData, err := io.ReadAll(jwksResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read JWKS response: %v", err)
	}

	// Parse the JWKS
	jwks, err := jwk.Parse(jwksData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWKS: %v", err)
	}

	// Update the cache
	a.cachedJWKS = jwks
	a.cacheExpiry = time.Now().Add(30 * time.Minute)

	return jwks, nil
}

func (a *AuthHelper) ParseAndValidateJWT(tokenString string) (*jwt.Token, error) {

	jwks, err := a.fetchJWKS()
	if err != nil {
		return nil, err
	}

	keyFunc := func(token *jwt.Token) (interface{}, error) {
		// Check if the signing method is what you expect
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Extract the "kid" from the token header
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("token header does not contain kid")
		}

		// Lookup the key by the "kid"
		key, found := jwks.LookupKeyID(kid)
		if !found {
			return nil, fmt.Errorf("unable to find key with kid: %s", kid)
		}

		var rawKey interface{}
		if err := key.Raw(&rawKey); err != nil {
			return nil, fmt.Errorf("failed to get raw key: %v", err)
		}

		return rawKey, nil
	}

	token, err := jwt.Parse(tokenString, keyFunc)
	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return token, nil
}

func (a *AuthHelper) ExchangeAuthCodeWithToken(ctx context.Context, code string, verifier string) (*oauth2.Token, error) {
	token, err := a.oauth2Config.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, err
	}
	return token, nil
}

func (a *AuthHelper) VerifyIdToken(ctx context.Context, rawIDToken string) (*oidc.IDToken, error) {
	idToken, err := a.idTokenVerifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, err
	}
	return idToken, nil
}
