package oauth

import (
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
)

// JWKSTokenParser validates tokens using the auth server JWKS endpoint.
// It does not rely on any database and is suitable for the admin console.
type JWKSTokenParser struct {
	jwksURL    string
	httpClient *http.Client

	mu         sync.RWMutex
	cachedJwks Jwks
}

// NewJWKSTokenParser creates a JWKS-based token parser. The baseURL should be the
// reachable base URL for the auth server (InternalBaseURL if set, otherwise BaseURL).
func NewJWKSTokenParser(baseURL string, httpClient *http.Client) *JWKSTokenParser {
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	return &JWKSTokenParser{
		jwksURL:    strings.TrimRight(baseURL, "/") + "/certs",
		httpClient: httpClient,
	}
}

func (tp *JWKSTokenParser) DecodeAndValidateTokenResponse(tokenResponse *TokenResponse) (*JwtInfo, error) {
	result := &JwtInfo{TokenResponse: *tokenResponse}

	var err error
	if len(tokenResponse.AccessToken) > 0 {
		result.AccessToken, err = tp.DecodeAndValidateTokenString(tokenResponse.AccessToken, nil, true)
		if err != nil {
			return nil, err
		}
	}

	if len(tokenResponse.IdToken) > 0 {
		result.IdToken, err = tp.DecodeAndValidateTokenString(tokenResponse.IdToken, nil, true)
		if err != nil {
			return nil, err
		}
	}

	if len(tokenResponse.RefreshToken) > 0 {
		result.RefreshToken, err = tp.DecodeAndValidateTokenString(tokenResponse.RefreshToken, nil, false)
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

func (tp *JWKSTokenParser) DecodeAndValidateTokenString(token string, _ *rsa.PublicKey, withExpirationCheck bool) (*JwtToken, error) {
	result := &JwtToken{TokenBase64: token}
	if len(token) == 0 {
		return result, nil
	}

	claims := jwt.MapClaims{}

	opts := []jwt.ParserOption{}
	if withExpirationCheck {
		opts = append(opts, jwt.WithExpirationRequired())
	} else {
		opts = append(opts, jwt.WithoutClaimsValidation())
	}

	keyFunc := func(t *jwt.Token) (interface{}, error) {
		kid, _ := t.Header["kid"].(string)
		// Try cached first
		if pub := tp.getPublicKeyFromCache(kid); pub != nil {
			return pub, nil
		}
		// Refresh JWKS and try again
		if err := tp.refreshJwks(); err != nil {
			return nil, err
		}
		if pub := tp.getPublicKeyFromCache(kid); pub != nil {
			return pub, nil
		}
		return nil, errors.New("public key not found for token kid")
	}

	if _, err := jwt.ParseWithClaims(token, claims, keyFunc, opts...); err != nil {
		return nil, err
	}
	result.Claims = claims
	return result, nil
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

func (tp *JWKSTokenParser) refreshJwks() error {
	req, err := http.NewRequest(http.MethodGet, tp.jwksURL, nil)
	if err != nil {
		return err
	}
	resp, err := tp.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		slog.Error("failed to fetch JWKS", "status", resp.StatusCode)
		return errors.New("failed to fetch JWKS")
	}
	var jwks Jwks
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return err
	}
	tp.mu.Lock()
	tp.cachedJwks = jwks
	tp.mu.Unlock()
	return nil
}

func jwkToRSAPublicKey(j Jwk) (*rsa.PublicKey, error) {
	if j.Kty != "RSA" {
		return nil, errors.New("unsupported JWK kty")
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
