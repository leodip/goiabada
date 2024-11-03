package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"go-webapp/config"
	"io"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/sessions"
	"github.com/lestrrat-go/jwx/jwk"
	"golang.org/x/oauth2"
)

var (
	sessionStore    sessions.Store
	oauth2Config    *oauth2.Config
	idTokenVerifier *oidc.IDTokenVerifier
	provider        *oidc.Provider
)

func InitAuth(ctx context.Context, appConfig *config.AppConfig, store sessions.Store) error {

	proivderConfig := oidc.ProviderConfig{
		IssuerURL:   config.IssuerURL,
		AuthURL:     config.AuthURL,
		TokenURL:    config.TokenURL,
		UserInfoURL: config.UserInfoURL,
		JWKSURL:     config.JWKSURL,
	}
	provider := proivderConfig.NewProvider(ctx)

	oauth2Config = &oauth2.Config{
		ClientID:     appConfig.ClientID,
		ClientSecret: appConfig.ClientSecret,
		RedirectURL:  appConfig.RedirectURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  config.AuthURL,
			TokenURL: config.TokenURL,
		},
	}

	idTokenVerifier = provider.Verifier(&oidc.Config{
		ClientID: appConfig.ClientID,
	})

	sessionStore = store

	return nil
}

func VerifyIdToken(ctx context.Context, rawIDToken string) (*oidc.IDToken, error) {
	idToken, err := idTokenVerifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, err
	}
	return idToken, nil
}

func GetOAuth2Config() *oauth2.Config {
	return oauth2Config
}

func GenerateRandomString() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// fetchJWKS fetches the JWKS from the JWKS URL
func fetchJWKS() (jwk.Set, error) {
	jwksResp, err := http.Get(config.JWKSURL)
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

	return jwks, nil
}

// This is the keyfunc required by the jwt library to verify the signature of jwt tokens
func keyFunc(token *jwt.Token) (interface{}, error) {
	jwks, err := fetchJWKS()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %v", err)
	}

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

// VerifyJWTToken verifies any JWT token (can be used for both access and refresh tokens)
func VerifyJWTToken(ctx context.Context, tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, jwt.MapClaims{}, keyFunc)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims type")
	}

	return claims, nil
}
