package core

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	b64 "encoding/base64"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/golang-jwt/jwt/v5"
	"github.com/leodip/goiabada/internal/core"
	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/dtos"
)

type TokenValidator struct {
	database core.Database
}

func NewTokenValidator(database core.Database) *TokenValidator {
	return &TokenValidator{
		database: database,
	}
}

func (val *TokenValidator) ValidateScopes(ctx context.Context, scope string, clientIdentifier string) error {

	if len(scope) == 0 {
		return nil
	}
	requestId := middleware.GetReqID(ctx)

	client, err := val.database.GetClientByClientIdentifier(clientIdentifier)
	if err != nil {
		return customerrors.NewInternalServerError(err, requestId)
	}
	if client == nil {
		return customerrors.NewAppError(nil, "server_error", fmt.Sprintf("Could not find client by identifier '%v'", clientIdentifier), http.StatusInternalServerError)
	}

	space := regexp.MustCompile(`\s+`)
	scope = space.ReplaceAllString(scope, " ")

	scopes := strings.Split(scope, " ")

	for _, scopeStr := range scopes {

		if core.IsOIDCScope(scopeStr) || scopeStr == "roles" {
			return customerrors.NewAppError(nil, "invalid_request", fmt.Sprintf("OpenID Connect scopes (such as '%v') are not supported in the client credentials flow. Please use scopes in the format 'resource:permission' (e.g., 'backendA:read'). Multiple scopes can be specified, separated by spaces.", scopeStr), http.StatusBadRequest)
		}

		parts := strings.Split(scopeStr, ":")
		if len(parts) != 2 {
			return customerrors.NewAppError(nil, "invalid_scope", fmt.Sprintf("Invalid scope format: '%v'. Scopes must adhere to the resource-identifier:permission-identifier format. For instance: backend-service:create-product.", scopeStr), http.StatusBadRequest)
		}

		res, err := val.database.GetResourceByResourceIdentifier(parts[0])
		if err != nil {
			return customerrors.NewInternalServerError(err, requestId)
		}
		if res == nil {
			return customerrors.NewAppError(nil, "invalid_scope", fmt.Sprintf("Invalid scope: '%v'. Could not find a resource with identifier '%v'.", scopeStr, parts[0]), http.StatusBadRequest)
		}

		permissions, err := val.database.GetResourcePermissions(res.ID)
		if err != nil {
			return customerrors.NewInternalServerError(err, requestId)
		}

		permissionExists := false
		for _, perm := range permissions {
			if perm.PermissionIdentifier == parts[1] {
				permissionExists = true
				break
			}
		}

		if !permissionExists {
			return customerrors.NewAppError(nil, "invalid_scope", fmt.Sprintf("Scope '%v' is not recognized. The resource identified by '%v' doesn't grant the '%v' permission.", scopeStr, parts[0], parts[1]), http.StatusBadRequest)
		}

		clientHasPermission := false
		for _, perm := range client.Permissions {
			if perm.PermissionIdentifier == parts[1] {
				clientHasPermission = true
				break
			}
		}

		if !clientHasPermission {
			return customerrors.NewAppError(nil, "invalid_scope", fmt.Sprintf("Permission to access scope '%v' is not granted to the client.", scopeStr), http.StatusBadRequest)
		}
	}
	return nil
}

func (val *TokenValidator) ValidateJwtSignature(ctx context.Context, tokenResponse *dtos.TokenResponse) (*dtos.JwtInfo, error) {

	keyPair, err := val.database.GetSigningKey()
	if err != nil {
		return nil, err
	}

	publicKeyPEMBytes, err := b64.StdEncoding.DecodeString(keyPair.PublicKeyPEM)
	if err != nil {
		return nil, err
	}
	pubKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyPEMBytes)
	if err != nil {
		return nil, err
	}

	result := &dtos.JwtInfo{
		TokenResponse: *tokenResponse,
	}

	if len(tokenResponse.AccessToken) > 0 {
		claimsAccessToken := jwt.MapClaims{}
		result.AccessTokenIsPresent = true

		token, err := jwt.ParseWithClaims(tokenResponse.AccessToken, claimsAccessToken, func(token *jwt.Token) (interface{}, error) {
			return pubKey, nil
		})
		if err != nil {
			return nil, err
		}

		result.AccessTokenSignatureIsValid = token.Valid
		if !token.Valid {
			return nil, customerrors.NewAppError(nil, "", "The access token signature is invalid", http.StatusInternalServerError)
		}

		exp := claimsAccessToken["exp"].(float64)
		expirationTime := time.Unix(int64(exp), 0).UTC()
		currentTime := time.Now().UTC()
		if currentTime.After(expirationTime) {
			result.AccessTokenIsExpired = true
		} else {
			result.AccessTokenClaims = claimsAccessToken
		}
	}

	if len(tokenResponse.IdToken) > 0 {
		claimsIdToken := jwt.MapClaims{}
		result.IdTokenIsPresent = true

		token, err := jwt.ParseWithClaims(tokenResponse.IdToken, claimsIdToken, func(token *jwt.Token) (interface{}, error) {
			return pubKey, nil
		})
		if err != nil {
			return nil, err
		}

		result.IdTokenSignatureIsValid = token.Valid
		if !token.Valid {
			return nil, customerrors.NewAppError(nil, "", "The id token signature is invalid", http.StatusInternalServerError)
		}

		exp := claimsIdToken["exp"].(float64)
		expirationTime := time.Unix(int64(exp), 0).UTC()
		currentTime := time.Now().UTC()
		if currentTime.After(expirationTime) {
			result.IdTokenIsExpired = true
		} else {
			result.IdTokenClaims = claimsIdToken
		}
	}

	if len(tokenResponse.RefreshToken) > 0 {
		claimsRefreshToken := jwt.MapClaims{}
		result.RefreshTokenIsPresent = true

		token, err := jwt.ParseWithClaims(tokenResponse.RefreshToken, claimsRefreshToken, func(token *jwt.Token) (interface{}, error) {
			return pubKey, nil
		})
		if err != nil {
			return nil, err
		}

		result.RefreshTokenSignatureIsValid = token.Valid
		if !token.Valid {
			return nil, customerrors.NewAppError(nil, "", "The refresh token signature is invalid", http.StatusInternalServerError)
		}

		exp := claimsRefreshToken["exp"].(float64)
		expirationTime := time.Unix(int64(exp), 0).UTC()
		currentTime := time.Now().UTC()
		if currentTime.After(expirationTime) {
			result.RefreshTokenIsExpired = true
		} else {
			result.RefreshTokenClaims = claimsRefreshToken
		}
	}

	return result, nil
}
