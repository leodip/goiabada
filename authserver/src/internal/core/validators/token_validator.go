package core

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/core"
	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/data"
	"github.com/leodip/goiabada/internal/dtos"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/lib"
)

type TokenValidator struct {
	database *data.Database
}

func NewTokenValidator(database *data.Database) *TokenValidator {
	return &TokenValidator{
		database: database,
	}
}

type ValidateTokenRequestInput struct {
	GrantType    string
	Code         string
	RedirectURI  string
	CodeVerifier string
	ClientId     string
	ClientSecret string
	Scope        string
	RefreshToken string
}

type ValidateTokenRequestResult struct {
	CodeEntity   *entities.Code
	Client       *entities.Client
	Scope        string
	RefreshToken *entities.RefreshToken
}

func (val *TokenValidator) ValidateTokenRequest(ctx context.Context, input *ValidateTokenRequestInput) (*ValidateTokenRequestResult, error) {

	settings := ctx.Value(common.ContextKeySettings).(*entities.Settings)

	if len(input.ClientId) == 0 {
		return nil, customerrors.NewValidationError("invalid_request", "Missing required client_id parameter.")
	}

	client, err := val.database.GetClientByClientIdentifier(input.ClientId)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, customerrors.NewValidationError("invalid_request", "Client does not exist.")
	}

	clientSecretRequiredErrorMsg := "This client is configured as confidential (not public), which means a client_secret is required for authentication. Please provide a valid client_secret to proceed."

	if input.GrantType == "authorization_code" {
		if len(input.Code) == 0 {
			return nil, customerrors.NewValidationError("invalid_request", "Missing required code parameter.")
		}

		if len(input.RedirectURI) == 0 {
			return nil, customerrors.NewValidationError("invalid_request", "Missing required redirect_uri parameter.")
		}

		if len(input.CodeVerifier) == 0 {
			return nil, customerrors.NewValidationError("invalid_request", "Missing required code_verifier parameter.")
		}

		codeHash, err := lib.HashString(input.Code)
		if err != nil {
			return nil, err
		}
		codeEntity, err := val.database.GetCode(codeHash, false)
		if err != nil {
			return nil, err
		}
		if codeEntity == nil {
			return nil, customerrors.NewValidationError("invalid_grant", "Code is invalid.")
		}

		if codeEntity.RedirectURI != input.RedirectURI {
			return nil, customerrors.NewValidationError("invalid_grant", "Invalid redirect_uri.")
		}

		if codeEntity.Client.ClientIdentifier != input.ClientId {
			return nil, customerrors.NewValidationError("invalid_grant", "The client_id provided does not match the client_id from code.")
		}

		if !client.IsPublic {
			if len(input.ClientSecret) == 0 {
				return nil, customerrors.NewValidationError("invalid_request", clientSecretRequiredErrorMsg)
			}

			clientSecretDecrypted, err := lib.DecryptText(client.ClientSecretEncrypted, settings.AESEncryptionKey)
			if err != nil {
				return nil, err
			}
			if clientSecretDecrypted != input.ClientSecret {
				return nil, customerrors.NewValidationError("invalid_grant", "Client authentication failed. Please review your client_secret.")
			}
		} else {
			if len(input.ClientSecret) > 0 {
				return nil, customerrors.NewValidationError("invalid_request", "This client is configured as public, which means a client_secret is not required. To proceed, please remove the client_secret from your request.")
			}
		}

		codeChallenge := lib.GeneratePKCECodeChallenge(input.CodeVerifier)
		if codeEntity.CodeChallenge != codeChallenge {
			return nil, customerrors.NewValidationError("invalid_grant", "Invalid code_verifier (PKCE).")
		}

		return &ValidateTokenRequestResult{
			CodeEntity: codeEntity,
		}, nil

	} else if input.GrantType == "client_credentials" {

		if client.IsPublic {
			return nil, customerrors.NewValidationError("unauthorized_client", "A public client is not eligible for the client credentials flow. Please review the client configuration.")
		}

		if len(input.ClientSecret) == 0 {
			return nil, customerrors.NewValidationError("invalid_request", clientSecretRequiredErrorMsg)
		}

		clientSecretDescrypted, err := lib.DecryptText(client.ClientSecretEncrypted, settings.AESEncryptionKey)
		if err != nil {
			return nil, err
		}
		if clientSecretDescrypted != input.ClientSecret {
			return nil, customerrors.NewValidationError("invalid_client", "Client authentication failed.")
		}

		if len(input.Scope) == 0 {
			// no scope was passed, let's include all possible permissions
			for _, perm := range client.Permissions {
				res, err := val.database.GetResourceByResourceIdentifier(perm.Resource.ResourceIdentifier)
				if err != nil {
					return nil, err
				}
				input.Scope = input.Scope + " " + res.ResourceIdentifier + ":" + perm.PermissionIdentifier
			}
			input.Scope = strings.TrimSpace(input.Scope)
		}

		err = val.validateClientCredentialsScopes(ctx, input.Scope, client)
		if err != nil {
			return nil, err
		}

		return &ValidateTokenRequestResult{
			Client: client,
			Scope:  input.Scope,
		}, nil
	} else if input.GrantType == "refresh_token" {

		if !client.IsPublic {
			if len(input.ClientSecret) == 0 {
				return nil, customerrors.NewValidationError("invalid_request", clientSecretRequiredErrorMsg)
			}

			clientSecretDecrypted, err := lib.DecryptText(client.ClientSecretEncrypted, settings.AESEncryptionKey)
			if err != nil {
				return nil, err
			}
			if clientSecretDecrypted != input.ClientSecret {
				return nil, customerrors.NewValidationError("invalid_grant", "Client authentication failed. Please review your client_secret.")
			}
		}

		if len(input.RefreshToken) == 0 {
			return nil, customerrors.NewValidationError("invalid_request", "Missing required refresh_token parameter.")
		}

		refreshTokenInfo, err := val.ParseRefreshToken(ctx, input.RefreshToken)
		if err != nil {
			return nil, customerrors.NewValidationError("invalid_grant", "The refresh token is invalid ("+err.Error()+").")
		}

		jti := refreshTokenInfo.GetStringClaim("jti")
		if len(jti) == 0 {
			return nil, errors.New("the refresh token is invalid because it does not contain a jti claim")
		}

		refreshToken, err := val.database.GetRefreshTokenByJti(jti)
		if err != nil {
			return nil, err
		}
		if refreshToken == nil {
			return nil, errors.New("the refresh token is invalid because it does not exist in the database")
		}

		if refreshToken.Code.ClientId != client.Id {
			return nil, customerrors.NewValidationError("invalid_request", "The refresh token is invalid because it does not belong to the client.")
		}

		if len(input.Scope) > 0 {
			// must be equal to, or a subset of the original scopes requested
			space := regexp.MustCompile(`\s+`)
			inputScopeSanitized := space.ReplaceAllString(input.Scope, " ")
			inputScopes := strings.Split(inputScopeSanitized, " ")

			for _, inputScopeStr := range inputScopes {

				scopesFromCode := strings.Split(refreshToken.Code.Scope, " ")

				scopeExists := false
				for _, scopeFromCode := range scopesFromCode {
					if scopeFromCode == inputScopeStr {
						scopeExists = true
						break
					}
				}

				if !scopeExists {
					return nil, customerrors.NewValidationError("invalid_grant",
						fmt.Sprintf("Scope '%v' is not recognized. The original access token does not grant the '%v' permission.", inputScopeStr, inputScopeStr))
				}
			}
		}

		scopes := refreshToken.Code.Scope
		if len(input.Scope) > 0 {
			scopes = input.Scope
		}
		inputScopes := strings.Split(scopes, " ")

		for _, inputScopeStr := range inputScopes {
			if client.ConsentRequired {
				// check if user still consents to this scope
				consent, err := val.database.GetUserConsent(refreshToken.Code.UserId, refreshToken.Code.ClientId)
				if err != nil {
					return nil, err
				}
				if consent == nil {
					return nil,
						customerrors.NewValidationError("invalid_grant", "The user has not consented to this client.")
				}

				consentScopeExists := false
				scopesFromConsent := strings.Split(consent.Scope, " ")
				for _, scopeFromConsent := range scopesFromConsent {
					if scopeFromConsent == inputScopeStr {
						consentScopeExists = true
						break
					}
				}

				if !consentScopeExists {
					return nil,
						customerrors.NewValidationError("invalid_grant",
							fmt.Sprintf("Scope '%v' is not recognized. The user has not consented to the '%v' permission.", inputScopeStr, inputScopeStr))
				}
			}
		}

		return &ValidateTokenRequestResult{
			CodeEntity:   &refreshToken.Code,
			Client:       client,
			RefreshToken: refreshToken,
		}, nil
	}

	return nil, customerrors.NewValidationError("unsupported_grant_type", "Unsupported grant_type.")
}

func (val *TokenValidator) validateClientCredentialsScopes(ctx context.Context, scope string, client *entities.Client) error {

	if len(scope) == 0 {
		return nil
	}

	space := regexp.MustCompile(`\s+`)
	scope = space.ReplaceAllString(scope, " ")

	scopes := strings.Split(scope, " ")

	for _, scopeStr := range scopes {

		if core.IsIdTokenScope(scopeStr) {
			return customerrors.NewValidationError("invalid_request", fmt.Sprintf("Id token scopes (such as '%v') are not supported in the client credentials flow. Please use scopes in the format 'resource:permission' (e.g., 'backendA:read'). Multiple scopes can be specified, separated by spaces.", scopeStr))
		}

		parts := strings.Split(scopeStr, ":")
		if len(parts) != 2 {
			return customerrors.NewValidationError("invalid_scope", fmt.Sprintf("Invalid scope format: '%v'. Scopes must adhere to the resource-identifier:permission-identifier format. For instance: backend-service:create-product.", scopeStr))
		}

		res, err := val.database.GetResourceByResourceIdentifier(parts[0])
		if err != nil {
			return err
		}
		if res == nil {
			return customerrors.NewValidationError("invalid_scope", fmt.Sprintf("Invalid scope: '%v'. Could not find a resource with identifier '%v'.", scopeStr, parts[0]))
		}

		permissions, err := val.database.GetResourcePermissions(res.Id)
		if err != nil {
			return err
		}

		permissionExists := false
		for _, perm := range permissions {
			if perm.PermissionIdentifier == parts[1] {
				permissionExists = true
				break
			}
		}

		if !permissionExists {
			return customerrors.NewValidationError("invalid_scope", fmt.Sprintf("Scope '%v' is not recognized. The resource identified by '%v' doesn't grant the '%v' permission.", scopeStr, parts[0], parts[1]))
		}

		clientHasPermission := false
		for _, perm := range client.Permissions {
			if perm.PermissionIdentifier == parts[1] {
				clientHasPermission = true
				break
			}
		}

		if !clientHasPermission {
			return customerrors.NewValidationError("invalid_scope", fmt.Sprintf("Permission to access scope '%v' is not granted to the client.", scopeStr))
		}
	}
	return nil
}

func (val *TokenValidator) ParseTokenResponse(ctx context.Context, tokenResponse *dtos.TokenResponse) (*dtos.JwtInfo, error) {

	keyPair, err := val.database.GetCurrentSigningKey()
	if err != nil {
		return nil, err
	}

	pubKey, err := jwt.ParseRSAPublicKeyFromPEM(keyPair.PublicKeyPEM)
	if err != nil {
		return nil, err
	}

	result := &dtos.JwtInfo{
		TokenResponse: *tokenResponse,
	}

	if len(tokenResponse.AccessToken) > 0 {
		claimsAccessToken := jwt.MapClaims{}
		result.AccessToken = &dtos.JwtToken{
			TokenBase64: tokenResponse.AccessToken,
		}

		token, err := jwt.ParseWithClaims(tokenResponse.AccessToken, claimsAccessToken, func(token *jwt.Token) (interface{}, error) {
			return pubKey, nil
		})
		if err != nil {
			return nil, err
		}

		result.AccessToken.SignatureIsValid = token.Valid
		exp := claimsAccessToken["exp"].(float64)
		expirationTime := time.Unix(int64(exp), 0).UTC()
		currentTime := time.Now().UTC()
		if currentTime.After(expirationTime) {
			result.AccessToken.IsExpired = true
		} else {
			result.AccessToken.Claims = claimsAccessToken
		}
	}

	if len(tokenResponse.IdToken) > 0 {
		claimsIdToken := jwt.MapClaims{}
		result.IdToken = &dtos.JwtToken{
			TokenBase64: tokenResponse.IdToken,
		}

		token, err := jwt.ParseWithClaims(tokenResponse.IdToken, claimsIdToken, func(token *jwt.Token) (interface{}, error) {
			return pubKey, nil
		})
		if err != nil {
			return nil, err
		}

		result.IdToken.SignatureIsValid = token.Valid
		exp := claimsIdToken["exp"].(float64)
		expirationTime := time.Unix(int64(exp), 0).UTC()
		currentTime := time.Now().UTC()
		if currentTime.After(expirationTime) {
			result.IdToken.IsExpired = true
		} else {
			result.IdToken.Claims = claimsIdToken
		}
	}

	if len(tokenResponse.RefreshToken) > 0 {
		claimsRefreshToken := jwt.MapClaims{}
		result.RefreshToken = &dtos.JwtToken{
			TokenBase64: tokenResponse.RefreshToken,
		}

		token, err := jwt.ParseWithClaims(tokenResponse.RefreshToken, claimsRefreshToken, func(token *jwt.Token) (interface{}, error) {
			return pubKey, nil
		})
		if err != nil {
			return nil, err
		}

		result.RefreshToken.SignatureIsValid = token.Valid
		exp := claimsRefreshToken["exp"].(float64)
		expirationTime := time.Unix(int64(exp), 0).UTC()
		currentTime := time.Now().UTC()
		if currentTime.After(expirationTime) {
			result.RefreshToken.IsExpired = true
		} else {
			result.RefreshToken.Claims = claimsRefreshToken
		}
	}

	return result, nil
}

func (val *TokenValidator) ParseRefreshToken(ctx context.Context, refreshToken string) (*dtos.JwtToken, error) {
	keyPair, err := val.database.GetCurrentSigningKey()
	if err != nil {
		return nil, err
	}

	pubKey, err := jwt.ParseRSAPublicKeyFromPEM(keyPair.PublicKeyPEM)
	if err != nil {
		return nil, err
	}

	result := &dtos.JwtToken{
		TokenBase64: refreshToken,
	}

	if len(refreshToken) > 0 {
		claimsRefreshToken := jwt.MapClaims{}

		token, err := jwt.ParseWithClaims(refreshToken, claimsRefreshToken, func(token *jwt.Token) (interface{}, error) {
			return pubKey, nil
		})
		if err != nil {
			return nil, err
		}

		result.SignatureIsValid = token.Valid
		exp := claimsRefreshToken["exp"].(float64)
		expirationTime := time.Unix(int64(exp), 0).UTC()
		currentTime := time.Now().UTC()
		if currentTime.After(expirationTime) {
			result.IsExpired = true
		} else {
			result.Claims = claimsRefreshToken
		}
	}

	return result, nil
}
