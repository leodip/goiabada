package validators

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/data"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/leodip/goiabada/internal/models"
	"github.com/leodip/goiabada/internal/oidc"
	"github.com/leodip/goiabada/internal/security"
)

type TokenValidator struct {
	database          data.Database
	tokenParser       *security.TokenParser
	permissionChecker *security.PermissionChecker
}

func NewTokenValidator(database data.Database, tokenParser *security.TokenParser,
	permissionChecker *security.PermissionChecker) *TokenValidator {
	return &TokenValidator{
		database:          database,
		tokenParser:       tokenParser,
		permissionChecker: permissionChecker,
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
	CodeEntity       *models.Code
	Client           *models.Client
	Scope            string
	RefreshToken     *models.RefreshToken
	RefreshTokenInfo *security.JwtToken
}

func (val *TokenValidator) ValidateTokenRequest(ctx context.Context, input *ValidateTokenRequestInput) (*ValidateTokenRequestResult, error) {

	settings := ctx.Value(constants.ContextKeySettings).(*models.Settings)

	if len(input.ClientId) == 0 {
		return nil, customerrors.NewValidationError("invalid_request", "Missing required client_id parameter.")
	}

	client, err := val.database.GetClientByClientIdentifier(nil, input.ClientId)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, customerrors.NewValidationError("invalid_request", "Client does not exist.")
	}
	if !client.Enabled {
		return nil, customerrors.NewValidationError("invalid_grant", "Client is disabled.")
	}

	clientSecretRequiredErrorMsg := "This client is configured as confidential (not public), which means a client_secret is required for authentication. Please provide a valid client_secret to proceed."

	switch input.GrantType {
	case "authorization_code":
		if !client.AuthorizationCodeEnabled {
			return nil, customerrors.NewValidationError("unauthorized_client", "The client associated with the provided client_id does not support authorization code flow.")
		}

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
		codeEntity, err := val.database.GetCodeByCodeHash(nil, codeHash, false)
		if err != nil {
			return nil, err
		}
		if codeEntity == nil {
			return nil, customerrors.NewValidationError("invalid_grant", "Code is invalid.")
		}

		if codeEntity.RedirectURI != input.RedirectURI {
			return nil, customerrors.NewValidationError("invalid_grant", "Invalid redirect_uri.")
		}

		err = val.database.CodeLoadClient(nil, codeEntity)
		if err != nil {
			return nil, err
		}

		err = val.database.CodeLoadUser(nil, codeEntity)
		if err != nil {
			return nil, err
		}

		if codeEntity.Client.ClientIdentifier != input.ClientId {
			return nil, customerrors.NewValidationError("invalid_grant", "The client_id provided does not match the client_id from code.")
		}

		if !codeEntity.User.Enabled {
			lib.LogAudit(constants.AuditUserDisabled, map[string]interface{}{
				"userId": codeEntity.User.Id,
			})
			return nil, customerrors.NewValidationError("invalid_grant", "The user account is disabled.")
		}

		const authCodeExpirationInSeconds = 60
		if time.Now().UTC().After(codeEntity.CreatedAt.Time.Add(time.Second * time.Duration(authCodeExpirationInSeconds))) {
			// code has expired
			codeEntity.Used = true
			err = val.database.UpdateCode(nil, codeEntity)
			if err != nil {
				return nil, err
			}
			return nil, customerrors.NewValidationError("invalid_grant", "Code has expired.")
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
		} else if len(input.ClientSecret) > 0 {
			return nil, customerrors.NewValidationError("invalid_request", "This client is configured as public, which means a client_secret is not required. To proceed, please remove the client_secret from your request.")
		}

		codeChallenge := lib.GeneratePKCECodeChallenge(input.CodeVerifier)
		if codeEntity.CodeChallenge != codeChallenge {
			return nil, customerrors.NewValidationError("invalid_grant", "Invalid code_verifier (PKCE).")
		}

		return &ValidateTokenRequestResult{
			CodeEntity: codeEntity,
		}, nil
	case "client_credentials":
		if !client.ClientCredentialsEnabled {
			return nil, customerrors.NewValidationError("unauthorized_client", "The client associated with the provided client_id does not support client credentials flow.")
		}

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

		err = val.database.ClientLoadPermissions(nil, client)
		if err != nil {
			return nil, err
		}

		err = val.database.PermissionsLoadResources(nil, client.Permissions)
		if err != nil {
			return nil, err
		}

		if len(input.Scope) == 0 {
			// no scope was passed, let's include all possible permissions
			for _, perm := range client.Permissions {
				res, err := val.database.GetResourceByResourceIdentifier(nil, perm.Resource.ResourceIdentifier)
				if err != nil {
					return nil, err
				}
				input.Scope = input.Scope + " " + res.ResourceIdentifier + ":" + perm.PermissionIdentifier
			}
			input.Scope = strings.TrimSpace(input.Scope)
		}

		err = val.validateClientCredentialsScopes(input.Scope, client)
		if err != nil {
			return nil, err
		}

		return &ValidateTokenRequestResult{
			Client: client,
			Scope:  input.Scope,
		}, nil
	case "refresh_token":
		if !client.AuthorizationCodeEnabled {
			return nil, customerrors.NewValidationError("unauthorized_client", "The client associated with the provided client_id does not support authorization code flow.")
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
		}

		if len(input.RefreshToken) == 0 {
			return nil, customerrors.NewValidationError("invalid_request", "Missing required refresh_token parameter.")
		}

		refreshTokenInfo, err := val.tokenParser.DecodeAndValidateTokenString(ctx, input.RefreshToken, nil)
		if err != nil {
			return nil, customerrors.NewValidationError("invalid_grant", "The refresh token is invalid ("+err.Error()+").")
		}

		jti := refreshTokenInfo.GetStringClaim("jti")
		if len(jti) == 0 {
			return nil, errors.WithStack(errors.New("the refresh token is invalid because it does not contain a jti claim"))
		}

		refreshToken, err := val.database.GetRefreshTokenByJti(nil, jti)
		if err != nil {
			return nil, err
		}
		if refreshToken == nil {
			return nil, errors.WithStack(errors.New("the refresh token is invalid because it does not exist in the database"))
		}

		err = val.database.RefreshTokenLoadCode(nil, refreshToken)
		if err != nil {
			return nil, err
		}

		err = val.database.CodeLoadUser(nil, &refreshToken.Code)
		if err != nil {
			return nil, err
		}

		if refreshToken.Code.ClientId != client.Id {
			return nil, customerrors.NewValidationError("invalid_request", "The refresh token is invalid because it does not belong to the client.")
		}

		if !refreshToken.Code.User.Enabled {
			return nil, customerrors.NewValidationError("invalid_grant", "The user account is disabled.")
		}

		refreshTokenType := refreshTokenInfo.GetStringClaim("typ")
		switch refreshTokenType {
		case "Refresh":
			// this is a normal refresh token
			// check the associated user session to see if it's still valid

			userSession, err := val.database.GetUserSessionBySessionIdentifier(nil, refreshToken.SessionIdentifier)
			if err != nil {
				return nil, err
			}
			const invalidTokenMessage = "The refresh token is invalid because the associated session has expired or been terminated."
			if userSession == nil {
				return nil, customerrors.NewValidationError("invalid_grant", invalidTokenMessage)
			}
			isSessionValid := userSession.IsValid(settings.UserSessionIdleTimeoutInSeconds, settings.UserSessionMaxLifetimeInSeconds, nil)
			if !isSessionValid {
				return nil, customerrors.NewValidationError("invalid_grant", invalidTokenMessage)
			}
		case "Offline":
			// this is an offline refresh token
			// its lifetime is not linked to the user session

			// check if it's still valid according to its max lifetime
			maxLifetime := refreshTokenInfo.GetTimeClaim("offline_access_max_lifetime")
			if maxLifetime.IsZero() {
				return nil, errors.WithStack(errors.New("the refresh token is invalid because it does not contain an offline_access_max_lifetime claim"))
			}
			if time.Now().UTC().After(maxLifetime) {
				return nil, customerrors.NewValidationError("invalid_grant", "The refresh token is invalid because it has expired (offline_access_max_lifetime).")
			}
		default:
			return nil, errors.WithStack(errors.New("the refresh token is invalid because it does not contain a valid typ claim"))
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

		sub := refreshTokenInfo.GetStringClaim("sub")
		user, err := val.database.GetUserBySubject(nil, sub)
		if err != nil {
			return nil, err
		}

		for _, inputScopeStr := range inputScopes {
			if client.ConsentRequired || refreshTokenType == "Offline" {
				// check if user still consents to this scope
				consent, err := val.database.GetConsentByUserIdAndClientId(nil, refreshToken.Code.UserId, refreshToken.Code.ClientId)
				if err != nil {
					return nil, err
				}
				if consent == nil {
					return nil,
						customerrors.NewValidationError("invalid_grant", "The user has either not given consent to this client or the previously granted consent has been revoked.")
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

			// check if user still has permission to the scope
			if !oidc.IsIdTokenScope(inputScopeStr) {
				userHasPermission, err := val.permissionChecker.UserHasScopePermission(user.Id, inputScopeStr)
				if err != nil {
					return nil, err
				}
				if !userHasPermission {
					return nil,
						customerrors.NewValidationError("invalid_grant",
							fmt.Sprintf("Scope '%v' is not recognized. The user does not have the '%v' permission.", inputScopeStr, inputScopeStr))
				}
			}
		}

		return &ValidateTokenRequestResult{
			CodeEntity:       &refreshToken.Code,
			Client:           client,
			RefreshToken:     refreshToken,
			RefreshTokenInfo: refreshTokenInfo,
		}, nil
	default:
		return nil, customerrors.NewValidationError("unsupported_grant_type", "Unsupported grant_type.")
	}
}

func (val *TokenValidator) validateClientCredentialsScopes(scope string, client *models.Client) error {

	if len(scope) == 0 {
		return nil
	}

	space := regexp.MustCompile(`\s+`)
	scope = space.ReplaceAllString(scope, " ")

	scopes := strings.Split(scope, " ")

	for _, scopeStr := range scopes {

		if oidc.IsIdTokenScope(scopeStr) {
			return customerrors.NewValidationError("invalid_request", fmt.Sprintf("Id token scopes (such as '%v') are not supported in the client credentials flow. Please use scopes in the format 'resource:permission' (e.g., 'backendA:read'). Multiple scopes can be specified, separated by spaces.", scopeStr))
		}

		parts := strings.Split(scopeStr, ":")
		if len(parts) != 2 {
			return customerrors.NewValidationError("invalid_scope", fmt.Sprintf("Invalid scope format: '%v'. Scopes must adhere to the resource-identifier:permission-identifier format. For instance: backend-service:create-product.", scopeStr))
		}

		res, err := val.database.GetResourceByResourceIdentifier(nil, parts[0])
		if err != nil {
			return err
		}
		if res == nil {
			return customerrors.NewValidationError("invalid_scope", fmt.Sprintf("Invalid scope: '%v'. Could not find a resource with identifier '%v'.", scopeStr, parts[0]))
		}

		permissions, err := val.database.GetPermissionsByResourceId(nil, res.Id)
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
