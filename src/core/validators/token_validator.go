package validators

import (
	"context"
	"crypto/rsa"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/oidc"
)

type PermissionChecker interface {
	UserHasScopePermission(userId int64, scope string) (bool, error)
}

type TokenParser interface {
	DecodeAndValidateTokenString(ctx context.Context, token string, pubKey *rsa.PublicKey) (*oauth.JwtToken, error)
}

type AuditLogger interface {
	Log(auditEvent string, details map[string]interface{})
}

type TokenValidator struct {
	database          data.Database
	tokenParser       TokenParser
	permissionChecker PermissionChecker
	auditLogger       AuditLogger
}

func NewTokenValidator(database data.Database, tokenParser TokenParser,
	permissionChecker PermissionChecker, auditLogger AuditLogger) *TokenValidator {
	return &TokenValidator{
		database:          database,
		tokenParser:       tokenParser,
		permissionChecker: permissionChecker,
		auditLogger:       auditLogger,
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
	RefreshTokenInfo *oauth.JwtToken
}

func (val *TokenValidator) ValidateTokenRequest(ctx context.Context, input *ValidateTokenRequestInput) (*ValidateTokenRequestResult, error) {

	settings := ctx.Value(constants.ContextKeySettings).(*models.Settings)

	if len(input.ClientId) == 0 {
		return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
			"Missing required client_id parameter.", http.StatusBadRequest)
	}

	client, err := val.database.GetClientByClientIdentifier(nil, input.ClientId)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
			"Client does not exist.", http.StatusBadRequest)
	}
	if !client.Enabled {
		return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant", "Client is disabled.",
			http.StatusBadRequest)
	}

	clientSecretRequiredErrorMsg := "This client is configured as confidential (not public), which means a client_secret is required for authentication. Please provide a valid client_secret to proceed."

	switch input.GrantType {
	case "authorization_code":
		if !client.AuthorizationCodeEnabled {
			return nil, customerrors.NewErrorDetailWithHttpStatusCode("unauthorized_client",
				"The client associated with the provided client_id does not support authorization code flow.",
				http.StatusBadRequest)
		}

		if len(input.Code) == 0 {
			return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
				"Missing required code parameter.", http.StatusBadRequest)
		}

		if len(input.RedirectURI) == 0 {
			return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
				"Missing required redirect_uri parameter.", http.StatusBadRequest)
		}

		if len(input.CodeVerifier) == 0 {
			return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
				"Missing required code_verifier parameter.", http.StatusBadRequest)
		}

		codeHash, err := hashutil.HashString(input.Code)
		if err != nil {
			return nil, err
		}
		codeEntity, err := val.database.GetCodeByCodeHash(nil, codeHash, false)
		if err != nil {
			return nil, err
		}
		if codeEntity == nil {
			return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant", "Code is invalid.",
				http.StatusBadRequest)
		}

		if codeEntity.RedirectURI != input.RedirectURI {
			return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant", "Invalid redirect_uri.",
				http.StatusBadRequest)
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
			return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
				"The client_id provided does not match the client_id from code.",
				http.StatusBadRequest)
		}

		if !codeEntity.User.Enabled {
			val.auditLogger.Log(constants.AuditUserDisabled, map[string]interface{}{
				"userId": codeEntity.User.Id,
			})
			return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
				"The user account is disabled.",
				http.StatusBadRequest)
		}

		const authCodeExpirationInSeconds = 60
		if time.Now().UTC().After(codeEntity.CreatedAt.Time.Add(time.Second * time.Duration(authCodeExpirationInSeconds))) {
			return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
				"Code has expired.", http.StatusBadRequest)
		}

		if !client.IsPublic {
			if len(input.ClientSecret) == 0 {
				return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
					clientSecretRequiredErrorMsg, http.StatusBadRequest)
			}

			clientSecretDecrypted, err := encryption.DecryptText(client.ClientSecretEncrypted, settings.AESEncryptionKey)
			if err != nil {
				return nil, err
			}
			if clientSecretDecrypted != input.ClientSecret {
				return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
					"Client authentication failed. Please review your client_secret.",
					http.StatusBadRequest)
			}
		} else if len(input.ClientSecret) > 0 {
			return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
				"This client is configured as public, which means a client_secret is not required. To proceed, please remove the client_secret from your request.",
				http.StatusBadRequest)
		}

		codeChallenge := oauth.GeneratePKCECodeChallenge(input.CodeVerifier)
		if codeEntity.CodeChallenge != codeChallenge {
			return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
				"Invalid code_verifier (PKCE).", http.StatusBadRequest)
		}

		return &ValidateTokenRequestResult{
			CodeEntity: codeEntity,
		}, nil
	case "client_credentials":
		if !client.ClientCredentialsEnabled {
			return nil, customerrors.NewErrorDetailWithHttpStatusCode("unauthorized_client",
				"The client associated with the provided client_id does not support client credentials flow.",
				http.StatusBadRequest)
		}

		if client.IsPublic {
			return nil, customerrors.NewErrorDetailWithHttpStatusCode("unauthorized_client",
				"A public client is not eligible for the client credentials flow. Please review the client configuration.",
				http.StatusBadRequest)
		}

		if len(input.ClientSecret) == 0 {
			return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_request", clientSecretRequiredErrorMsg,
				http.StatusBadRequest)
		}

		clientSecretDescrypted, err := encryption.DecryptText(client.ClientSecretEncrypted, settings.AESEncryptionKey)
		if err != nil {
			return nil, err
		}
		if clientSecretDescrypted != input.ClientSecret {
			return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_client",
				"Client authentication failed.", http.StatusUnauthorized)
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
			return nil, customerrors.NewErrorDetailWithHttpStatusCode("unauthorized_client",
				"The client associated with the provided client_id does not support authorization code flow.",
				http.StatusBadRequest)
		}

		if !client.IsPublic {
			if len(input.ClientSecret) == 0 {
				return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
					clientSecretRequiredErrorMsg, http.StatusBadRequest)
			}

			clientSecretDecrypted, err := encryption.DecryptText(client.ClientSecretEncrypted, settings.AESEncryptionKey)
			if err != nil {
				return nil, err
			}
			if clientSecretDecrypted != input.ClientSecret {
				return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
					"Client authentication failed. Please review your client_secret.",
					http.StatusBadRequest)
			}
		}

		if len(input.RefreshToken) == 0 {
			return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
				"Missing required refresh_token parameter.", http.StatusBadRequest)
		}

		refreshTokenInfo, err := val.tokenParser.DecodeAndValidateTokenString(ctx, input.RefreshToken, nil)
		if err != nil {
			return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
				"The refresh token is invalid ("+err.Error()+").",
				http.StatusBadRequest)
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
			return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
				"The refresh token is invalid because it does not belong to the client.", http.StatusBadRequest)
		}

		if !refreshToken.Code.User.Enabled {
			return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
				"The user account is disabled.",
				http.StatusBadRequest)
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
				return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant", invalidTokenMessage,
					http.StatusBadRequest)
			}
			isSessionValid := userSession.IsValid(settings.UserSessionIdleTimeoutInSeconds, settings.UserSessionMaxLifetimeInSeconds, nil)
			if !isSessionValid {
				return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant", invalidTokenMessage,
					http.StatusBadRequest)
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
				return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
					"The refresh token is invalid because it has expired (offline_access_max_lifetime).",
					http.StatusBadRequest)
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
					return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
						fmt.Sprintf("Scope '%v' is not recognized. The original access token does not grant the '%v' permission.", inputScopeStr, inputScopeStr),
						http.StatusBadRequest)
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
						customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
							"The user has either not given consent to this client or the previously granted consent has been revoked.",
							http.StatusBadRequest)
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
						customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
							fmt.Sprintf("Scope '%v' is not recognized. The user has not consented to the '%v' permission.", inputScopeStr, inputScopeStr),
							http.StatusBadRequest)
				}
			}

			// check if user still has permission to the scope
			if !oidc.IsIdTokenScope(inputScopeStr) && !oidc.IsOfflineAccessScope(inputScopeStr) {
				userHasPermission, err := val.permissionChecker.UserHasScopePermission(user.Id, inputScopeStr)
				if err != nil {
					return nil, err
				}
				if !userHasPermission {
					return nil,
						customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
							fmt.Sprintf("Scope '%v' is not recognized. The user does not have the '%v' permission.", inputScopeStr, inputScopeStr),
							http.StatusBadRequest)
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
		return nil, customerrors.NewErrorDetailWithHttpStatusCode("unsupported_grant_type", "Unsupported grant_type.",
			http.StatusBadRequest)
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

		if oidc.IsIdTokenScope(scopeStr) || oidc.IsOfflineAccessScope(scopeStr) {
			return customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
				fmt.Sprintf("Id token scopes (such as '%v') are not supported in the client credentials flow. Please use scopes in the format 'resource:permission' (e.g., 'backendA:read'). Multiple scopes can be specified, separated by spaces.", scopeStr),
				http.StatusBadRequest)
		}

		parts := strings.Split(scopeStr, ":")
		if len(parts) != 2 {
			return customerrors.NewErrorDetailWithHttpStatusCode("invalid_scope",
				fmt.Sprintf("Invalid scope format: '%v'. Scopes must adhere to the resource-identifier:permission-identifier format. For instance: backend-service:create-product.", scopeStr),
				http.StatusBadRequest)
		}

		res, err := val.database.GetResourceByResourceIdentifier(nil, parts[0])
		if err != nil {
			return err
		}
		if res == nil {
			return customerrors.NewErrorDetailWithHttpStatusCode("invalid_scope",
				fmt.Sprintf("Invalid scope: '%v'. Could not find a resource with identifier '%v'.", scopeStr, parts[0]),
				http.StatusBadRequest)
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
			return customerrors.NewErrorDetailWithHttpStatusCode("invalid_scope",
				fmt.Sprintf("Scope '%v' is not recognized. The resource identified by '%v' doesn't grant the '%v' permission.", scopeStr, parts[0], parts[1]),
				http.StatusBadRequest)
		}

		clientHasPermission := false
		for _, perm := range client.Permissions {
			if perm.PermissionIdentifier == parts[1] {
				clientHasPermission = true
				break
			}
		}

		if !clientHasPermission {
			return customerrors.NewErrorDetailWithHttpStatusCode("invalid_scope",
				fmt.Sprintf("Permission to access scope '%v' is not granted to the client.", scopeStr),
				http.StatusBadRequest)
		}
	}
	return nil
}
