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
	DecodeAndValidateTokenString(token string, pubKey *rsa.PublicKey, withExpirationCheck bool) (*oauth.JwtToken, error)
}

type TokenValidator struct {
	database          data.Database
	tokenParser       TokenParser
	permissionChecker PermissionChecker
}

func NewTokenValidator(database data.Database, tokenParser TokenParser,
	permissionChecker PermissionChecker) *TokenValidator {
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
	// Username and Password are used for ROPC grant (RFC 6749 Section 4.3)
	Username string
	Password string
}

type ValidateTokenRequestResult struct {
	CodeEntity       *models.Code
	Client           *models.Client
	Scope            string
	RefreshToken     *models.RefreshToken
	RefreshTokenInfo *oauth.JwtToken
	// User is set for ROPC grant (RFC 6749 Section 4.3)
	User *models.User
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

		// Note: code_verifier validation is done later after loading the code entity
		// to check if PKCE was used during authorization

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
			return nil, customerrors.ErrUserDisabled
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

		// PKCE validation: if code_challenge was stored, code_verifier is required
		if codeEntity.CodeChallenge.Valid && codeEntity.CodeChallenge.String != "" {
			// PKCE was used during authorization - verify the code_verifier
			if len(input.CodeVerifier) == 0 {
				return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
					"Missing required code_verifier parameter.", http.StatusBadRequest)
			}

			codeChallenge := oauth.GeneratePKCECodeChallenge(input.CodeVerifier)
			if codeEntity.CodeChallenge.String != codeChallenge {
				return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
					"Invalid code_verifier (PKCE).", http.StatusBadRequest)
			}
		} else if len(input.CodeVerifier) > 0 {
			// PKCE was not used during authorization but code_verifier was provided
			// This is an error - strict mode
			return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
				"The code_verifier parameter was provided, but PKCE was not used during authorization.", http.StatusBadRequest)
		}
		// If PKCE was not used and code_verifier was not provided, that's fine

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

		refreshTokenInfo, err := val.tokenParser.DecodeAndValidateTokenString(input.RefreshToken, nil, true)
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

		// Determine if this is an auth code flow token (with CodeId) or ROPC token (with UserId/ClientId)
		isROPCToken := !refreshToken.CodeId.Valid

		var tokenClientId int64
		var tokenUserId int64
		var tokenScope string

		if isROPCToken {
			// ROPC refresh token - load User and Client directly from RefreshToken
			err = val.database.RefreshTokenLoadUser(nil, refreshToken)
			if err != nil {
				return nil, err
			}
			err = val.database.RefreshTokenLoadClient(nil, refreshToken)
			if err != nil {
				return nil, err
			}

			tokenClientId = refreshToken.ClientId.Int64
			tokenUserId = refreshToken.UserId.Int64
			tokenScope = refreshToken.Scope

			if !refreshToken.User.Enabled {
				return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
					"The user account is disabled.",
					http.StatusBadRequest)
			}
		} else {
			// Auth code flow refresh token - load Code and User from Code
			err = val.database.RefreshTokenLoadCode(nil, refreshToken)
			if err != nil {
				return nil, err
			}

			err = val.database.CodeLoadUser(nil, &refreshToken.Code)
			if err != nil {
				return nil, err
			}

			tokenClientId = refreshToken.Code.ClientId
			tokenUserId = refreshToken.Code.UserId
			tokenScope = refreshToken.Code.Scope

			if !refreshToken.Code.User.Enabled {
				return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
					"The user account is disabled.",
					http.StatusBadRequest)
			}
		}

		if tokenClientId != client.Id {
			return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
				"The refresh token is invalid because it does not belong to the client.", http.StatusBadRequest)
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

				scopesFromOriginal := strings.Split(tokenScope, " ")

				scopeExists := false
				for _, scopeFromOriginal := range scopesFromOriginal {
					if scopeFromOriginal == inputScopeStr {
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

		scopes := tokenScope
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
			// For ROPC tokens, skip consent check (ROPC bypasses consent - user providing credentials = implicit consent)
			// For auth code flow tokens, check consent if required
			if !isROPCToken && (client.ConsentRequired || refreshTokenType == "Offline") {
				// check if user still consents to this scope
				consent, err := val.database.GetConsentByUserIdAndClientId(nil, tokenUserId, tokenClientId)
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

		// For auth code flow tokens, return the Code entity
		// For ROPC tokens, CodeEntity will be nil (the handler will use RefreshToken.User and RefreshToken.Client)
		var codeEntity *models.Code
		if !isROPCToken {
			codeEntity = &refreshToken.Code
		}

		return &ValidateTokenRequestResult{
			CodeEntity:       codeEntity,
			Client:           client,
			RefreshToken:     refreshToken,
			RefreshTokenInfo: refreshTokenInfo,
		}, nil
	case "password":
		// RFC 6749 Section 4.3 - Resource Owner Password Credentials Grant
		// SECURITY NOTE: ROPC is deprecated in OAuth 2.1 due to credential exposure risks.

		// Check if ROPC is enabled for this client
		ropcEnabled := client.IsResourceOwnerPasswordCredentialsEnabled(settings.ResourceOwnerPasswordCredentialsEnabled)
		if !ropcEnabled {
			return nil, customerrors.NewErrorDetailWithHttpStatusCode("unauthorized_client",
				"The client is not authorized to use the resource owner password credentials grant type. "+
					"To enable it, go to the client's settings in the admin console under 'OAuth2 flows', "+
					"or enable it globally in 'Settings > General'.",
				http.StatusBadRequest)
		}

		// Validate required parameters (RFC 6749 Section 4.3.2)
		if len(input.Username) == 0 {
			return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
				"Missing required username parameter.", http.StatusBadRequest)
		}
		if len(input.Password) == 0 {
			return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
				"Missing required password parameter.", http.StatusBadRequest)
		}

		// Confidential clients MUST authenticate (RFC 6749 Section 4.3.2)
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
				return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_client",
					"Client authentication failed.", http.StatusUnauthorized)
			}
		}

		// Validate resource owner credentials
		user, err := val.database.GetUserByEmail(nil, input.Username)
		if err != nil {
			return nil, err
		}
		if user == nil {
			return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
				"Invalid resource owner credentials.", http.StatusBadRequest)
		}

		if !hashutil.VerifyPasswordHash(user.PasswordHash, input.Password) {
			return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
				"Invalid resource owner credentials.", http.StatusBadRequest)
		}

		if !user.Enabled {
			return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
				"The user account is disabled.", http.StatusBadRequest)
		}

		// Block ROPC for users with 2FA enabled
		// ROPC cannot securely support a second factor, so allowing it would bypass 2FA security
		if user.OTPEnabled {
			return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
				"Resource owner password credentials grant is not available for accounts with "+
					"two-factor authentication enabled. Please use the authorization code flow instead.",
				http.StatusBadRequest)
		}

		// Validate scopes - follow authorization code flow pattern
		// Note: consent_required is BYPASSED for ROPC (user providing credentials = implicit consent)
		err = val.database.UserLoadPermissions(nil, user)
		if err != nil {
			return nil, err
		}

		err = val.database.UserLoadGroups(nil, user)
		if err != nil {
			return nil, err
		}

		validatedScope, err := val.validateROPCScopes(input.Scope, user)
		if err != nil {
			return nil, err
		}

		return &ValidateTokenRequestResult{
			Client: client,
			User:   user,
			Scope:  validatedScope,
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

// validateROPCScopes validates scopes for Resource Owner Password Credentials grant.
// It follows the authorization code flow pattern for scope validation.
// OIDC scopes (openid, profile, email, etc.) and offline_access are allowed.
// Resource scopes (resource:permission) require the user to have the permission.
// Note: consent_required is BYPASSED for ROPC - user providing credentials = implicit consent.
func (val *TokenValidator) validateROPCScopes(scope string, user *models.User) (string, error) {
	if len(scope) == 0 {
		// Default to openid scope if none provided
		return "openid", nil
	}

	space := regexp.MustCompile(`\s+`)
	scope = space.ReplaceAllString(scope, " ")
	scopes := strings.Split(scope, " ")

	validatedScopes := []string{}

	for _, scopeStr := range scopes {
		scopeStr = strings.TrimSpace(scopeStr)
		if len(scopeStr) == 0 {
			continue
		}

		// Allow OIDC scopes and offline_access
		if oidc.IsIdTokenScope(scopeStr) || oidc.IsOfflineAccessScope(scopeStr) {
			validatedScopes = append(validatedScopes, scopeStr)
			continue
		}

		// Validate resource:permission format
		parts := strings.Split(scopeStr, ":")
		if len(parts) != 2 {
			return "", customerrors.NewErrorDetailWithHttpStatusCode("invalid_scope",
				fmt.Sprintf("Invalid scope format: '%v'. Scopes must be either OIDC scopes (openid, profile, email, address, phone, groups, attributes) or resource-identifier:permission-identifier format.", scopeStr),
				http.StatusBadRequest)
		}

		resourceIdentifier := parts[0]
		permissionIdentifier := parts[1]

		// Check if resource exists
		res, err := val.database.GetResourceByResourceIdentifier(nil, resourceIdentifier)
		if err != nil {
			return "", err
		}
		if res == nil {
			return "", customerrors.NewErrorDetailWithHttpStatusCode("invalid_scope",
				fmt.Sprintf("Invalid scope: '%v'. Could not find a resource with identifier '%v'.", scopeStr, resourceIdentifier),
				http.StatusBadRequest)
		}

		// Check if permission exists for this resource
		permissions, err := val.database.GetPermissionsByResourceId(nil, res.Id)
		if err != nil {
			return "", err
		}

		permissionExists := false
		for _, perm := range permissions {
			if perm.PermissionIdentifier == permissionIdentifier {
				permissionExists = true
				break
			}
		}

		if !permissionExists {
			return "", customerrors.NewErrorDetailWithHttpStatusCode("invalid_scope",
				fmt.Sprintf("Scope '%v' is not recognized. The resource identified by '%v' doesn't grant the '%v' permission.", scopeStr, resourceIdentifier, permissionIdentifier),
				http.StatusBadRequest)
		}

		// Check if user has this permission (directly or via groups)
		userHasPermission, err := val.permissionChecker.UserHasScopePermission(user.Id, scopeStr)
		if err != nil {
			return "", err
		}
		if !userHasPermission {
			return "", customerrors.NewErrorDetailWithHttpStatusCode("invalid_scope",
				fmt.Sprintf("The user does not have permission for scope '%v'.", scopeStr),
				http.StatusBadRequest)
		}

		validatedScopes = append(validatedScopes, scopeStr)
	}

	if len(validatedScopes) == 0 {
		return "openid", nil
	}

	return strings.Join(validatedScopes, " "), nil
}
