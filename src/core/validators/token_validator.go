package validators

import (
	"context"
	"crypto/rsa"
	"crypto/subtle"
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
	// UsedBasicAuth indicates if the client used HTTP Basic Authentication (Authorization header).
	// Per RFC 6749 Section 5.2, when client auth fails and Basic auth was used, the server
	// MUST respond with 401 and include WWW-Authenticate header.
	UsedBasicAuth bool
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

// invalidGenerationMessage is returned when a refresh token's authentication generation
// no longer matches its user's. Deliberately identical in shape to the other invalid_grant
// refusals: a client cannot act on the distinction, and spelling out that a credential
// change superseded the grant would tell an attacker holding a stolen token exactly what
// happened (#106).
const invalidGenerationMessage = "The refresh token is invalid because it was superseded."

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

		// If the code was not found among unused codes, retry against the full
		// code set to detect reuse. We can only act on a reuse hit after the
		// request authenticates against the used code (client_id + redirect_uri
		// + client_secret/PKCE); otherwise an attacker could force-revoke a
		// victim's session by replaying observed codes with wrong credentials.
		wasReused := false
		if codeEntity == nil {
			codeEntity, err = val.database.GetCodeByCodeHash(nil, codeHash, true)
			if err != nil {
				return nil, err
			}
			if codeEntity == nil {
				return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant", "Code is invalid.",
					http.StatusBadRequest)
			}
			wasReused = true
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

		// User-state and code-age checks only apply to first-use exchanges.
		// On reuse, those failures would mask the revocation signal we want
		// to deliver after the auth gate (client_secret + PKCE) passes below.
		if !wasReused {
			if !codeEntity.User.Enabled {
				return nil, customerrors.ErrUserDisabled
			}

			// The generation boundary (#106). A code carries the generation its ceremony
			// authenticated under, so a code issued before a credential change no longer
			// matches and cannot be redeemed. That covers both an outstanding code and a
			// ceremony that straddled the change, neither of which the revocation sweep can
			// reach: the sweep can only act on rows that exist when it runs.
			//
			// Inside the !wasReused guard for the same reason as the checks around it: on
			// reuse the revocation signal must not be masked by a different rejection.
			if codeEntity.AuthStateGeneration != codeEntity.User.AuthStateGeneration {
				return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
					"Code is invalid.", http.StatusBadRequest)
			}

			const authCodeExpirationInSeconds = 60
			if time.Now().UTC().After(codeEntity.CreatedAt.Time.Add(time.Second * time.Duration(authCodeExpirationInSeconds))) {
				return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
					"Code has expired.", http.StatusBadRequest)
			}
		}

		if !client.IsPublic {
			if len(input.ClientSecret) == 0 {
				// RFC 6749 Section 5.2: invalid_client for missing credentials
				if input.UsedBasicAuth {
					return nil, customerrors.NewErrorDetailWithHttpStatusCodeAndWWWAuthenticate("invalid_client",
						clientSecretRequiredErrorMsg, http.StatusUnauthorized, "Basic")
				}
				return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_client",
					clientSecretRequiredErrorMsg, http.StatusUnauthorized)
			}

			clientSecretDecrypted, err := encryption.DecryptData(client.ClientSecretEncrypted)
			if err != nil {
				return nil, err
			}
			if subtle.ConstantTimeCompare([]byte(clientSecretDecrypted), []byte(input.ClientSecret)) != 1 {
				// RFC 6749 Section 5.2: invalid_client for failed authentication
				if input.UsedBasicAuth {
					return nil, customerrors.NewErrorDetailWithHttpStatusCodeAndWWWAuthenticate("invalid_client",
						"Client authentication failed. Please review your client_secret.",
						http.StatusUnauthorized, "Basic")
				}
				return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_client",
					"Client authentication failed. Please review your client_secret.",
					http.StatusUnauthorized)
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

		if wasReused {
			return nil, &customerrors.AuthCodeReusedError{
				Detail: customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant", "Code is invalid.",
					http.StatusBadRequest),
				Code: codeEntity,
			}
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
			// RFC 6749 Section 5.2: invalid_client for missing credentials
			if input.UsedBasicAuth {
				return nil, customerrors.NewErrorDetailWithHttpStatusCodeAndWWWAuthenticate("invalid_client",
					clientSecretRequiredErrorMsg, http.StatusUnauthorized, "Basic")
			}
			return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_client",
				clientSecretRequiredErrorMsg, http.StatusUnauthorized)
		}

		clientSecretDescrypted, err := encryption.DecryptData(client.ClientSecretEncrypted)
		if err != nil {
			return nil, err
		}
		if subtle.ConstantTimeCompare([]byte(clientSecretDescrypted), []byte(input.ClientSecret)) != 1 {
			// RFC 6749 Section 5.2: invalid_client for failed authentication
			if input.UsedBasicAuth {
				return nil, customerrors.NewErrorDetailWithHttpStatusCodeAndWWWAuthenticate("invalid_client",
					"Client authentication failed.", http.StatusUnauthorized, "Basic")
			}
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
			// No scope was passed, so grant every permission the client holds.
			//
			// perm.Resource is already populated: PermissionsLoadResources ran immediately above.
			// This used to call GetResourceByResourceIdentifier(nil, perm.Resource.ResourceIdentifier)
			// and then use res.ResourceIdentifier, the very string it had just passed in, which was
			// one database round-trip per granted permission per request for a value already in hand.
			//
			// No empty-identifier guard on perm.Resource, deliberately, and NOT because the state is
			// unreachable. Resource is a value field, so there is no nil to check; a map miss in
			// PermissionsLoadResources silently leaves it zero-valued, with ResourceIdentifier == "".
			//
			// That state IS reachable. The two loads above are separate non-transactional queries,
			// so a resource deleted between them leaves this loop holding permission rows that the
			// database has already cascade-deleted, and GetResourcesByIds finds nothing for them.
			// ON DELETE CASCADE does not help: the cascade happens in the database while these rows
			// are already in memory.
			//
			// No guard is needed because the path fails closed. A zero-valued resource yields the
			// scope ":<permission>", which validateClientCredentialsScopes below rejects with
			// invalid_scope, "Could not find a resource with identifier ''". Verified by executing
			// that fixture: a 400 naming the problem, which is the right outcome for a request whose
			// grant vanished mid-flight.
			//
			// The old code did NOT fail closed here: it passed that empty identifier to
			// GetResourceByResourceIdentifier, got nil back, and dereferenced it. Also verified by
			// execution, which panics with a nil pointer dereference. Removing the round-trip removed
			// a latent panic in that race, not merely a wasted query.
			//
			// Note the scopes built here are resource-qualified, which matters more since the
			// ownership check became resource-scoped: a client holding "read" on two resources gets
			// both "a:read" and "b:read", not one of them twice.
			for _, perm := range client.Permissions {
				input.Scope = input.Scope + " " + perm.Resource.ResourceIdentifier + ":" + perm.PermissionIdentifier
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
				// RFC 6749 Section 5.2: invalid_client for missing credentials
				if input.UsedBasicAuth {
					return nil, customerrors.NewErrorDetailWithHttpStatusCodeAndWWWAuthenticate("invalid_client",
						clientSecretRequiredErrorMsg, http.StatusUnauthorized, "Basic")
				}
				return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_client",
					clientSecretRequiredErrorMsg, http.StatusUnauthorized)
			}

			clientSecretDecrypted, err := encryption.DecryptData(client.ClientSecretEncrypted)
			if err != nil {
				return nil, err
			}
			if subtle.ConstantTimeCompare([]byte(clientSecretDecrypted), []byte(input.ClientSecret)) != 1 {
				// RFC 6749 Section 5.2: invalid_client for failed authentication
				if input.UsedBasicAuth {
					return nil, customerrors.NewErrorDetailWithHttpStatusCodeAndWWWAuthenticate("invalid_client",
						"Client authentication failed. Please review your client_secret.",
						http.StatusUnauthorized, "Basic")
				}
				return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_client",
					"Client authentication failed. Please review your client_secret.",
					http.StatusUnauthorized)
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

			// Read from the TOKEN row, not from any joined record (#106 decision 11(a)).
			if refreshToken.AuthStateGeneration != refreshToken.User.AuthStateGeneration {
				return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
					invalidGenerationMessage, http.StatusBadRequest)
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

			// refreshToken.AuthStateGeneration, NOT refreshToken.Code.AuthStateGeneration.
			// The two legitimately differ: a self-service password change promotes the
			// preserved session's tokens to the new generation while their codes stay on the
			// old one, so reading the code here would reject exactly the tokens decision 4
			// exists to keep working (#106 decision 11(a)).
			if refreshToken.AuthStateGeneration != refreshToken.Code.User.AuthStateGeneration {
				return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
					invalidGenerationMessage, http.StatusBadRequest)
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

		// Both values are loop-invariant, so compute them once rather than per scope. They gate
		// the injected-userinfo exception in the permission re-check below; see the comment there
		// for why the OIDC-scope condition is required rather than skipping the scope outright.
		//
		// Derived from tokenScope, the ORIGINAL grant, not from `scopes`, which is what this
		// request asked for. The two differ only when the caller down-scopes, and then the choice
		// decides one case: a legacy grant of `openid authserver:userinfo` refreshed with
		// `scope=authserver:userinfo`. Using tokenScope sees the openid and treats the userinfo
		// scope as injected, so the permission check is skipped and the refresh succeeds. Using
		// `scopes` would see no OIDC scope and apply the check, rejecting it.
		//
		// tokenScope is right because the capability is already unconditional for this grant: a
		// refresh of the full scope injects authserver:userinfo into the new access token whatever
		// the user holds, so refusing the narrower request would deny a subset of what the same
		// token can have for the asking. Whether the scope was injected is a property of the
		// grant, and the grant is tokenScope.
		//
		// Pinned by the "legacy grant down-scoped to bare userinfo" case in
		// TestValidateTokenRequest_RefreshToken_ROPC_InjectedUserInfoScope, which is the only test
		// that can tell the two sources apart: in every other case `scopes` == tokenScope.
		userInfoScope := fmt.Sprintf("%v:%v", constants.AuthServerResourceIdentifier,
			constants.UserinfoPermissionIdentifier)
		storedScopeHasOidcScope := false
		for _, storedScopeStr := range strings.Split(tokenScope, " ") {
			if oidc.IsIdTokenScope(storedScopeStr) {
				storedScopeHasOidcScope = true
				break
			}
		}

		sub := refreshTokenInfo.GetStringClaim("sub")
		user, err := val.database.GetUserBySubject(nil, sub)
		if err != nil {
			return nil, err
		}

		// For ROPC tokens, skip consent check (ROPC bypasses consent - user providing credentials = implicit consent)
		// For auth code flow tokens, check consent if required. Both the lookup arguments and the consent
		// scope list are loop-invariant, so fetch and split the consent once here instead of on every
		// scope iteration.
		var scopesFromConsent []string
		consentCheckRequired := !isROPCToken && (client.ConsentRequired || refreshTokenType == "Offline")
		if consentCheckRequired {
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
			scopesFromConsent = strings.Split(consent.Scope, " ")
		}

		for _, inputScopeStr := range inputScopes {
			// check if user still consents to this scope
			if consentCheckRequired {
				consentScopeExists := false
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
			//
			// The injected userinfo scope is skipped: generateAccessTokenCore appends
			// authserver:userinfo to any token carrying an OIDC scope so the token can reach
			// /userinfo, so it is a server grant rather than a user permission and re-checking it
			// against the user's permissions is a category error. Before this, an ROPC refresh
			// token recording that appended scope could never be redeemed unless the user had
			// separately been granted the built-in permission.
			//
			// storedScopeHasOidcScope is what keeps this narrow, and it is load-bearing.
			// validateROPCScopes has no guard against requesting authserver:userinfo explicitly
			// (unlike the authorize endpoint), so the scope can also be a genuine user grant. It
			// is only ever injected when an OIDC scope is present, so gating on that reproduces
			// the injection condition and leaves an explicit grant that stands alone still
			// subject to the check, which is what keeps revoking that permission effective.
			//
			// Deliberately unfixable residual case: an explicit grant alongside an OIDC scope is
			// indistinguishable from an injected one, because the injection is idempotent. Such a
			// token skips the check, which costs nothing, since it carries an OIDC scope and would
			// therefore receive authserver:userinfo regardless of what the user holds.
			isInjectedUserInfoScope := storedScopeHasOidcScope && inputScopeStr == userInfoScope
			if !oidc.IsIdTokenScope(inputScopeStr) && !oidc.IsOfflineAccessScope(inputScopeStr) &&
				!isInjectedUserInfoScope {
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
				// RFC 6749 Section 5.2: invalid_client for missing credentials
				if input.UsedBasicAuth {
					return nil, customerrors.NewErrorDetailWithHttpStatusCodeAndWWWAuthenticate("invalid_client",
						clientSecretRequiredErrorMsg, http.StatusUnauthorized, "Basic")
				}
				return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_client",
					clientSecretRequiredErrorMsg, http.StatusUnauthorized)
			}

			clientSecretDecrypted, err := encryption.DecryptData(client.ClientSecretEncrypted)
			if err != nil {
				return nil, err
			}
			if subtle.ConstantTimeCompare([]byte(clientSecretDecrypted), []byte(input.ClientSecret)) != 1 {
				// RFC 6749 Section 5.2: invalid_client for failed authentication
				if input.UsedBasicAuth {
					return nil, customerrors.NewErrorDetailWithHttpStatusCodeAndWWWAuthenticate("invalid_client",
						"Client authentication failed.", http.StatusUnauthorized, "Basic")
				}
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

		// Resolve the requested permission ON THIS RESOURCE. `permissions` is already
		// narrowed to parts[0] by the query above, and (permission_identifier, resource_id)
		// is unique on every supported engine via idx_permission_identifier_resource, so at
		// most one row here can match.
		var requestedPermission *models.Permission
		for i := range permissions {
			if permissions[i].PermissionIdentifier == parts[1] {
				requestedPermission = &permissions[i]
				break
			}
		}

		if requestedPermission == nil {
			return customerrors.NewErrorDetailWithHttpStatusCode("invalid_scope",
				fmt.Sprintf("Scope '%v' is not recognized. The resource identified by '%v' doesn't grant the '%v' permission.", scopeStr, parts[0], parts[1]),
				http.StatusBadRequest)
		}

		// Compare the resource-scoped permission id, never the bare identifier.
		// client.Permissions is loaded by ClientLoadPermissions across EVERY resource, so a
		// bare identifier comparison here matched any permission the client held anywhere: a
		// client granted "billing-api:read" was handed "reports-api:read", and one granted
		// "<custom>:manage" was handed "authserver:manage" and with it the whole Admin
		// API (#104).
		clientHasPermission := false
		for _, perm := range client.Permissions {
			if perm.Id == requestedPermission.Id {
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

		// An explicitly requested resource scope is retained in the grant. Unlike the authorize
		// endpoint, this function has no guard against requesting authserver:userinfo directly, so
		// a user who holds that permission can put it here deliberately rather than having it
		// injected. The refresh path relies on that distinction; see the injected-userinfo exception
		// in ValidateTokenRequest.
		validatedScopes = append(validatedScopes, scopeStr)
	}

	if len(validatedScopes) == 0 {
		return "openid", nil
	}

	return strings.Join(validatedScopes, " "), nil
}
