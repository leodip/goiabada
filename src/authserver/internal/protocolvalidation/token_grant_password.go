package protocolvalidation

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/permissions"
	"github.com/leodip/goiabada/core/customerrors"
)

// ROPCNotAuthorizedErrorMsg is the refusal for a client that may not use the resource owner
// password credentials grant. Two places emit it: the password grant below, which refuses a
// new login, and the token handler's refresh responder, which answers with it when the refresh
// redemption refuses a token ROPC issued. They have to say the same thing, because an operator turning the switch off is
// doing one act with two consequences, and a reader told two different stories about it will
// think only new logins stopped. Exported and package-level because the second user lives in
// the authserver module (#250).
const ROPCNotAuthorizedErrorMsg = "The client is not authorized to use the resource owner password credentials grant type. " +
	"To enable it, go to the client's settings in the admin console under 'OAuth2 flows', " +
	"or enable it globally in 'Settings > General'."

// PasswordGrant is a validated resource owner password credentials request: the client, the user
// whose password was just checked, and the scope granted to them.
type PasswordGrant struct {
	Client *models.Client
	User   *models.User
	Scope  string
}

func (*PasswordGrant) GrantType() oidc.GrantType { return oidc.GrantTypePassword }

// validatePasswordGrant validates a resource owner password credentials request (RFC 6749
// section 4.3.2) for a client ValidateTokenRequest has already found and found enabled.
func (val *TokenValidator) validatePasswordGrant(ctx context.Context, settings *models.Settings,
	client *models.Client, input *ValidateTokenRequestInput) (*PasswordGrant, error) {
	// RFC 6749 Section 4.3 - Resource Owner Password Credentials Grant
	// SECURITY NOTE: ROPC is deprecated in OAuth 2.1 due to credential exposure risks.

	// Check if ROPC is enabled for this client
	ropcEnabled := client.IsResourceOwnerPasswordCredentialsEnabled(settings.ResourceOwnerPasswordCredentialsEnabled)
	if !ropcEnabled {
		return nil, customerrors.NewErrorDetailWithHttpStatusCode("unauthorized_client",
			ROPCNotAuthorizedErrorMsg, http.StatusBadRequest)
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
	if err := val.authenticateClient(client, input.ClientSecret); err != nil {
		return nil, err
	}

	// Validate resource owner credentials.
	//
	// Normalized to exactly what the rate limiter's account key does, and to what every
	// write path stores, for the reasons at /auth/pwd: the limiter and the account it
	// protects must agree about which account a request is, and mysql and mssql compare
	// email case-insensitively while postgres and sqlite do not (#219).
	//
	// Deliberately not applied to the missing-username check above, which stays on the
	// raw value: normalizing first would turn a whitespace-only username from
	// invalid_grant into invalid_request, and only invalid_grant is a guess against an
	// account.
	username := strings.ToLower(strings.TrimSpace(input.Username))
	user, err := val.database.GetUserByEmail(ctx, nil, username)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
			"Invalid resource owner credentials.", http.StatusBadRequest)
	}

	if !passwordhash.Verify(user.PasswordHash, input.Password) {
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
	err = val.database.UserLoadPermissions(ctx, nil, user)
	if err != nil {
		return nil, err
	}

	err = val.database.UserLoadGroups(ctx, nil, user)
	if err != nil {
		return nil, err
	}

	validatedScope, err := val.validateROPCScopes(ctx, input.Scope, user)
	if err != nil {
		return nil, err
	}

	return &PasswordGrant{
		Client: client,
		User:   user,
		Scope:  validatedScope,
	}, nil
}

// validateROPCScopes validates scopes for Resource Owner Password Credentials grant.
// It follows the authorization code flow pattern for scope validation.
// OIDC scopes (openid, profile, email, etc.) and offline_access are allowed.
// Resource scopes (resource:permission) require the user to have the permission.
// Note: consent_required is BYPASSED for ROPC - user providing credentials = implicit consent.
func (val *TokenValidator) validateROPCScopes(ctx context.Context, scope string, user *models.User) (string, error) {
	if len(scope) == 0 {
		// Default to openid scope if none provided
		return "openid", nil
	}

	validatedScopes := []string{}

	for _, scopeStr := range oidc.SplitScope(scope) {
		// Allow OIDC scopes and offline_access
		if oidc.IsClaimScope(scopeStr) || oidc.IsOfflineAccessScope(scopeStr) {
			validatedScopes = append(validatedScopes, scopeStr)
			continue
		}

		// Resolve resource:permission against the database. The malformed-pair wording here is
		// this grant's own - it names the OIDC scopes, which the other two sites do not - so the
		// resolver answers with an outcome and each site writes its own message (#124).
		resolution, err := permissions.ResolveScope(ctx, val.database, scopeStr)
		if err != nil {
			return "", err
		}

		switch resolution.Outcome {
		case permissions.ScopeMalformed:
			return "", customerrors.NewErrorDetailWithHttpStatusCode("invalid_scope",
				fmt.Sprintf("Invalid scope format: '%v'. Scopes must be either OIDC scopes (openid, profile, email, address, phone, groups, attributes) or resource-identifier:permission-identifier format.", scopeStr),
				http.StatusBadRequest)
		case permissions.ScopeResourceUnknown:
			return "", customerrors.NewErrorDetailWithHttpStatusCode("invalid_scope",
				fmt.Sprintf("Invalid scope: '%v'. Could not find a resource with identifier '%v'.", scopeStr, resolution.ResourceIdentifier),
				http.StatusBadRequest)
		case permissions.ScopePermissionUnknown:
			return "", customerrors.NewErrorDetailWithHttpStatusCode("invalid_scope",
				fmt.Sprintf("Scope '%v' is not recognized. The resource identified by '%v' doesn't grant the '%v' permission.", scopeStr, resolution.ResourceIdentifier, resolution.PermissionIdentifier),
				http.StatusBadRequest)
		}

		// Check if user has this permission (directly or via groups)
		userHasPermission, err := val.permissionChecker.UserHasScopePermission(ctx, user.Id, scopeStr)
		if err != nil {
			return "", err
		}
		if !userHasPermission {
			return "", customerrors.NewErrorDetailWithHttpStatusCode("invalid_scope",
				fmt.Sprintf("The user does not have permission for scope '%v'.", scopeStr),
				http.StatusBadRequest)
		}

		// An explicitly requested resource scope is retained in the grant.
		validatedScopes = append(validatedScopes, scopeStr)
	}

	if len(validatedScopes) == 0 {
		return "openid", nil
	}

	return strings.Join(validatedScopes, " "), nil
}
