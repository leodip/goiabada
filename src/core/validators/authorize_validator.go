package validators

import (
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/oidc"
)

type AuthorizeValidator struct {
	database data.Database
}

type ValidateClientAndRedirectURIInput struct {
	RequestId    string
	ClientId     string
	RedirectURI  string
	ResponseType string // Needed to determine if auth code or implicit flow is being requested
}

type ValidateRequestInput struct {
	ResponseType         string
	CodeChallengeMethod  string
	CodeChallenge        string
	ResponseMode         string
	PKCERequired         bool
	ImplicitGrantEnabled bool   // Whether implicit flow is allowed for this client
	Scope                string // Needed to validate openid requirement for id_token
	Nonce                string // Needed to validate nonce requirement for id_token
}

func NewAuthorizeValidator(database data.Database) *AuthorizeValidator {
	return &AuthorizeValidator{
		database: database,
	}
}

func (val *AuthorizeValidator) ValidateScopes(scope string) error {

	// trim leading and trailing whitespace
	scope = strings.TrimSpace(scope)

	if len(scope) == 0 {
		return customerrors.NewErrorDetailWithHttpStatusCode("invalid_scope",
			"The 'scope' parameter is missing. Ensure to include one or more scopes, separated by spaces. Scopes can be an OpenID Connect scope, a resource:permission scope, or a combination of both.",
			http.StatusBadRequest)
	}

	// remove duplicated spaces
	space := regexp.MustCompile(`\s+`)
	scope = space.ReplaceAllString(scope, " ")

	scopes := strings.Split(scope, " ")

	for _, scopeStr := range scopes {

		// these scopes don't need further validation
		if oidc.IsIdTokenScope(scopeStr) || oidc.IsOfflineAccessScope(scopeStr) {
			continue
		}

		userInfoScope := fmt.Sprintf("%v:%v", constants.AuthServerResourceIdentifier, constants.UserinfoPermissionIdentifier)
		if scopeStr == userInfoScope {
			return customerrors.NewErrorDetailWithHttpStatusCode("invalid_scope",
				fmt.Sprintf("The '%v' scope is automatically included in the access token when an OpenID Connect scope is present. There's no need to request it explicitly. Please remove it from your request.", userInfoScope),
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
				fmt.Sprintf("Scope '%v' is invalid. The resource identified by '%v' does not have a permission with identifier '%v'.", scopeStr, parts[0], parts[1]),
				http.StatusBadRequest)
		}
	}
	return nil
}

func (val *AuthorizeValidator) ValidateClientAndRedirectURI(input *ValidateClientAndRedirectURIInput) error {
	if len(input.ClientId) == 0 {
		return customerrors.NewErrorDetail("", "The client_id parameter is missing.")
	}

	client, err := val.database.GetClientByClientIdentifier(nil, input.ClientId)
	if err != nil {
		return err
	}
	if client == nil {
		return customerrors.NewErrorDetail("", "Invalid client_id parameter. The client does not exist.")
	}
	if !client.Enabled {
		return customerrors.NewErrorDetail("", "Invalid client_id parameter. The client is disabled.")
	}

	// Parse response_type to determine which flow is being requested
	// For implicit flow, we check later in ValidateRequest if it's actually enabled
	// Here we just need to verify the client supports at least one of the requested flows
	rtInfo := oauth.ParseResponseType(input.ResponseType)

	if rtInfo.IsImplicitFlow() {
		// For implicit flow, we don't require AuthorizationCodeEnabled
		// The actual implicit grant enablement is checked in ValidateRequest
		// We just need the client to be enabled (already checked above)
	} else {
		// Authorization code flow requires AuthorizationCodeEnabled
		if !client.AuthorizationCodeEnabled {
			return customerrors.NewErrorDetail("", "Invalid client_id parameter. The client does not support the authorization code flow.")
		}
	}

	if len(input.RedirectURI) == 0 {
		return customerrors.NewErrorDetail("", "The redirect_uri parameter is missing.")
	}

	err = val.database.ClientLoadRedirectURIs(nil, client)
	if err != nil {
		return err
	}

	clientHasRedirectURI := false
	for _, r := range client.RedirectURIs {
		if input.RedirectURI == r.URI {
			clientHasRedirectURI = true
		}
	}
	if !clientHasRedirectURI {
		return customerrors.NewErrorDetail("", "Invalid redirect_uri parameter. The client does not have this redirect URI registered.")
	}
	return nil
}

func (val *AuthorizeValidator) ValidateRequest(input *ValidateRequestInput) error {

	// Check for empty/missing response_type first
	if strings.TrimSpace(input.ResponseType) == "" {
		return customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
			"The response_type parameter is missing.", http.StatusBadRequest)
	}

	// Parse response_type (can be space-separated for OIDC, e.g., "id_token token")
	rtInfo := oauth.ParseResponseType(input.ResponseType)
	isImplicitFlow := rtInfo.IsImplicitFlow()

	// Validate response_type combinations
	// Supported: "code", "token", "id_token", "id_token token" (or "token id_token")
	// Count how many recognized response types are present
	responseTypeCount := 0
	if rtInfo.HasCode {
		responseTypeCount++
	}
	if rtInfo.HasToken {
		responseTypeCount++
	}
	if rtInfo.HasIdToken {
		responseTypeCount++
	}

	validResponseType := false
	switch responseTypeCount {
	case 1:
		validResponseType = true // Any single valid type is OK (code, token, or id_token)
	case 2:
		// Only "id_token token" or "token id_token" is valid for 2 tokens
		validResponseType = rtInfo.HasToken && rtInfo.HasIdToken && !rtInfo.HasCode
	}

	if !validResponseType {
		return customerrors.NewErrorDetailWithHttpStatusCode("unsupported_response_type",
			"The authorization server does not support this response_type. Supported values: code, token, id_token, id_token token.",
			http.StatusBadRequest)
	}

	// Check if implicit flow is authorized for this client
	if isImplicitFlow && !input.ImplicitGrantEnabled {
		return customerrors.NewErrorDetailWithHttpStatusCode("unauthorized_client",
			"The client is not authorized to use the implicit grant type. To enable it, go to the client's settings in the admin console under 'OAuth2 flows', or enable it globally in 'Settings > General'.",
			http.StatusBadRequest)
	}

	// OIDC: id_token requires openid scope
	if rtInfo.HasIdToken {
		scopes := strings.Fields(input.Scope)
		hasOpenid := false
		for _, s := range scopes {
			if s == "openid" {
				hasOpenid = true
				break
			}
		}
		if !hasOpenid {
			return customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
				"The 'openid' scope is required when requesting an id_token.",
				http.StatusBadRequest)
		}
	}

	// OIDC: nonce is REQUIRED for implicit flow with id_token (OIDC Core 3.2.2.1)
	if rtInfo.HasIdToken && isImplicitFlow && input.Nonce == "" {
		return customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
			"The 'nonce' parameter is required for implicit flow when requesting an id_token.",
			http.StatusBadRequest)
	}

	// PKCE validation only applies to authorization code flow
	if rtInfo.HasCode && !isImplicitFlow {
		// Check if PKCE parameters were provided
		pkceProvided := input.CodeChallengeMethod != "" || input.CodeChallenge != ""

		if input.PKCERequired {
			// PKCE is required - validate that it's provided and correct
			if input.CodeChallengeMethod != "S256" {
				return customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
					"PKCE is required. Ensure code_challenge_method is set to 'S256'.", http.StatusBadRequest)
			}

			if len(input.CodeChallenge) < 43 || len(input.CodeChallenge) > 128 {
				return customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
					"The code_challenge parameter is either missing or incorrect. It should be 43 to 128 characters long.",
					http.StatusBadRequest)
			}
		} else if pkceProvided {
			// PKCE is optional but was provided - validate format (strict mode)
			if input.CodeChallengeMethod != "S256" {
				return customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
					"Invalid code_challenge_method. Only 'S256' is supported.", http.StatusBadRequest)
			}

			if len(input.CodeChallenge) < 43 || len(input.CodeChallenge) > 128 {
				return customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
					"The code_challenge parameter is incorrect. It should be 43 to 128 characters long.",
					http.StatusBadRequest)
			}
		}
		// If PKCE is not required and not provided, that's fine - skip validation
	}

	// Response mode validation
	if len(input.ResponseMode) > 0 {
		if !slices.Contains([]string{"query", "fragment", "form_post"}, input.ResponseMode) {
			return customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
				"Invalid response_mode parameter. Supported values are: query, fragment, form_post.",
				http.StatusBadRequest)
		}
	}

	// Per RFC 6749 4.2.2 and OIDC Core 3.2.2.5: implicit grant tokens MUST be in fragment
	// If response_mode is explicitly set for implicit flow, it must be fragment
	if isImplicitFlow && len(input.ResponseMode) > 0 && input.ResponseMode != "fragment" {
		return customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
			"Implicit flow requires response_mode=fragment or no response_mode (fragment is the default for implicit flow).",
			http.StatusBadRequest)
	}

	return nil
}
