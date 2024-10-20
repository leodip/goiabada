package validators

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"slices"

	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/oidc"
)

type AuthorizeValidator struct {
	database data.Database
}

type ValidateClientAndRedirectURIInput struct {
	RequestId   string
	ClientId    string
	RedirectURI string
}

type ValidateRequestInput struct {
	ResponseType        string
	CodeChallengeMethod string
	CodeChallenge       string
	ResponseMode        string
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
	if !client.AuthorizationCodeEnabled {
		return customerrors.NewErrorDetail("", "Invalid client_id parameter. The client does not support the authorization code flow.")
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

	if input.ResponseType != "code" {
		return customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
			"Ensure response_type is set to 'code' as it's the only supported value.", http.StatusBadRequest)
	}

	if input.CodeChallengeMethod != "S256" {
		return customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
			"Ensure code_challenge_method is set to 'S256' as it's the only supported value.", http.StatusBadRequest)
	}

	if len(input.CodeChallenge) < 43 || len(input.CodeChallenge) > 128 {
		return customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
			"The code_challenge parameter is either missing or incorrect. It should be 43 to 128 characters long.",
			http.StatusBadRequest)
	}

	if len(input.ResponseMode) > 0 {
		if !slices.Contains([]string{"query", "fragment", "form_post"}, input.ResponseMode) {
			return customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
				"Invalid response_mode parameter. Supported values are: query, fragment, form_post.",
				http.StatusBadRequest)
		}
	}
	return nil
}
