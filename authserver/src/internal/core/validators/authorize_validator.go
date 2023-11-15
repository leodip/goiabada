package core

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"slices"

	"github.com/leodip/goiabada/internal/core"
	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/data"
)

type AuthorizeValidator struct {
	database *data.Database
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

func NewAuthorizeValidator(database *data.Database) *AuthorizeValidator {
	return &AuthorizeValidator{
		database: database,
	}
}

func (val *AuthorizeValidator) ValidateScopes(ctx context.Context, scope string) error {

	if len(strings.TrimSpace(scope)) == 0 {
		return customerrors.NewValidationError("invalid_scope", "The 'scope' parameter is missing. Ensure to include one or more scopes, separated by spaces. Scopes can be an OpenID Connect scope, a resource:permission scope, or a combination of both.")
	}

	// remove duplicated spaces
	space := regexp.MustCompile(`\s+`)
	scope = space.ReplaceAllString(scope, " ")

	scopes := strings.Split(scope, " ")

	for _, scopeStr := range scopes {

		if core.IsIdTokenScope(scopeStr) {
			continue
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
	}
	return nil
}

func (val *AuthorizeValidator) ValidateClientAndRedirectURI(ctx context.Context, input *ValidateClientAndRedirectURIInput) error {
	if len(input.ClientId) == 0 {
		return customerrors.NewValidationError("", "The client_id parameter is missing.")
	}

	client, err := val.database.GetClientByClientIdentifier(input.ClientId)
	if err != nil {
		return err
	}
	if client == nil {
		return customerrors.NewValidationError("", "We couldn't find a client associated with the provided client_id.")
	}
	if !client.Enabled {
		return customerrors.NewValidationError("", "The client associated with the provided client_id is not enabled.")
	}

	if len(input.RedirectURI) == 0 {
		return customerrors.NewValidationError("", "The redirect_uri parameter is missing.")
	}

	clientHasRedirectURI := false
	for _, r := range client.RedirectURIs {
		if input.RedirectURI == r.URI {
			clientHasRedirectURI = true
		}
	}
	if !clientHasRedirectURI {
		return customerrors.NewValidationError("", "Invalid redirect_uri parameter. The client does not have this redirect uri configured.")
	}
	return nil
}

func (val *AuthorizeValidator) ValidateRequest(ctx context.Context, input *ValidateRequestInput) error {

	if input.ResponseType != "code" {
		return customerrors.NewValidationError("invalid_request", "Ensure response_type is set to 'code' as it's the only supported value.")
	}

	if input.CodeChallengeMethod != "S256" {
		return customerrors.NewValidationError("invalid_request", "Ensure code_challenge_method is set to 'S256' as it's the only supported value.")
	}

	if len(input.CodeChallenge) < 43 || len(input.CodeChallenge) > 128 {
		return customerrors.NewValidationError("invalid_request", "The code_challenge parameter is either missing or incorrect. It should be 43 to 128 characters long.")
	}

	if len(input.ResponseMode) > 0 {
		if !slices.Contains([]string{"query", "fragment", "form_post"}, input.ResponseMode) {
			return customerrors.NewValidationError("invalid_request", "Please use 'query,' 'fragment,' or 'form_post' as the response_mode value.")
		}
	}
	return nil
}
