package core

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/leodip/goiabada/internal/core"
	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/entities"
	"golang.org/x/exp/slices"
)

type AuthorizeValidator struct {
	database core.Database
}

type ValidateClientAndRedirectUriInput struct {
	RequestId   string
	ClientId    string
	RedirectUri string
}

type ValidateRequestInput struct {
	ResponseType        string
	CodeChallengeMethod string
	CodeChallenge       string
	ResponseMode        string
}

func NewAuthorizeValidator(database core.Database) *AuthorizeValidator {
	return &AuthorizeValidator{
		database: database,
	}
}

func (val *AuthorizeValidator) ValidateScopes(ctx context.Context, scope string, user *entities.User) error {

	requestId := middleware.GetReqID(ctx)

	if len(strings.TrimSpace(scope)) == 0 {
		return nil
	}

	// remove duplicated spaces
	space := regexp.MustCompile(`\s+`)
	scope = space.ReplaceAllString(scope, " ")

	scopes := strings.Split(scope, " ")

	for _, scopeStr := range scopes {

		if core.IsOIDCScope(scopeStr) {
			continue
		}

		if scopeStr == "roles" {
			continue
		}

		parts := strings.Split(scopeStr, ":")
		if len(parts) != 2 {
			err := customerrors.NewAppError(nil, "invalid_scope", fmt.Sprintf("Invalid scope format: '%v'. Scopes must adhere to the resource-identifier:permission-identifier format. For instance: backend-service:create-product.", scopeStr), http.StatusBadRequest)
			err.UseRedirectUri = true
			return err
		}

		res, err := val.database.GetResourceByResourceIdentifier(parts[0])
		if err != nil {
			err := customerrors.NewInternalServerError(err, requestId)
			err.UseRedirectUri = true
			return err
		}
		if res == nil {
			err := customerrors.NewAppError(nil, "invalid_scope", fmt.Sprintf("Invalid scope: '%v'. Could not find a resource with identifier '%v'.", scopeStr, parts[0]), http.StatusBadRequest)
			err.UseRedirectUri = true
			return err
		}

		permissions, err := val.database.GetResourcePermissions(res.ID)
		if err != nil {
			err := customerrors.NewInternalServerError(err, requestId)
			err.UseRedirectUri = true
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
			err := customerrors.NewAppError(nil, "invalid_scope", fmt.Sprintf("Scope '%v' is not recognized. The resource identified by '%v' doesn't grant the '%v' permission.", scopeStr, parts[0], parts[1]), http.StatusBadRequest)
			err.UseRedirectUri = true
			return err
		}

		if user != nil {

			userHasPermission := false
			for _, perm := range user.Permissions {
				if perm.PermissionIdentifier == parts[1] {
					userHasPermission = true
					break
				}
			}

			if !userHasPermission {
				err := customerrors.NewAppError(nil, "invalid_scope", fmt.Sprintf("Permission to access scope '%v' is not granted to the user.", scopeStr), http.StatusBadRequest)
				err.UseRedirectUri = true
				return err
			}
		}
	}
	return nil
}

func (val *AuthorizeValidator) ValidateClientAndRedirectUri(ctx context.Context, input *ValidateClientAndRedirectUriInput) error {
	if len(input.ClientId) == 0 {
		return customerrors.NewAppError(nil, "", "The client_id parameter is missing.", http.StatusBadRequest)
	}

	client, err := val.database.GetClientByClientIdentifier(input.ClientId)
	if err != nil {
		return customerrors.NewInternalServerError(err, input.RequestId)
	}
	if client == nil {
		return customerrors.NewAppError(nil, "", "We couldn't find a client associated with the provided client_id.", http.StatusBadRequest)
	}
	if !client.Enabled {
		return customerrors.NewAppError(nil, "", "The client associated with the provided client_id is not enabled.", http.StatusBadRequest)
	}

	if len(input.RedirectUri) == 0 {
		return customerrors.NewAppError(nil, "", "The redirect_uri parameter is missing.", http.StatusBadRequest)
	}

	clientHasRedirectUri := false
	for _, r := range client.RedirectUris {
		if input.RedirectUri == r.Uri {
			clientHasRedirectUri = true
		}
	}
	if !clientHasRedirectUri {
		return customerrors.NewAppError(nil, "", "Invalid redirect_uri parameter. The client does not have this redirect uri configured.", http.StatusBadRequest)
	}
	return nil
}

func (val *AuthorizeValidator) ValidateRequest(ctx context.Context, input *ValidateRequestInput) error {

	if input.ResponseType != "code" {
		err := customerrors.NewAppError(nil, "invalid_request", "Ensure response_type is set to 'code' as it's the only supported value.", http.StatusBadRequest)
		err.UseRedirectUri = true
		return err
	}

	if input.CodeChallengeMethod != "S256" {
		err := customerrors.NewAppError(nil, "invalid_request", "Ensure code_challenge_method is set to 'S256' as it's the only supported value.", http.StatusBadRequest)
		err.UseRedirectUri = true
		return err
	}

	if len(input.CodeChallenge) < 43 || len(input.CodeChallenge) > 128 {
		err := customerrors.NewAppError(nil, "invalid_request", "The code_challenge parameter is either missing or incorrect. It should be 43 to 128 characters long.", http.StatusBadRequest)
		err.UseRedirectUri = true
		return err
	}

	if len(input.ResponseMode) > 0 {
		if !slices.Contains([]string{"query", "fragment", "form_post"}, input.ResponseMode) {
			err := customerrors.NewAppError(nil, "invalid_request", "Please use 'query,' 'fragment,' or 'form_post' as the response_mode value.", http.StatusBadRequest)
			err.UseRedirectUri = true
			return err
		}
	}
	return nil
}
