package adminresourcehandlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/oauth"
)

func HandleAdminResourcePermissionsGet(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "resourceId")
		if len(idStr) == 0 {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("resourceId is required")))
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		// Get JWT info from context to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
			return
		}

		resource, err := apiClient.GetResourceById(jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if resource == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("resource not found")))
			return
		}

		sess, err := httpSession.Get(r, constants.AdminConsoleSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		savedSuccessfully := sess.Flashes("savedSuccessfully")
		if savedSuccessfully != nil {
			err = httpSession.Save(r, w, sess)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		permissions, err := apiClient.GetPermissionsByResource(jwtInfo.TokenResponse.AccessToken, resource.Id)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}

	// Prepare built-in permission identifiers for the authserver resource
	var builtInPermissionIdentifiers []string
	if resource.ResourceIdentifier == constants.AuthServerResourceIdentifier {
		builtInPermissionIdentifiers = constants.BuiltInAuthServerPermissionIdentifiers
	} else {
		builtInPermissionIdentifiers = []string{}
	}

	bind := map[string]interface{}{
		"resourceId":                   resource.Id,
		"resourceIdentifier":           resource.ResourceIdentifier,
		"resourceDescription":          resource.Description,
		"isSystemLevelResource":        resource.IsSystemLevelResource(),
		"builtInPermissionIdentifiers": builtInPermissionIdentifiers,
		"savedSuccessfully":            len(savedSuccessfully) > 0,
		"permissions":                  permissions,
		"csrfField":                    csrf.TemplateField(r),
	}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_resources_permissions.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminResourcePermissionsPost(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		result := SavePermissionsResult{}

		idStr := chi.URLParam(r, "resourceId")
		if len(idStr) == 0 {
			httpHelper.JsonError(w, r, errors.WithStack(errors.New("resourceId is required")))
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}
		// Get JWT info
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.JsonError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
			return
		}
		resource, err := apiClient.GetResourceById(jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if resource == nil {
			httpHelper.JsonError(w, r, errors.WithStack(errors.New("resource not found")))
			return
		}

		var data SavePermissionsInput
		err = json.NewDecoder(r.Body).Decode(&data)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		if data.ResourceId != resource.Id {
			httpHelper.JsonError(w, r, errors.WithStack(errors.New("resourceId mismatch")))
			return
		}

		// Build request for auth server
		upserts := make([]api.ResourcePermissionUpsert, 0, len(data.Permissions))
		for _, p := range data.Permissions {
			upserts = append(upserts, api.ResourcePermissionUpsert{
				Id:                   p.Id,
				PermissionIdentifier: strings.TrimSpace(p.Identifier),
				Description:          strings.TrimSpace(p.Description),
			})
		}
		updateReq := &api.UpdateResourcePermissionsRequest{Permissions: upserts}
		if err := apiClient.UpdateResourcePermissions(jwtInfo.TokenResponse.AccessToken, resource.Id, updateReq); err != nil {
			if apiErr, ok := err.(*apiclient.APIError); ok {
				result.Error = apiErr.Message
				httpHelper.EncodeJson(w, r, result)
				return
			}
			httpHelper.JsonError(w, r, err)
			return
		}

		sess, err := httpSession.Get(r, constants.AdminConsoleSessionName)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		sess.AddFlash("true", "savedSuccessfully")
		err = httpSession.Save(r, w, sess)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		result.Success = true
		httpHelper.EncodeJson(w, r, result)
	}
}

func HandleAdminResourceValidatePermissionPost(
	httpHelper handlers.HttpHelper,
	identifierValidator handlers.IdentifierValidator,
	inputSanitizer handlers.InputSanitizer,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		result := ValidatePermissionResult{}

		var data map[string]string
		err := json.NewDecoder(r.Body).Decode(&data)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		permissionIdentifier := inputSanitizer.Sanitize(strings.TrimSpace(data["permissionIdentifier"]))

		originalDescription := strings.TrimSpace(data["description"])
		description := inputSanitizer.Sanitize(strings.TrimSpace(data["description"]))

		if originalDescription != description {
			result.Error = "The description contains invalid characters, as we do not permit the use of HTML in the description."
			httpHelper.EncodeJson(w, r, result)
			return
		}

		if len(permissionIdentifier) == 0 {
			result.Error = "Permission identifier is required."
			httpHelper.EncodeJson(w, r, result)
			return
		}

		err = identifierValidator.ValidateIdentifier(permissionIdentifier, true)
		if err != nil {
			if valError, ok := err.(*customerrors.ErrorDetail); ok {
				result.Error = valError.GetDescription()
				httpHelper.EncodeJson(w, r, result)
			} else {
				httpHelper.JsonError(w, r, err)
			}
			return
		}

		const maxLengthDescription = 100
		if len(description) > maxLengthDescription {
			result.Error = "The description cannot exceed a maximum length of " + strconv.Itoa(maxLengthDescription) + " characters."
			httpHelper.EncodeJson(w, r, result)
			return
		}

		result.Valid = true
		httpHelper.EncodeJson(w, r, result)
	}
}
