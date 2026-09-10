package adminresourcehandlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/leodip/goiabada/core/validators"
)

func HandleAdminResourcePermissionsGet(
	httpHelper handlers.HttpHelper,
	httpSession sessionstore.Store,
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

		_, savedSuccessfully := sess.TakeFlash("savedSuccessfully")
		if savedSuccessfully {
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
			"savedSuccessfully":            savedSuccessfully,
			"permissions":                  permissions,
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
	httpSession sessionstore.Store,
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
			var apiErr *apiclient.APIError
			if errors.As(err, &apiErr) {
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

		sess.SetFlash("savedSuccessfully", "true")
		err = httpSession.Save(r, w, sess)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		result.Success = true
		httpHelper.EncodeJson(w, r, result)
	}
}

// HandleAdminResourceValidatePermissionPost answers the permission form's pre-save check, and it
// has to agree with the API's own refusal at PUT .../permissions: whatever this accepts, the save
// that follows must accept too.
//
// It used to detect markup by sanitizing the description and seeing whether the value changed,
// which disagreed on everything the sanitizer's allowlist let through: "<b>x</b>" survived
// unchanged, so this said valid and the API then refused the save. Asking the same validator both
// sites ask is what makes the two agree (#275). The identifier is checked raw for the same reason:
// sanitizing it first turned "valid<b" into "valid" and reported a name the API would reject as
// available.
func HandleAdminResourceValidatePermissionPost(
	httpHelper handlers.HttpHelper,
	identifierValidator handlers.IdentifierValidator,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		result := ValidatePermissionResult{}

		var data map[string]string
		err := json.NewDecoder(r.Body).Decode(&data)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		permissionIdentifier := strings.TrimSpace(data["permissionIdentifier"])
		description := strings.TrimSpace(data["description"])

		// i18n surface: A — admin browser-flow, JSON to in-page handler.
		if validators.ContainsAngleBrackets(description) {
			result.Error = i18n.NewLocalizedError(i18n.ErrCodeAdminResourcePermissionsDescriptionHtmlNotAllowed, nil).Localize(r.Context())
			httpHelper.EncodeJson(w, r, result)
			return
		}

		if len(permissionIdentifier) == 0 {
			result.Error = i18n.NewLocalizedError(i18n.ErrCodeAdminResourcePermissionsIdentifierRequired, nil).Localize(r.Context())
			httpHelper.EncodeJson(w, r, result)
			return
		}

		err = identifierValidator.ValidateIdentifier(permissionIdentifier, true)
		if err != nil {
			// i18n surface: A — admin browser-flow, JSON to in-page handler.
			switch e := err.(type) {
			case *i18n.LocalizedError:
				result.Error = e.Localize(r.Context())
				httpHelper.EncodeJson(w, r, result)
			case *customerrors.ErrorDetail:
				result.Error = e.GetDescription()
				httpHelper.EncodeJson(w, r, result)
			default:
				httpHelper.JsonError(w, r, err)
			}
			return
		}

		const maxLengthDescription = 100
		if len(description) > maxLengthDescription {
			// i18n surface: A — admin browser-flow, JSON to in-page handler.
			result.Error = i18n.NewLocalizedError(i18n.ErrCodeAdminResourcePermissionsDescriptionTooLong, map[string]any{"max": maxLengthDescription}).Localize(r.Context())
			httpHelper.EncodeJson(w, r, result)
			return
		}

		result.Valid = true
		httpHelper.EncodeJson(w, r, result)
	}
}
