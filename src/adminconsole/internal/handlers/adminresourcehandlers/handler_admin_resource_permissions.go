package adminresourcehandlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/errs"
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
			httpHelper.NotFound(w, r)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.NotFound(w, r)
			return
		}
		// Get JWT info from context to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errs.New("no JWT info found in context"))
			return
		}

		resource, err := apiClient.GetResourceById(jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if resource == nil {
			httpHelper.NotFound(w, r)
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
			handlers.JsonNotFound(httpHelper, w, r)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			handlers.JsonNotFound(httpHelper, w, r)
			return
		}
		// Get JWT info
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.JsonError(w, r, errs.New("no JWT info found in context"))
			return
		}
		resource, err := apiClient.GetResourceById(jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			handlers.HandleAPIErrorJson(httpHelper, w, r, err)
			return
		}
		if resource == nil {
			handlers.JsonNotFound(httpHelper, w, r)
			return
		}

		var data SavePermissionsInput
		err = json.NewDecoder(r.Body).Decode(&data)
		if err != nil {
			handlers.JsonBadRequestBody(httpHelper, w, r)
			return
		}

		if data.ResourceId != resource.Id {
			httpHelper.JsonError(w, r, errs.New("resourceId mismatch"))
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
			// Forward the API's status rather than dressing a 400 as a 200 carrying result.Error.
			// The administrator still reads the API's sentence either way: sendAjaxRequest draws
			// error_description from any non-2xx into this same modal, and escapes it on the way
			// in, where the 200 path passed the value straight to showModalDialog, which assigns
			// innerHTML. Answering 200 also reported a save that had not happened to anything
			// reading the status rather than the body (#279 decision 13).
			handlers.HandleAPIErrorJson(httpHelper, w, r, err)
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
			handlers.JsonBadRequestBody(httpHelper, w, r)
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
			// errors.As in the switch's own order, not a type switch: both read the dynamic type,
			// so anything that wrapped the validator's result on the way here would fall through
			// to default and answer a 500 with the sentence in the log rather than in the form
			// (#279 decision 6).
			var localizedErr *i18n.LocalizedError
			var errorDetail *customerrors.ErrorDetail
			switch {
			case errors.As(err, &localizedErr):
				result.Error = localizedErr.Localize(r.Context())
				httpHelper.EncodeJson(w, r, result)
			case errors.As(err, &errorDetail):
				result.Error = errorDetail.GetDescription()
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
