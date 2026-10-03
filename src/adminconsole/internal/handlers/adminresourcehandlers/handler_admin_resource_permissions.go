package adminresourcehandlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/inputvalidation"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/sessionstore"
)

// resourcePermissionsAPI is what the resource permissions page needs: the resource, its
// permissions, and the write.
type resourcePermissionsAPI interface {
	GetPermissionsByResource(ctx context.Context, accessToken string, resourceId int64) ([]api.PermissionResponse, error)
	GetResourceById(ctx context.Context, accessToken string, resourceId int64) (*api.ResourceResponse, error)
	UpdateResourcePermissions(ctx context.Context, accessToken string, resourceId int64, request *api.UpdateResourcePermissionsRequest) error
}

func HandleAdminResourcePermissionsGet(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient resourcePermissionsAPI,
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
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		resource, err := apiClient.GetResourceById(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if resource == nil {
			httpHelper.NotFound(w, r)
			return
		}

		sess, err := httpSession.Get(r, builtin.AdminConsoleSessionName)
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

		permissions, err := apiClient.GetPermissionsByResource(r.Context(), jwtInfo.TokenResponse.AccessToken, resource.Id)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}

		// Prepare built-in permission identifiers for the authserver resource
		var builtInPermissionIdentifiers []string
		if resource.ResourceIdentifier == builtin.AuthServerResourceIdentifier {
			builtInPermissionIdentifiers = builtin.AuthServerPermissionIdentifiers()
		} else {
			builtInPermissionIdentifiers = []string{}
		}

		bind := map[string]interface{}{
			"resourceId":                   resource.Id,
			"resourceIdentifier":           resource.ResourceIdentifier,
			"resourceDescription":          resource.Description,
			"isSystemLevelResource":        resource.IsSystemLevelResource,
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
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient resourcePermissionsAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		result := SavePermissionsResult{}

		idStr := chi.URLParam(r, "resourceId")
		if len(idStr) == 0 {
			render.JSONNotFound(httpHelper, w, r)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			render.JSONNotFound(httpHelper, w, r)
			return
		}
		// Get JWT info
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.JSONError(w, r, reqctx.ErrNoJwtInfo)
			return
		}
		resource, err := apiClient.GetResourceById(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			render.HandleAPIErrorJSON(httpHelper, w, r, err)
			return
		}
		if resource == nil {
			render.JSONNotFound(httpHelper, w, r)
			return
		}

		var data SavePermissionsInput
		err = json.NewDecoder(r.Body).Decode(&data)
		if err != nil {
			render.JSONBadRequestBody(httpHelper, w, r)
			return
		}

		if data.ResourceId != resource.Id {
			render.JSONBadRequestBody(httpHelper, w, r)
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
		// The loaded list goes as the page sent it, untrimmed, since the auth server compares it
		// with the stored entries exactly; and an absent one stays nil, which the API refuses,
		// rather than become a list that would pass (#428).
		var expected []api.ResourcePermissionUpsert
		if data.ExpectedPermissions != nil {
			expected = make([]api.ResourcePermissionUpsert, 0, len(data.ExpectedPermissions))
			for _, p := range data.ExpectedPermissions {
				expected = append(expected, api.ResourcePermissionUpsert{
					Id:                   p.Id,
					PermissionIdentifier: p.Identifier,
					Description:          p.Description,
				})
			}
		}
		updateReq := &api.UpdateResourcePermissionsRequest{Permissions: upserts, ExpectedPermissions: expected}
		if updateResourcePermissionsErr := apiClient.UpdateResourcePermissions(r.Context(), jwtInfo.TokenResponse.AccessToken, resource.Id, updateReq); updateResourcePermissionsErr != nil {
			// Forward the API's status rather than dressing a 400 as a 200 carrying result.Error.
			// The administrator still reads the API's sentence either way: sendAjaxRequest draws
			// error_description from any non-2xx into this same modal, and escapes it on the way
			// in, where the 200 path passed the value straight to showModalDialog, which assigns
			// innerHTML. Answering 200 also reported a save that had not happened to anything
			// reading the status rather than the body (#279 decision 13).
			render.HandleAPIErrorJSON(httpHelper, w, r, updateResourcePermissionsErr)
			return
		}

		sess, err := httpSession.Get(r, builtin.AdminConsoleSessionName)
		if err != nil {
			httpHelper.JSONError(w, r, err)
			return
		}

		sess.SetFlash("savedSuccessfully", "true")
		err = httpSession.Save(r, w, sess)
		if err != nil {
			httpHelper.JSONError(w, r, err)
			return
		}

		result.Success = true
		httpHelper.EncodeJSON(w, r, result)
	}
}

// IdentifierValidator is the one check the permission form's pre-save asks, the same one the API
// asks before the save (#275). It lives beside its one consumer (#440).
type IdentifierValidator interface {
	Validate(identifier string, enforceMinLength bool) error
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
	httpHelper HttpHelper,
	identifierValidator IdentifierValidator,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		result := ValidatePermissionResult{}

		var data map[string]string
		err := json.NewDecoder(r.Body).Decode(&data)
		if err != nil {
			render.JSONBadRequestBody(httpHelper, w, r)
			return
		}

		permissionIdentifier := strings.TrimSpace(data["permissionIdentifier"])
		description := strings.TrimSpace(data["description"])

		// i18n surface: A — admin browser-flow, JSON to in-page handler.
		if inputvalidation.ContainsAngleBrackets(description) {
			result.Error = i18n.NewLocalizedError(i18n.ErrCodeAdminResourcePermissionsDescriptionHtmlNotAllowed, nil).Localize(r.Context())
			httpHelper.EncodeJSON(w, r, result)
			return
		}

		if len(permissionIdentifier) == 0 {
			result.Error = i18n.NewLocalizedError(i18n.ErrCodeAdminResourcePermissionsIdentifierRequired, nil).Localize(r.Context())
			httpHelper.EncodeJSON(w, r, result)
			return
		}

		err = identifierValidator.Validate(permissionIdentifier, true)
		if err != nil {
			// i18n surface: A — admin browser-flow, JSON to in-page handler.
			// errors.As in the switch's own order, not a type switch: both read the dynamic type,
			// so anything that wrapped the validator's result on the way here would fall through
			// to default and answer a 500 with the sentence in the log rather than in the form
			// (#279 decision 6).
			var localizedErr *i18n.LocalizedError
			var errorDetail *oauth.ErrorDetail
			switch {
			case errors.As(err, &localizedErr):
				result.Error = localizedErr.Localize(r.Context())
				httpHelper.EncodeJSON(w, r, result)
			case errors.As(err, &errorDetail):
				result.Error = errorDetail.Description()
				httpHelper.EncodeJSON(w, r, result)
			default:
				httpHelper.JSONError(w, r, err)
			}
			return
		}

		const maxLengthDescription = 100
		if len(description) > maxLengthDescription {
			// i18n surface: A — admin browser-flow, JSON to in-page handler.
			result.Error = i18n.NewLocalizedError(i18n.ErrCodeAdminResourcePermissionsDescriptionTooLong, map[string]any{"max": maxLengthDescription}).Localize(r.Context())
			httpHelper.EncodeJSON(w, r, result)
			return
		}

		result.Valid = true
		httpHelper.EncodeJSON(w, r, result)
	}
}
