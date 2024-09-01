package adminresourcehandlers

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/data"
)

func HandleAdminResourceSettingsGet(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	database data.Database,
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
		resource, err := database.GetResourceById(nil, id)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if resource == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("resource not found")))
			return
		}

		sess, err := httpSession.Get(r, constants.SessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		savedSuccessfully := sess.Flashes("savedSuccessfully")
		if savedSuccessfully != nil {
			err = sess.Save(r, w)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		bind := map[string]interface{}{
			"resourceId":            resource.Id,
			"resourceIdentifier":    resource.ResourceIdentifier,
			"description":           resource.Description,
			"isSystemLevelResource": resource.IsSystemLevelResource(),
			"savedSuccessfully":     len(savedSuccessfully) > 0,
			"csrfField":             csrf.TemplateField(r),
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_resources_settings.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminResourceSettingsPost(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	authHelper handlers.AuthHelper,
	database data.Database,
	identifierValidator handlers.IdentifierValidator,
	inputSanitizer handlers.InputSanitizer,
	auditLogger handlers.AuditLogger,
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
		resource, err := database.GetResourceById(nil, id)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if resource == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("resource not found")))
			return
		}

		if resource.IsSystemLevelResource() {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("cannot update settings for a system level resource")))
			return
		}

		resourceIdentifier := r.FormValue("resourceIdentifier")
		description := r.FormValue("description")

		renderError := func(message string) {
			bind := map[string]interface{}{
				"resourceId":         resource.Id,
				"resourceIdentifier": resourceIdentifier,
				"description":        description,
				"error":              message,
				"csrfField":          csrf.TemplateField(r),
			}

			err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_resources_settings.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		err = identifierValidator.ValidateIdentifier(resourceIdentifier, true)
		if err != nil {
			if valError, ok := err.(*customerrors.ErrorDetail); ok {
				renderError(valError.GetDescription())
			} else {
				httpHelper.InternalServerError(w, r, err)
			}
			return
		}

		existingResource, err := database.GetResourceByResourceIdentifier(nil, resourceIdentifier)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if existingResource != nil && existingResource.Id != resource.Id {
			renderError("The resource identifier is already in use.")
			return
		}

		const maxLengthDescription = 100
		if len(description) > maxLengthDescription {
			renderError("The description cannot exceed a maximum length of " + strconv.Itoa(maxLengthDescription) + " characters.")
			return
		}

		resource.ResourceIdentifier = strings.TrimSpace(inputSanitizer.Sanitize(resourceIdentifier))
		resource.Description = strings.TrimSpace(inputSanitizer.Sanitize(description))

		err = database.UpdateResource(nil, resource)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		sess, err := httpSession.Get(r, constants.SessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		sess.AddFlash("true", "savedSuccessfully")
		err = sess.Save(r, w)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		auditLogger.Log(constants.AuditUpdatedResource, map[string]interface{}{
			"resourceId":         resource.Id,
			"resourceIdentifier": resource.ResourceIdentifier,
			"loggedInUser":       authHelper.GetLoggedInSubject(r),
		})

		http.Redirect(w, r, fmt.Sprintf("%v/admin/resources/%v/settings", config.Get().BaseURL, resource.Id), http.StatusFound)
	}
}
