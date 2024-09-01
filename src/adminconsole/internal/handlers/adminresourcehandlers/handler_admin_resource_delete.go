package adminresourcehandlers

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/pkg/errors"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
)

func HandleAdminResourceDeleteGet(
	httpHelper handlers.HttpHelper,
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

		permissions, err := database.GetPermissionsByResourceId(nil, resource.Id)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		bind := map[string]interface{}{
			"resource":    resource,
			"permissions": permissions,
			"csrfField":   csrf.TemplateField(r),
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_resources_delete.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminResourceDeletePost(
	httpHelper handlers.HttpHelper,
	authHelper handlers.AuthHelper,
	database data.Database,
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
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("system level resources cannot be deleted")))
			return
		}

		permissions, err := database.GetPermissionsByResourceId(nil, resource.Id)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		renderError := func(message string) {
			bind := map[string]interface{}{
				"resource":    resource,
				"permissions": permissions,
				"error":       message,
				"csrfField":   csrf.TemplateField(r),
			}

			err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_resources_delete.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		resourceIdentifier := r.FormValue("resourceIdentifier")
		if len(resourceIdentifier) == 0 {
			renderError("Resource identifier is required.")
			return
		}

		if resource.ResourceIdentifier != resourceIdentifier {
			renderError("Resource identifier does not match the resource being deleted.")
			return
		}

		err = database.DeleteResource(nil, resource.Id)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		auditLogger.Log(constants.AuditDeletedResource, map[string]interface{}{
			"resourceId":         resource.Id,
			"resourceIdentifier": resource.ResourceIdentifier,
			"loggedInUser":       authHelper.GetLoggedInSubject(r),
		})

		http.Redirect(w, r, fmt.Sprintf("%v/admin/resources", config.Get().BaseURL), http.StatusFound)
	}
}
