package adminresourcehandlers

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/models"
)

func HandleAdminResourceNewGet(
	httpHelper handlers.HttpHelper,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		bind := map[string]interface{}{
			"csrfField": csrf.TemplateField(r),
		}

		err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_resources_new.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminResourceNewPost(
	httpHelper handlers.HttpHelper,
	authHelper handlers.AuthHelper,
	database data.Database,
	identifierValidator handlers.IdentifierValidator,
	inputSanitizer handlers.InputSanitizer,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		renderError := func(message string) {
			bind := map[string]interface{}{
				"error":              message,
				"resourceIdentifier": r.FormValue("resourceIdentifier"),
				"description":        r.FormValue("description"),
				"csrfField":          csrf.TemplateField(r),
			}

			err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_resources_new.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		resourceIdentifier := r.FormValue("resourceIdentifier")
		description := r.FormValue("description")

		if strings.TrimSpace(resourceIdentifier) == "" {
			renderError("Resource identifier is required.")
			return
		}

		const maxLengthDescription = 100
		if len(description) > maxLengthDescription {
			renderError("The description cannot exceed a maximum length of " + strconv.Itoa(maxLengthDescription) + " characters.")
			return
		}

		err := identifierValidator.ValidateIdentifier(resourceIdentifier, true)
		if err != nil {
			renderError(err.Error())
			return
		}

		existingResource, err := database.GetResourceByResourceIdentifier(nil, resourceIdentifier)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if existingResource != nil {
			renderError("The resource identifier is already in use.")
			return
		}

		resource := &models.Resource{
			ResourceIdentifier: strings.TrimSpace(inputSanitizer.Sanitize(resourceIdentifier)),
			Description:        strings.TrimSpace(inputSanitizer.Sanitize(description)),
		}
		err = database.CreateResource(nil, resource)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		auditLogger.Log(constants.AuditCreatedResource, map[string]interface{}{
			"resourceId":         resource.Id,
			"resourceIdentifier": resource.ResourceIdentifier,
			"loggedInUser":       authHelper.GetLoggedInSubject(r),
		})

		http.Redirect(w, r, fmt.Sprintf("%v/admin/resources", config.Get().BaseURL), http.StatusFound)
	}
}
