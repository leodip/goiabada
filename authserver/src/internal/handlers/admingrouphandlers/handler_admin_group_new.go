package admingrouphandlers

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/data"
	"github.com/leodip/goiabada/internal/handlers"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/leodip/goiabada/internal/models"
)

func HandleAdminGroupNewGet(
	httpHelper handlers.HttpHelper,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		bind := map[string]interface{}{
			"csrfField": csrf.TemplateField(r),
		}

		err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_groups_new.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminGroupNewPost(
	httpHelper handlers.HttpHelper,
	authHelper handlers.AuthHelper,
	database data.Database,
	identifierValidator handlers.IdentifierValidator,
	inputSanitizer handlers.InputSanitizer,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		renderError := func(message string) {
			bind := map[string]interface{}{
				"error":           message,
				"groupIdentifier": r.FormValue("groupIdentifier"),
				"description":     r.FormValue("description"),
				"csrfField":       csrf.TemplateField(r),
			}

			err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_groups_new.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		groupIdentifier := r.FormValue("groupIdentifier")
		description := strings.TrimSpace(r.FormValue("description"))

		if strings.TrimSpace(groupIdentifier) == "" {
			renderError("Group identifier is required.")
			return
		}

		const maxLengthDescription = 100
		if len(description) > maxLengthDescription {
			renderError("The description cannot exceed a maximum length of " + strconv.Itoa(maxLengthDescription) + " characters.")
			return
		}

		err := identifierValidator.ValidateIdentifier(groupIdentifier, true)
		if err != nil {
			renderError(err.Error())
			return
		}

		existingGroup, err := database.GetGroupByGroupIdentifier(nil, groupIdentifier)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if existingGroup != nil {
			renderError("The group identifier is already in use.")
			return
		}

		includeInIdToken := r.FormValue("includeInIdToken") == "on"
		includeInAccessToken := r.FormValue("includeInAccessToken") == "on"

		group := &models.Group{
			GroupIdentifier:      strings.TrimSpace(inputSanitizer.Sanitize(groupIdentifier)),
			Description:          strings.TrimSpace(inputSanitizer.Sanitize(description)),
			IncludeInIdToken:     includeInIdToken,
			IncludeInAccessToken: includeInAccessToken,
		}
		err = database.CreateGroup(nil, group)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		lib.LogAudit(constants.AuditCreatedGroup, map[string]interface{}{
			"groupId":         group.Id,
			"groupIdentifier": group.GroupIdentifier,
			"loggedInUser":    authHelper.GetLoggedInSubject(r),
		})

		http.Redirect(w, r, fmt.Sprintf("%v/admin/groups", lib.GetBaseUrl()), http.StatusFound)
	}
}
