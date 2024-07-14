package admingrouphandlers

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/data"
	"github.com/leodip/goiabada/internal/handlers"
	"github.com/leodip/goiabada/internal/lib"
)

func HandleAdminGroupSettingsGet(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	database data.Database,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "groupId")
		if len(idStr) == 0 {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("groupId is required")))
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		group, err := database.GetGroupById(nil, id)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if group == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("group not found")))
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
			"groupId":              group.Id,
			"groupIdentifier":      group.GroupIdentifier,
			"description":          group.Description,
			"includeInIdToken":     group.IncludeInIdToken,
			"includeInAccessToken": group.IncludeInAccessToken,
			"savedSuccessfully":    len(savedSuccessfully) > 0,
			"csrfField":            csrf.TemplateField(r),
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_groups_settings.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminGroupSettingsPost(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	authHelper handlers.AuthHelper,
	database data.Database,
	identifierValidator handlers.IdentifierValidator,
	inputSanitizer handlers.InputSanitizer,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "groupId")
		if len(idStr) == 0 {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("groupId is required")))
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		group, err := database.GetGroupById(nil, id)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if group == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("group not found")))
			return
		}

		groupIdentifier := r.FormValue("groupIdentifier")
		description := r.FormValue("description")

		renderError := func(message string) {
			bind := map[string]interface{}{
				"groupId":         group.Id,
				"groupIdentifier": groupIdentifier,
				"description":     description,
				"error":           message,
				"csrfField":       csrf.TemplateField(r),
			}

			err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_groups_settings.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		err = identifierValidator.ValidateIdentifier(groupIdentifier, true)
		if err != nil {
			if valError, ok := err.(*customerrors.ErrorDetail); ok {
				renderError(valError.GetDescription())
			} else {
				httpHelper.InternalServerError(w, r, err)
			}
			return
		}

		existingGroup, err := database.GetGroupByGroupIdentifier(nil, groupIdentifier)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if existingGroup != nil && existingGroup.Id != group.Id {
			renderError("The group identifier is already in use.")
			return
		}

		const maxLengthDescription = 100
		if len(description) > maxLengthDescription {
			renderError("The description cannot exceed a maximum length of " + strconv.Itoa(maxLengthDescription) + " characters.")
			return
		}

		group.GroupIdentifier = strings.TrimSpace(inputSanitizer.Sanitize(groupIdentifier))
		group.Description = strings.TrimSpace(inputSanitizer.Sanitize(description))
		group.IncludeInIdToken = r.FormValue("includeInIdToken") == "on"
		group.IncludeInAccessToken = r.FormValue("includeInAccessToken") == "on"

		err = database.UpdateGroup(nil, group)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		lib.LogAudit(constants.AuditUpdatedGroup, map[string]interface{}{
			"groupId":         group.Id,
			"groupIdentifier": group.GroupIdentifier,
			"loggedInUser":    authHelper.GetLoggedInSubject(r),
		})

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
		http.Redirect(w, r, fmt.Sprintf("%v/admin/groups/%v/settings", lib.GetBaseUrl(), group.Id), http.StatusFound)
	}
}
