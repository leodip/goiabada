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
	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/oauth"
)

func HandleAdminGroupSettingsGet(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	apiClient apiclient.ApiClient,
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

		// Get JWT info from context to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
			return
		}

		group, err := apiClient.GetGroupById(jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			if apiErr, ok := err.(*apiclient.APIError); ok && apiErr.StatusCode == http.StatusNotFound {
				httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("group not found")))
				return
			}
			httpHelper.InternalServerError(w, r, err)
			return
		}

		sess, err := httpSession.Get(r, constants.SessionName)
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
	apiClient apiclient.ApiClient,
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

		// Get JWT info from context to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
			return
		}

		// Parse form data
		groupIdentifier := strings.TrimSpace(r.FormValue("groupIdentifier"))
		description := strings.TrimSpace(r.FormValue("description"))
		includeInIdToken := r.FormValue("includeInIdToken") == "on"
		includeInAccessToken := r.FormValue("includeInAccessToken") == "on"

		renderError := func(message string) {
			bind := map[string]interface{}{
				"groupId":              id,
				"groupIdentifier":      groupIdentifier,
				"description":          description,
				"includeInIdToken":     includeInIdToken,
				"includeInAccessToken": includeInAccessToken,
				"error":                message,
				"csrfField":            csrf.TemplateField(r),
			}

			err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_groups_settings.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		// Create API request
		updateReq := &api.UpdateGroupRequest{
			GroupIdentifier:      groupIdentifier,
			Description:          description,
			IncludeInIdToken:     includeInIdToken,
			IncludeInAccessToken: includeInAccessToken,
		}

		// Call API to update group
		_, err = apiClient.UpdateGroup(jwtInfo.TokenResponse.AccessToken, id, updateReq)
		if err != nil {
			if apiErr, ok := err.(*apiclient.APIError); ok {
				// Show validation errors from API
				renderError(apiErr.Message)
				return
			}
			// Handle other errors
			httpHelper.InternalServerError(w, r, err)
			return
		}

		sess, err := httpSession.Get(r, constants.SessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		sess.AddFlash("true", "savedSuccessfully")
		err = httpSession.Save(r, w, sess)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		http.Redirect(w, r, fmt.Sprintf("%v/admin/groups/%v/settings", config.GetAdminConsole().BaseURL, id), http.StatusFound)
	}
}
