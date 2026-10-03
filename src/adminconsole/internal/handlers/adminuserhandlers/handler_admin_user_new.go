package adminuserhandlers

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/sessionstore"
)

func HandleNewGet(
	httpHelper HttpHelper,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		settings, ok := reqctx.SettingsFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoSettings)
			return
		}

		bind := map[string]interface{}{
			"smtpEnabled":     settings.SMTPEnabled,
			"setPasswordType": api.SetPasswordTypeNow,
			"page":            r.URL.Query().Get("page"),
			"query":           r.URL.Query().Get("query"),
		}

		err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_new.html", bind)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}
	}
}

// userNewAPI is what the new user page needs: the one write it makes.
type userNewAPI interface {
	CreateUserAdmin(ctx context.Context, accessToken string, request *api.CreateUserAdminRequest) (*api.UserResponse, error)
}

func HandleNewPost(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient userNewAPI,
	baseURL string,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		settings, ok := reqctx.SettingsFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoSettings)
			return
		}

		renderError := func(message string) {
			bind := map[string]interface{}{
				"error":           message,
				"smtpEnabled":     settings.SMTPEnabled,
				"setPasswordType": r.FormValue("setPasswordType"),
				"page":            r.URL.Query().Get("page"),
				"query":           r.URL.Query().Get("query"),
				"email":           r.FormValue("email"),
				"emailVerified":   r.FormValue("emailVerified") == "on",
				"givenName":       r.FormValue("givenName"),
				"middleName":      r.FormValue("middleName"),
				"familyName":      r.FormValue("familyName"),
			}

			err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_new.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		// Get JWT info from context to extract access token
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		// Basic validation
		email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
		if len(email) == 0 {
			renderError("The email address cannot be empty.")
			return
		}

		// Prepare request for new API
		setPasswordType := r.FormValue("setPasswordType")
		password := ""
		// The same rule the API applies, so the form asks for exactly what the endpoint will
		// require: a password unless a setup email will be sent. Derived from the email arm rather
		// than written as a test for "now", so an absent or unexpected value asks for a password
		// here exactly as it does there (#350).
		if !settings.SMTPEnabled || setPasswordType != api.SetPasswordTypeEmail {
			// r.PostFormValue rather than r.FormValue: r.Form merges the URL query behind the
			// request body, so /admin/users/new?password=... would have set the new account's
			// password, leaving it in the browser's history, in the Referer of anything the page
			// loads, and in the access log of every proxy in front of the deployment. This route is
			// POST-only with a separate GET handler rendering the form, so the query was never a
			// submission (#202).
			password = r.PostFormValue("password")
		}

		user, err := apiClient.CreateUserAdmin(r.Context(), jwtInfo.TokenResponse.AccessToken, &api.CreateUserAdminRequest{
			Email:           email,
			EmailVerified:   r.FormValue("emailVerified") == "on",
			GivenName:       r.FormValue("givenName"),
			MiddleName:      r.FormValue("middleName"),
			FamilyName:      r.FormValue("familyName"),
			SetPasswordType: setPasswordType,
			Password:        password,
		})
		if err != nil {
			render.HandleAPIErrorWithCallback(httpHelper, w, r, err, renderError)
			return
		}

		// Handle success flow
		sess, err := httpSession.Get(r, builtin.AdminConsoleSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		sess.SetFlash("userCreated", "true")
		err = httpSession.Save(r, w, sess)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		http.Redirect(w, r, withListPosition(baseURL, fmt.Sprintf("/admin/users/%v/details", user.Id), r), http.StatusFound)
	}
}
