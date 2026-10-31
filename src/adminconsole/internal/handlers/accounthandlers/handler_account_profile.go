package accounthandlers

import (
	"context"
	"net/http"

	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/adminconsole/internal/sessionkeys"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/locales"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/leodip/goiabada/core/timezones"
)

// accountProfileAPI is what the account profile page needs: the profile it renders from, and the
// write.
type accountProfileAPI interface {
	GetAccountProfile(ctx context.Context, accessToken string) (*api.UserResponse, error)
	UpdateAccountProfile(ctx context.Context, accessToken string, request *api.UpdateUserProfileRequest) (*api.UserResponse, error)
}

// copyPageLanguage writes the profile's page language into the session's copy, which every signed-in
// console page is drawn from (#631 decision 7), and reports whether the copy changed, so a page that
// changed nothing else saves no session for it; a session with no copy is on Automatic already. The
// profile page refreshes the copy each time it fetches the profile, which is how a choice made
// elsewhere, by an administrator or in another browser, reaches this session before its next
// sign-in, and its save writes the choice the API stored.
func copyPageLanguage(sess *sessionstore.Session, pageLanguage string) bool {
	if copied, _ := sess.Values[sessionkeys.PageLanguage].(string); copied == pageLanguage {
		return false
	}
	sess.Values[sessionkeys.PageLanguage] = pageLanguage
	return true
}

func HandleProfileGet(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient accountProfileAPI,
) http.HandlerFunc {

	timezones := timezones.All()
	locales := locales.All()

	return func(w http.ResponseWriter, r *http.Request) {

		// Get JWT info to extract access token
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		user, err := apiClient.GetAccountProfile(r.Context(), jwtInfo.TokenResponse.AccessToken)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}

		sess, err := httpSession.Get(r, builtin.AdminConsoleSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		_, savedSuccessfully := sess.TakeFlash("savedSuccessfully")
		copied := copyPageLanguage(sess, user.PageLanguage)
		if savedSuccessfully || copied {
			err = httpSession.Save(r, w, sess)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		bind := map[string]interface{}{
			"user":              user,
			"timezones":         timezones,
			"locales":           locales,
			"pageLanguages":     render.PageLanguageOptions(),
			"pageLanguage":      render.SelectedPageLanguage(user.PageLanguage),
			"savedSuccessfully": savedSuccessfully,
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_profile.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleProfilePost(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient accountProfileAPI,
	baseURL string,
) http.HandlerFunc {

	timezones := timezones.All()
	locales := locales.All()

	return func(w http.ResponseWriter, r *http.Request) {

		// Get access token
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		// Load current profile (for successful render or error rebound)
		user, err := apiClient.GetAccountProfile(r.Context(), jwtInfo.TokenResponse.AccessToken)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}

		request, err := render.ParseProfileForm(r)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		// Call API to update
		updatedUser, err := apiClient.UpdateAccountProfile(r.Context(), jwtInfo.TokenResponse.AccessToken, request)
		if err != nil {
			// Render validation error retaining input
			render.HandleAPIErrorWithCallback(httpHelper, w, r, err, func(errorMessage string) {
				// reflect submitted values onto user for display
				render.EchoProfileForm(user, request)

				bind := map[string]interface{}{
					"user":                 user,
					"submittedDateOfBirth": render.SubmittedDateOfBirth(r),
					"timezones":            timezones,
					"locales":              locales,
					"pageLanguages":        render.PageLanguageOptions(),
					"pageLanguage":         render.SelectedPageLanguage(user.PageLanguage),
					"error":                errorMessage,
					"errorField":           render.ErrorField(err, render.ProfileErrorFields),
				}

				if renderErr := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_profile.html", bind); renderErr != nil {
					httpHelper.InternalServerError(w, r, renderErr)
					return
				}
			})
			return
		}

		sess, err := httpSession.Get(r, builtin.AdminConsoleSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		sess.SetFlash("savedSuccessfully", "true")
		copyPageLanguage(sess, updatedUser.PageLanguage)
		err = httpSession.Save(r, w, sess)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		http.Redirect(w, r, baseURL+"/account/profile", http.StatusFound)
	}
}
