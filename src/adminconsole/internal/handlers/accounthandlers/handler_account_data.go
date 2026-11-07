package accounthandlers

import (
	"context"
	"net/http"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/errs"
)

// stepUpAcrValues is the level the download asks for, which the refusal names in its acr_values:
// the password, and the code from a user who has set up two-factor authentication. Sent as the
// sign-in's acr_values, it raises the console client's configured level and never lowers it.
const stepUpAcrValues = "urn:goiabada:level2_optional"

// signedInAgainParam is the query parameter the sign-in brings the browser back to the page with,
// set to 1, which draws the notice to press the button again.
const signedInAgainParam = "signed_in_again"

// accountDataAPI is what the Your data page needs: the user's own export.
type accountDataAPI interface {
	GetAccountExport(ctx context.Context, accessToken string) (*apiclient.UserExport, error)
}

// stepUpSignIn is the console's sign-in redirect, with the options a fresh, stronger sign-in adds.
type stepUpSignIn interface {
	RedirToAuthorizeWith(w http.ResponseWriter, r *http.Request, clientIdentifier string, scope string,
		redirectBack string, options oauthclient.SignInOptions) error
}

// HandleDataGet draws the Your data page: what the file holds, that an older sign-in is asked to
// sign in again first, and Download my data (#782 decision 6). Back from that sign-in, the page
// says to press the button again.
func HandleDataGet(httpHelper HttpHelper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		renderDataPage(httpHelper, w, r, map[string]interface{}{
			"signedInAgain": r.URL.Query().Get(signedInAgainParam) == "1",
		})
	}
}

// HandleDataPost answers Download my data with the user's own export, through GET
// /api/v1/account/export, passed through as the administrator's download passes it, by render's
// export pass-through. It is a form's POST rather than a link for the reason that download's is:
// the origin check covers unsafe methods only.
//
// The step-up refusal, render.IsStepUpRequired, is answered here, before the classifier, which
// would leave the user signed in but answer it with the 500 page (#782 decision 1). The browser
// goes through the console's own sign-in for signInScope, the account pages' scope, with
// prompt=login and acr_values, not max_age: prompt=login keeps the user's session and gives it a
// fresh sign-in time, where a max_age sign-in past the window would replace it and sign the user
// out of their other apps. The sign-in brings them back to the page, which says to press the button again; the
// download is not repeated for them, since that would make a POST of a redirect. A 429 is drawn on
// the page with the console's rate-limit sentence. Any other failure goes to the API error
// classifier, so any other 401 still ends the session.
func HandleDataPost(
	httpHelper HttpHelper,
	apiClient accountDataAPI,
	signIn stepUpSignIn,
	signInScope string,
	baseURL string,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		render.LiftExportWriteDeadline(w, r)

		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		export, err := apiClient.GetAccountExport(r.Context(), jwtInfo.TokenResponse.AccessToken)
		if err != nil {
			if render.IsStepUpRequired(err) {
				redirectBack := baseURL + "/account/data?" + signedInAgainParam + "=1"
				signInErr := signIn.RedirToAuthorizeWith(w, r, builtin.AdminConsoleClientIdentifier, signInScope, redirectBack,
					oauthclient.SignInOptions{Prompt: "login", AcrValues: stepUpAcrValues})
				if signInErr != nil {
					httpHelper.InternalServerError(w, r, errs.Wrap(signInErr, "unable to send the browser to sign in again for the download"))
				}
				return
			}
			if render.IsRateLimited(err) {
				renderDataPage(httpHelper, w, r, map[string]interface{}{
					"signedInAgain": false,
					"error":         render.RateLimitedMessage(r.Context()),
				})
				return
			}
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}
		render.ServeExport(w, r, export)
	}
}

func renderDataPage(httpHelper HttpHelper, w http.ResponseWriter, r *http.Request, bind map[string]interface{}) {
	if err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_data.html", bind); err != nil {
		httpHelper.InternalServerError(w, r, err)
	}
}
