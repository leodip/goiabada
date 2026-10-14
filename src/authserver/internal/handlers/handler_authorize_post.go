package handlers

import (
	"net/http"
	"net/url"

	"github.com/go-chi/chi/v5/middleware"

	"github.com/leodip/goiabada/authserver/internal/authflow"
	"github.com/leodip/goiabada/authserver/internal/authorizerequest"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/i18n"
)

// HandleAuthorizePost answers a POST to the authorization endpoint with a 303 to a GET, once
// authflow.AuthorizationParking has parked the request under a one-time handle. It checks the
// request's settings first, as every ceremony handler does (#580 decision 5), then reads the
// parameters, refines the request's localizer to their ui_locales hint for the refusal page, and
// writes the answer: the refusal page, a 500, or the redirect. The browser's own session is neither
// read nor written here; the GET runs the ceremony (#246).
func HandleAuthorizePost(
	pageRenderer PageRenderer,
	parking *authflow.AuthorizationParking,
	baseURL string,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := reqctx.SettingsFrom(r.Context()); !ok {
			pageRenderer.InternalServerError(w, r, reqctx.ErrNoSettings)
			return
		}

		params, err := authorizeParameters(r)
		if err != nil {
			renderAuthorizeRefusal(pageRenderer, w, r, i18n.T(r.Context(), "auth_error.malformed_request.message"), http.StatusBadRequest)
			return
		}

		r = withUILocales(r, authflow.AuthorizeUILocales(params))

		result, err := parking.Run(r.Context(), params, middleware.GetReqID(r.Context()))
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}
		if result.PageRefusal != nil {
			answerAuthorizePageRefusal(pageRenderer, w, r, result.PageRefusal)
			return
		}

		// The handle rides in the Location, so the answer is kept out of every cache, and the
		// redirect sets no cookie: the browser's own row is the GET's to read.
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, baseURL+"/auth/authorize?"+url.Values{authorizerequest.HandleParameter: {result.Handle}}.Encode(),
			http.StatusSeeOther)
	}
}
