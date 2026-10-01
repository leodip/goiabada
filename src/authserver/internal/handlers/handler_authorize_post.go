package handlers

import (
	"net/http"
	"net/url"
	"slices"

	"github.com/go-chi/chi/v5/middleware"

	"github.com/leodip/goiabada/authserver/internal/authorizerequest"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
	"github.com/leodip/goiabada/core/i18n"
)

// authorizeParkedParameters are the parameters a POST parks for its GET: every one the
// authorization endpoint reads a value of, and request and request_uri, which it reads only to
// refuse. Everything else the browser sent is dropped rather than stored: nothing reads it, a
// login_hint is an address for whoever reads the table, and a row's size is then the size of what
// the endpoint uses. Not request_handle either, so a parked request can never name another
// (#246).
//
// TestAuthorizeParkedParameters_CoverEveryRead holds the list to the handler's reads, so a
// parameter read later cannot be left out and silently vanish between a POST and its GET.
var authorizeParkedParameters = append(slices.Clone(authorizeRequestParameters), "request", "request_uri")

// parkedAuthorizeForm is what a POST parks: the parameters the endpoint reads, every copy of each,
// in the order they arrived.
func parkedAuthorizeForm(params url.Values) url.Values {
	form := make(url.Values, len(authorizeParkedParameters))
	for _, name := range authorizeParkedParameters {
		if values, ok := params[name]; ok {
			form[name] = slices.Clone(values)
		}
	}
	return form
}

// HandleAuthorizePost answers a POST to the authorization endpoint (OIDC Core 3.1.2.1 requires the
// endpoint to accept one) with a 303 to a GET, having parked the request under a one-time handle.
//
// The ceremony does not begin here, and nothing of the browser's own session is read or written.
// A POST that comes from another site arrives without the SameSite=Lax session cookie, so an
// answer that began the ceremony would set a new cookie over the one the browser holds, and the
// browser would lose the pointer to a session it was already signed in with; a cross-site iframe
// could never see the session at all. The GET this redirects to is a top-level safe navigation,
// which does carry the cookie, and HandleAuthorizeGet runs the ceremony from the parked request,
// so SSO and prompt=none work over POST as they do over GET (#246).
//
// A request the GET would refuse on the page is refused here, before a row is written, so a POST
// that could never begin a ceremony costs no row. The rest is refused, or not, when the GET runs it.
func HandleAuthorizePost(
	pageRenderer PageRenderer,
	authorizeValidator AuthorizeValidator,
	database authorizerequest.Parking,
	baseURL string,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		requestId := middleware.GetReqID(r.Context())

		params, err := authorizeParameters(r)
		if err != nil {
			renderAuthorizeRefusal(pageRenderer, w, r, i18n.T(r.Context(), "auth_error.malformed_request.message"), http.StatusBadRequest)
			return
		}

		r = withUILocales(r, authorizeUILocales(params))

		if refuseUnaddressableAuthorizeRequest(w, r, pageRenderer, authorizeValidator, requestId, params) {
			return
		}

		handle, err := authorizerequest.Park(r.Context(), database, parkedAuthorizeForm(params))
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}

		// The handle rides in the Location, so the answer is kept out of every cache, and the
		// redirect sets no cookie: the browser's own row is the GET's to read.
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, baseURL+"/auth/authorize?"+url.Values{authorizerequest.HandleParameter: {handle}}.Encode(),
			http.StatusSeeOther)
	}
}

// resolveParkedAuthorizeRequest answers the parameters an authorization request runs from: the
// request's own when it names no handle, and what the POST parked when it does. It reports false
// when it has answered the request itself, on the refusal page.
//
// A handle beside any other authorization parameter is refused and never merged: which of the two
// a parameter came from would decide what the ceremony did, and no request this server issued
// looks like that. A handle that is unknown, expired, already consumed or malformed gets one
// answer, so the page says nothing about which it was.
func resolveParkedAuthorizeRequest(w http.ResponseWriter, r *http.Request, pageRenderer PageRenderer,
	database authorizerequest.Consuming, params url.Values) (url.Values, bool) {

	if !params.Has(authorizerequest.HandleParameter) {
		return params, true
	}

	refuse := func() (url.Values, bool) {
		renderAuthorizeRefusal(pageRenderer, w, r, i18n.T(r.Context(), "auth_error.request_handle_unusable.message"),
			http.StatusBadRequest)
		return nil, false
	}

	// A handle sent twice is refused like any other repeated parameter, whether or not the copies
	// agree (#228).
	if protocolvalidation.RepeatedParameter(params, []string{authorizerequest.HandleParameter}) != "" {
		return refuse()
	}
	for _, name := range authorizeParkedParameters {
		if params.Has(name) {
			return refuse()
		}
	}

	form, found, err := authorizerequest.Consume(r.Context(), database, params.Get(authorizerequest.HandleParameter))
	if err != nil {
		pageRenderer.InternalServerError(w, r, err)
		return nil, false
	}
	if !found {
		return refuse()
	}
	return form, true
}
