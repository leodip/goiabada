package handlers

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/leodip/goiabada/authserver/internal/authflow"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/middleware"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/requestid"
)

// HandleAuthorizeGet answers GET /auth/authorize, and the GET a POST to it redirects to. It reads the
// request and writes the response; authflow.Authorization decides and writes everything between:
//
//  1. Reads the request's settings, a 500 without them, and its parameters, the query and a form
//     body merged (authorizeParameters). A request that does not parse is answered on the refusal
//     page and never by redirect: a malformed escape drops the field it sits in, so the client_id
//     or redirect_uri a redirect would be built from may be one the client never sent (#228).
//  2. Swaps in the parameters a POST parked when they name a request_handle
//     (Authorization.ResolveParked). This request's cookie is the browser's own, which is why the
//     POST answered with a redirect here (#246).
//  3. Refines the request's localizer to the ui_locales hint (withUILocales), so the refusal page and
//     every page this ceremony renders are in the relying party's stated language. The browser
//     adapter holds the request as this step left it.
//  4. Runs the ceremony's start (Authorization.Run) and writes the answer its result names: the
//     refusal page, the error response to the client, the step redirect, or a 500.
func HandleAuthorizeGet(
	boundary *CeremonyBoundary,
	responder *ClientErrorResponder,
	pageRenderer PageRenderer,
	ceremonyStore CeremonyStore,
	authorization *authflow.Authorization,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		settings, ok := reqctx.SettingsFrom(r.Context())
		if !ok {
			pageRenderer.InternalServerError(w, r, reqctx.ErrNoSettings)
			return
		}

		params, err := authorizeParameters(r)
		if err != nil {
			renderAuthorizeRefusal(pageRenderer, w, r, i18n.T(r.Context(), "auth_error.malformed_request.message"), http.StatusBadRequest)
			return
		}

		params, pageRefusal, err := authorization.ResolveParked(r.Context(), params)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}
		if pageRefusal != nil {
			answerAuthorizePageRefusal(pageRenderer, w, r, pageRefusal)
			return
		}

		r = withUILocales(r, authflow.AuthorizeUILocales(params))

		sessionIdentifier, _ := reqctx.SessionIdentifierFrom(r.Context())
		result, err := authorization.Run(r.Context(), newBrowserSession(w, r, ceremonyStore), settings, params,
			authflow.AuthorizeArrival{
				RequestId:         requestid.FromContext(r.Context()),
				SessionIdentifier: sessionIdentifier,
				UserAgent:         r.UserAgent(),
				IpAddress:         middleware.ClientIP(r),
			})
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}

		switch {
		case result.PageRefusal != nil:
			answerAuthorizePageRefusal(pageRenderer, w, r, result.PageRefusal)

		case result.ClientRefusal != nil:
			// Nothing was written for it, so there is no clear to answer server_error for: the
			// sign-in the browser holds is left as it was (#246).
			input := redirectErrorFromAuthContext(result.AuthContext, result.ClientRefusal.Client,
				result.ClientRefusal.Code, result.ClientRefusal.Description)
			input.redirectAlreadyWithheld = result.RedirectWithheld
			if err := responder.redirToClientWithError(w, r, input); err != nil {
				pageRenderer.InternalServerError(w, r, err)
			}

		case result.SaveErr != nil:
			pageRenderer.InternalServerError(w, r, result.SaveErr)

		default:
			boundary.stepRedirect(w, r, result.NextStep, result.AuthContext)
		}
	}
}

// authorizeParameters answers the authorization request's parameters, the query and a form body
// merged, as the one source HandleAuthorizeGet reads them from, or the error that stopped them
// parsing. A multipart body is read as r.FormValue reads it, so a body that is simply not multipart
// is no error.
func authorizeParameters(r *http.Request) (url.Values, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	// net/http's defaultMaxMemory, the limit r.FormValue parses with.
	//nolint:gosec // G120: bounded by the server's request-body table, the same bound r.FormValue's own parse applies; G120 flags every multipart parse
	if err := r.ParseMultipartForm(32 << 20); err != nil && !errors.Is(err, http.ErrNotMultipart) {
		return nil, err
	}
	return r.Form, nil
}

// renderAuthorizeRefusal is the refusal page, which is how the authorization endpoint answers
// anything it must not send to the client. The status is a parameter because the conditions that
// reach it differ on it: a bad client_id or redirect_uri answers 200, while an
// unsupported response_mode is answered 400 because OIDC Core 3.1.2.6 names that code (#213), and
// a request that cannot be parsed, repeats a delivery parameter or names a handle that is no longer
// good is 400 as the malformed request it is (#228, #246).
func renderAuthorizeRefusal(pageRenderer PageRenderer, w http.ResponseWriter, r *http.Request, message string, httpStatus int) {
	bind := map[string]interface{}{
		"title":       i18n.T(r.Context(), "auth_error.unable_to_authorize.title"),
		"error":       message,
		"_httpStatus": httpStatus,
	}

	renderTemplateErr := pageRenderer.RenderTemplate(w, r, "/layouts/no_menu_layout.html", "/auth_error.html", bind)
	if renderTemplateErr != nil {
		pageRenderer.InternalServerError(w, r, renderTemplateErr)
	}
}

// answerAuthorizePageRefusal renders the refusal page with the message and the status a refusal's
// reason calls for. The client_id or redirect_uri refusal is the one localized from the validator's
// own error; OIDC Core 1.0 requires an OP to honour ui_locales for its user interface, and this page
// is the whole answer to such a request.
func answerAuthorizePageRefusal(pageRenderer PageRenderer, w http.ResponseWriter, r *http.Request,
	refusal *authflow.AuthorizePageRefusal) {

	switch refusal.Reason {
	case authflow.AuthorizePageRefusalUnusableHandle:
		renderAuthorizeRefusal(pageRenderer, w, r, i18n.T(r.Context(), "auth_error.request_handle_unusable.message"),
			http.StatusBadRequest)
	case authflow.AuthorizePageRefusalRepeatedParameter:
		renderAuthorizeRefusal(pageRenderer, w, r, i18n.T(r.Context(), "auth_error.repeated_parameter.message",
			map[string]any{"parameter": refusal.Parameter}), http.StatusBadRequest)
	case authflow.AuthorizePageRefusalClientOrRedirectURI:
		renderAuthorizeRefusal(pageRenderer, w, r, refusal.ClientRefusal.Localize(r.Context()), http.StatusOK)
	case authflow.AuthorizePageRefusalUnsupportedResponseMode:
		renderAuthorizeRefusal(pageRenderer, w, r, i18n.T(r.Context(), "auth_error.unsupported_response_mode.message"),
			http.StatusBadRequest)
	case authflow.AuthorizePageRefusalFormPostUnreachable:
		// An implicit request may not use the query (#231), so its page names the fragment alone.
		message := "auth_error.form_post_unreachable.code.message"
		if refusal.ImplicitFlow {
			message = "auth_error.form_post_unreachable.implicit.message"
		}
		renderAuthorizeRefusal(pageRenderer, w, r, i18n.T(r.Context(), message), http.StatusBadRequest)
	default:
		pageRenderer.InternalServerError(w, r, errs.Errorf("authorization request refused for an unknown reason (%v)", refusal.Reason))
	}
}

// withUILocales refines the request's localizer to the ui_locales hint. The global locale
// middleware ran on this request but only sees the query string, so a hint that came in a form
// body, or in a request parked by a POST, has to be applied here for anything browser-visible on
// this request (the refusal page, the level 1 password page) to render in the chosen locale.
func withUILocales(r *http.Request, uiLocales []string) *http.Request {
	if len(uiLocales) == 0 {
		return r
	}
	return r.WithContext(i18n.WithLocale(r.Context(), true, uiLocales...))
}

// answerClientAfterStepClear answers the client with an error once the step's authflow operation
// has made its clear, which comes first because every response mode commits the response and the
// clear persists through a Set-Cookie on w (#141). A clear that found the ceremony no longer held,
// ended by another request of it, pushed out by newer sign-ins or its session gone, wrote nothing,
// and the client is not answered: the browser has abandoned this ceremony, and a client keeping one
// pending state per browser could take this error as the answer to a newer request, so the step
// answers the "no longer active" page
// (#579 decision 2, #79 decision 5). Otherwise the responder answers, with server_error when the
// clear failed (ClientErrorResponder.answerClientAfterClear).
func answerClientAfterStepClear(w http.ResponseWriter, r *http.Request, boundary *CeremonyBoundary,
	responder *ClientErrorResponder, input redirectErrorInput, clearErr error) {

	if errors.Is(clearErr, ceremony.ErrCeremonyReplaced) {
		boundary.answerCeremonyReplaced(w, r)
		return
	}
	responder.answerClientAfterClear(w, r, input, clearErr)
}
