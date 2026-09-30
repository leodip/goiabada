package handlers

import (
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/middleware"
	"github.com/leodip/goiabada/core/i18n"
)

// ceremonyIdField is the hidden form field naming the authorization ceremony, and its name is
// duplicated in the auth-flow templates because a template cannot read a Go constant. A rename
// in one place alone renders a form whose every submission is refused, which the integration
// cases catch: they read the field out of the rendered page rather than building the form.
const ceremonyIdField = "ceremonyId"

// ceremonyMatches reports whether a submitted form, or a step's page load, belongs to the ceremony
// the session currently holds.
//
// An empty stored id is refused rather than matched against an empty submission. Only an auth
// context written by a binary from before #79 can carry one, and treating "" as equal to ""
// would make such a context accept a form naming no ceremony at all, which is every forged
// form. The cost is that a user mid-flow across a deploy is refused once and starts the
// authorization again.
//
// Constant time, like forgotPasswordCodeMatches and the client secret comparison in
// protocolvalidation.ValidateTokenRequest. Not because this value is guessed at, but because a
// plain comparison stopping at the first differing byte is the kind of thing that is cheap to avoid
// and expensive to notice later.
func ceremonyMatches(contextCeremonyId string, submitted string) bool {
	if contextCeremonyId == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(contextCeremonyId), []byte(submitted)) == 1
}

// rejectCeremonyMismatch answers a request that names a ceremony the session no longer holds, or
// none: audit it, then render the error page at 400.
//
// The auth context is deliberately NOT touched. The ceremony that is current is the one the
// user is actually working on, in another tab, and clearing or advancing it here would let a
// forgotten tab cancel a live authorization with nothing left to recover from. The stale form
// or page is simply dead. The client is not told either, for the same reason: the client that
// would receive an error is the current one, whose authorization the user still wants (#79
// decision 5).
//
// Mirrors accounthandlers' rejectResetPassword: audit, then render, at http.StatusBadRequest because a
// submission was genuinely refused.
func rejectCeremonyMismatch(pageRenderer PageRenderer, auditLogger AuditLogger, w http.ResponseWriter,
	r *http.Request, authContext *ceremony.AuthContext) {

	const maxAuditedValueLength = 100

	// Truncated for the same reason accounthandlers' auditedClientIP truncates it for the two
	// emailed-link flows: MiddlewareRealIP resolves the IP from a forwarded header in a proxied
	// deployment, so this is a sink for a value that originates outside the process.
	clientIP := middleware.GetClientIPFromRequest(r)
	if len(clientIP) > maxAuditedValueLength {
		clientIP = clientIP[:maxAuditedValueLength]
	}

	details := map[string]interface{}{
		"clientId":  authContext.ClientId,
		"authState": string(authContext.AuthState),
		"ipAddress": clientIP,
	}
	// Absent rather than zero when the ceremony has not identified anyone yet, which is every
	// submission of the password form. A payload naming user 0 asserts a row that does not exist.
	if authContext.UserId != 0 {
		details["userId"] = authContext.UserId
	}
	auditLogger.Log(r.Context(), audit.AuditAuthCeremonyMismatch, details)

	bind := map[string]interface{}{
		"title":       i18n.T(r.Context(), "auth_error.ceremony_mismatch.title"),
		"error":       i18n.T(r.Context(), "auth_error.ceremony_mismatch.message"),
		"_httpStatus": http.StatusBadRequest,
	}

	if err := pageRenderer.RenderTemplate(w, r, "/layouts/no_menu_layout.html", "/auth_error.html", bind); err != nil {
		pageRenderer.InternalServerError(w, r, err)
	}
}

// loadAuthContext reads the ceremony's auth context for a gated route, and answers the request
// itself when there is none to read or it is not the one the request names. It reports false when it
// answered, and the caller then returns without writing anything.
//
//   - A missing context redirects to the account page with a warn line, since a visitor who reaches a
//     step after the ceremony ended has nothing to resume and somewhere better to be. The load comes
//     first for that reason: a request naming any ceremony, or none, still ends there when nothing is
//     stored.
//   - A request that does not name the stored ceremony is rejectCeremonyMismatch's 400, before
//     requireAuthState and before anything else is read: a submission never reaches a credential check
//     and a page load never reaches a step's loads (#79 for the forms, #246 and #437 for the pages).
//   - Any other failure is a 500.
//
// Every step names its ceremony because a browser holds ONE auth context, so a second
// /auth/authorize replaces it while every tab of the first is still open. A form carries the id in its
// body and a page load in the URL every redirect between the steps builds (ceremonyStepURL). Without
// the second half, a tab of the replaced sign-in that reached its next step acted on the newer
// sign-in and could finish another application's authorization (#246 decision 22). Take the
// comparison out and every step accepts any request while a context is stored, silently, since the
// flows that follow their own redirects still pass.
func loadAuthContext(pageRenderer PageRenderer, ceremonyStore CeremonyStore, auditLogger AuditLogger,
	w http.ResponseWriter, r *http.Request, adminConsoleBaseURL string) (*ceremony.AuthContext, bool) {

	authContext, err := ceremonyStore.GetAuthContext(r)
	if err != nil {
		if errors.Is(err, ceremony.ErrNoAuthContext) {
			var profileUrl = profileURL(adminConsoleBaseURL)
			slog.WarnContext(r.Context(), "auth context is missing, redirecting", "redirect", profileUrl)
			http.Redirect(w, r, profileUrl, http.StatusFound)
		} else {
			pageRenderer.InternalServerError(w, r, err)
		}
		return nil, false
	}

	if !ceremonyMatches(authContext.CeremonyId, submittedCeremonyId(r)) {
		rejectCeremonyMismatch(pageRenderer, auditLogger, w, r, authContext)
		return nil, false
	}
	return authContext, true
}

// submittedCeremonyId is the ceremony id a request to a step names: the form's field on a POST, and
// the URL's parameter on anything else.
//
// A POST reads its body alone, with r.PostFormValue and not r.FormValue: these forms post to
// action="", so r.Form would let /auth/pwd?ceremonyId=... supply the id, and only the submitted body
// is a submission. The URL's parameter is named differently on purpose (ceremony.QueryParameter), so
// even a query naming the field can never satisfy a POST, and on a POST the query is not read at all,
// so the current id in the URL of a stale form's page cannot stand in for the one the form carries
// (#79, #437).
func submittedCeremonyId(r *http.Request) string {
	if r.Method == http.MethodPost {
		return r.PostFormValue(ceremonyIdField)
	}
	return r.URL.Query().Get(ceremony.QueryParameter)
}

// ceremonyStepURL is where a ceremony's next step is: the route under the base URL, naming the
// ceremony the step belongs to. Every redirect between two ceremony routes is built here, and with
// url.Values, so the parameter is written once and the id is encoded rather than trusted to need no
// escaping.
func ceremonyStepURL(baseURL string, path string, authContext *ceremony.AuthContext) string {
	return baseURL + path + "?" + url.Values{ceremony.QueryParameter: {authContext.CeremonyId}}.Encode()
}

// requireAuthState is every gated route's check that the ceremony is on a step the route accepts.
// When it is not, it renders the error page at 400, logs the accepted states and the actual one at
// warn, and reports false; the caller then returns without writing anything.
//
// A mismatch is a client's mistake and not a server fault. The ordinary way to reach one is the Back
// button: the browser returns to /auth/pwd after the password was accepted, the context has moved on
// to level1_password_completed, and a 500 page with a stack would tell the visitor the server had
// broken. RFC 9110 section 15.5.1 is the fit, "the server cannot or will not process the request due
// to something that is perceived to be a client error"; 15.6.1's 500 is for "an unexpected
// condition", and a stale tab is not unexpected (#279 decision 21, #248 part 1). Every route answers
// through here, /auth/level1completed with its two accepted states included, so no gate can drift
// back to a 500 on its own (#436).
//
// warn rather than error, and with both sides named: the pair is the whole diagnosis, and an
// operator watching error-level lines should not be paged by a Back button. There is no stack
// because there is no failure to trace to a line of code.
//
// The auth context is deliberately NOT touched, for rejectCeremonyMismatch's reason: the state it
// holds belongs to the step the user is actually on, and advancing or clearing it here would let a
// stale page cancel a live authorization. The client is not told either, for the same reason.
func requireAuthState(pageRenderer PageRenderer, w http.ResponseWriter, r *http.Request,
	authContext *ceremony.AuthContext, accepted ...ceremony.AuthState) bool {

	if authContext.InState(accepted...) {
		return true
	}

	acceptedStates := make([]string, len(accepted))
	for i, state := range accepted {
		acceptedStates[i] = string(state)
	}
	slog.WarnContext(r.Context(), "auth state mismatch, refusing the request",
		"accepted_states", acceptedStates, "actual_state", string(authContext.AuthState))

	bind := map[string]interface{}{
		"title":       i18n.T(r.Context(), "auth_error.state_mismatch.title"),
		"error":       i18n.T(r.Context(), "auth_error.state_mismatch.message"),
		"_httpStatus": http.StatusBadRequest,
	}

	if err := pageRenderer.RenderTemplate(w, r, "/layouts/no_menu_layout.html", "/auth_error.html", bind); err != nil {
		pageRenderer.InternalServerError(w, r, err)
	}
	return false
}
