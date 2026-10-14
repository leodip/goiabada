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
// Constant time, like emailedCodeMatches and the client secret comparison in
// protocolvalidation.ValidateTokenRequest. Not because this value is guessed at, but because a
// plain comparison stopping at the first differing byte is the kind of thing that is cheap to avoid
// and expensive to notice later.
func ceremonyMatches(contextCeremonyId string, submitted string) bool {
	if contextCeremonyId == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(contextCeremonyId), []byte(submitted)) == 1
}

// CeremonyBoundary is what every step of an authorization ceremony does at its route boundary,
// before and after the step's own work: load the auth context and check that the request names it,
// gate on the state the step accepts, redirect to the next step, and answer a save, clear or rotation
// that failed. The route table builds one and hands it to every step handler, so these answers are
// written once and no step can drift from them.
//
// It never decides a step and never writes the browser session: a step's saves and clears go through
// the ceremony store the handler holds. The boundary only reads the auth context.
type CeremonyBoundary struct {
	pageRenderer        PageRenderer
	ceremonyStore       CeremonyStore
	auditLogger         AuditLogger
	baseURL             string
	adminConsoleBaseURL string
}

// NewCeremonyBoundary builds the route boundary every step handler shares. baseURL is the auth
// server's, which the step redirects are built under; adminConsoleBaseURL is the console's, where a
// visitor with no ceremony left is sent.
func NewCeremonyBoundary(pageRenderer PageRenderer, ceremonyStore CeremonyStore, auditLogger AuditLogger,
	baseURL string, adminConsoleBaseURL string) *CeremonyBoundary {

	return &CeremonyBoundary{
		pageRenderer:        pageRenderer,
		ceremonyStore:       ceremonyStore,
		auditLogger:         auditLogger,
		baseURL:             baseURL,
		adminConsoleBaseURL: adminConsoleBaseURL,
	}
}

// rejectCeremonyMismatch answers a request that names a ceremony the session no longer holds, or
// none: audit it, then render the "no longer active" page at 400.
//
// The auth context is not touched. The ceremony that is current is the one the user is working on,
// in another tab, and clearing or advancing it here would let a forgotten tab cancel a live
// authorization. The client is not told either: the client that would receive an error is the
// current one, whose authorization the user still wants (#79 decision 5).
func (b *CeremonyBoundary) rejectCeremonyMismatch(w http.ResponseWriter, r *http.Request,
	authContext *ceremony.AuthContext) {

	const maxAuditedValueLength = 100

	// httpmw.RealIP resolves the IP from a forwarded header in a proxied deployment, so the value
	// originates outside the process and is bounded before it reaches the audit log.
	clientIP := middleware.ClientIP(r)
	if len(clientIP) > maxAuditedValueLength {
		clientIP = clientIP[:maxAuditedValueLength]
	}

	details := map[string]interface{}{
		"client_identifier": authContext.ClientId,
		"auth_state":        string(authContext.AuthState),
		"ip":                clientIP,
	}
	// Absent rather than zero when the ceremony has not identified anyone yet, which is every
	// submission of the password form: a payload naming user 0 asserts a row that does not exist.
	if authContext.UserId != 0 {
		details["user_id"] = authContext.UserId
	}
	b.auditLogger.Log(r.Context(), audit.EventAuthCeremonyMismatch, details)

	b.renderCeremonyNoLongerActive(w, r)
}

// renderCeremonyNoLongerActive renders the page a ceremony this browser has replaced is answered
// with, at 400, touching no auth context. It answers a request naming another ceremony
// (rejectCeremonyMismatch), a step whose save found another ceremony in the session
// (answerCeremonyReplaced), and /auth/completed's bind that found a newer sign-in already on the
// session (#538).
func (b *CeremonyBoundary) renderCeremonyNoLongerActive(w http.ResponseWriter, r *http.Request) {
	bind := map[string]interface{}{
		"title":       i18n.T(r.Context(), "auth_error.ceremony_mismatch.title"),
		"error":       i18n.T(r.Context(), "auth_error.ceremony_mismatch.message"),
		"_httpStatus": http.StatusBadRequest,
	}

	if err := b.pageRenderer.RenderTemplate(w, r, "/layouts/no_menu_layout.html", "/auth_error.html", bind); err != nil {
		b.pageRenderer.InternalServerError(w, r, err)
	}
}

// answerStepSaveFailure answers a step whose save or clear of its auth context, or rotation of the
// browser session's identifier, failed. A failure that found the browser session no longer holding
// this ceremony (ceremony.ErrCeremonyReplaced) wrote nothing and is answerCeremonyReplaced's; any
// other failure is a 500.
func (b *CeremonyBoundary) answerStepSaveFailure(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, ceremony.ErrCeremonyReplaced) {
		b.answerCeremonyReplaced(w, r)
		return
	}
	b.pageRenderer.InternalServerError(w, r, err)
}

// answerCeremonyReplaced answers a step whose save or clear found the browser session no longer
// holding its ceremony: another /auth/authorize replaced it, it ended, or the session is gone. That
// write changed nothing, and the answer is the "no longer active" page at 400, so the newer sign-in
// carries on (#579). Whatever the step would otherwise have answered, an error redirect, a refusal
// page or a code, is not sent: nothing goes to the client, for rejectCeremonyMismatch's reason. Logged
// at warn and audited nowhere, because the request named its ceremony correctly and so is no ceremony
// mismatch (#578).
func (b *CeremonyBoundary) answerCeremonyReplaced(w http.ResponseWriter, r *http.Request) {
	slog.WarnContext(r.Context(), "the browser session no longer holds this ceremony, answering it as no longer active")
	b.renderCeremonyNoLongerActive(w, r)
}

// loadAuthContext reads the ceremony's auth context for a step, and answers the request itself when
// there is none or it is not the one the request names. It reports false when it answered, and the
// caller then returns without writing anything.
//
//   - A missing context redirects to the account page with a warn line: a visitor who reaches a step
//     after the ceremony ended has nothing to resume. The load comes first, so a request naming any
//     ceremony, or none, ends there when nothing is stored.
//   - A request that does not name the stored ceremony is rejectCeremonyMismatch's 400, before the
//     state gate and before anything else is read: a submission never reaches a credential check and
//     a page load never reaches a step's loads (#79 for the forms, #246 and #437 for the pages).
//   - Any other failure is a 500.
//
// A browser holds one auth context, so a second /auth/authorize replaces it while every tab of the
// first is still open. A form names its ceremony in its body and a page load in the URL every step
// redirect builds (stepRedirect). Without the comparison, a tab of the replaced sign-in that reached
// its next step would act on the newer sign-in and could finish another application's authorization
// (#246 decision 22).
func (b *CeremonyBoundary) loadAuthContext(w http.ResponseWriter, r *http.Request) (*ceremony.AuthContext, bool) {
	authContext, err := b.ceremonyStore.GetAuthContext(r)
	if err != nil {
		if errors.Is(err, ceremony.ErrNoAuthContext) {
			var profileUrl = profileURL(b.adminConsoleBaseURL)
			slog.WarnContext(r.Context(), "auth context is missing, redirecting", "redirect", profileUrl)
			http.Redirect(w, r, profileUrl, http.StatusFound)
		} else {
			b.pageRenderer.InternalServerError(w, r, err)
		}
		return nil, false
	}

	if !ceremonyMatches(authContext.CeremonyId, submittedCeremonyId(r)) {
		b.rejectCeremonyMismatch(w, r, authContext)
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

// stepRedirect answers with a 302 to the ceremony's next step, at path under the auth server's base
// URL and naming the ceremony (ceremonyStepURL).
func (b *CeremonyBoundary) stepRedirect(w http.ResponseWriter, r *http.Request, path string,
	authContext *ceremony.AuthContext) {

	//nolint:gosec // G710: every path is one of the ceremony's own routes, a constant at each caller, under the configured base URL
	http.Redirect(w, r, ceremonyStepURL(b.baseURL, path, authContext), http.StatusFound)
}

// requireAuthState is every step's check that the ceremony is on a step the route accepts. When it is
// not, it renders the state mismatch page at 400, logs the accepted states and the actual one at warn,
// and reports false; the caller then returns without writing anything.
//
// A mismatch is a client's mistake and not a server fault. The ordinary way to reach one is the Back
// button: the browser returns to /auth/pwd after the password was accepted and the context has moved
// on to level1_password_completed. RFC 9110 section 15.5.1 fits, "the server cannot or will not process
// the request due to something that is perceived to be a client error"; 15.6.1's 500 is for "an
// unexpected condition", and a stale tab is not unexpected (#279 decision 21, #248 part 1, #436).
//
// Warn rather than error, with both sides named: the pair is the whole diagnosis, and an operator
// watching error-level lines should not be paged by a Back button. There is no stack because there is
// no failure to trace.
//
// The auth context is not touched, for rejectCeremonyMismatch's reason: the state belongs to the step
// the user is actually on, and advancing or clearing it here would let a stale page cancel a live
// authorization. The client is not told either.
func (b *CeremonyBoundary) requireAuthState(w http.ResponseWriter, r *http.Request,
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

	if err := b.pageRenderer.RenderTemplate(w, r, "/layouts/no_menu_layout.html", "/auth_error.html", bind); err != nil {
		b.pageRenderer.InternalServerError(w, r, err)
	}
	return false
}
