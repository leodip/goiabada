package handlers

import (
	"errors"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/middleware"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/render"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/i18n"
)

// CeremonyBoundary is what every step of an authorization ceremony does at its route boundary,
// before and after the step's own work: load the auth context and check that the request names it,
// gate on the state the step accepts, redirect to the next step, and answer a save, clear or rotation
// that failed. The route table builds one and hands it to every step handler, so these answers are
// written once and no step can drift from them.
//
// It never decides a step and never writes the browser session: a step's saves, clears and rotations
// go through the per-request adapter (browserSession) its authflow operation writes through. The
// boundary only reads the auth context.
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

// beginStep is what a step does before its own work, in order: read the request's settings, load
// the auth context and check the ceremony id (loadAuthContext), and gate on the states the step
// accepts (requireAuthState). It reports false when it answered, and the caller then returns without
// writing anything.
//
// The settings come first, before anything is read or written. middleware.Settings runs on every
// application route and answers its own failure, so a step without settings is a wiring defect; it
// answers the 500 page carrying reqctx.ErrNoSettings and reads no ceremony. A step hands the
// settings to its operation as a plain value (#580 decision 5).
func (b *CeremonyBoundary) beginStep(w http.ResponseWriter, r *http.Request,
	accepted ...ceremony.AuthState) (*record.Settings, *ceremony.AuthContext, bool) {

	settings, ok := reqctx.SettingsFrom(r.Context())
	if !ok {
		b.pageRenderer.InternalServerError(w, r, reqctx.ErrNoSettings)
		return nil, nil, false
	}

	authContext, ok := b.loadAuthContext(w, r)
	if !ok {
		return nil, nil, false
	}

	if !b.requireAuthState(w, r, authContext, accepted...) {
		return nil, nil, false
	}
	return settings, authContext, true
}

// redirectAfterSave answers a step that saved its ceremony towards nextStep: the redirect to it when
// the save landed, and answerStepSaveFailure's answer when it did not.
func (b *CeremonyBoundary) redirectAfterSave(w http.ResponseWriter, r *http.Request,
	authContext *ceremony.AuthContext, nextStep string, saveErr error) {

	if saveErr != nil {
		b.answerStepSaveFailure(w, r, saveErr)
		return
	}
	b.stepRedirect(w, r, nextStep, authContext)
}

// rejectCeremonyMismatch answers a request that names a ceremony the session no longer holds, or
// none: audit it, recording authContext, the ceremony the browser most recently wrote, then render the
// "no longer active" page at 400.
//
// No auth context is touched. The ceremonies the browser holds are the ones the user is working on,
// in other tabs, and clearing or advancing one here would let a forgotten tab cancel a live
// authorization. The client is not told either: the client that would receive an error is one whose
// authorization the user still wants (#79 decision 5).
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
// holding its ceremony: another request of it ended it, newer sign-ins pushed it out, or the session
// is gone. That write changed nothing, and the answer is the "no longer active" page at 400, so the
// sign-ins the browser holds carry on (#579, #246). Whatever the step would otherwise have answered, an error redirect, a refusal
// page or a code, is not sent: nothing goes to the client, for rejectCeremonyMismatch's reason. Logged
// at warn and audited nowhere, because the request named its ceremony correctly and so is no ceremony
// mismatch (#578).
func (b *CeremonyBoundary) answerCeremonyReplaced(w http.ResponseWriter, r *http.Request) {
	slog.WarnContext(r.Context(), "the browser session no longer holds this ceremony, answering it as no longer active")
	b.renderCeremonyNoLongerActive(w, r)
}

// loadAuthContext reads the ceremony a step's request names, and answers the request itself when
// the browser holds none or not that one. It reports false when it answered, and the caller then
// returns without writing anything.
//
// The store reads the ceremony the request names (ceremony.Store.GetAuthContext, through
// ceremony.RequestedId): a form names its ceremony in its body and a page load in the URL every step
// redirect builds (stepRedirect). Without that, a tab of a sign-in the browser no longer holds that
// reached its next step would act on another sign-in and could finish another application's
// authorization (#246 decision 22).
//
//   - A browser holding no ceremony at all is redirected to the account page with a warn line: a
//     visitor who reaches a step after the ceremony ended has nothing to resume, whatever the
//     request names.
//   - A request naming a ceremony the browser does not hold, or none, while it holds others, is
//     rejectCeremonyMismatch's 400, before the state gate and before anything else is read: a
//     submission never reaches a credential check and a page load never reaches a step's loads (#79
//     for the forms, #246 and #437 for the pages). The audit event records the ceremony the browser
//     most recently wrote (ceremony.Store.LatestAuthContext).
//   - Any other failure is a 500.
func (b *CeremonyBoundary) loadAuthContext(w http.ResponseWriter, r *http.Request) (*ceremony.AuthContext, bool) {
	authContext, err := b.ceremonyStore.GetAuthContext(r)
	switch {
	case err == nil:
		return authContext, true
	case errors.Is(err, ceremony.ErrNoAuthContext):
		var profileUrl = profileURL(b.adminConsoleBaseURL)
		slog.WarnContext(r.Context(), "auth context is missing, redirecting", "redirect", profileUrl)
		http.Redirect(w, r, profileUrl, redirectStatus(r))
	case errors.Is(err, ceremony.ErrCeremonyNotHeld):
		latest, latestErr := b.ceremonyStore.LatestAuthContext(r)
		if latestErr != nil {
			b.pageRenderer.InternalServerError(w, r, latestErr)
			return nil, false
		}
		b.rejectCeremonyMismatch(w, r, latest)
	default:
		b.pageRenderer.InternalServerError(w, r, err)
	}
	return nil, false
}

// ceremonyStepURL is where a ceremony's next step is: the route under the base URL, naming the
// ceremony the step belongs to. Every redirect between two ceremony routes is built here, and with
// url.Values, so the parameter is written once and the id is encoded rather than trusted to need no
// escaping.
func ceremonyStepURL(baseURL string, path string, authContext *ceremony.AuthContext) string {
	return baseURL + path + "?" + url.Values{ceremony.QueryParameter: {authContext.CeremonyId}}.Encode()
}

// stepRedirect redirects to the ceremony's next step, at path under the auth server's base URL and
// naming the ceremony (ceremonyStepURL), with redirectStatus's code. path is always one of the
// ceremony's own routes, a constant in the step's handler or its authflow operation, never anything
// the request carries.
func (b *CeremonyBoundary) stepRedirect(w http.ResponseWriter, r *http.Request, path string,
	authContext *ceremony.AuthContext) {

	http.Redirect(w, r, ceremonyStepURL(b.baseURL, path, authContext), redirectStatus(r))
}

// redirectStatus is the code of every redirect the sign-in ceremony sends: 303 when it answers a
// POST, and 302 when it answers anything else. RFC 9700 section 4.12 says a redirect of a request
// that "potentially contains the user's credentials" MUST NOT be 307 and SHOULD be 303, which RFC 9110
// section 15.4.4 has the browser follow with a GET, so the form's body is never sent on. A 302 leaves
// the method to the browser (section 15.4.3). The password, one-time code and consent submissions,
// a POST that finds no ceremony, and the declined consent's redirect to the client all answer a POST;
// a step reached by a GET keeps its 302, which changes nothing for it (#576, decision 6).
func redirectStatus(r *http.Request) int {
	if r.Method == http.MethodPost {
		return http.StatusSeeOther
	}
	return http.StatusFound
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
		// The page belongs to a sign-in for this app, so its footer links the app's own legal
		// documents as well (#622).
		render.LegalFooterClient: authContext.ClientId,
	}

	if err := b.pageRenderer.RenderTemplate(w, r, "/layouts/no_menu_layout.html", "/auth_error.html", bind); err != nil {
		b.pageRenderer.InternalServerError(w, r, err)
	}
	return false
}
