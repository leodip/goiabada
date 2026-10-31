package handlers

import (
	"context"
	"database/sql"
	"io/fs"
	"log/slog"
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/urlmatch"
	"github.com/leodip/goiabada/authserver/web"
	"github.com/leodip/goiabada/core/loopback"
	"github.com/leodip/goiabada/core/oauth"
)

// clientErrorDatabase is what the client-error responder reads: the redirect URIs a client has
// registered now, for the registration gate. data.Database satisfies it.
type clientErrorDatabase interface {
	GetRedirectURIsByClientId(ctx context.Context, tx *sql.Tx, clientId int64) ([]record.RedirectURI, error)
}

// ClientErrorResponder answers a client with an authorization error response: it decides whether
// the response may leave this server at all (RedirectWillBeEmitted's four gates), writes it in the
// query, the fragment or a form_post, renders the refusal interstitial in its place when it may not,
// and answers server_error when the step's clear of its auth context failed. The route table builds
// one and hands it to every handler that answers a client with an error.
//
// It writes the HTTP response and nothing else: it never saves or clears an auth context. A caller
// clears first and then answers through here, because every response mode commits the response, and
// a Set-Cookie written after it would leave the browser holding an auth context it can replay (#141).
type ClientErrorResponder struct {
	database     clientErrorDatabase
	pageRenderer PageRenderer
	// formPostFS is where form_post.html is read from, for an error and for a success response alike.
	formPostFS fs.FS
}

// NewClientErrorResponder builds the responder. Its form_post page is the built-in one whatever
// GOIABADA_AUTHSERVER_TEMPLATEDIR says, so no constructor parameter can hand it the directory: the
// page encodes an authorization response, and an operator's copy taken from an older release would
// drop iss while discovery advertises it, which RFC 9207 section 2.4 has a client reject (#576,
// decision 5).
func NewClientErrorResponder(database clientErrorDatabase, pageRenderer PageRenderer) *ClientErrorResponder {
	return &ClientErrorResponder{
		database:     database,
		pageRenderer: pageRenderer,
		formPostFS:   web.TemplateFS(),
	}
}

// redirectErrorInput carries what an error response to a client is built from: what to say, where
// and how to say it, and which client is being answered, since RFC 9700 4.11.2 makes the source of
// the redirect URI an input to whether it is trusted (#108).
type redirectErrorInput struct {
	// client is the client being answered, or nil when its provenance could not be resolved
	// (authflow.ClientError.Client). Nil means "provenance unknown", never "there is no client": the trust
	// decision is about where the redirect URI came from, so an unresolved client is the
	// untrusted case rather than an exempt one.
	client *record.Client

	code         string
	description  string
	responseMode string
	redirectURI  string
	state        string
	responseType string

	// redirectAlreadyWithheld records that RedirectWillBeEmitted has already answered no for this
	// request, so the emitter does not ask again. It is a floor, never a ceiling: false means
	// "nothing has refused yet", not "a redirect is permitted", and the emitter still runs the live
	// gates on top of it.
	//
	// The registration gate reads the database, so the two answers one authorization request can get
	// may differ. authflow.Authorization asks before routing, and a refusal there is what lets it answer a
	// validation failure at once instead of parking it behind a login: no redirect leaves this server,
	// so RFC 9700 4.11.2 has nothing to govern. Were the emitter to ask again and get yes (a transient
	// read failure the first time, or the callback re-added between the reads), a logged-out browser
	// holding one crafted link would be redirected to the client's host on a request this server
	// refused, which is attack 1 of RFC 9700 4.11.2 (#213, #241). So a later read may narrow yes to
	// no, and may never widen no to yes.
	redirectAlreadyWithheld bool
}

// redirectErrorFromAuthContext builds the input for an error response whose parameters come from
// the ceremony, which is where every error response takes them from. At /auth/authorize that is the
// context authflow.Authorization has just built, holding the four as the request sent them before
// anything is validated, so an error arising there answers what the request carried.
func redirectErrorFromAuthContext(authContext *ceremony.AuthContext, client *record.Client,
	code string, description string) redirectErrorInput {

	return redirectErrorInput{
		client:       client,
		code:         code,
		description:  description,
		responseMode: authContext.ResponseMode,
		redirectURI:  authContext.RedirectURI,
		state:        authContext.State,
		responseType: authContext.ResponseType,
	}
}

// answerClientAfterClear answers the client with input once the step's clear of its auth context
// has run, or with server_error when the clear failed (clearErr non-nil): the browser then still
// holds the auth context, but the client's redirect URI was validated upstream, so OIDC Core 1.0
// 3.1.2.2 with 3.1.2.6 applies and RFC 6749 4.1.2.1 mints server_error for this condition (#141).
// The fallback is the caller's own input with its code and description swapped. When even that
// response cannot be written, the 500 page is the last resort.
func (rsp *ClientErrorResponder) answerClientAfterClear(w http.ResponseWriter, r *http.Request,
	input redirectErrorInput, clearErr error) {

	if clearErr != nil {
		slog.ErrorContext(r.Context(), "unable to clear the auth context, answering the client with server_error",
			"error", clearErr)

		fallback := input
		fallback.code = "server_error"
		fallback.description = "Internal server error"

		err := rsp.redirToClientWithError(w, r, fallback)
		if err != nil {
			rsp.pageRenderer.InternalServerError(w, r, err)
		}
		return
	}

	err := rsp.redirToClientWithError(w, r, input)
	if err != nil {
		rsp.pageRenderer.InternalServerError(w, r, err)
		return
	}
}

// RedirectWillBeEmitted answers whether an error response to this client would leave the server as a
// redirect, or would be withheld and replaced by the refusal interstitial. It is four gates asked as
// one question, so the callers that need the answer before building a response and the emitter that
// enforces it cannot drift apart. site names the caller for the log line; the URI itself is never
// logged (#159).
//
// The provenance gate. RFC 9700 4.11.2: an attacker who registers a client anonymously can use this
// server's own error redirect to deliver a victim to a host they control, by getting the user to
// decline (attack 2), by sending a deliberately invalid request (attack 1), or by sending a valid
// silent request with prompt=none (attack 3). The RFC leaves "trusted" to the server and names the
// source of the redirect URI among its inputs, so a client that registered itself is untrusted and an
// administrator-registered one, whose redirect URI a person vetted, is not. An unresolved client is
// untrusted too. A silent request is not exempt: attack 3 needs neither a session nor any victim
// interaction. OIDC Core 3.1.2.1 is not violated by rendering the interstitial for one, since that
// page asks for neither authentication nor consent; the cost, accepted knowingly, is that a
// self-registered client's silent renewal receives no readable error and falls back to an
// interactive authorization (#108 decision 15).
//
// The insecure-http gate: the redirect URI is not plain http off the loopback interface. RFC 9700
// section 2.6 forbids carrying an authorization response over cleartext, and an error response is
// one (RFC 6749 4.1.2.1). /auth/authorize refuses a request for such a URI, so only a ceremony it
// validated before that refusal existed reaches here, when a step in between answers with an error,
// consent declined among them. That is expected rather than a bypassed gate, so it is asked here,
// with a Warn record naming the client, before the emittability gate would log an Error (#590).
//
// The emittability gate: whether the string can name the host it appears to
// (checkRedirectURIEmittable). An administrator-registered client passes the provenance gate and can
// still hold a stored URI that does not. Unreachable once the authorization endpoint has refused the
// URI; kept so that a test enforces it (#122).
//
// The registration gate, the only one that reads anything: the redirect URI must still be one the
// client has registered now. A ceremony can sit on the consent screen as long as a person takes to
// read it, and an administrator who deletes a callback in that window expects the deletion to reach
// the sign-in already running. Every error response from a ceremony in progress navigates the browser
// to the URI stored when it began, so the check lives in the one predicate they share (#241 decision
// 11). Loopback port flexibility follows the response type, exactly as at
// protocolvalidation.ValidateClientAndRedirectURI and /auth/issue: RFC 8252 section 7.3 makes
// http://127.0.0.1:49152/cb covered by a registered http://127.0.0.1/cb on a code request, and calling
// it unregistered here would withhold an error RFC 6749 4.1.2.1 says the client is owed. Every
// implicit response stays strict.
//
// A failed load answers no: an unresolved answer is the untrusted case, as an unresolved client is.
//
// This predicate is asked twice within one authorization request, first by authflow.Authorization
// through its port, and the second answer may not be more permissive than the first: see
// redirectErrorInput.redirectAlreadyWithheld.
func (rsp *ClientErrorResponder) RedirectWillBeEmitted(ctx context.Context, client *record.Client, redirectURI string,
	responseType string, site string) bool {

	if client == nil || client.CreatedViaDCR {
		return false
	}

	// Asked of an absolute URI only, so a non-absolute one still reaches the emittability gate's
	// Error: that one is a bypassed gate, whatever its scheme.
	if urlmatch.IsAbsoluteRedirectURI(redirectURI) && loopback.IsPlainHTTPOff(redirectURI) {
		// The client identifier is a bounded stored value and is safe to log; the URI is not (#159).
		slog.WarnContext(ctx, "the redirect URI this client would be answered at uses plain http off the loopback interface, so the redirect is withheld",
			"client_identifier", client.ClientIdentifier, "site", site)
		return false
	}

	if err := checkRedirectURIEmittable(ctx, site, redirectURI); err != nil {
		return false
	}

	redirectURIs, err := rsp.database.GetRedirectURIsByClientId(ctx, nil, client.Id)
	if err != nil {
		// The client identifier is a bounded stored value and is safe to log; the URI is not (#159).
		slog.ErrorContext(ctx, "unable to load the client's redirect URIs while answering it with an error, withholding the redirect",
			"client_identifier", client.ClientIdentifier, "site", site, "error", err)
		return false
	}

	registered := make([]string, 0, len(redirectURIs))
	for _, uri := range redirectURIs {
		registered = append(registered, uri.URI)
	}

	// IsCodeOnly, for the reason stated at protocolvalidation.ValidateClientAndRedirectURI: only the
	// exact type "code" buys an arbitrary loopback port (#244).
	allowLoopbackPortFlexibility := protocolvalidation.ParseResponseType(responseType).IsCodeOnly()

	if !urlmatch.RedirectURIIsRegistered(registered, redirectURI, allowLoopbackPortFlexibility) {
		slog.WarnContext(ctx, "the redirect URI this client would be answered at is no longer registered on it, so the redirect is withheld",
			"client_identifier", client.ClientIdentifier, "site", site)
		return false
	}

	return true
}

// redirToClientWithError answers the client with an error response, or renders the refusal
// interstitial in its place when RedirectWillBeEmitted, or an earlier refusal carried on the input,
// says the redirect may not leave this server. It returns an error only when no response could be
// written, and the caller then answers 500.
//
// The gates come first, above the response-mode dispatch, so they cover query, fragment and form_post
// alike, and they can only withhold: nothing below is reached, no state is written and no route is
// added, so there is nothing here for an attacker to drive (#108, #122, #241).
//
// The parameters, in the order they reach the client:
//   - error, then error_description, conformed to RFC 6749 Appendix A.8's NQSCHAR once, here, since
//     descriptions interpolate request text (#213). The interstitial is a user interface and not a
//     protocol parameter, so it keeps the text as the validator wrote it.
//   - state, when its value is non-empty, byte for byte and untrimmed. RFC 6749 section 3.1 treats a
//     parameter sent without a value as omitted, Appendix A.5 admits no empty state in a response,
//     and 4.1.2.1 requires "the exact value received from the client", so a whitespace-only state is
//     a real one (#146). The end_session_endpoint differs because its specification does: see
//     buildPostLogoutRedirect.
//   - iss, which writeAuthorizationResponse appends to every authorization response (RFC 9207).
//
// An implicit response type's error goes in the fragment, or in the form_post the request asked for,
// never in the query, per RFC 6749 4.2.2.1 and OIDC Core 3.2.2.5 (implicitResponseMode, #231).
func (rsp *ClientErrorResponder) redirToClientWithError(w http.ResponseWriter, r *http.Request,
	input redirectErrorInput) error {

	if input.redirectAlreadyWithheld ||
		!rsp.RedirectWillBeEmitted(r.Context(), input.client, input.redirectURI, input.responseType,
			"redirToClientWithError") {
		return rsp.renderRedirectBlocked(w, r, input)
	}

	description := oauth.ConformErrorDescription(input.description)

	rtInfo := protocolvalidation.ParseResponseType(input.responseType)
	effectiveResponseMode := input.responseMode
	if rtInfo.IsImplicitFlow() {
		effectiveResponseMode = implicitResponseMode(input.responseMode)
	}

	params := []responseParam{
		{"error", input.code},
		{"error_description", description},
	}
	if input.state != "" {
		params = append(params, responseParam{"state", input.state})
	}

	return writeAuthorizationResponse(w, r, rsp.formPostFS, effectiveResponseMode, input.redirectURI, params)
}
