package handlers

import (
	"bytes"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"time"

	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/pkg/errors"
)

func HandleIssueGet(
	httpHelper HttpHelper,
	authHelper AuthHelper,
	templateFS fs.FS,
	codeIssuer CodeIssuer,
	tokenIssuer TokenIssuer,
	database data.Database,
	auditLogger AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authContext, err := authHelper.GetAuthContext(r)
		if err != nil {
			if errDetail, ok := err.(*customerrors.ErrorDetail); ok && errDetail.IsError(customerrors.ErrNoAuthContext) {
				var profileUrl = GetProfileURL()
				slog.Warn(fmt.Sprintf("auth context is missing, redirecting to %v", profileUrl))
				http.Redirect(w, r, profileUrl, http.StatusFound)
			} else {
				httpHelper.InternalServerError(w, r, err)
			}
			return
		}

		requiredState := oauth.AuthStateReadyToIssueCode
		if authContext.AuthState != requiredState {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("authContext.AuthState is not "+requiredState)))
			return
		}

		// id_token_hint sub enforcement (OIDC Core 3.1.2.2, Authentication Request Validation):
		// "The Authorization Server MUST NOT reply with an ID Token or Access Token for a
		// different user, even if they have an active session with the Authorization Server."
		// This is the critical safety net that catches mismatched users even after successful authentication.
		if authContext.IdTokenHintSub != "" {
			user, err := database.GetUserById(nil, authContext.UserId)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
			if user == nil || user.Subject.String() != authContext.IdTokenHintSub {
				// Cannot issue tokens for a different user than the hint identifies.
				//
				// This handler issues codes and tokens rather than loading clients, so the only
				// client load in the file sits inside handleImplicitFlow, far below and in a
				// different function. An error redirect now carries the client it is answering, so
				// provenance is resolved here, ahead of the dispatch (#108).
				//
				// The clear goes FIRST, the order the prompt=none refusal below and the success
				// path both use. ClearAuthContext persists the deletion through a Set-Cookie on
				// w, and redirToClientWithError commits the response in every response mode, so
				// clearing afterwards leaves the header on a response already written. This is
				// the one refusal that leaves the context in ready_to_issue_code, the state that
				// mints codes, so a browser keeping it can replay this endpoint with only the
				// comparison above standing between the replay and a code (#141).
				refusedClient := clientProvenance(database, authContext.ClientId)

				err := authHelper.ClearAuthContext(w, r)
				if err != nil {
					// The clear failed, so Save wrote no cookie and the browser still holds the
					// auth context. The client is owed an error response regardless: its redirect
					// URI was validated upstream, so OIDC Core 1.0 3.1.2.2 with 3.1.2.6 applies,
					// and RFC 6749 4.1.2.1 mints server_error for exactly this condition (#141).
					slog.Error("failed to clear the auth context, answering the client with server_error",
						"error", err)
					err = redirToClientWithError(w, r, httpHelper, templateFS,
						redirectErrorFromAuthContext(authContext, refusedClient, "server_error", "Internal server error"))
					if err != nil {
						// Nowhere left to send the client, so the 500 is the last resort here.
						httpHelper.InternalServerError(w, r, err)
					}
					return
				}

				err = redirToClientWithError(w, r, httpHelper, templateFS,
					redirectErrorFromAuthContext(authContext, refusedClient, constants.ErrorLoginRequired,
						"The authenticated user does not match the id_token_hint"))
				if err != nil {
					httpHelper.InternalServerError(w, r, err)
					return
				}
				return
			}
		}

		sessionIdentifier := ""
		if r.Context().Value(constants.ContextKeySessionIdentifier) != nil {
			sessionIdentifier = r.Context().Value(constants.ContextKeySessionIdentifier).(string)
		}

		// A ceremony must not bind a grant to a session that no longer exists (#129
		// decision 6, second half). The session was alive at /auth/completed, which bumped
		// or created it, and the user may then have spent minutes on the consent screen;
		// if it was ended in between, the grant minted below is brand new and no marker
		// written by the termination can reach it, because the row did not exist yet.
		//
		// An EMPTY identifier is the shape that case actually arrives in, not a stale one.
		// MiddlewareSessionIdentifier looks the session up on every request and puts the
		// identifier in the request context ONLY when the row exists, so the read above
		// yields "" for a ceremony whose session was ended. The non-empty branch below
		// covers the narrower race where the middleware saw the session alive on this very
		// request and the termination committed afterwards.
		//
		// Neither case is inert. grantIsOffline treats an empty session identifier as an
		// offline grant on its own, so a code issued here would yield an Offline refresh
		// token: it stores a max lifetime instead of a session identifier and the validator
		// never consults a session, which means it outlives the terminated session by up to
		// RefreshTokenOfflineMaxLifetimeInSeconds whether or not offline_access was asked
		// for.
		//
		// Liveness is not enough, though, which is what #133 adds: the row can resolve and
		// still belong to somebody else. User A is signed in, the browser holds A's session
		// cookie, and prompt=login or an id_token_hint sends user B through a fresh
		// authentication without the cookie ever being cleared. Binding B's grant to A's
		// session hands B a code or a token stamped with A's session identifier, which then
		// governs B's access by A's lifetimes and dies when A's session does. So the
		// question here is ownership, and liveness is the half of it that a missing row
		// already answers.
		//
		// Neither check is a validity check: they ask whether the row resolves and whose it
		// is, and leave idle timeout and max age to /auth/completed, which has already
		// applied them. Restarting level 1 rather than failing to the client is decision 6's
		// answer for the same reason the gate at /auth/completed uses it, and the second
		// pass mints a session of its own before arriving back here. It cannot loop: the
		// second visit to /auth/completed terminates the foreign session and starts one
		// owned by this ceremony.
		var ambientSession *models.UserSession
		if sessionIdentifier != "" {
			ambientSession, err = database.GetUserSessionBySessionIdentifier(nil, sessionIdentifier)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		// The gate sits ABOVE the response-type dispatch on purpose. handleImplicitFlow
		// copies sessionIdentifier straight into ImplicitGrantInput.SessionIdentifier and
		// never loads the session, so a response_type of token, id_token or id_token token
		// would otherwise mint a signed token for B carrying A's sid with every check in
		// this handler above it. The later backstops cannot cover that: a third-party
		// resource server validating an already-signed token has no way to compare the
		// session's owner against the token's subject (#133).
		isImplicitFlow := oauth.ParseResponseType(authContext.ResponseType).IsImplicitFlow()

		mayBind := authContext.OwnsSession(ambientSession)
		if isImplicitFlow && sessionIdentifier == "" {
			// No ambient session at all, so there is nothing to cross-bind to. The code flow
			// still refuses here, because #129 showed an empty identifier there produces an
			// Offline refresh token that outlives the session it came from. The implicit
			// flow issues no refresh token and its access token carries the identifier only
			// as a claim, so refusing would change behaviour in a case where no session is
			// being taken over. Whether implicit should require a session at all is a
			// separate question from this one (#133).
			mayBind = true
		}

		if !mayBind {
			// A session that resolves but belongs to another user gets its own line: "the
			// session backing this ceremony is gone" would be the wrong sentence, and an
			// operator reading it needs to see the two user ids that failed to match
			// (#133 decision 7).
			sessionIsForeign := ambientSession != nil

			// prompt=none is the one ceremony that cannot be restarted: /auth/level1 sends the
			// browser to /auth/pwd, which renders a form, and this request forbids any UI at
			// all (OIDC Core 3.1.2.1, and concepts/prompt-parameter.mdx says the same). Nothing
			// between here and the form reads the prompt, so the client would be handed a login
			// page and no error, and a silent-renewal iframe would wait for its own timeout
			// instead. It gets login_required instead (#129 decision 16), which is what
			// handlePromptNone itself returns when its session lookup finds no row: the
			// condition really is the same one, arriving one redirect hop later, so the client
			// cannot tell the two apart and does not need to. No code is minted on either
			// branch, so the fail-open decision 6 closes stays closed.
			if authContext.HasPromptValue("none") {
				if sessionIsForeign {
					slog.Warn("the session in this browser belongs to a different user, returning login_required instead of binding this silent ceremony to it",
						"sessionIdentifier", sessionIdentifier,
						"sessionUserId", ambientSession.UserId,
						"ceremonyUserId", authContext.UserId)
				} else {
					slog.Warn("the session backing this silent ceremony is gone, returning login_required instead of issuing a code",
						"sessionIdentifier", sessionIdentifier)
				}
				// The clear goes FIRST, which is the order the code path below uses too.
				// ClearAuthContext persists the deletion through a Set-Cookie on w, and
				// redirToClientWithError commits the response in every response mode, so
				// clearing afterwards leaves the header on a response already written and
				// the browser keeps a ready_to_issue_code context it can replay.
				//
				// Provenance is resolved before the dispatch, for the same reason as at the
				// id_token_hint refusal above: this handler holds no client of its own (#108).
				refusedClient := clientProvenance(database, authContext.ClientId)

				err := authHelper.ClearAuthContext(w, r)
				if err != nil {
					// Every error return in ChunkedCookieStore.Save is above its first
					// http.SetCookie, so a failed clear writes zero cookies and the browser keeps
					// the auth context whether this answers 500 or redirects. Withholding the
					// client's response therefore buys nothing, and the client is owed one: its
					// redirect URI was validated upstream, so OIDC Core 1.0 3.1.2.2 with 3.1.2.6
					// applies, and RFC 6749 4.1.2.1 mints server_error for exactly this
					// condition (#141).
					slog.Error("failed to clear the auth context, answering the client with server_error",
						"error", err)
					err = redirToClientWithError(w, r, httpHelper, templateFS,
						redirectErrorFromAuthContext(authContext, refusedClient, "server_error", "Internal server error"))
					if err != nil {
						// Nowhere left to send the client, so the 500 is the last resort here.
						httpHelper.InternalServerError(w, r, err)
					}
					return
				}
				err = redirToClientWithError(w, r, httpHelper, templateFS,
					redirectErrorFromAuthContext(authContext, refusedClient, constants.ErrorLoginRequired,
						"User authentication is required"))
				if err != nil {
					httpHelper.InternalServerError(w, r, err)
					return
				}
				return
			}

			if sessionIsForeign {
				slog.Warn("the session in this browser belongs to a different user, restarting level 1 instead of binding this ceremony to it",
					"sessionIdentifier", sessionIdentifier,
					"sessionUserId", ambientSession.UserId,
					"ceremonyUserId", authContext.UserId)
			} else {
				slog.Warn("the session backing this ceremony is gone, restarting level 1 instead of issuing a code",
					"sessionIdentifier", sessionIdentifier)
			}
			authContext.AuthState = oauth.AuthStateRequiresLevel1
			err = authHelper.SaveAuthContext(w, r, authContext)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, config.GetAuthServer().BaseURL+"/auth/level1", http.StatusFound)
			return
		}

		if isImplicitFlow {
			err = handleImplicitFlow(w, r, authContext, sessionIdentifier, authHelper, tokenIssuer, database, auditLogger)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
			return
		}

		// Authorization Code Flow

		createCodeInput := &oauth.CreateCodeInput{
			AuthContext:       *authContext,
			SessionIdentifier: sessionIdentifier,
		}
		code, err := codeIssuer.CreateAuthCode(createCodeInput)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		// The check above is a read followed by an insert, so a termination can commit
		// between the two. This compensates for that (#129 decision 12): the two sweepers
		// cover each other, since a code committing before the termination's UPDATE reads
		// the codes table is marked by the termination, and a code committing after it is
		// marked here. Only a code landing between that UPDATE and its COMMIT escapes both,
		// which is recorded as a residual in the #129 agreement rather than closed here.
		//
		// A failure is a 500 rather than a code handed over: the row exists and carries no
		// marker at this point, so returning it is exactly the fail-open this statement is
		// for. Unredeemed it expires in 60 seconds.
		codeRevoked, err := database.RevokeCodeIfSessionGone(nil, code.Id, sessionIdentifier)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if codeRevoked {
			slog.Warn("the session backing this ceremony was ended while its code was being issued, so the code was revoked",
				"codeId", code.Id, "sessionIdentifier", sessionIdentifier)
		}

		auditLogger.Log(constants.AuditCreatedAuthCode, map[string]interface{}{
			"userId":   createCodeInput.UserId,
			"clientId": code.ClientId,
			"codeId":   code.Id,
		})

		err = authHelper.ClearAuthContext(w, r)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		err = issueAuthCode(w, r, templateFS, code, authContext.ResponseMode)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
		}
	}
}

// handleImplicitFlow handles the implicit grant flow token issuance.
// Per RFC 6749 4.2.2 and OIDC Core 3.2.2.5, tokens are returned in fragment.
func handleImplicitFlow(
	w http.ResponseWriter,
	r *http.Request,
	authContext *oauth.AuthContext,
	sessionIdentifier string,
	authHelper AuthHelper,
	tokenIssuer TokenIssuer,
	database data.Database,
	auditLogger AuditLogger,
) error {
	// Load client
	client, err := database.GetClientByClientIdentifier(nil, authContext.ClientId)
	if err != nil {
		return err
	}
	if client == nil {
		return errors.WithStack(errors.New(fmt.Sprintf("client %v not found", authContext.ClientId)))
	}

	// Load user
	user, err := database.GetUserById(nil, authContext.UserId)
	if err != nil {
		return err
	}
	if user == nil {
		return errors.WithStack(errors.New(fmt.Sprintf("user %v not found", authContext.UserId)))
	}

	// Determine what tokens to issue based on response_type
	rtInfo := oauth.ParseResponseType(authContext.ResponseType)
	issueAccessToken := rtInfo.HasToken
	issueIdToken := rtInfo.HasIdToken

	// Use provided AuthenticatedAt if set (for prompt=none, preserves session's auth_time),
	// otherwise use current time (normal flow, prompt=login).
	authenticatedAt := time.Now().UTC()
	if authContext.AuthenticatedAt != nil && !authContext.AuthenticatedAt.IsZero() {
		authenticatedAt = *authContext.AuthenticatedAt
	}

	// Determine the scope to use (consented scope if available, otherwise requested scope)
	scope := authContext.Scope
	if authContext.ConsentedScope != "" {
		scope = authContext.ConsentedScope
	}

	// Generate tokens
	implicitInput := &oauth.ImplicitGrantInput{
		Client:            client,
		User:              user,
		Scope:             scope,
		AcrLevel:          authContext.AcrLevel,
		AuthMethods:       authContext.AuthMethods,
		SessionIdentifier: sessionIdentifier,
		Nonce:             authContext.Nonce,
		AuthenticatedAt:   authenticatedAt,

		AuthStateGeneration: authContext.AuthStateGeneration,
	}

	tokenResponse, err := tokenIssuer.GenerateTokenResponseForImplicit(r.Context(), implicitInput, issueAccessToken, issueIdToken)
	if err != nil {
		return err
	}

	// Audit log
	auditLogger.Log(constants.AuditTokenIssuedImplicitResponse, map[string]interface{}{
		"userId":           user.Id,
		"clientId":         client.Id,
		"scope":            scope,
		"responseType":     authContext.ResponseType,
		"issueAccessToken": issueAccessToken,
		"issueIdToken":     issueIdToken,
	})

	// Clear auth context
	err = authHelper.ClearAuthContext(w, r)
	if err != nil {
		return err
	}

	// Issue tokens via fragment (implicit flow always uses fragment response mode)
	return issueImplicitTokens(w, r, authContext.RedirectURI, authContext.State, tokenResponse)
}

// issueImplicitTokens redirects to the client with tokens in the fragment.
// Per RFC 6749 4.2.2, implicit grant tokens MUST be delivered via fragment.
func issueImplicitTokens(
	w http.ResponseWriter,
	r *http.Request,
	redirectURI string,
	state string,
	tokenResponse *oauth.ImplicitGrantResponse,
) error {
	// Gate 4, the last resort. This flow hands over access and ID tokens rather than a code, so a
	// redirect URI that resolves to a host the operator never registered exfiltrates credentials
	// directly rather than something still to be exchanged. Nothing can reach here with such a value
	// once the authorization endpoint has refused it, and the check stays so that the property is
	// enforced by a test rather than claimed by a comment (#122).
	if err := checkRedirectURIEmittable("issueImplicitTokens", redirectURI); err != nil {
		return err
	}

	// The response's parameters, in the order they reach the client. Each carries the condition it
	// already had; what changed is the construction underneath and the rule for state.
	//
	// state is appended on its value being non-empty and nothing else. There is no TrimSpace: RFC
	// 6749 section 3.1 says "Parameters sent without a value MUST be treated as if they were
	// omitted from the request", so "?state=" and "?state" are requests that carried no state, and
	// Appendix A.5's "state = 1*VSCHAR" admits no empty value in the response either. Space is
	// %x20 and so is VSCHAR, so a whitespace-only state is a value the client chose and section
	// 4.2.2 requires "the exact value received from the client": trimming it away substituted this
	// server's judgement for the client's (#146).
	params := make([]responseParam, 0, 6)

	if tokenResponse.AccessToken != "" {
		params = append(params,
			responseParam{"access_token", tokenResponse.AccessToken},
			responseParam{"token_type", tokenResponse.TokenType},
			responseParam{"expires_in", fmt.Sprintf("%d", tokenResponse.ExpiresIn)},
		)
	}

	if tokenResponse.IdToken != "" {
		params = append(params, responseParam{"id_token", tokenResponse.IdToken})
	}

	if tokenResponse.Scope != "" {
		params = append(params, responseParam{"scope", tokenResponse.Scope})
	}

	if state != "" {
		params = append(params, responseParam{"state", state})
	}

	// Appended rather than written through writeResponseParams, for the same reason the error
	// emitter's fragment branch appends: the redirect URI cannot carry a fragment of its own for
	// these fields to collide with, since RFC 6749 3.1.2 forbids one and checkRedirectURIEmittable
	// refuses one just above. Its query, if it registered one, is left exactly as it stands.
	//
	// Field order is now declaration order rather than Encode's alphabetical sort. Nothing depends
	// on it: RFC 6749 4.2.2 defines a set of parameters and not a sequence.
	http.Redirect(w, r, redirectURI+"#"+encodeResponseParams(params), http.StatusFound)
	return nil
}

func issueAuthCode(w http.ResponseWriter, r *http.Request, templateFS fs.FS, code *models.Code, responseMode string) error {

	// Gate 4, the last resort, ABOVE the response-mode dispatch so that it covers query, fragment
	// and form_post alike. All three emit the stored value: the first two into a Location header,
	// the third into the action of an auto-submitting form, which html/template's URL filter passes
	// through untouched for a scheme-relative value. Unreachable once the authorization endpoint has
	// refused the URI, and kept so that a test enforces it (#122).
	//
	// The caller answers a non-nil error with a 500, which leaves the code unredeemed rather than
	// delivered to the wrong host; it expires in 60 seconds.
	if err := checkRedirectURIEmittable("issueAuthCode", code.RedirectURI); err != nil {
		return err
	}

	if responseMode == "" {
		responseMode = "query"
	}

	// The response's parameters, in the order they reach the client, built once for all three
	// response modes because all three answer with the same two fields.
	//
	// state is appended on its value being non-empty and nothing else, the same rule the error
	// emitter states at length: RFC 6749 section 3.1 makes a parameter sent without a value an
	// omitted one, and Appendix A.5's "state = 1*VSCHAR" admits no empty value in the response. A
	// whitespace-only state is a real value, because space is %x20 and so is VSCHAR, and section
	// 4.1.2 requires "the exact value received from the client", so the TrimSpace that used to drop
	// it is gone (#146).
	params := []responseParam{{"code", code.Code}}
	if code.State != "" {
		params = append(params, responseParam{"state", code.State})
	}

	if responseMode == "fragment" {
		// Appended rather than written through writeResponseParams: a redirect URI cannot carry a
		// fragment of its own for these fields to collide with, so there is no registered field
		// list here to preserve or replace, and its query is left exactly as registered.
		http.Redirect(w, r, code.RedirectURI+"#"+encodeResponseParams(params), http.StatusFound)
		return nil
	}
	if responseMode == "form_post" {
		m := make(map[string]interface{})
		m["redirectURI"] = code.RedirectURI
		m["code"] = code.Code
		// The same rule as the params slice above, restated because this branch answers through a
		// bind map rather than a field list. What the client actually receives is then decided by
		// form_post.html, whose {{if .state}} omits the input entirely.
		//
		// {{.state}} and {{if .state}} cannot tell an absent key from a key holding "", but a
		// template that enumerates the map can: range yields the key only when it is present, and
		// len counts it. form_post.html is operator supplied whenever GOIABADA_AUTHSERVER_TEMPLATEDIR
		// is set, so that is a real reader, and it is what pins this guard in
		// TestFormPostBindMapOmitsAnAbsentState (#146).
		if code.State != "" {
			m["state"] = code.State
		}

		t, err := template.ParseFS(templateFS, "form_post.html")
		if err != nil {
			return errors.Wrap(err, "unable to parse template")
		}

		// Render into a buffer, not straight to w, matching the error emitter's twin. Execute
		// writes as it walks the template, so a template that parses and then fails part way
		// through leaves a partial body and an implicit 200 already on the wire; the caller answers
		// an error from here with httpHelper.InternalServerError, and a WriteHeader after the
		// response is committed changes nothing, so the client would be told 200 for a page that
		// was never finished. Here that half-written page would be a form carrying an
		// authorization code with no submit to deliver it. form_post.html is operator supplied
		// whenever GOIABADA_AUTHSERVER_TEMPLATEDIR is set, so this is reachable in a real
		// deployment rather than only in tests (#141, #146 decision 10).
		var rendered bytes.Buffer
		err = t.Execute(&rendered, m)
		if err != nil {
			return errors.Wrap(err, "unable to execute template")
		}
		// OAuth 2.0 Form Post Response Mode section 2: "Because the Authorization Response is
		// intended to be used only once, the Authorization Server MUST instruct the User Agent (and
		// any intermediaries) not to store or reuse the content of the response." This page carries
		// an authorization code and the client's state, so a cached or reused copy is a replayable
		// response sitting in an intermediary. This pair is what the rest of this codebase already
		// writes for a no-store response (#146).
		//
		// Set here rather than before Execute deliberately: a render that fails must leave the
		// response completely untouched, so the caller's last-resort InternalServerError owns every
		// header as well as the status (#141).
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")

		_, err = w.Write(rendered.Bytes())
		if err != nil {
			// The connection itself failed. Nothing can be recovered from here, including the
			// caller's 500, but the error is still worth reporting rather than swallowing.
			return errors.Wrap(err, "unable to write the form_post response")
		}
		return nil
	}

	// default to query
	//
	// writeResponseParams, not ParseRequestURI() then Query() then Encode(). That sequence seeded
	// url.Values from the registered redirect URI's own query and Add'ed on top of it, so a client
	// that had registered "?state=fixed" got back two state parameters and Go's own
	// url.Values.Get answers with the first, which is the registered one. This is the redirect
	// carrying the authorization code, so it is the response an RP's RFC 9700 2.1 CSRF check exists
	// to guard, and unlike the error path it fired on every successful authorization rather than
	// only on a refusal. Re-encoding also rewrote the registered query in five separate ways,
	// against RFC 6749 3.1.2's "MUST be retained". Both are the shared helper's to prevent, and its
	// comment carries the detail (#146).
	location, err := writeResponseParams(code.RedirectURI, params)
	if err != nil {
		return errors.Wrap(err, "unable to build the authorization code redirect")
	}

	http.Redirect(w, r, location, http.StatusFound)
	return nil
}
