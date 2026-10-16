package handlers

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/authflow"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/issuance"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/i18n"
)

// HandleIssueGet is GET /auth/issue, which accepts ready_to_issue_code and runs authflow.Issuance,
// then answers what it did: the code or the implicit tokens to the client, an error to the client,
// the redirect to /auth/level1 on a restart, or one of the two refusal pages that reach no client, a
// redirect URI no longer registered and a client disabled since /auth/authorize.
func HandleIssueGet(
	boundary *CeremonyBoundary,
	responder *ClientErrorResponder,
	pageRenderer PageRenderer,
	ceremonyStore CeremonyStore,
	issuanceStep *authflow.Issuance,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		settings, authContext, ok := boundary.beginStep(w, r, ceremony.AuthStateReadyToIssueCode)
		if !ok {
			return
		}

		sessionIdentifier, _ := reqctx.SessionIdentifierFrom(r.Context())
		result, err := issuanceStep.Run(r.Context(), newBrowserSession(w, r, ceremonyStore), settings, authContext,
			sessionIdentifier)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}

		switch {
		case result.UnregisteredRedirect:
			if errors.Is(result.ClearErr, ceremony.ErrCeremonyReplaced) {
				boundary.answerCeremonyReplaced(w, r)
				return
			}
			if result.ClearErr != nil {
				slog.ErrorContext(r.Context(), "unable to clear the auth context while withholding a redirect to a deregistered URI, rendering the refusal anyway",
					"error", result.ClearErr)
			}
			// Rendered here, never redirected: the URI must receive nothing (#241 decision 4). The page
			// reads only the client's name, none for a client that no longer exists, and the URI.
			err = responder.renderRedirectBlocked(w, r, redirectErrorInput{
				client:      result.Client,
				redirectURI: authContext.RedirectURI,
			})
			if err != nil {
				pageRenderer.InternalServerError(w, r, err)
			}

		case result.ClientDisabled:
			if errors.Is(result.ClearErr, ceremony.ErrCeremonyReplaced) {
				boundary.answerCeremonyReplaced(w, r)
				return
			}
			if result.ClearErr != nil {
				slog.ErrorContext(r.Context(), "unable to clear the auth context while refusing a disabled client, rendering the refusal anyway",
					"error", result.ClearErr)
			}
			message := i18n.NewLocalizedError(i18n.ErrCodeAuthorizeClientDisabled, nil).Localize(r.Context())
			renderAuthorizeRefusal(pageRenderer, w, r, message, http.StatusOK)

		case result.ClientError != nil:
			answerClientAfterStepClear(w, r, boundary, responder,
				redirectErrorFromAuthContext(authContext, result.ClientError.Client,
					result.ClientError.Code, result.ClientError.Description),
				result.ClearErr)

		case result.Code != nil:
			if result.ClearErr != nil {
				boundary.answerStepSaveFailure(w, r, result.ClearErr)
				return
			}
			warnInsecureHTTPRedirect(r.Context(), "issueAuthCode", authContext.ClientId, result.Code.RedirectURI)
			// A failure here leaves the code unredeemed rather than delivered; it expires in 60 seconds.
			err = issueAuthCode(w, r, responder.formPostFS, result.Code, authContext.ResponseMode)
			if err != nil {
				pageRenderer.InternalServerError(w, r, err)
			}

		case result.Tokens != nil:
			if result.ClearErr != nil {
				boundary.answerStepSaveFailure(w, r, result.ClearErr)
				return
			}
			warnInsecureHTTPRedirect(r.Context(), "issueImplicitTokens", authContext.ClientId, authContext.RedirectURI)
			err = issueImplicitTokens(w, r, responder.formPostFS, authContext.ResponseMode, authContext.RedirectURI,
				authContext.State, result.Tokens)
			if err != nil {
				pageRenderer.InternalServerError(w, r, err)
			}

		default:
			boundary.redirectAfterSave(w, r, authContext, result.NextStep, result.SaveErr)
		}
	}
}

// issueImplicitTokens answers the client with tokens: in the fragment of its redirect URI, which is
// what RFC 6749 4.2.2 defines and the default, or in an auto-submitting form when the request asked
// for response_mode=form_post. The mode is implicitResponseMode's, so the query is not reachable
// from here whatever the ceremony holds (#231).
func issueImplicitTokens(
	w http.ResponseWriter,
	r *http.Request,
	formPostFS fs.FS,
	responseMode string,
	redirectURI string,
	state string,
	tokenResponse *issuance.ImplicitGrantResponse,
) error {
	// checkRedirectURIEmittable, the last resort, above the response-mode dispatch so that it covers
	// the fragment and form_post alike, as issueAuthCode's does. This flow hands over access and ID tokens rather than
	// a code, so a redirect URI that resolves to a host the operator never registered exfiltrates
	// credentials directly rather than something still to be exchanged, and the form's action is the
	// one place html/template's URL filter passes a scheme-relative value through untouched. Nothing
	// can reach here with such a value once the authorization endpoint has refused it, and the check
	// stays so that the property is enforced by a test rather than claimed by a comment (#122).
	if err := checkRedirectURIEmittable(r.Context(), "issueImplicitTokens", redirectURI); err != nil {
		return err
	}

	// The response's parameters, in the order they reach the client, iss last: writeAuthorizationResponse
	// appends it for every response.
	//
	// state is appended on its value being non-empty and nothing else. There is no TrimSpace: RFC
	// 6749 section 3.1 says "Parameters sent without a value MUST be treated as if they were
	// omitted from the request", so "?state=" and "?state" are requests that carried no state, and
	// Appendix A.5's "state = 1*VSCHAR" admits no empty value in the response either. Space is
	// %x20 and so is VSCHAR, so a whitespace-only state is a value the client chose and section
	// 4.2.2 requires "the exact value received from the client": trimming it would substitute this
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

	// Written by writeAuthorizationResponse, whose fragment branch appends rather than going through
	// writeResponseParams: the redirect URI cannot carry a fragment of its own for these fields to
	// collide with, since RFC 6749 3.1.2 forbids one and checkRedirectURIEmittable refuses one just
	// above. Its query, if it registered one, is left exactly as it stands. The form_post branch is
	// the one the authorization code and the error emitter use: OAuth 2.0 Form Post Response Mode
	// section 4 makes it safe for the parameters whose default is the fragment, and it sets
	// Cache-Control: no-store and Pragma: no-cache once the page has rendered, which matters more
	// here than on the code path since the page holds the tokens themselves.
	//
	// Field order is declaration order rather than Encode's alphabetical sort. Nothing depends on
	// it: RFC 6749 4.2.2 defines a set of parameters and not a sequence.
	return writeAuthorizationResponse(w, r, formPostFS, implicitResponseMode(responseMode), redirectURI, params)
}

func issueAuthCode(w http.ResponseWriter, r *http.Request, formPostFS fs.FS, code *record.Code, responseMode string) error {

	// checkRedirectURIEmittable, the last resort, above the response-mode dispatch so that it covers
	// query, fragment and form_post alike. All three emit the stored value: the first two into a Location header,
	// the third into the action of an auto-submitting form, which html/template's URL filter passes
	// through untouched for a scheme-relative value. Unreachable once the authorization endpoint has
	// refused the URI, and kept so that a test enforces it (#122).
	//
	// The caller answers a non-nil error with a 500, which leaves the code unredeemed rather than
	// delivered to the wrong host; it expires in 60 seconds.
	if err := checkRedirectURIEmittable(r.Context(), "issueAuthCode", code.RedirectURI); err != nil {
		return err
	}

	// The response's parameters, in the order they reach the client, built once for all three
	// response modes because all three answer with the same fields. writeAuthorizationResponse
	// appends iss after them.
	//
	// state is appended on its value being non-empty and nothing else, the same rule the error
	// emitter states at length: RFC 6749 section 3.1 makes a parameter sent without a value an
	// omitted one, and Appendix A.5's "state = 1*VSCHAR" admits no empty value in the response. A
	// whitespace-only state is a real value, because space is %x20 and so is VSCHAR, and section
	// 4.1.2 requires "the exact value received from the client", so it is never trimmed (#146).
	params := []responseParam{{"code", code.Code}}
	if code.State != "" {
		params = append(params, responseParam{"state", code.State})
	}

	// An empty response mode is the query, the default for response_type=code (OAuth 2.0 Multiple
	// Response Type Encoding Practices 2.1).
	return writeAuthorizationResponse(w, r, formPostFS, responseMode, code.RedirectURI, params)
}
