package handlers

import (
	"net/http"
	"net/url"
	"strings"
)

// This file is the refusal interstitial: the page a user is shown instead of being redirected to a
// client that registered itself. redirToClientWithError decides when it renders; everything here is
// what it renders and the two pure predicates behind that decision.
//
// RFC 9700 section 4.11.2 describes the attack it answers. An attacker registers a client
// anonymously, pointing its redirect URI at a host it controls, and then either gets a user to
// decline the authorization (attack 2) or sends a deliberately invalid request (attack 1). Either
// way this server's own error redirect delivers the user agent to the attacker's host, and attack 1
// needs no victim interaction at all. The RFC answers with "The authorization server MUST take
// precautions to prevent these threats" and then declines to define "trusted", handing the
// judgement to the server and naming "the source of the redirection URI and other client data"
// among its inputs. created_via_dcr is that source, recorded (#108).

// redirectDestinationLabel names, for a user, where a client asked to send them. It is the host
// alone for an ordinary web redirect URI, because the path and query are noise nobody can evaluate
// and a long one pushes the host off the line.
//
// When there is no host, the whole URI is shown instead. Dynamic registration accepts private-use
// URI schemes and mailto today, and its own validator test table asserts both acceptable, so
// "com.example.app:/oauth" and "mailto:a@b.c" both parse cleanly to an empty Host. A blank
// destination line defeats the entire point of the page, and a URI url.Parse rejects outright is
// the same case: show what was registered rather than nothing (#108).
func redirectDestinationLabel(redirectURI string) string {
	parsed, err := url.Parse(redirectURI)
	if err != nil || parsed.Host == "" {
		return redirectURI
	}
	return parsed.Host
}

// promptRequestsSilence reports whether a raw prompt parameter, straight off the request, asks for
// silent authentication.
//
// It exists because the two error redirects inside HandleAuthorizeGet's own closure run before
// authContext.Prompt has been validated and assigned, so the stored ceremony cannot answer this
// question there. Everywhere the ceremony can answer it, it does, through
// redirectErrorFromAuthContext: POST /auth/consent and GET /auth/issue carry no prompt parameter of
// their own, so reading the request at those sites would report every silent ceremony as
// interactive and render a page OIDC Core 3.1.2.1 forbids (#108).
//
// The split on whitespace matches AuthContext.HasPromptValue, and matching whole fields rather than
// searching for a substring is what keeps "nonetheless" from exempting a request that asked for
// nothing.
func promptRequestsSilence(prompt string) bool {
	for _, value := range strings.Fields(prompt) {
		if value == "none" {
			return true
		}
	}
	return false
}

// renderRedirectBlocked renders the terminal page that replaces an error redirect to a client this
// server cannot vouch for. The authorization ends here: there is no action on the page, no form, no
// route and nothing persisted, so the client receives nothing and there is no pending state for
// anyone to replay (#108, decision 14).
//
// Rendered the way rejectCeremonyMismatch renders auth_error.html, and at 200 for the same reason
// renderErrorUi answers 200: this is an authorization the server refused to complete, reported to
// the person in front of it, rather than a fault in the HTTP request that carried it.
func renderRedirectBlocked(httpHelper HttpHelper, w http.ResponseWriter, r *http.Request,
	input redirectErrorInput) error {

	bind := map[string]interface{}{
		"destination": redirectDestinationLabel(input.redirectURI),
	}

	// The client is nil only when the handler could not resolve one, which is the untrusted case
	// rather than an exempt one. There is then no name to show and no marking to make: saying the
	// application registered itself would be a claim this server cannot back at that moment.
	if input.client != nil {
		name, unverified := consentClientName(input.client)
		bind["clientName"] = name
		bind["clientNameUnverified"] = unverified
	}

	return httpHelper.RenderTemplate(w, r, "/layouts/no_menu_layout.html", "/auth_redirect_blocked.html", bind)
}
