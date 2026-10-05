package handlers

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/internal/revocation"
	"github.com/leodip/goiabada/authserver/internal/tokenmetrics"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
)

// HandleTokenPost is the token endpoint, RFC 6749 section 3.2. It parses the request, has the
// validator turn it into one typed grant, and hands that grant to its own responder in
// handler_token_<grant>.go, which redeems it through the issuer, audits it and answers. A refusal
// is audited and answered here, whatever the grant (#437).
//
// database is the revocation port alone, because the one write this file makes is the cascade
// that answers a reused authorization code; every other write of a grant is its issuer's.
//
// tokenMetrics counts every token response by its grant and every refusal this endpoint answers by
// the grant asked for and the error code answered (#400 decision 5). The grant a refusal is counted
// under is the request's grant_type parameter, mapped into the four this endpoint redeems, so a
// request refused before it was parsed or validated is still counted under the grant it named.
func HandleTokenPost(
	jsonWriter JSONWriter,
	database revocation.Database,
	tokenIssuer TokenIssuer,
	tokenValidator TokenValidator,
	auditLogger AuditLogger,
	credentialFailures CredentialFailureRecorder,
	tokenMetrics *tokenmetrics.Recorder,
) http.HandlerFunc {
	responder := tokenResponder{jsonWriter: jsonWriter, issuer: tokenIssuer, auditLogger: auditLogger, metrics: tokenMetrics}

	return func(w http.ResponseWriter, r *http.Request) {
		input, err := parseTokenRequest(r)
		if err != nil {
			responder.refuse(w, r, requestedGrantType(r), err)
			return
		}

		settings, ok := reqctx.SettingsFrom(r.Context())
		if !ok {
			responder.refuse(w, r, input.GrantType, reqctx.ErrNoSettings)
			return
		}

		grant, err := tokenValidator.ValidateTokenRequest(r.Context(), settings, input)
		if err != nil {
			responder.refuse(w, r, input.GrantType, auditTokenRefusal(r, database, auditLogger, credentialFailures, input, err))
			return
		}

		switch grant := grant.(type) {
		case *protocolvalidation.AuthorizationCodeGrant:
			responder.respondAuthorizationCode(w, r, settings, grant)
		case *protocolvalidation.ClientCredentialsGrant:
			responder.respondClientCredentials(w, r, settings, grant)
		case *protocolvalidation.RefreshTokenGrant:
			responder.respondRefreshToken(w, r, settings, grant)
		case *protocolvalidation.PasswordGrant:
			responder.respondPassword(w, r, settings, grant)
		default:
			// Reachable only if the validator returns a grant this endpoint has no responder for.
			responder.refuse(w, r, input.GrantType, errs.Errorf("the token validator returned a grant (%T) the token endpoint does not answer", grant))
		}
	}
}

// requestedGrantType is the grant_type the request's body named, read for a request refused before
// it was parsed into the validator's input. net/http keeps the pairs that parsed before a malformed
// one, and an empty form names none.
func requestedGrantType(r *http.Request) oidc.GrantType {
	return oidc.GrantType(r.PostForm.Get("grant_type"))
}

// tokenRequestParameters are every form parameter the token endpoint reads, and so every one whose
// copies must agree. TestTokenRequestParameters_EveryReadIsListed holds the list to the reads (#228).
var tokenRequestParameters = []string{
	"grant_type", "code", "redirect_uri", "code_verifier", "client_id", "client_secret",
	"scope", "refresh_token", "username", "password",
}

// parseTokenRequest reads the token request's form into the validator's input, refusing what can be
// refused before any client is known: a body that cannot be parsed, a repeated parameter, two
// client authentication methods at once, and a scope that is not well formed.
func parseTokenRequest(r *http.Request) (*protocolvalidation.ValidateTokenRequestInput, error) {
	// A body that cannot be parsed is the client's malformed request, RFC 6749 section 5.2's
	// invalid_request, and not a server fault: a url-encoding broken by the client, or a body cut
	// at the request-body limit (#426). Answered as a 500 it wrote an Error record for every one.
	// With the ROPC limiter on, its own ParseForm meets the failure first and answers it with this
	// same refusal. It cannot forward the request: net/http keeps the pairs that did parse, and this
	// ParseForm would then answer nil over them (#437).
	if err := r.ParseForm(); err != nil {
		return nil, protocolvalidation.UnparseableRequest()
	}

	// RFC 6749 5.2 names a request that "repeats a parameter" or "includes multiple credentials"
	// as invalid_request. Checked before anything is read, so a repeated grant_type cannot pick the
	// grant and a repeated client_id or client_secret cannot pick the client. The body only, as every
	// read below is; copies that agree are refused too (#228).
	if err := protocolvalidation.ValidateNoRepeatedParameters(r.PostForm, tokenRequestParameters); err != nil {
		return nil, err
	}

	// Extract client credentials - supports both client_secret_basic and client_secret_post
	clientId, clientSecret, err := extractClientCredentials(r)
	if err != nil {
		return nil, err
	}

	grantType := oidc.GrantType(r.PostForm.Get("grant_type"))

	// Normalize the scope HERE, at the entry point, and not inside the validator. The
	// placement is load-bearing in both directions:
	//
	//   - It must run before token_grant_client_credentials.go's `len(input.Scope) == 0`
	//     test, which is what selects the client credentials "no scope given, grant everything the client holds"
	//     branch. Normalizing after that test means a scope of "   " has non-zero length,
	//     skips the branch, then trims to empty inside validateClientCredentialsScopes and
	//     hits its early return, so the ownership loop never runs at all. That yields a 500
	//     from the issuer rather than the 400 the request deserves.
	//   - It must run before that same test for the opposite reason too: normalizing "   " to
	//     "" WOULD select the all-permissions branch, turning an accidentally malformed
	//     least-privilege request into a maximal one. The rejection below, which refuses a scope
	//     of spaces alone as malformed, is what stops that.
	//
	// So the normalization and the rejection belong together, upstream of the validator.
	// Moving either into the validator reopens one of the two holes.
	rawScope := r.PostForm.Get("scope")

	// A scope that is not well formed, one space between each two values and none at either end
	// (RFC 6749 section 3.3), is refused as invalid_scope for the grant types that read it, before
	// it is normalized, since normalizing would hide the runs of spaces it is refused for (#244).
	// That covers a scope of spaces alone, which is refused rather than treated as omitted. An
	// explicitly empty `scope=` is not refused: PostForm.Get cannot tell it from an absent
	// parameter, RFC 6749 3.1 treats a parameter sent without a value as omitted, and plenty of
	// clients serialize empty values.
	//
	// Deliberately NOT audited: this runs before the client is authenticated, so emitting an
	// audit event here would record an unverified, caller-chosen client_id and let anyone
	// manufacture log rows against a legitimate client.
	//
	// The message is grant-neutral by necessity. It fires for three grant types whose
	// omitted-scope behaviour differs (client credentials grants everything the client holds,
	// refresh preserves the original token's scope, ROPC defaults to "openid"), so naming any
	// one of those would be wrong for the other two.
	if grantType.ReadsScope() {
		if err := protocolvalidation.ValidateSpaceDelimited("scope", "invalid_scope", rawScope); err != nil {
			return nil, err
		}
	}
	normalizedScope := oidc.NormalizeScope(rawScope)

	return &protocolvalidation.ValidateTokenRequestInput{
		GrantType:    grantType,
		Code:         r.PostForm.Get("code"),
		RedirectURI:  r.PostForm.Get("redirect_uri"),
		CodeVerifier: r.PostForm.Get("code_verifier"),
		ClientId:     clientId,
		ClientSecret: clientSecret,
		Scope:        normalizedScope,
		RefreshToken: r.PostForm.Get("refresh_token"),
		// ROPC parameters (RFC 6749 Section 4.3)
		Username: r.PostForm.Get("username"),
		Password: r.PostForm.Get("password"),
	}, nil
}

// auditTokenRefusal records what a refused token request calls for, the audit events, the
// password-guess charge and the reuse cascade, and returns the error the client is answered with:
// the validator's own, or the cascade's failure when it could not commit.
//
// input is the validator's input as the validator left it, so the scope an audit row records for a
// client credentials request is the scope the validator expanded an omitted one to.
func auditTokenRefusal(r *http.Request, database revocation.Database, auditLogger AuditLogger,
	credentialFailures CredentialFailureRecorder, input *protocolvalidation.ValidateTokenRequestInput, err error) error {

	// RFC 6749 §4.1.2: when an authorization code is reused by an
	// authenticated requester, the server MUST deny the request and
	// SHOULD revoke all tokens previously issued from that code.
	// The validator returns AuthCodeReusedError only after the request
	// has authenticated against the used code (client_id, redirect_uri,
	// client_secret/PKCE), so revocation here cannot be triggered by
	// an unauthenticated attacker.
	var reused *protocolvalidation.AuthCodeReusedError
	if errors.As(err, &reused) {
		// The audit row waits for the transaction to commit: it lists JTIs that were
		// really revoked, and on SQLite an audit write inside the transaction would wait
		// on the one connection the transaction holds.
		result, revokeErr := revocation.RevokeOnAuthCodeReuseTx(r.Context(), database, reused.Code)
		if revokeErr != nil {
			return revokeErr
		}
		revocation.LogAuthCodeReuse(r.Context(), auditLogger, reused.Code, result)
		return reused.Detail
	}
	// A grant refused because its user is disabled, on the code, refresh or password grant.
	// Matched by type, never by the answer's value: a code or refresh grant answers with its
	// generic refusal, which other failures share, so that the answer tells an unauthenticated
	// presenter nothing about the account (#137).
	var userDisabled *protocolvalidation.UserDisabledError
	if errors.As(err, &userDisabled) {
		auditLogger.Log(r.Context(), audit.EventUserDisabled, map[string]interface{}{
			"clientId": input.ClientId,
		})
	}

	// The redemption half of #241's registration boundary. The validator refuses an
	// authorization code whose own redirect URI has been deregistered since it was
	// minted, and this is what makes that refusal answerable from the admin console
	// and GET /api/v1/admin/audit-logs rather than only from a server log file
	// (decision 10). Matched by value against the sentinel, because the code is
	// invalid_grant, which 22 unrelated failures also carry, so a bare code test would
	// name the wrong ones; the value is unique to this refusal.
	//
	// clientIdentifier, the string from the request, rather than the numeric clientId
	// the issuance events use, for the reason EventTokenScopeDenied gives: the
	// validator discards the client model on failure. Unlike that event, this one is
	// reached only below client authentication and PKCE, so the identifier here has
	// been proved rather than merely asserted.
	if errors.Is(err, protocolvalidation.ErrCodeRedirectURIDeregistered) {
		auditLogger.Log(r.Context(), audit.EventRedemptionRefusedRedirectURI, map[string]interface{}{
			"clientIdentifier": input.ClientId,
		})
	}

	// Record scope validation failures, on any grant type. Nothing recorded them before.
	//
	// **What this is and is not.** It is every authenticated invalid_scope failure: the two
	// scope validators', and the refresh arm's request for a scope its grant does not hold.
	// That is a POSITIONAL boundary, not a semantic one. Only three of the nine branches it
	// covers are authorization denials in any strict sense: "not granted to the client",
	// "the user does not have permission" and the refresh request beyond its grant. The rest
	// are malformed format and unknown resource or permission, which usually mean a
	// misconfigured client rather than a caller probing for access it was not granted. So
	// read a row as "a request that got past authentication and then asked for a scope the
	// server would not give", and check the message before treating it as an authorization
	// probe.
	//
	// Keyed on the error code rather than the grant type, deliberately: within the validator
	// invalid_scope is returned only by the two scope validators and the refresh arm's
	// beyond-the-grant check, so the predicate cannot pick up unrelated failures and stays
	// correct if any of them gains another branch. It covers nine of the eleven scope denial
	// branches. Two are outside it: the client credentials OIDC-scope rejection returns
	// invalid_request, and the provided-but-empty rejection in parseTokenRequest fires before
	// authentication. The refresh request beyond its grant was a third, and the one genuine
	// authorization denial this missed, until #425 answered it with the invalid_scope RFC
	// 6749 section 5.2 names for it rather than invalid_grant, a code 22 unrelated failures
	// share. The refresh arm's refusals of the grant itself (consent withdrawn, a permission
	// since revoked, a stored value this server does not issue) stay invalid_grant, and are
	// not scope denials of the request.
	//
	// THIS IS THE ONLY CALL SITE, and adding a second at the provided-but-empty rejection is
	// the obvious-looking completeness fix and is wrong: that branch runs before the client
	// is authenticated, so it would write a caller-chosen client_id into the audit log and
	// let anyone manufacture rows implicating a legitimate client. That degrades the exact
	// signal this event exists to provide. A handler test asserts the ABSENCE of an event
	// there; if it fails, do not "fix" it by adding the call.
	// A resource-owner password guess that failed: charge the rate limiter's
	// reservation and record the event RFC 6749 Section 4.3.2 contemplates when it
	// names "generating alerts" beside rate limitation. Both belong here because
	// this is the only place that knows the guess was wrong; the limiter reserved
	// the account's slot before the handler ran and drops it silently otherwise.
	//
	// invalid_grant is the whole of the predicate, and it is narrower than it looks.
	// The validator's other password-grant failures are unauthorized_client (the
	// grant is switched off), invalid_request (a missing username or password) and
	// invalid_client (client authentication), none of which compared a credential
	// against an account, so charging them would let a caller spend an account's
	// budget without guessing and would fill the audit log with rows naming a
	// username nothing checked. What invalid_grant does cover is a wrong password,
	// an unknown user, a disabled user and a 2FA-blocked user, which is exactly the
	// set EventROPCAuthFailed is documented to mean.
	//
	// The checks that run before the grant is looked at read no credential either, and none
	// of them answers invalid_grant: a missing client_id is invalid_request, an unknown or
	// disabled client invalid_client. The disabled client was invalid_grant until #437 and had
	// to be excluded here by value (#219); if a prelude refusal ever becomes invalid_grant
	// again, it needs that exclusion back.
	var errDetail *oauth.ErrorDetail
	if errors.As(err, &errDetail) &&
		input.GrantType == oidc.GrantTypePassword && errDetail.Code() == "invalid_grant" {

		credentialFailures.RecordCredentialFailure(r)
		auditLogger.Log(r.Context(), audit.EventROPCAuthFailed, map[string]interface{}{
			// Normalized to what the limiter keyed its bucket on and to what every
			// write path stores, so the audit row and the budget name one account.
			"email": strings.ToLower(strings.TrimSpace(input.Username)),
			// clientIdentifier, the string from the request, for the reason
			// EventTokenScopeDenied gives: the validator discards the client model on
			// failure. A public client's identifier is caller-supplied, so read it as
			// the client the caller named rather than as proof of who called.
			"clientIdentifier": input.ClientId,
		})
	}

	if errors.As(err, &errDetail) && errDetail.Code() == "invalid_scope" {
		auditLogger.Log(r.Context(), audit.EventTokenScopeDenied, map[string]interface{}{
			// clientIdentifier, the string from the request, not the numeric clientId the
			// issuance events use: the validator discards the client model on failure. See
			// the constant's doc comment for what this attests to per grant type.
			"clientIdentifier": input.ClientId,
			"grantType":        input.GrantType.String(),
			"scope":            input.Scope,
		})
	}

	return err
}

// tokenResponder answers a validated grant: one method per grant, each in handler_token_<grant>.go,
// redeeming the grant through the issuer, writing its audit events and answering with the token
// response (#437).
type tokenResponder struct {
	jsonWriter  JSONWriter
	issuer      TokenIssuer
	auditLogger AuditLogger
	metrics     *tokenmetrics.Recorder
}

// writeTokenResponse answers a successful grant, counting it as tokens issued under grantType. The
// response carries tokens, so RFC 6749 section 5.1 requires Cache-Control: no-store and Pragma:
// no-cache on it.
func (tr tokenResponder) writeTokenResponse(w http.ResponseWriter, r *http.Request, grantType oidc.GrantType,
	tokenResponse *oauth.TokenResponse) {

	tr.metrics.Issued(grantType)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	tr.jsonWriter.EncodeJSON(w, r, tokenResponse)
}

// refuse answers a token request with err, as RFC 6749 section 5.2's error response, counting it as
// refused under grantType and the error code err is answered with. Every refusal this endpoint
// writes goes through here, so none is answered uncounted.
func (tr tokenResponder) refuse(w http.ResponseWriter, r *http.Request, grantType oidc.GrantType, err error) {
	tr.metrics.Refused(grantType, err)
	tr.jsonWriter.JSONError(w, r, err)
}

// extractClientCredentials extracts client_id and client_secret from the request.
// It supports both client_secret_basic (Authorization header) and client_secret_post (form body).
// Per RFC 6749 clients MUST NOT use more than one authentication method per request.
// Which of the two was used is not returned: every invalid_client carries the same challenge
// whichever it was (#437).
func extractClientCredentials(r *http.Request) (clientId, clientSecret string, err error) {
	// Check for Basic auth in Authorization header
	basicClientId, basicClientSecret, hasBasicAuth := parseBasicAuth(r.Header.Get("Authorization"))

	// Get credentials from POST body
	postClientId := r.PostForm.Get("client_id")
	postClientSecret := r.PostForm.Get("client_secret")
	hasPostAuth := postClientSecret != ""

	// RFC 6749 clients MUST NOT use more than one authentication method
	if hasBasicAuth && hasPostAuth {
		return "", "", oauth.NewErrorDetailWithHTTPStatus("invalid_request",
			"Client authentication failed: multiple authentication methods provided. "+
				"Use either HTTP Basic authentication OR client_secret in the request body, but not both.",
			http.StatusBadRequest)
	}

	// Use Basic auth if present
	if hasBasicAuth {
		return basicClientId, basicClientSecret, nil
	}

	// Fall back to POST body credentials
	return postClientId, postClientSecret, nil
}

// parseBasicAuth parses an HTTP Basic Authentication header value.
// It returns the client_id, client_secret, and whether Basic auth was present.
func parseBasicAuth(authHeader string) (clientId, clientSecret string, ok bool) {
	if authHeader == "" {
		return "", "", false
	}

	// Must start with "Basic "
	const prefix = "Basic "
	if !strings.HasPrefix(authHeader, prefix) {
		return "", "", false
	}

	// Decode base64
	encoded := authHeader[len(prefix):]
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", "", false
	}

	// Split on first colon (password may contain colons)
	credentials := string(decoded)
	colonIdx := strings.Index(credentials, ":")
	if colonIdx < 0 {
		return "", "", false
	}

	return credentials[:colonIdx], credentials[colonIdx+1:], true
}
