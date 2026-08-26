package handlers

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/validators"
)

// jsonErrorConformed answers an RFC 6749 5.2 error response with its description conformed to
// Appendix A.8's character set, which is the same production that governs the authorization
// endpoint's error redirect. It is the token endpoint's boundary: every exit in this file goes
// through it, so a description that interpolates request text cannot carry a byte the RFC forbids
// into the JSON body (#213).
//
// It wraps httpHelper.JsonError rather than changing it. That writer has 186 call sites, of which 9
// are this file and 2 are /userinfo; the remaining 175 are the admin console's AJAX API, which RFC
// 6749 5.2 does not govern and which this server deliberately answers in the administrator's
// language. Filtering there would be #213 quietly forbidding a Portuguese sentence on an admin
// screen.
//
// Both of the writer's branches are conformed, because both interpolate text the caller chooses.
// The *ErrorDetail branch interpolates request text into a validator's description. The other
// branch reads chi's request id, and chi takes that id verbatim from the caller's own header
// (`requestID := r.Header.Get(RequestIDHeader)`, go-chi/chi/v5 middleware.RequestID), so a request
// carrying `X-Request-Id: a"b` puts 0x22 into error_description with no validator involved at all.
// A non-*ErrorDetail is therefore rebuilt here as the generic server error the shared writer would
// have produced, conformed, which is also why the log line that writer emits on that branch is
// emitted here instead: the branch it now takes does not log.
func jsonErrorConformed(httpHelper HttpHelper, w http.ResponseWriter, r *http.Request, err error) {
	errorDetail, ok := err.(*customerrors.ErrorDetail)
	if !ok {
		requestId := middleware.GetReqID(r.Context())
		slog.Error(fmt.Sprintf("%+v\nrequest-id: %v", err, requestId))
		errorDetail = customerrors.NewErrorDetailWithHttpStatusCode("server_error",
			fmt.Sprintf(genericServerErrorDescription, requestId), http.StatusInternalServerError)
	}

	// One call, on the final description, so neither branch can reach the wire unfiltered and a
	// future third branch has to come through here to be written at all.
	httpHelper.JsonError(w, r,
		errorDetail.WithDescription(customerrors.ConformErrorDescription(errorDetail.GetDescription())))
}

// genericServerErrorDescription repeats HttpHelper.JsonError's own sentence for an error that is
// not an *ErrorDetail. That writer builds the sentence after the last point this boundary can
// reach, and #213 deliberately leaves it alone because its other 177 call sites are the admin
// console's AJAX API and /userinfo, which RFC 6749 5.2 does not govern. Repeating it is the price
// of not filtering there; TestJsonErrorConformed_GenericDescriptionMatchesSharedWriter fails if the
// two ever drift apart.
const genericServerErrorDescription = "An unexpected server error has occurred. For additional information, refer to the server logs. Request Id: %v"

// authCodeNotAuthorizedErrorMsg refuses a refresh token that an authorization code minted, for a
// client whose authorization code flow is now off. The wording is what the token validator's
// refresh arm carried before the gate moved into this handler, kept verbatim so that half of the
// endpoint's observable behaviour did not change (#250).
const authCodeNotAuthorizedErrorMsg = "The client associated with the provided client_id does not support authorization code flow."

func HandleTokenPost(
	httpHelper HttpHelper,
	userSessionManager UserSessionManager,
	database data.Database,
	tokenIssuer TokenIssuer,
	tokenValidator TokenValidator,
	auditLogger AuditLogger,
	credentialFailures CredentialFailureRecorder,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			jsonErrorConformed(httpHelper, w, r, err)
			return
		}

		// Extract client credentials - supports both client_secret_basic and client_secret_post
		clientId, clientSecret, usedBasicAuth, err := extractClientCredentials(r)
		if err != nil {
			jsonErrorConformed(httpHelper, w, r, err)
			return
		}

		grantType := r.PostForm.Get("grant_type")

		// Normalize the scope HERE, at the entry point, and not inside the validator. The
		// placement is load-bearing in both directions:
		//
		//   - It must run before token_validator.go's `len(input.Scope) == 0` test, which is what
		//     selects the client credentials "no scope given, grant everything the client holds"
		//     branch. Normalizing after that test means a scope of "   " has non-zero length,
		//     skips the branch, then trims to empty inside validateClientCredentialsScopes and
		//     hits its early return, so the ownership loop never runs at all. That yields a 500
		//     from the issuer rather than the 400 the request deserves.
		//   - It must run before that same test for the opposite reason too: normalizing "   " to
		//     "" WOULD select the all-permissions branch, turning an accidentally malformed
		//     least-privilege request into a maximal one. The rejection below is what stops that.
		//
		// So the normalization and the rejection belong together, upstream of the validator.
		// Moving either into the validator reopens one of the two holes.
		rawScope := r.PostForm.Get("scope")
		normalizedScope := normalizeScope(rawScope)

		// A scope that was provided but contains nothing is rejected rather than treated as
		// omitted, for the grant types that read it. Note `rawScope != ""`: PostForm.Get cannot
		// distinguish `scope=` from an absent parameter, and an explicitly empty `scope=` is
		// already accepted today as "omitted", so whitespace-only is the only input in this
		// category. Plenty of clients serialize empty values, and newly rejecting them would break
		// working integrations for no security gain.
		//
		// Deliberately NOT audited: this runs before the client is authenticated, so emitting an
		// audit event here would record an unverified, caller-chosen client_id and let anyone
		// manufacture log rows against a legitimate client.
		//
		// The message is grant-neutral by necessity. It fires for three grant types whose
		// omitted-scope behaviour differs (client credentials grants everything the client holds,
		// refresh preserves the original token's scope, ROPC defaults to "openid"), so naming any
		// one of those would be wrong for the other two.
		if rawScope != "" && normalizedScope == "" && grantTypeConsumesScope(grantType) {
			jsonErrorConformed(httpHelper, w, r, customerrors.NewErrorDetailWithHttpStatusCode("invalid_scope",
				"The 'scope' parameter was provided but contains no scopes. Either omit it entirely or supply one or more scopes separated by spaces.",
				http.StatusBadRequest))
			return
		}

		input := validators.ValidateTokenRequestInput{
			GrantType:    grantType,
			Code:         r.PostForm.Get("code"),
			RedirectURI:  r.PostForm.Get("redirect_uri"),
			CodeVerifier: r.PostForm.Get("code_verifier"),
			ClientId:     clientId,
			ClientSecret: clientSecret,
			Scope:        normalizedScope,
			RefreshToken: r.PostForm.Get("refresh_token"),
			// ROPC parameters (RFC 6749 Section 4.3)
			Username:      r.PostForm.Get("username"),
			Password:      r.PostForm.Get("password"),
			UsedBasicAuth: usedBasicAuth,
		}

		validateResult, err := tokenValidator.ValidateTokenRequest(r.Context(), &input)
		if err != nil {
			// RFC 6749 §4.1.2: when an authorization code is reused by an
			// authenticated requester, the server MUST deny the request and
			// SHOULD revoke all tokens previously issued from that code.
			// The validator returns AuthCodeReusedError only after the request
			// has authenticated against the used code (client_id, redirect_uri,
			// client_secret/PKCE), so revocation here cannot be triggered by
			// an unauthenticated attacker.
			if reused, ok := err.(*customerrors.AuthCodeReusedError); ok {
				if revokeErr := revokeAndAuditAuthCodeReuse(database, auditLogger, reused.Code); revokeErr != nil {
					httpHelper.InternalServerError(w, r, revokeErr)
					return
				}
				jsonErrorConformed(httpHelper, w, r, reused.Detail)
				return
			}
			// Check if user is disabled and log audit event
			if errDetail, ok := err.(*customerrors.ErrorDetail); ok && errDetail.IsError(customerrors.ErrUserDisabled) {
				auditLogger.Log(constants.AuditUserDisabled, map[string]interface{}{
					"clientId": input.ClientId,
				})
			}

			// The redemption half of #241's registration boundary. The validator refuses an
			// authorization code whose own redirect URI has been deregistered since it was
			// minted, and this is what makes that refusal answerable from the admin console
			// and GET /api/v1/admin/audit-logs rather than only from a server log file
			// (decision 10). Matched by value against the sentinel for the reason the
			// ErrUserDisabled block above is: the code is invalid_grant, which 22 unrelated
			// failures also carry, so a bare code test would name the wrong ones.
			//
			// clientIdentifier, the string from the request, rather than the numeric clientId
			// the issuance events use, for the reason AuditTokenScopeDenied gives: the
			// validator discards the client model on failure. Unlike that event, this one is
			// reached only below client authentication and PKCE, so the identifier here has
			// been proved rather than merely asserted.
			if errDetail, ok := err.(*customerrors.ErrorDetail); ok &&
				errDetail.IsError(customerrors.ErrCodeRedirectURIDeregistered) {

				auditLogger.Log(constants.AuditRedemptionRefusedRedirectURI, map[string]interface{}{
					"clientIdentifier": input.ClientId,
				})
			}

			// Record scope validation failures, on any grant type. Nothing recorded them before.
			//
			// **What this is and is not.** It is every authenticated invalid_scope failure from the
			// two scope validators, which is a POSITIONAL boundary, not a semantic one. Only two of
			// the eight branches it covers are authorization denials in any strict sense: "not
			// granted to the client" and "the user does not have permission". The rest are malformed
			// format and unknown resource or permission, which usually mean a misconfigured client
			// rather than a caller probing for access it was not granted. So read a row as "a
			// request that got past authentication and then asked for a scope the server would not
			// give", and check the message before treating it as an authorization probe.
			//
			// Keyed on the error code rather than the grant type, deliberately: within the validator
			// invalid_scope is returned only by the two scope validators, so the predicate cannot
			// pick up unrelated failures and stays correct if either gains another branch. It covers
			// eight of the eleven scope denial branches. Three are outside it: the client credentials
			// OIDC-scope rejection returns invalid_request, the refresh down-scope denial returns
			// invalid_grant (a code used for 22 unrelated failures, so it cannot be isolated), and
			// the provided-but-empty rejection above fires before authentication. Note the refresh
			// down-scope denial IS a genuine authorization denial and is missed: the error taxonomy
			// cannot isolate it, so this event's coverage does not line up with the semantic
			// category in either direction.
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
			// set AuditROPCAuthFailed is documented to mean.
			//
			// ErrClientDisabled is the one exception, and it is the reason this is not a
			// bare code test: that check runs before the grant-type switch and before any
			// credential is read, so it is an invalid_grant that guessed nothing.
			if errDetail, ok := err.(*customerrors.ErrorDetail); ok &&
				input.GrantType == "password" && errDetail.GetCode() == "invalid_grant" &&
				!errDetail.IsError(customerrors.ErrClientDisabled) {

				credentialFailures.RecordCredentialFailure(r)
				auditLogger.Log(constants.AuditROPCAuthFailed, map[string]interface{}{
					// Normalized to what the limiter keyed its bucket on and to what every
					// write path stores, so the audit row and the budget name one account.
					"email": strings.ToLower(strings.TrimSpace(input.Username)),
					// clientIdentifier, the string from the request, for the reason
					// AuditTokenScopeDenied gives: the validator discards the client model on
					// failure. A public client's identifier is caller-supplied, so read it as
					// the client the caller named rather than as proof of who called.
					"clientIdentifier": input.ClientId,
				})
			}

			if errDetail, ok := err.(*customerrors.ErrorDetail); ok && errDetail.GetCode() == "invalid_scope" {
				auditLogger.Log(constants.AuditTokenScopeDenied, map[string]interface{}{
					// clientIdentifier, the string from the request, not the numeric clientId the
					// issuance events use: the validator discards the client model on failure. See
					// the constant's doc comment for what this attests to per grant type.
					"clientIdentifier": input.ClientId,
					"grantType":        input.GrantType,
					"scope":            input.Scope,
				})
			}

			jsonErrorConformed(httpHelper, w, r, err)
			return
		}

		switch input.GrantType {
		case "authorization_code":
			// Atomically claim the code (compare-and-set on `used`) BEFORE issuing
			// any tokens. Redemption spans a read in the validator and this mark, so
			// a plain read-then-unconditional-update leaves a window where two
			// concurrent requests both observe used=false and both mint tokens.
			// MarkCodeAsUsed returns true only for the request that flips the flag,
			// which is the single winner allowed to proceed (#77).
			//
			// A failed mint after a successful claim consumes the code (the client
			// must re-authenticate): acceptable, since codes are one-time and 60s
			// lived, and it is the price of never issuing two token sets from one code.
			claimed, err := database.MarkCodeAsUsed(nil, validateResult.CodeEntity.Id)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
			if !claimed {
				// No row transitioned. Usually that means another request concurrently
				// redeemed this same code and won the atomic claim above, and since #129
				// it can also mean the code was revoked between validation and this claim
				// because its session was terminated. The two are not distinguishable from
				// here and do not need to be: both refuse generically.
				//
				// Reject WITHOUT running the session-wide reuse cascade. In the race case
				// the winner is a legitimate in-flight redemption (a concurrent duplicate
				// still had to carry the correct PKCE verifier), and tearing the session
				// down here would fight the winner's in-progress token minting on the same
				// rows. In the revoked case the session is already gone and its grants are
				// already swept, so there is nothing left to cascade over.
				//
				// This does not weaken reuse protection: a genuine *later* replay of an
				// already-used code is still detected and fully revoked by the
				// sequential-reuse path in the validator above (#77).
				slog.Debug("authorization_code: code could not be claimed, rejecting redemption",
					"codeId", validateResult.CodeEntity.Id)
				jsonErrorConformed(httpHelper, w, r, customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
					"Code is invalid.", http.StatusBadRequest))
				return
			}

			tokenResp, err := tokenIssuer.GenerateTokenResponseForAuthCode(r.Context(), validateResult.CodeEntity)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			auditLogger.Log(constants.AuditTokenIssuedAuthorizationCodeResponse, map[string]interface{}{
				"codeId": validateResult.CodeEntity.Id,
			})

			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Pragma", "no-cache")
			httpHelper.EncodeJson(w, r, tokenResp)
			return

		case "client_credentials":
			tokenResp, err := tokenIssuer.GenerateTokenResponseForClientCred(r.Context(), validateResult.Client, validateResult.Scope)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			auditLogger.Log(constants.AuditTokenIssuedClientCredentialsResponse, map[string]interface{}{
				"clientId": validateResult.Client.Id,
				// Which scopes were issued, to whom. Absent before, which is why exploitation of
				// the #104 cross-resource escalation cannot be reconstructed from the audit log for
				// any period before this release. Forward-looking only.
				"scope": validateResult.Scope,
			})

			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Pragma", "no-cache")
			httpHelper.EncodeJson(w, r, tokenResp)
			return

		case "refresh_token":
			refreshToken := validateResult.RefreshToken
			if refreshToken.Revoked {
				// The validation-time read observed this token already revoked, so it is
				// a replay CANDIDATE: rotation retired it and it came back. Contain the
				// whole rotation family, since a thief holding one member can otherwise
				// keep rotating while the victim is locked out (#128).
				//
				// Attempt containment even though the server cannot distinguish a
				// malicious replay from a legitimate concurrent duplicate whose lookup
				// landed after the winner's claim. That is RFC 9700 Section 4.14.2's
				// strict model, and it is deliberate: no overlap window, because any
				// window leaves the defining theft scenario uncontained.
				revokedCount, err := database.RevokeRefreshTokenFamily(nil, refreshToken.FirstRefreshTokenJti)
				if err != nil {
					httpHelper.InternalServerError(w, r, err)
					return
				}

				// Audited only when containment actually moved a member from live to
				// revoked. A zero count means containment changed no state, which an
				// already-swept family, an earlier auth-code-reuse cascade and a repeated
				// replay all produce. Suppressing the event there avoids duplicate and
				// misattributed audit rows and stops a client amplifying the log by
				// replaying the same token repeatedly.
				//
				// It does NOT classify the presentation as benign. A repeated replay may
				// well be malicious; it simply caused no new containment, and the
				// presentation that DID contain the family is the one that recorded it.
				//
				// No explicit transaction: containment is one statement, so its
				// successful return IS its commit, and the event is emitted after it.
				if revokedCount > 0 {
					// The principal fields are populated uniformly for both linkage
					// shapes, so a security-event consumer does not need flow-specific
					// logic just to identify the client and user. This deliberately
					// departs from AuditTokenIssuedRefreshTokenResponse below, which
					// logs codeId on one shape and userId/clientId on the other.
					replayClientId := refreshToken.ClientId.Int64
					replayUserId := refreshToken.UserId.Int64
					replayFlow := "ropc"
					if validateResult.CodeEntity != nil {
						replayClientId = validateResult.CodeEntity.ClientId
						replayUserId = validateResult.CodeEntity.UserId
						replayFlow = "auth_code"
					}

					auditLogger.Log(constants.AuditRefreshTokenReplayDetected, map[string]interface{}{
						"presentedRefreshTokenJti": refreshToken.RefreshTokenJti,
						"firstRefreshTokenJti":     refreshToken.FirstRefreshTokenJti,
						"revokedCount":             revokedCount,
						"clientId":                 replayClientId,
						"userId":                   replayUserId,
						"flow":                     replayFlow,
					})
				} else {
					slog.Debug("refresh_token: revoked token presented, no live family members to revoke",
						"refreshTokenId", refreshToken.Id)
				}

				jsonErrorConformed(httpHelper, w, r, customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
					"This refresh token has been revoked.", http.StatusBadRequest))
				return
			}

			// A refresh is governed by the switch of the flow that ISSUED the token, not by
			// the authorization code flag alone. Until this landed the whole arm refused on
			// !AuthorizationCodeEnabled, so an ROPC-only client could never redeem the token
			// ROPC handed it, and turning ROPC off stopped nothing already issued (#250).
			//
			// It sits BELOW containment on purpose. A stolen token replayed while its flow is
			// switched off must still revoke its rotation family and still be audited;
			// refusing first would leave the family live and the theft unrecorded, which is
			// what the old placement did.
			//
			// It sits ABOVE MarkRefreshTokenAsRevoked on purpose too, so a token this refuses
			// is not spent: the operator may turn the switch back on, and a live token should
			// still be live when they do.
			//
			// The ROPC arm resolves the global setting rather than reading only the per-client
			// override, because the issuing arm does. Otherwise turning the global switch off
			// would block new logins while inheriting clients kept refreshing indefinitely,
			// which is not what the switch says it does.
			settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
			if validateResult.CodeEntity == nil {
				// Same ROPC marker the containment block above reads to set replayFlow, so
				// the two cannot disagree about what an ROPC token is.
				if !validateResult.Client.IsResourceOwnerPasswordCredentialsEnabled(settings.ResourceOwnerPasswordCredentialsEnabled) {
					jsonErrorConformed(httpHelper, w, r, customerrors.NewErrorDetailWithHttpStatusCode(
						"unauthorized_client", validators.ROPCNotAuthorizedErrorMsg, http.StatusBadRequest))
					return
				}
			} else if !validateResult.Client.AuthorizationCodeEnabled {
				jsonErrorConformed(httpHelper, w, r, customerrors.NewErrorDetailWithHttpStatusCode(
					"unauthorized_client", authCodeNotAuthorizedErrorMsg, http.StatusBadRequest))
				return
			}

			// Atomically claim the row before minting anything. Until this landed the
			// handler read Revoked during request validation and then wrote
			// unconditionally, so two presentations of one refresh token could both
			// observe revoked = false and each mint a token set (#128).
			//
			// A false return does NOT mean specifically "another rotation claimed it".
			// It means the row is no longer live, which a concurrent rotation, a
			// concurrent security revocation such as RevokeUserAuthState, or the row
			// having been deleted all produce.
			//
			// Refusing without any family cascade follows from that AMBIGUITY, not from
			// the three cases being individually harmless. One of them is a concurrent
			// rotation whose freshly minted child a cascade would destroy, and nothing
			// here can tell which case this is, so containment must not fire. Same
			// reasoning as the authorization code path's lost claim (#77): it protects
			// the requests whose lookup preceded the winning claim, so a legitimate
			// double-submit does not tear down the winner's in-flight mint.
			//
			// A credential-change revocation is genuinely benign here, since it advanced
			// the user's generation and the validator rejects the whole family before
			// this handler runs. A DELETED row is an accepted residual: deletion is
			// row-scoped and says nothing about descendants, so live family members can
			// outlive their deleted ancestor without being contained on this path.
			// Containment still fires on the next replay presented against any surviving
			// member, because that request reads its own row revoked.
			//
			// It does not protect EVERY concurrent duplicate. One whose lookup lands
			// after the winner's claim reads the row already revoked and takes the
			// branch above instead. That is the strict rotation policy, chosen
			// deliberately: the server cannot tell a delayed legitimate duplicate from
			// a malicious replay from the token and the row alone.
			claimed, err := database.MarkRefreshTokenAsRevoked(nil, refreshToken.Id)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
			if !claimed {
				slog.Debug("refresh_token: token was no longer live at claim time, rejecting",
					"refreshTokenId", refreshToken.Id)
				jsonErrorConformed(httpHelper, w, r, customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
					"This refresh token has been revoked.", http.StatusBadRequest))
				return
			}

			var tokenResp *oauth.TokenResponse

			// Check if this is an ROPC refresh token (no CodeEntity) or auth code flow token
			if validateResult.CodeEntity == nil {
				// ROPC refresh token - use dedicated ROPC refresh flow
				ropcInput := &oauth.GenerateTokenForRefreshROPCInput{
					RefreshToken:     validateResult.RefreshToken,
					ScopeRequested:   input.Scope,
					RefreshTokenInfo: validateResult.RefreshTokenInfo,
				}

				tokenResp, err = tokenIssuer.GenerateTokenResponseForRefreshROPC(r.Context(), ropcInput)
				if err != nil {
					httpHelper.InternalServerError(w, r, err)
					return
				}

				auditLogger.Log(constants.AuditTokenIssuedRefreshTokenResponse, map[string]interface{}{
					"userId":          validateResult.RefreshToken.UserId.Int64,
					"clientId":        validateResult.RefreshToken.ClientId.Int64,
					"refreshTokenJti": validateResult.RefreshToken.RefreshTokenJti,
					"flow":            "ropc",
				})
			} else {
				// Auth code flow refresh token
				refreshInput := &oauth.GenerateTokenForRefreshInput{
					Code:             validateResult.CodeEntity,
					ScopeRequested:   input.Scope,
					RefreshToken:     validateResult.RefreshToken,
					RefreshTokenInfo: validateResult.RefreshTokenInfo,
				}

				tokenResp, err = tokenIssuer.GenerateTokenResponseForRefresh(r.Context(), refreshInput)
				if err != nil {
					httpHelper.InternalServerError(w, r, err)
					return
				}

				// bump user session (only for auth code flow - ROPC doesn't use sessions)
				// For refresh token requests, we're not doing step-up authentication,
				// so we pass empty strings for authMethods and acrLevel to preserve
				// the session's existing values.
				if len(refreshToken.SessionIdentifier) > 0 {
					userSession, err := userSessionManager.BumpUserSession(r, refreshToken.SessionIdentifier,
						refreshToken.Code.ClientId, "", "")
					if err != nil {
						httpHelper.InternalServerError(w, r, err)
						return
					}

					auditLogger.Log(constants.AuditBumpedUserSession, map[string]interface{}{
						"userId":   userSession.UserId,
						"clientId": refreshToken.Code.ClientId,
					})
				}

				auditLogger.Log(constants.AuditTokenIssuedRefreshTokenResponse, map[string]interface{}{
					"codeId":          validateResult.CodeEntity.Id,
					"refreshTokenJti": validateResult.RefreshToken.RefreshTokenJti,
					"flow":            "auth_code",
				})
			}

			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Pragma", "no-cache")
			httpHelper.EncodeJson(w, r, tokenResp)
			return

		case "password":
			// RFC 6749 Section 4.3 - Resource Owner Password Credentials Grant
			// SECURITY NOTE: ROPC is deprecated in OAuth 2.1 due to credential exposure risks.

			// No session identifier is read here on purpose. MiddlewareSessionIdentifier is
			// mounted globally, so a browser cookie's session lands in the request context
			// even on the token endpoint, and forwarding it made a password grant for one
			// user carry another user's session identifier in its ID token whenever the
			// browser was logged in as somebody else. ROPC is a direct credential exchange
			// with no session of its own (#106).
			ropcInput := &oauth.ROPCGrantInput{
				Client: validateResult.Client,
				User:   validateResult.User,
				Scope:  validateResult.Scope,
			}

			tokenResp, err := tokenIssuer.GenerateTokenResponseForROPC(r.Context(), ropcInput)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			auditLogger.Log(constants.AuditTokenIssuedROPCResponse, map[string]interface{}{
				"userId":   validateResult.User.Id,
				"clientId": validateResult.Client.Id,
			})

			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Pragma", "no-cache")
			httpHelper.EncodeJson(w, r, tokenResp)
			return

		default:
			jsonErrorConformed(httpHelper, w, r, customerrors.NewErrorDetailWithHttpStatusCode("unsupported_grant_type",
				"Unsupported grant_type.", http.StatusBadRequest))
			return
		}
	}
}

// revokeAndAuditAuthCodeReuse runs the RFC 6749 §10.5 response to a reused
// authorization code: it revokes the associated token family/session and, only
// on a successful revoke, emits the reuse audit event (so the audit reflects
// real revoked JTIs). It is shared by the validator-driven sequential-reuse
// path and the concurrent double-spend guard in the authorization_code grant
// (#77). On a nil return the caller is responsible for writing the client-facing
// invalid_grant response; on a non-nil error the caller must surface a 500.
func revokeAndAuditAuthCodeReuse(database data.Database, auditLogger AuditLogger, code *models.Code) error {
	revokedJtis, err := revokeOnAuthCodeReuse(database, code)
	if err != nil {
		return err
	}
	if code != nil {
		auditLogger.Log(constants.AuditAuthCodeReuseDetected, map[string]interface{}{
			"clientId":                code.ClientId,
			"userId":                  code.UserId,
			"codeId":                  code.Id,
			"sessionIdentifier":       code.SessionIdentifier,
			"revokedRefreshTokenJtis": revokedJtis,
		})
	}
	return nil
}

// revokeOnAuthCodeReuse revokes refresh tokens linked to the replayed code's
// session and deletes the user session. All writes happen inside a single
// transaction so any failure rolls the entire revocation back rather than
// leaving partial state. The replay response itself must NOT look successful
// when revocation fails, so callers should surface a 500 to the client.
func revokeOnAuthCodeReuse(database data.Database, code *models.Code) ([]string, error) {
	if code == nil {
		return nil, nil
	}

	tx, err := database.BeginTransaction()
	if err != nil {
		return nil, err
	}
	defer database.RollbackTransaction(tx) //nolint:errcheck

	var refreshTokens []*models.RefreshToken
	if code.SessionIdentifier != "" {
		refreshTokens, err = database.GetRefreshTokensBySessionIdentifier(tx, code.SessionIdentifier)
	} else {
		// Defensive fallback: auth-code-flow codes always carry a session
		// identifier today, but if a future change ever produces a
		// session-less auth code, fall back to revoking only the refresh
		// tokens directly linked to this code so reuse still has teeth.
		slog.Warn("auth code reuse on a code without a session identifier, falling back to code-id-scoped revocation",
			"codeId", code.Id)
		refreshTokens, err = database.GetRefreshTokensByCodeId(tx, code.Id)
	}
	if err != nil {
		return nil, err
	}

	revokedJtis, err := revokeRefreshTokens(database, tx, refreshTokens)
	if err != nil {
		return nil, err
	}

	// Tear down the session only when we actually revoked tokens issued from the
	// replayed code. If there were none to revoke, there is nothing to contain, and
	// deleting the session would disrupt an unrelated/in-flight session. This is
	// what makes concurrent redemption safe: a losing racer's cascade finds no
	// committed tokens yet (revokedJtis is empty) and so leaves the winner's live
	// session intact, instead of tearing it down out from under the winner's
	// in-progress mint (which read that session for its refresh-token lifetime). (#77)
	if code.SessionIdentifier != "" && len(revokedJtis) > 0 {
		session, err := database.GetUserSessionBySessionIdentifier(tx, code.SessionIdentifier)
		if err != nil {
			return nil, err
		}
		if session != nil {
			if err := database.DeleteUserSession(tx, session.Id); err != nil {
				return nil, err
			}
		}
	}

	if err := database.CommitTransaction(tx); err != nil {
		return nil, err
	}
	return revokedJtis, nil
}

// extractClientCredentials extracts client_id and client_secret from the request.
// It supports both client_secret_basic (Authorization header) and client_secret_post (form body).
// Per RFC 6749 clients MUST NOT use more than one authentication method per request.
// Returns usedBasicAuth=true if the client used HTTP Basic Authentication.
func extractClientCredentials(r *http.Request) (clientId, clientSecret string, usedBasicAuth bool, err error) {
	// Check for Basic auth in Authorization header
	basicClientId, basicClientSecret, hasBasicAuth := parseBasicAuth(r.Header.Get("Authorization"))

	// Get credentials from POST body
	postClientId := r.PostForm.Get("client_id")
	postClientSecret := r.PostForm.Get("client_secret")
	hasPostAuth := postClientSecret != ""

	// RFC 6749 clients MUST NOT use more than one authentication method
	if hasBasicAuth && hasPostAuth {
		return "", "", false, customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
			"Client authentication failed: multiple authentication methods provided. "+
				"Use either HTTP Basic authentication OR client_secret in the request body, but not both.",
			http.StatusBadRequest)
	}

	// Use Basic auth if present
	if hasBasicAuth {
		return basicClientId, basicClientSecret, true, nil
	}

	// Fall back to POST body credentials
	return postClientId, postClientSecret, false, nil
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

// scopeWhitespaceRegex matches any run of whitespace, so runs collapse to a single space.
// Package-level so it compiles once rather than per request.
var scopeWhitespaceRegex = regexp.MustCompile(`\s+`)

// normalizeScope canonicalizes a raw `scope` form value: trim, collapse internal whitespace runs
// to single spaces, and drop duplicates preserving first-occurrence order.
//
// This is the same operation AuthContext.SetScope (core/oauth/auth_context.go) already applies on
// the authorize path, so with this in place all four of the codebase's scope-handling sites agree.
//
// What motivates it: the token endpoint used to collapse whitespace onto a LOCAL copy and never
// assign it back, so the caller's raw string was carried onward. A client separating scopes with a
// tab therefore passed scope validation, which collapses whitespace before checking, and then hit a
// **500**: the issuer re-parses the scope, splits it on spaces alone, and the whole tab-joined
// string arrives as one element whose colon-split yields three parts rather than two
// (token_issuer.go). Refresh had the same shape and the same outcome. Verified by reverting this
// normalization and re-running the end-to-end tests, which fail with server_error.
//
// So the defect cost functionality rather than security. Note it did NOT produce a token whose
// scopes silently match nothing: the issuer rejected first. Do not restate that older claim, which
// this project's spec made twice before it was measured.
//
// Deduplication is a consistency fix rather than a correctness one, since HasScope matches the
// first occurrence and a repeated scope is inert.
//
// Callers must handle the "provided but normalizes to empty" case themselves; see the call site in
// HandleTokenPost. Returning "" for whitespace-only input is deliberate, so that case is
// distinguishable.
func normalizeScope(scope string) string {
	collapsed := scopeWhitespaceRegex.ReplaceAllString(strings.TrimSpace(scope), " ")
	if collapsed == "" {
		return ""
	}

	unique := make([]string, 0, strings.Count(collapsed, " ")+1)
	for _, scopeStr := range strings.Split(collapsed, " ") {
		if scopeStr == "" || slices.Contains(unique, scopeStr) {
			continue
		}
		unique = append(unique, scopeStr)
	}

	return strings.Join(unique, " ")
}

// grantTypeConsumesScope reports whether a grant type reads the `scope` request parameter.
//
// Verified against every use of ValidateTokenRequestInput.Scope in the validator: client
// credentials, refresh and ROPC read it; the authorization code grant never does, because the
// scope comes from the stored code. RFC 6749 §4.1.3 does not define `scope` on that request in the
// first place, so rejecting a malformed one there would break an otherwise valid token exchange
// for no benefit.
func grantTypeConsumesScope(grantType string) bool {
	switch grantType {
	case "client_credentials", "refresh_token", "password":
		return true
	default:
		return false
	}
}
