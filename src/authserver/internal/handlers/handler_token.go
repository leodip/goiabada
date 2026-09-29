package handlers

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/issuance"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/internal/revocation"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/oauth"
)

// authCodeNotAuthorizedErrorMsg refuses a refresh token that an authorization code minted, for a
// client whose authorization code flow is now off. The wording is what the token validator's
// refresh arm carried before the gate moved into this handler, kept verbatim so that half of the
// endpoint's observable behaviour did not change (#250).
const authCodeNotAuthorizedErrorMsg = "The client associated with the provided client_id does not support authorization code flow."

// tokenDatabase is what the token endpoint needs: the code it marks used, the refresh tokens it
// rotates and revokes, and the session those grants hang from.
//
// It embeds the revocation port because the response to a reused code is
// revocation.RevokeOnAuthCodeReuseTx, which opens its own transaction on this handle.
type tokenDatabase interface {
	revocation.Database

	MarkCodeAsUsed(ctx context.Context, tx *sql.Tx, codeId int64) (bool, error)
	MarkRefreshTokenAsRevoked(ctx context.Context, tx *sql.Tx, refreshTokenId int64) (bool, error)
	RevokeRefreshTokenFamily(ctx context.Context, tx *sql.Tx, firstRefreshTokenJti string) (int64, error)
}

func HandleTokenPost(
	jsonWriter JSONWriter,
	userSessionManager UserSessionManager,
	database tokenDatabase,
	tokenIssuer TokenIssuer,
	tokenValidator TokenValidator,
	auditLogger AuditLogger,
	credentialFailures CredentialFailureRecorder,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// A body that cannot be parsed is the client's malformed request, RFC 6749 section
		// 5.2's invalid_request, and not a server fault: a url-encoding broken by the client,
		// or a body cut at the request-body limit (#426). Answered as a 500 it wrote an Error
		// record for every one. With the ROPC limiter on, its own ParseForm meets the failure
		// first and this one succeeds on an empty form, which is refused below for what it lacks.
		if err := r.ParseForm(); err != nil {
			jsonWriter.JsonError(w, r, customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
				"The request body could not be parsed.", http.StatusBadRequest))
			return
		}

		// Extract client credentials - supports both client_secret_basic and client_secret_post
		clientId, clientSecret, usedBasicAuth, err := extractClientCredentials(r)
		if err != nil {
			jsonWriter.JsonError(w, r, err)
			return
		}

		grantType := oidc.GrantType(r.PostForm.Get("grant_type"))

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
		normalizedScope := oidc.NormalizeScope(rawScope)

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
		if rawScope != "" && normalizedScope == "" && grantType.ReadsScope() {
			jsonWriter.JsonError(w, r, customerrors.NewErrorDetailWithHttpStatusCode("invalid_scope",
				"The 'scope' parameter was provided but contains no scopes. Either omit it entirely or supply one or more scopes separated by spaces.",
				http.StatusBadRequest))
			return
		}

		input := protocolvalidation.ValidateTokenRequestInput{
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

		settings, ok := reqctx.SettingsFrom(r.Context())
		if !ok {
			jsonWriter.JsonError(w, r, reqctx.ErrNoSettings)
			return
		}
		validateResult, err := tokenValidator.ValidateTokenRequest(r.Context(), settings, &input)
		if err != nil {
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
					jsonWriter.JsonError(w, r, revokeErr)
					return
				}
				revocation.LogAuthCodeReuse(r.Context(), auditLogger, reused.Code, result)
				jsonWriter.JsonError(w, r, reused.Detail)
				return
			}
			// Check if user is disabled and log audit event
			if errors.Is(err, protocolvalidation.ErrUserDisabled) {
				auditLogger.Log(r.Context(), audit.AuditUserDisabled, map[string]interface{}{
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
			if errors.Is(err, protocolvalidation.ErrCodeRedirectURIDeregistered) {
				auditLogger.Log(r.Context(), audit.AuditRedemptionRefusedRedirectURI, map[string]interface{}{
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
			// invalid_request, and the provided-but-empty rejection above fires before
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
			// set AuditROPCAuthFailed is documented to mean.
			//
			// ErrClientDisabled is the one exception, and it is the reason this is not a
			// bare code test: that check runs before the grant-type switch and before any
			// credential is read, so it is an invalid_grant that guessed nothing.
			var errDetail *customerrors.ErrorDetail
			if errors.As(err, &errDetail) &&
				input.GrantType == oidc.GrantTypePassword && errDetail.GetCode() == "invalid_grant" &&
				!errors.Is(err, protocolvalidation.ErrClientDisabled) {

				credentialFailures.RecordCredentialFailure(r)
				auditLogger.Log(r.Context(), audit.AuditROPCAuthFailed, map[string]interface{}{
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

			if errors.As(err, &errDetail) && errDetail.GetCode() == "invalid_scope" {
				auditLogger.Log(r.Context(), audit.AuditTokenScopeDenied, map[string]interface{}{
					// clientIdentifier, the string from the request, not the numeric clientId the
					// issuance events use: the validator discards the client model on failure. See
					// the constant's doc comment for what this attests to per grant type.
					"clientIdentifier": input.ClientId,
					"grantType":        input.GrantType.String(),
					"scope":            input.Scope,
				})
			}

			jsonWriter.JsonError(w, r, err)
			return
		}

		switch input.GrantType {
		case oidc.GrantTypeAuthorizationCode:
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
			claimed, err := database.MarkCodeAsUsed(r.Context(), nil, validateResult.CodeEntity.Id)
			if err != nil {
				jsonWriter.JsonError(w, r, err)
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
				slog.DebugContext(r.Context(), "code could not be claimed, rejecting the redemption",
					"grant_type", oidc.GrantTypeAuthorizationCode.String(),
					"code_id", validateResult.CodeEntity.Id)
				jsonWriter.JsonError(w, r, customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
					"Code is invalid.", http.StatusBadRequest))
				return
			}

			tokenResp, err := tokenIssuer.GenerateTokenResponseForAuthCode(r.Context(), settings, validateResult.CodeEntity)
			if err != nil {
				jsonWriter.JsonError(w, r, err)
				return
			}

			auditLogger.Log(r.Context(), audit.AuditTokenIssuedAuthorizationCodeResponse, map[string]interface{}{
				"codeId": validateResult.CodeEntity.Id,
			})

			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Pragma", "no-cache")
			jsonWriter.EncodeJson(w, r, tokenResp)
			return

		case oidc.GrantTypeClientCredentials:
			tokenResp, err := tokenIssuer.GenerateTokenResponseForClientCred(r.Context(), settings, validateResult.Client, validateResult.Scope)
			if err != nil {
				jsonWriter.JsonError(w, r, err)
				return
			}

			auditLogger.Log(r.Context(), audit.AuditTokenIssuedClientCredentialsResponse, map[string]interface{}{
				"clientId": validateResult.Client.Id,
				// Which scopes were issued, to whom. Absent before, which is why exploitation of
				// the #104 cross-resource escalation cannot be reconstructed from the audit log for
				// any period before this release. Forward-looking only.
				"scope": validateResult.Scope,
			})

			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Pragma", "no-cache")
			jsonWriter.EncodeJson(w, r, tokenResp)
			return

		case oidc.GrantTypeRefreshToken:
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
				revokedCount, err := database.RevokeRefreshTokenFamily(r.Context(), nil, refreshToken.FirstRefreshTokenJti)
				if err != nil {
					jsonWriter.JsonError(w, r, err)
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

					auditLogger.Log(r.Context(), audit.AuditRefreshTokenReplayDetected, map[string]interface{}{
						"presentedRefreshTokenJti": refreshToken.RefreshTokenJti,
						"firstRefreshTokenJti":     refreshToken.FirstRefreshTokenJti,
						"revokedCount":             revokedCount,
						"clientId":                 replayClientId,
						"userId":                   replayUserId,
						"flow":                     replayFlow,
					})
				} else {
					slog.DebugContext(r.Context(), "revoked refresh token presented, with no live family members to revoke",
						"grant_type", oidc.GrantTypeRefreshToken.String(),
						"refresh_token_id", refreshToken.Id)
				}

				jsonWriter.JsonError(w, r, customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
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
			if validateResult.CodeEntity == nil {
				// Same ROPC marker the containment block above reads to set replayFlow, so
				// the two cannot disagree about what an ROPC token is.
				if !validateResult.Client.IsResourceOwnerPasswordCredentialsEnabled(settings.ResourceOwnerPasswordCredentialsEnabled) {
					jsonWriter.JsonError(w, r, customerrors.NewErrorDetailWithHttpStatusCode(
						"unauthorized_client", protocolvalidation.ROPCNotAuthorizedErrorMsg, http.StatusBadRequest))
					return
				}
			} else if !validateResult.Client.AuthorizationCodeEnabled {
				jsonWriter.JsonError(w, r, customerrors.NewErrorDetailWithHttpStatusCode(
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
			// concurrent security revocation such as revocation.RevokeUserAuthState, or the row
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
			claimed, err := database.MarkRefreshTokenAsRevoked(r.Context(), nil, refreshToken.Id)
			if err != nil {
				jsonWriter.JsonError(w, r, err)
				return
			}
			if !claimed {
				slog.DebugContext(r.Context(), "refresh token was no longer live at claim time, rejecting",
					"grant_type", oidc.GrantTypeRefreshToken.String(),
					"refresh_token_id", refreshToken.Id)
				jsonWriter.JsonError(w, r, customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
					"This refresh token has been revoked.", http.StatusBadRequest))
				return
			}

			var tokenResp *oauth.TokenResponse

			// Check if this is an ROPC refresh token (no CodeEntity) or auth code flow token
			if validateResult.CodeEntity == nil {
				// ROPC refresh token - use dedicated ROPC refresh flow
				ropcInput := &issuance.GenerateTokenForRefreshROPCInput{
					RefreshToken:     validateResult.RefreshToken,
					ScopeRequested:   input.Scope,
					RefreshTokenInfo: validateResult.RefreshTokenInfo,
				}

				tokenResp, err = tokenIssuer.GenerateTokenResponseForRefreshROPC(r.Context(), settings, ropcInput)
				if err != nil {
					jsonWriter.JsonError(w, r, err)
					return
				}

				auditLogger.Log(r.Context(), audit.AuditTokenIssuedRefreshTokenResponse, map[string]interface{}{
					"userId":          validateResult.RefreshToken.UserId.Int64,
					"clientId":        validateResult.RefreshToken.ClientId.Int64,
					"refreshTokenJti": validateResult.RefreshToken.RefreshTokenJti,
					"flow":            "ropc",
				})
			} else {
				// Auth code flow refresh token
				refreshInput := &issuance.GenerateTokenForRefreshInput{
					Code:             validateResult.CodeEntity,
					ScopeRequested:   input.Scope,
					RefreshToken:     validateResult.RefreshToken,
					RefreshTokenInfo: validateResult.RefreshTokenInfo,
				}

				tokenResp, err = tokenIssuer.GenerateTokenResponseForRefresh(r.Context(), settings, refreshInput)
				if err != nil {
					jsonWriter.JsonError(w, r, err)
					return
				}

				// bump user session (only for auth code flow - ROPC doesn't use sessions)
				// For refresh token requests, we're not doing step-up authentication,
				// so we pass empty strings for authMethods and acrLevel to preserve
				// the session's existing values. The address is left as recorded too: a
				// session holds the latest address its user's browser was seen from, and a
				// refresh request often comes from the client's server instead (#243).
				if len(refreshToken.SessionIdentifier) > 0 {
					userSession, err := userSessionManager.BumpUserSession(r.Context(), refreshToken.SessionIdentifier,
						refreshToken.Code.ClientId, "", "", "")
					if err != nil {
						jsonWriter.JsonError(w, r, err)
						return
					}

					auditLogger.Log(r.Context(), audit.AuditBumpedUserSession, map[string]interface{}{
						"userId":   userSession.UserId,
						"clientId": refreshToken.Code.ClientId,
					})
				}

				auditLogger.Log(r.Context(), audit.AuditTokenIssuedRefreshTokenResponse, map[string]interface{}{
					"codeId":          validateResult.CodeEntity.Id,
					"refreshTokenJti": validateResult.RefreshToken.RefreshTokenJti,
					"flow":            "auth_code",
				})
			}

			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Pragma", "no-cache")
			jsonWriter.EncodeJson(w, r, tokenResp)
			return

		case oidc.GrantTypePassword:
			// RFC 6749 Section 4.3 - Resource Owner Password Credentials Grant
			// SECURITY NOTE: ROPC is deprecated in OAuth 2.1 due to credential exposure risks.

			// No session identifier is read here on purpose. MiddlewareSessionIdentifier is
			// mounted globally, so a browser cookie's session lands in the request context
			// even on the token endpoint, and forwarding it made a password grant for one
			// user carry another user's session identifier in its ID token whenever the
			// browser was logged in as somebody else. ROPC is a direct credential exchange
			// with no session of its own (#106).
			ropcInput := &issuance.ROPCGrantInput{
				Client: validateResult.Client,
				User:   validateResult.User,
				Scope:  validateResult.Scope,
			}

			tokenResp, err := tokenIssuer.GenerateTokenResponseForROPC(r.Context(), settings, ropcInput)
			if err != nil {
				jsonWriter.JsonError(w, r, err)
				return
			}

			auditLogger.Log(r.Context(), audit.AuditTokenIssuedROPCResponse, map[string]interface{}{
				"userId":   validateResult.User.Id,
				"clientId": validateResult.Client.Id,
			})

			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Pragma", "no-cache")
			jsonWriter.EncodeJson(w, r, tokenResp)
			return

		default:
			jsonWriter.JsonError(w, r, customerrors.NewErrorDetailWithHttpStatusCode("unsupported_grant_type",
				"Unsupported grant_type.", http.StatusBadRequest))
			return
		}
	}
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
