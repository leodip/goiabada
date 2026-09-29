package protocolvalidation

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/leodip/goiabada/core/errs"

	"github.com/leodip/goiabada/authserver/internal/issuance"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/permissions"
	"github.com/leodip/goiabada/core/customerrors"
)

// invalidGenerationMessage is returned when a refresh token's authentication generation
// no longer matches its user's. Deliberately identical in shape to the other invalid_grant
// refusals: a client cannot act on the distinction, and spelling out that a credential
// change superseded the grant would tell an attacker holding a stolen token exactly what
// happened (#106).
const invalidGenerationMessage = "The refresh token is invalid because it was superseded."

// invalidRefreshTokenMessage is the refusal that says nothing about why: a validly signed token
// with no row, and an ROPC token issued before its grant's authentication instant was recorded
// (#128, #125). Neither reason is something a client acts on differently, and naming the first
// would confirm which JTIs were ever issued.
const invalidRefreshTokenMessage = "The refresh token is invalid."

// validateRefreshTokenGrant validates a refresh (RFC 6749 section 6) for a client
// ValidateTokenRequest has already found and found enabled. It serves both shapes of refresh
// token: one descended from an authorization code, and one the password grant issued, which has
// no code.
func (val *TokenValidator) validateRefreshTokenGrant(ctx context.Context, settings *models.Settings,
	client *models.Client, input *ValidateTokenRequestInput) (*ValidateTokenRequestResult, error) {
	// No flow rule lives on this arm, deliberately. A refresh is governed by the switch
	// of the flow that ISSUED the token, and which flow that was is not known here: the
	// method reads the presented token's linkage further below, and the client's flags
	// say nothing about a token minted before they were last changed.
	//
	// The gate is in HandleTokenPost's refresh arm instead, below the replay containment
	// block. Moving it back up here would refuse a stolen token before containment runs,
	// so a thief replaying a token whose flow happens to be switched off would leave the
	// rotation family live and nothing in the audit log. Whether a theft is detected must
	// not depend on which switches are on (#250).
	if err := val.authenticateClient(client, input.ClientSecret, input.UsedBasicAuth, wrongClientSecretErrorMsg); err != nil {
		return nil, err
	}

	if len(input.RefreshToken) == 0 {
		return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
			"Missing required refresh_token parameter.", http.StatusBadRequest)
	}

	refreshTokenInfo, err := val.tokenParser.DecodeAndValidateTokenString(ctx, input.RefreshToken, true)
	if err != nil {
		return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
			"The refresh token is invalid ("+err.Error()+").",
			http.StatusBadRequest)
	}

	jti := refreshTokenInfo.GetStringClaim("jti")
	if len(jti) == 0 {
		return nil, errs.New("the refresh token is invalid because it does not contain a jti claim")
	}

	refreshToken, err := val.database.GetRefreshTokenByJti(ctx, nil, jti)
	if err != nil {
		return nil, err
	}
	if refreshToken == nil {
		// A validly signed, unexpired refresh token with no row. RFC 6749 Section 5.2
		// classifies an invalid, expired or revoked refresh token as invalid_grant, so
		// this is a 400 rather than the 500 a plain error would produce through
		// JsonError's fallback mapping (#128).
		//
		// Retention (DeleteExpiredRefreshTokens) makes this rare but cannot remove it:
		// user deletion, referential cascades and database restores all leave a signed
		// token with no row.
		//
		// The message stays generic and does NOT say the row was missing. A caller
		// cannot be told apart from an attacker here, and distinguishing "no such row"
		// from "revoked" would confirm which JTIs were ever issued.
		return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
			invalidRefreshTokenMessage, http.StatusBadRequest)
	}

	// Determine if this is an auth code flow token (with CodeId) or ROPC token (with UserId/ClientId)
	isROPCToken := !refreshToken.CodeId.Valid

	var tokenClientId int64
	var tokenUserId int64
	var tokenScope string

	if isROPCToken {
		// ROPC refresh token - load User and Client directly from RefreshToken
		err = val.database.RefreshTokenLoadUser(ctx, nil, refreshToken)
		if err != nil {
			return nil, err
		}
		err = val.database.RefreshTokenLoadClient(ctx, nil, refreshToken)
		if err != nil {
			return nil, err
		}

		tokenClientId = refreshToken.ClientId.Int64
		tokenUserId = refreshToken.UserId.Int64
		tokenScope = refreshToken.Scope

		if !refreshToken.User.Enabled {
			return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
				"The user account is disabled.",
				http.StatusBadRequest)
		}

		// Read from the TOKEN row, not from any joined record (#106 decision 11(a)).
		if refreshToken.AuthStateGeneration != refreshToken.User.AuthStateGeneration {
			return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
				invalidGenerationMessage, http.StatusBadRequest)
		}
	} else {
		// Auth code flow refresh token - load Code and User from Code
		err = val.database.RefreshTokenLoadCode(ctx, nil, refreshToken)
		if err != nil {
			return nil, err
		}

		err = val.database.CodeLoadUser(ctx, nil, &refreshToken.Code)
		if err != nil {
			return nil, err
		}

		tokenClientId = refreshToken.Code.ClientId
		tokenUserId = refreshToken.Code.UserId
		tokenScope = refreshToken.Code.Scope

		if !refreshToken.Code.User.Enabled {
			return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
				"The user account is disabled.",
				http.StatusBadRequest)
		}

		// refreshToken.AuthStateGeneration, NOT refreshToken.Code.AuthStateGeneration.
		// The two legitimately differ: a self-service password change promotes the
		// preserved session's tokens to the new generation while their codes stay on the
		// old one, so reading the code here would reject exactly the tokens decision 4
		// exists to keep working (#106 decision 11(a)).
		if refreshToken.AuthStateGeneration != refreshToken.Code.User.AuthStateGeneration {
			return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
				invalidGenerationMessage, http.StatusBadRequest)
		}
	}

	if tokenClientId != client.Id {
		return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
			"The refresh token is invalid because it does not belong to the client.", http.StatusBadRequest)
	}

	// An ROPC token issued before migration 000051 records no authentication instant, so no
	// refresh of it can issue the auth_time OpenID Connect Core 1.0 section 12.2 requires, the
	// time of the original authentication, and RFC 6749 section 5.2 answers a refresh token
	// that cannot be used as invalid_grant. Its client makes one password grant again, and the
	// new family records the instant (#125). After the ownership check, so another client
	// presenting it learns nothing about the token beyond that it is not theirs.
	if isROPCToken && !refreshToken.AuthenticatedAt.Valid {
		return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
			invalidRefreshTokenMessage, http.StatusBadRequest)
	}

	// One message for both ways a grant's session can stop backing it, so the two
	// cannot drift into two spellings of one fact. Declared here rather than inside the
	// Refresh branch because the revoked check below needs it too.
	const invalidTokenMessage = "The refresh token is invalid because the associated session has expired or been terminated."

	// The termination boundary (#129 decision 4), the half that closes gap 2 for free.
	// A rotated child inherits its parent's code_id, so a marked code rejects every
	// descendant of that grant, including one inserted after the termination committed:
	// the child is born already rejected rather than caught by a sweep.
	//
	// This is what reaches an OFFLINE token, which the typ switch below never can. Its
	// Offline branch checks only the max lifetime and deliberately does not consult the
	// session, because a session merely expiring must leave an offline grant working
	// (decision 2). Termination has to be a positive fact for exactly that reason.
	//
	// ROPC is excluded because it has no grant origin to terminate: code_id is NULL,
	// there is no session, and refreshToken.Code is the zero value on that path.
	//
	// Placed after the ownership check above so an unauthenticated presenter of someone
	// else's token cannot learn from it that a session was ended (decision 7).
	if !isROPCToken && refreshToken.Code.Revoked {
		return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
			invalidTokenMessage, http.StatusBadRequest)
	}

	// The PKCE boundary again, on the arm where the exposure is durable (#245). A code
	// lives 60 seconds; a refresh token descended from it lives for the grant's lifetime,
	// so a client that becomes public keeps handing out tokens against a challenge-less
	// grant indefinitely unless this refuses them.
	//
	// It costs nothing: RefreshTokenLoadCode above already put the code in hand, so this
	// is the same struct the revoked check just read, for the same kind of code-borne rule.
	//
	// ROPC is excluded by isROPCToken exactly as the revoked check excludes it: code_id is
	// NULL, there is no code, and refreshToken.Code is the zero value on that path. On the
	// auth code path a missing code row leaves the same zero value, so CodeChallenge.Valid
	// is false and the token is refused. Fail-closed either way.
	//
	// Placed after the ownership check above for the reason that check documents: an
	// unauthenticated presenter of someone else's token learns nothing from it.
	if !isROPCToken && client.IsPublic &&
		(!refreshToken.Code.CodeChallenge.Valid || refreshToken.Code.CodeChallenge.String == "") {
		return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
			"This refresh token descends from an authorization code issued without PKCE, and public clients are required to use PKCE.",
			http.StatusBadRequest)
	}

	refreshTokenType := refreshTokenInfo.GetStringClaim("typ")
	switch refreshTokenType {
	case issuance.TokenTypeRefresh.String():
		// this is a normal refresh token
		// check the associated user session to see if it's still valid

		userSession, getUserSessionErr := val.database.GetUserSessionBySessionIdentifier(ctx, nil, refreshToken.SessionIdentifier)
		if getUserSessionErr != nil {
			return nil, getUserSessionErr
		}
		if userSession == nil {
			return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant", invalidTokenMessage,
				http.StatusBadRequest)
		}
		isSessionValid := userSession.IsValid(time.Now().UTC(), settings.UserSessionIdleTimeoutInSeconds, settings.UserSessionMaxLifetimeInSeconds, nil)
		if !isSessionValid {
			return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant", invalidTokenMessage,
				http.StatusBadRequest)
		}

		// The session has to belong to the grant's user. Without this a token bound to
		// someone else's session refreshes indefinitely and bumps that session as it
		// goes, so the wrong person's activity keeps the session alive and the wrong
		// person's logout ends the grant (#133).
		//
		// tokenUserId is the code's user on this arm, and only auth code flow reaches
		// it: ROPC refresh tokens are typed Offline unconditionally because there is no
		// browser session to bind to (generateRefreshTokenForROPC).
		//
		// The shared message again, deliberately. "Expired or terminated" already covers
		// both ways a session stops backing a grant, and a third wording here would tell
		// a presenter that the session exists and belongs to someone else.
		if userSession.UserId != tokenUserId {
			return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant", invalidTokenMessage,
				http.StatusBadRequest)
		}
	case issuance.TokenTypeOffline.String():
		// this is an offline refresh token
		// its lifetime is not linked to the user session

		// check if it's still valid according to its max lifetime
		maxLifetime := refreshTokenInfo.GetTimeClaim("offline_access_max_lifetime")
		if maxLifetime.IsZero() {
			return nil, errs.New("the refresh token is invalid because it does not contain an offline_access_max_lifetime claim")
		}
		if time.Now().UTC().After(maxLifetime) {
			return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
				"The refresh token is invalid because it has expired (offline_access_max_lifetime).",
				http.StatusBadRequest)
		}

		// The ownership boundary (#133), the half the Refresh arm cannot reach. An offline
		// grant is meant to outlive its session, which is why this arm otherwise never
		// looks at one, and that deliberate silence is what a grant cross-bound before the
		// fix slips through: it keeps rotating for the offline maximum lifetime, seeded at
		// a year, re-copying the code's acr each time. That is the single claim the old
		// path took from a session belonging to somebody else; amr and auth_time always
		// described the ceremony that actually happened.
		//
		// Read from the CODE, not from the token row. Only a Refresh token stores a session
		// identifier of its own; for an Offline one the issuer records the max lifetime in
		// that column instead, so refreshToken.SessionIdentifier is empty here and the
		// grant's session is the one its code was stamped with.
		//
		// Refuses only while the row is still there and its owner differs, exactly as the
		// code branch does, and for the same reason: absence is the ordinary state of a
		// healthy offline grant, so absence must not refuse. That is also the precise limit
		// of what this reaches, since the session sweep removes the evidence long before
		// the grant expires.
		//
		// Placed after the max-lifetime check so an already-expired token is refused
		// without a lookup, and ROPC excluded for the same reason as the revoked check
		// above: code_id is NULL, refreshToken.Code is the zero value, and there was never
		// a session to own the grant.
		if !isROPCToken && refreshToken.Code.SessionIdentifier != "" {
			codeSession, getUserSessionErr := val.database.GetUserSessionBySessionIdentifier(ctx, nil, refreshToken.Code.SessionIdentifier)
			if getUserSessionErr != nil {
				return nil, getUserSessionErr
			}
			if codeSession != nil && codeSession.UserId != tokenUserId {
				return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
					invalidTokenMessage, http.StatusBadRequest)
			}
		}
	default:
		return nil, errs.New("the refresh token is invalid because it does not contain a valid typ claim")
	}

	if len(input.Scope) > 0 {
		// must be equal to, or a subset of the original scopes requested
		scopesFromOriginal := oidc.SplitScope(tokenScope)

		for _, inputScopeStr := range oidc.SplitScope(input.Scope) {

			// invalid_scope, not invalid_grant: the grant is intact and the request asks for
			// more than it holds, which is what RFC 6749 section 5.2 names invalid_scope for
			// ("exceeds the scope granted by the resource owner") and what the endpoints
			// reference has always documented. It answered invalid_grant until #425. The
			// token is not spent, so the client can ask again within its grant.
			if !slices.Contains(scopesFromOriginal, inputScopeStr) {
				return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_scope",
					fmt.Sprintf("Scope '%v' is not recognized. The original access token does not grant the '%v' permission.", inputScopeStr, inputScopeStr),
					http.StatusBadRequest)
			}
		}
	}

	scopes := tokenScope
	if len(input.Scope) > 0 {
		scopes = input.Scope
	}
	inputScopes := oidc.SplitScope(scopes)

	sub := refreshTokenInfo.GetStringClaim("sub")
	user, err := val.database.GetUserBySubject(ctx, nil, sub)
	if err != nil {
		return nil, err
	}

	// GetUserBySubject answers (nil, nil) for a subject that names no row, and user.Id is
	// dereferenced by the permission re-check further down, so an unresolvable sub panicked the
	// process. The refusal belongs here rather than at the dereference: that branch is skipped
	// for an OIDC scope and offline_access, so a check placed there would refuse a
	// resource-scope refresh and let an openid-only one succeed against a subject that names
	// no user.
	//
	// A 500 rather than invalid_grant, because no supported operation can produce such a token:
	// DeleteUser deletes the user's refresh tokens in the same transaction, and the
	// authorization-code ones go with codes.user_id CASCADE. So this is a disagreement between
	// the tokens and the users table, which is the operator's to see, and it is what this arm
	// already answers for its other signed-but-impossible states (#123).
	if user == nil {
		return nil, errs.Errorf("subject not found: %v", sub)
	}

	// For ROPC tokens, skip consent check (ROPC bypasses consent - user providing credentials = implicit consent)
	// For auth code flow tokens, check consent if required. Both the lookup arguments and the consent
	// scope list are loop-invariant, so fetch and split the consent once here instead of on every
	// scope iteration.
	var scopesFromConsent []string
	consentCheckRequired := !isROPCToken && (client.ConsentRequired || refreshTokenType == issuance.TokenTypeOffline.String())
	if consentCheckRequired {
		consent, err := val.database.GetConsentByUserIdAndClientId(ctx, nil, tokenUserId, tokenClientId)
		if err != nil {
			return nil, err
		}
		if consent == nil {
			return nil,
				customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
					"The user has either not given consent to this client or the previously granted consent has been revoked.",
					http.StatusBadRequest)
		}
		scopesFromConsent = strings.Split(consent.Scope, " ")
	}

	for _, inputScopeStr := range inputScopes {
		// A value that is none of the scopes this server issues: not a claim scope, not
		// offline_access, and not resource:permission shaped. Refused first, so it gets one
		// answer whatever the client's consent setting.
		//
		// Every issuing path validates the scope before storing it, so only a grant stored
		// before a rule change can carry one. The case that exists is OFFLINE_ACCESS: until
		// #425 the validators case-folded offline_access, so a client that sent the uppercase
		// spelling had it stored, and #425 made the match exact, per RFC 6749 section 3.3.
		// Such a value used to fall through to the permission check below as if it were a
		// resource scope, which refused it as a caller's bug and answered 500.
		//
		// invalid_grant rather than 500, by the rule the unresolvable-subject check above
		// states: a 500 is for a state no supported operation can produce, and a previous
		// release produced this one (#123). invalid_grant rather than skipping the value,
		// because RFC 6749 section 6 keeps a rotated refresh token's scope identical to the
		// presented one: the value would have to be skipped on every refresh for the life of
		// the grant, and issuance, which reads the stored scope when the request omits one,
		// would need the same leniency. So the grant is refused, as one whose resource scope
		// names a deleted resource already is. The refusal comes before
		// MarkRefreshTokenAsRevoked, so the token is not spent, and a client that narrows
		// `scope` to leave the value out still refreshes.
		if !oidc.IsClaimScope(inputScopeStr) && !oidc.IsOfflineAccessScope(inputScopeStr) &&
			!permissions.IsResourceScope(inputScopeStr) {
			return nil, customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
				fmt.Sprintf("Scope '%v' is not recognized. It is not a scope this server issues.", inputScopeStr),
				http.StatusBadRequest)
		}

		// check if user still consents to this scope
		if consentCheckRequired {
			consentScopeExists := false
			for _, scopeFromConsent := range scopesFromConsent {
				if scopeFromConsent == inputScopeStr {
					consentScopeExists = true
					break
				}
			}

			if !consentScopeExists {
				return nil,
					customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
						fmt.Sprintf("Scope '%v' is not recognized. The user has not consented to the '%v' permission.", inputScopeStr, inputScopeStr),
						http.StatusBadRequest)
			}
		}

		// check if user still has permission to the scope. A claim scope and offline_access
		// are not permissions, so they are not re-checked.
		if !oidc.IsClaimScope(inputScopeStr) && !oidc.IsOfflineAccessScope(inputScopeStr) {
			userHasPermission, err := val.permissionChecker.UserHasScopePermission(ctx, user.Id, inputScopeStr)
			if err != nil {
				return nil, err
			}
			if !userHasPermission {
				return nil,
					customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
						fmt.Sprintf("Scope '%v' is not recognized. The user does not have the '%v' permission.", inputScopeStr, inputScopeStr),
						http.StatusBadRequest)
			}
		}
	}

	// For auth code flow tokens, return the Code entity
	// For ROPC tokens, CodeEntity will be nil (the handler will use RefreshToken.User and RefreshToken.Client)
	var codeEntity *models.Code
	if !isROPCToken {
		codeEntity = &refreshToken.Code
	}

	return &ValidateTokenRequestResult{
		CodeEntity:       codeEntity,
		Client:           client,
		RefreshToken:     refreshToken,
		RefreshTokenInfo: refreshTokenInfo,
	}, nil
}
