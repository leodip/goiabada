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
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/permissions"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/oauth"
)

// invalidGenerationMessage is returned when a refresh token's authentication generation
// no longer matches its user's. Deliberately identical in shape to the other invalid_grant
// refusals: a client cannot act on the distinction, and spelling out that a credential
// change superseded the grant would tell an attacker holding a stolen token exactly what
// happened (#106).
const invalidGenerationMessage = "The refresh token is invalid because it was superseded."

// invalidRefreshTokenMessage is the refusal that says nothing about why: a validly signed token
// with no row, an ROPC token issued before its grant's authentication instant was recorded, and a
// token whose user is disabled (#128, #125, #137). None of these is something a client acts on
// differently, naming the first would confirm which JTIs were ever issued, and naming the last
// would tell whoever holds a stolen token what became of the account.
const invalidRefreshTokenMessage = "The refresh token is invalid."

// RefreshTokenGrant is a validated refresh: the presented token as it was read, which may already be
// revoked (the issuer contains its family then, #128), the client that owns it, and the narrower
// scope the request asked for, empty to keep the token's own.
//
// IsROPC says which grant minted the token, which decides both the flow switch that governs the
// refresh (#250) and where its user and client are read from. A password grant's token carries no
// code, so its user and client are on the token row; an authorization code's are on
// RefreshToken.Code, loaded by the validator.
type RefreshTokenGrant struct {
	Client         *record.Client
	RefreshToken   *record.RefreshToken
	ScopeRequested string
	IsROPC         bool
}

func (*RefreshTokenGrant) GrantType() oidc.GrantType { return oidc.GrantTypeRefreshToken }

// validateRefreshTokenGrant validates a refresh (RFC 6749 section 6) for a client
// ValidateTokenRequest has already found and found enabled. It serves both shapes of refresh
// token: one descended from an authorization code, and one the password grant issued, which has
// no code.
func (val *TokenValidator) validateRefreshTokenGrant(ctx context.Context, settings *record.Settings,
	client *record.Client, input *ValidateTokenRequestInput) (*RefreshTokenGrant, error) {
	// No flow rule lives on this arm, deliberately. A refresh is governed by the switch
	// of the flow that ISSUED the token, and which flow that was is not known here: the
	// method reads the presented token's linkage further below, and the client's flags
	// say nothing about a token minted before they were last changed.
	//
	// The gate is in the refresh redemption instead (issuance.IssueRefreshTokenGrant), below the
	// replay containment. Moving it back up here would refuse a stolen token before containment runs,
	// so a thief replaying a token whose flow happens to be switched off would leave the
	// rotation family live and nothing in the audit log. Whether a theft is detected must
	// not depend on which switches are on (#250).
	if err := val.authenticateClient(client, input.ClientSecret); err != nil {
		return nil, err
	}

	if len(input.RefreshToken) == 0 {
		return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_request",
			"Missing required refresh_token parameter.", http.StatusBadRequest)
	}

	refreshTokenInfo, err := val.tokenParser.DecodeAndValidateTokenString(ctx, input.RefreshToken, true)
	if err != nil {
		return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
			"The refresh token is invalid ("+err.Error()+").",
			http.StatusBadRequest)
	}

	jti := refreshTokenInfo.StringClaim("jti")
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
		// JSONError's fallback mapping (#128).
		//
		// Retention (DeleteExpiredRefreshTokens) makes this rare but cannot remove it:
		// user deletion, referential cascades and database restores all leave a signed
		// token with no row.
		//
		// The message stays generic and does NOT say the row was missing. A caller
		// cannot be told apart from an attacker here, and distinguishing "no such row"
		// from "revoked" would confirm which JTIs were ever issued.
		return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
			invalidRefreshTokenMessage, http.StatusBadRequest)
	}

	// Determine if this is an auth code flow token (with CodeId) or ROPC token (with UserId/ClientId)
	isROPCToken := !refreshToken.CodeId.Valid

	var tokenClientId int64
	var tokenUserId int64
	var tokenScope string
	// tokenUser is the grant's user as loaded: the token row's for ROPC, the code's otherwise.
	var tokenUser *record.User

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
		tokenUser = &refreshToken.User
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
		tokenUser = &refreshToken.Code.User
	}

	// RFC 6749 section 5.2 names this case under invalid_grant: a refresh token "issued to another
	// client". It was invalid_request, the code for a malformed request, so a client following the
	// RFC read its own bug where there was a token to throw away. The authorization code arm
	// answers the same situation with invalid_grant.
	if tokenClientId != client.Id {
		return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
			"The refresh token is invalid because it does not belong to the client.", http.StatusBadRequest)
	}

	// The user's state is read only below the ownership check, for both shapes of token. A
	// public client_id is no secret, so until #137 anyone holding a stolen refresh token could
	// present it under any public client and tell three outcomes apart: "does not belong to the
	// client" for an untouched account, "The user account is disabled." and the superseded
	// wording. A check on the grant's user placed above ownership reopens that.
	//
	// A disabled user's token gets the wording that says nothing about why (#137), and
	// UserDisabledError is what still tells the handler to write EventUserDisabled.
	if !tokenUser.Enabled {
		return nil, userDisabled(invalidRefreshTokenMessage, tokenUser.Id)
	}

	// The generation boundary (#106), read from the TOKEN row, not from any joined record (#106
	// decision 11(a)): refreshToken.AuthStateGeneration, NOT refreshToken.Code.AuthStateGeneration.
	// The two legitimately differ on the code shape: a self-service password change promotes the
	// preserved session's tokens to the new generation while their codes stay on the old one, so
	// reading the code here would reject exactly the tokens #106 decision 4 exists to keep working.
	if refreshToken.AuthStateGeneration != tokenUser.AuthStateGeneration {
		return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
			invalidGenerationMessage, http.StatusBadRequest)
	}

	// An ROPC token issued before migration 000051 records no authentication instant, so no
	// refresh of it can issue the auth_time OpenID Connect Core 1.0 section 12.2 requires, the
	// time of the original authentication, and RFC 6749 section 5.2 answers a refresh token
	// that cannot be used as invalid_grant. Its client makes one password grant again, and the
	// new family records the instant (#125). After the ownership check, so another client
	// presenting it learns nothing about the token beyond that it is not theirs.
	if isROPCToken && !refreshToken.AuthenticatedAt.Valid {
		return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
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
		return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
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
		return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
			"This refresh token descends from an authorization code issued without PKCE, and public clients are required to use PKCE.",
			http.StatusBadRequest)
	}

	// A live token whose rotation family is recorded as revoked is refused here. The record is
	// written by replay containment and by a client made public, in the same transaction as the
	// revocation, and it outlives every member of the family, which is what makes it more than the
	// live-row sweep it accompanies: a rotation claims its parent and inserts its child in separate
	// statements, so a sweep that ran between them found no child to revoke, the child then
	// committed live, and this is the check that refuses it when it is presented. It is born
	// refused, as #129 and #245 make a code's child (#132, #259).
	//
	// Below every refusal above it, so a token one of them already answers keeps its wording: the
	// revoked code's marker (which refuses a flipped client's code-descended children first), the
	// user's state, the generation and the authentication instant. Below the ownership check for the
	// reason those are (#137): another client presenting a token must learn nothing about what
	// became of it.
	//
	// Skipped for a token whose own row is revoked: that one is a replay, which the refresh
	// redemption contains and audits, and its answer says the token was revoked. The record exists
	// for the live token nothing else refuses.
	//
	// The same text as a disabled user's token and as an unknown jti, because the record says
	// nothing a client can act on and naming it would confirm which families were contained.
	if !refreshToken.Revoked {
		familyRevoked, familyErr := val.database.IsRefreshTokenFamilyRevoked(ctx, nil, refreshToken.FirstRefreshTokenJti)
		if familyErr != nil {
			return nil, familyErr
		}
		if familyRevoked {
			return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
				invalidRefreshTokenMessage, http.StatusBadRequest)
		}
	}

	refreshTokenType := refreshTokenInfo.StringClaim("typ")
	switch refreshTokenType {
	case issuance.TokenTypeRefresh.String():
		// this is a normal refresh token
		// check the associated user session to see if it's still valid

		userSession, getUserSessionErr := val.database.GetUserSessionBySessionIdentifier(ctx, nil, refreshToken.SessionIdentifier)
		if getUserSessionErr != nil {
			return nil, getUserSessionErr
		}
		if userSession == nil {
			return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant", invalidTokenMessage,
				http.StatusBadRequest)
		}
		isSessionValid := userSession.IsValid(time.Now().UTC(), settings.UserSessionIdleTimeoutInSeconds, settings.UserSessionMaxLifetimeInSeconds, nil)
		if !isSessionValid {
			return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant", invalidTokenMessage,
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
			return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant", invalidTokenMessage,
				http.StatusBadRequest)
		}
	case issuance.TokenTypeOffline.String():
		// this is an offline refresh token
		// its lifetime is not linked to the user session

		// check if it's still valid according to its max lifetime
		maxLifetime := refreshTokenInfo.TimeClaim("offline_access_max_lifetime")
		if maxLifetime.IsZero() {
			return nil, errs.New("the refresh token is invalid because it does not contain an offline_access_max_lifetime claim")
		}
		if time.Now().UTC().After(maxLifetime) {
			return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
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
				return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
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
				return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_scope",
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

	// Only a client allowed to request the administrative scopes may renew one on a user's behalf,
	// read now and not when the token was issued, so a token issued before the upgrade or before an
	// operator withdrew the allowance is not renewed with it (#499 decision 6). Judged on the scope
	// this refresh would issue, so a request that leaves the administrative scope out is not
	// refused: RFC 6749 section 6 lets it narrow the grant. invalid_grant in the shape of the
	// per-scope re-checks below, and before the token is spent, as they are (decision 7). Ahead of
	// them because it is the client's to answer and reads nothing; the scope is in the grant, so the
	// comparison above has passed it.
	if refused := RefusedAdministrativeScopes(client, scopes); len(refused) > 0 {
		return nil, &AdministrativeScopeRefusedError{
			Detail: oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
				fmt.Sprintf("Scope '%v' is not recognized. %v", refused[0], AdministrativeScopeRefusal(refused).Description()),
				http.StatusBadRequest),
			Client: client,
			Scopes: refused,
			UserId: tokenUserId,
		}
	}

	sub := refreshTokenInfo.StringClaim("sub")
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
				oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
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
			return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
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
					oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
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
					oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
						fmt.Sprintf("Scope '%v' is not recognized. The user does not have the '%v' permission.", inputScopeStr, inputScopeStr),
						http.StatusBadRequest)
			}
		}
	}

	return &RefreshTokenGrant{
		Client:         client,
		RefreshToken:   refreshToken,
		ScopeRequested: input.Scope,
		IsROPC:         isROPCToken,
	}, nil
}
