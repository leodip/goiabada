package protocolvalidation

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/leodip/goiabada/core/errs"

	"github.com/leodip/goiabada/authserver/internal/issuance"
	"github.com/leodip/goiabada/authserver/internal/liveness"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/permissions"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/signingkeys"
	"github.com/leodip/goiabada/authserver/internal/userconsent"
	"github.com/leodip/goiabada/core/oauth"
)

// invalidGenerationMessage is returned when a refresh token's authentication generation
// no longer matches its user's. Deliberately identical in shape to the other invalid_grant
// refusals: a client cannot act on the distinction, and spelling out that a credential
// change superseded the grant would tell an attacker holding a stolen token exactly what
// happened (#106).
const invalidGenerationMessage = "The refresh token is invalid because it was superseded."

// invalidRefreshTokenMessage is the refusal that says nothing about why: a validly signed token
// with no row, an ROPC token issued before its grant's authentication instant was recorded, a
// token whose user is disabled, and a token the parser refuses for anything but its expiry, such as
// a malformed one or one no stored key verifies (#128, #125, #137, #680). None of these is something
// a client acts on differently, naming the first would confirm which JTIs were ever issued, naming
// the last would tell whoever holds a stolen token what became of the account, and naming the
// parser's check would tell a forger which one failed.
const invalidRefreshTokenMessage = "The refresh token is invalid."

// expiredRefreshTokenMessage refuses a token the parser found expired, which it says only once the
// signature verified. It is the one distinction among the parser's refusals a client acts on, and
// it names nothing a holder of the token cannot read from its exp (#680).
const expiredRefreshTokenMessage = "The refresh token is invalid because it has expired."

// RefreshTokenGrant is a validated refresh: the presented token as it was read, which may already be
// revoked (the issuer contains its family then, #128), the client that owns it, and the narrower
// scope the request asked for, empty to keep the token's own.
//
// IsROPC says which grant minted the token, which decides both the flow switch that governs the
// refresh (#250) and where its user and client are read from. A password grant's token carries no
// code, so its user and client are on the token row; an authorization code's are on
// RefreshToken.Code, loaded by the refresh token check (liveness.FindRefreshToken).
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
// no code. The token's state is judged by the refresh token check, liveness.RefreshToken, which
// introspection is to share (#676 decision 7); what is left here belongs to the request:
// authenticating the client, matching it to the token, PKCE for a public client, and the scope.
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
	if err := val.clients.VerifySecret(ctx, client, input.ClientSecret); err != nil {
		return nil, err
	}

	if len(input.RefreshToken) == 0 {
		return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_request",
			"Missing required refresh_token parameter.", http.StatusBadRequest)
	}

	refreshTokenInfo, err := val.tokenParser.DecodeAndValidateTokenString(ctx, input.RefreshToken, true)
	if err != nil {
		// A token the parser could not check, because the signing keys could not be read or
		// decoded, says nothing about the token: answered as a server fault, so the client keeps
		// its refresh token and may retry instead of reading it as dead (#680).
		if !errors.Is(err, signingkeys.ErrTokenRefused) {
			return nil, errs.Wrap(err, "unable to check the refresh token")
		}
		// The parser's error names the library and the check that failed, so it goes to the log
		// only. The client is told only whether the token expired: the parser says expired only
		// once the signature verified, and exp is readable by whoever holds the token.
		slog.WarnContext(ctx, "refused a refresh token the token parser did not accept",
			"error", err, "client_identifier", client.ClientIdentifier)
		description := invalidRefreshTokenMessage
		if errors.Is(err, signingkeys.ErrTokenExpired) {
			description = expiredRefreshTokenMessage
		}
		return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant", description, http.StatusBadRequest)
	}

	stored, err := liveness.FindRefreshToken(ctx, val.database, *refreshTokenInfo)
	if err != nil {
		return nil, err
	}
	if stored == nil {
		// A validly signed, unexpired refresh token with no row. RFC 6749 Section 5.2
		// classifies an invalid, expired or revoked refresh token as invalid_grant, so
		// this is a 400 rather than the 500 a plain error would produce through
		// JSONError's fallback mapping (#128).
		//
		// The message stays generic and does NOT say the row was missing. A caller
		// cannot be told apart from an attacker here, and distinguishing "no such row"
		// from "revoked" would confirm which JTIs were ever issued.
		return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
			invalidRefreshTokenMessage, http.StatusBadRequest)
	}
	refreshToken := stored.Row
	isROPCToken := stored.IsROPC
	tokenClientId := stored.ClientId
	tokenUserId := stored.UserId
	tokenScope := stored.Scope

	// RFC 6749 section 5.2 names this case under invalid_grant: a refresh token "issued to another
	// client". It was invalid_request, the code for a malformed request, so a client following the
	// RFC read its own bug where there was a token to throw away. The authorization code arm
	// answers the same situation with invalid_grant.
	//
	// Between the two calls of the refresh token check, so nothing about the token's state is
	// answered to another client: a public client_id is no secret, so until #137 anyone holding a
	// stolen refresh token could present it under any public client and tell three outcomes apart:
	// "does not belong to the client" for an untouched account, "The user account is disabled." and
	// the superseded wording. A check on the token's state placed above ownership reopens that.
	if tokenClientId != client.Id {
		return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
			"The refresh token is invalid because it does not belong to the client.", http.StatusBadRequest)
	}

	// The PKCE boundary again, on the arm where the exposure is durable (#245). A code
	// lives 60 seconds; a refresh token descended from it lives for the grant's lifetime,
	// so a client that becomes public keeps handing out tokens against a challenge-less
	// grant indefinitely unless this refuses them.
	//
	// It costs nothing: FindRefreshToken already put the code in hand. ROPC is excluded: code_id
	// is NULL, there is no code, and refreshToken.Code is the zero value on that path. On the
	// auth code path a missing code row leaves the same zero value, so CodeChallenge.Valid is
	// false and the token is refused. Fail-closed either way.
	//
	// Decided here and answered below, at its place among the check's refusals.
	challengeless := !isROPCToken && client.IsPublic &&
		(!refreshToken.Code.CodeChallenge.Valid || refreshToken.Code.CodeChallenge.String == "")

	refusal, err := liveness.RefreshToken(ctx, val.database, stored, *refreshTokenInfo, settings, time.Now().UTC())

	// One message for every way a grant's session can stop backing it, so they cannot drift into
	// several spellings of one fact: a terminated grant, a session gone, past its bounds, or of
	// another user. "Expired or terminated" already covers each, and another wording would tell a
	// presenter that the session exists and belongs to someone else.
	const invalidTokenMessage = "The refresh token is invalid because the associated session has expired or been terminated."

	// The refusals the check reads off what was loaded with the row answer first, in its order: a
	// disabled user's token gets the wording that says nothing about why (#137), and
	// UserDisabledError is what still tells the handler to write EventUserDisabled. A revoked code's
	// marker refuses a flipped client's code-descended children before PKCE does.
	switch refusal {
	case liveness.RefreshUserDisabled:
		return nil, userDisabled(invalidRefreshTokenMessage, stored.User.Id)
	case liveness.RefreshGenerationSuperseded:
		return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
			invalidGenerationMessage, http.StatusBadRequest)
	case liveness.RefreshNoAuthenticationInstant:
		// RFC 6749 section 5.2 answers a refresh token that cannot be used as invalid_grant (#125).
		return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
			invalidRefreshTokenMessage, http.StatusBadRequest)
	case liveness.RefreshCodeRevoked:
		return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
			invalidTokenMessage, http.StatusBadRequest)
	}

	// Every refusal below, and every fault the check met, comes from what it read after those, and
	// PKCE was answered before any of it was read. It still is: a challenge-less token is refused
	// for PKCE whatever the family's record and the session say, and whether or not they could be
	// read.
	if challengeless {
		return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
			"This refresh token descends from an authorization code issued without PKCE, and public clients are required to use PKCE.",
			http.StatusBadRequest)
	}
	if err != nil {
		return nil, err
	}

	switch refusal {
	case liveness.RefreshFamilyRevoked:
		// The same text as a disabled user's token and as an unknown jti, because the record says
		// nothing a client can act on and naming it would confirm which families were contained.
		return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
			invalidRefreshTokenMessage, http.StatusBadRequest)
	case liveness.RefreshSessionNotFound, liveness.RefreshSessionOfAnotherUser, liveness.RefreshSessionExpired:
		return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
			invalidTokenMessage, http.StatusBadRequest)
	case liveness.RefreshOfflineExpired:
		return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
			"The refresh token is invalid because it has expired (offline_access_max_lifetime).",
			http.StatusBadRequest)
	case liveness.RefreshLive, liveness.RefreshTokenRevoked:
		// A token refused only for its own revoked row is a replay of a grant nothing else ended.
		// The refresh redemption contains its family and audits it, and its answer says the token
		// was revoked, so it goes on as a live one does.
	default:
		return nil, errs.Errorf("unexpected refresh token refusal %d", refusal)
	}

	refreshTokenType := refreshTokenInfo.StringClaim("typ")

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
	//
	// consentEveryScope is the client's own rule: every scope is re-checked when the client requires
	// consent or the token is offline. owed is what is re-checked whatever the client says,
	// authserver:manage-account to any client but the admin console's, judged on the scope this
	// refresh would issue, so a refresh narrowed to leave it out reads no consent (#509 decision 3).
	// A token issued before the upgrade gets no exception: nothing in it tells one obtained with no
	// consent from one obtained with it. The refusals are a client requiring consent's, and come
	// before the token is spent.
	//
	// Nothing is owed for a token whose own row is revoked: that one is a replay, and refused here
	// it would never reach the containment the refresh redemption gives it, so its live successor
	// would refresh on with manage-account narrowed away. Containment refuses it, and issues nothing.
	var scopesFromConsent []string
	consentEveryScope := client.ConsentRequired || refreshTokenType == issuance.TokenTypeOffline.String()
	var owed []string
	if !refreshToken.Revoked {
		owed = userconsent.AlwaysOwed(client.ClientIdentifier, scopes)
	}
	consentCheckRequired := !isROPCToken && (consentEveryScope || len(owed) > 0)
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
		if consentCheckRequired && (consentEveryScope || slices.Contains(owed, inputScopeStr)) {
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
