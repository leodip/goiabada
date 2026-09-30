package issuance

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
)

// RefreshTokenGrantInput is what a refresh redemption reads: the presented token as the validator
// read it, the client that owns it, the narrower scope the request asked for (empty keeps the
// token's own), and which grant minted the token.
//
// IsROPC is the validator's answer and is not derived again here, so the two cannot disagree about
// what a password grant's token is. A password grant's token carries no code: its user and client
// are on the token row. Otherwise they are on RefreshToken.Code, which the validator loaded.
type RefreshTokenGrantInput struct {
	Client         *models.Client
	RefreshToken   *models.RefreshToken
	ScopeRequested string
	IsROPC         bool
}

// RefreshOutcome is what a successful refresh did besides answering, for the token handler's audit.
type RefreshOutcome struct {
	// BumpedSession is the browser session the refresh kept alive: nil for a password grant's token,
	// which has no session, and for a token bound to none.
	BumpedSession *models.UserSession
}

// RefreshTokenReplayedError is a refresh whose token was already revoked when it was read, answered
// after its rotation family was contained. FamilyRevokedCount is how many live members containment
// revoked, and FamilyRecorded is whether this containment wrote the family's revocation record;
// either one is what makes the replay worth an audit event.
type RefreshTokenReplayedError struct {
	FamilyRevokedCount int64
	FamilyRecorded     bool
}

func (e *RefreshTokenReplayedError) Error() string {
	return fmt.Sprintf("the presented refresh token was already revoked; containment revoked %d live family members",
		e.FamilyRevokedCount)
}

// RevokedFamilyReasonReplay is the reason a family's revocation record carries when containment
// wrote it, after a revoked refresh token was presented again.
const RevokedFamilyReasonReplay = "refresh_token_replay"

var (
	// ErrRefreshFlowDisabled is a refresh whose token was minted by a flow now switched off for its
	// client (#250).
	ErrRefreshFlowDisabled = errors.New("the flow that issued the refresh token is disabled for the client")

	// ErrRefreshTokenNotClaimed is a refresh that lost the claim on its token: the row was no longer
	// live when it was marked revoked (#128).
	ErrRefreshTokenNotClaimed = errors.New("the refresh token was no longer live when it was claimed")

	// ErrRefreshFamilyRevoked is a refresh whose family was recorded as revoked between the
	// validator's read and the rotation's own transaction: a containment or a client made public
	// committed in that gap. The rotation rolls back, so the claim on the presented token is undone
	// and no child is inserted (#132, #259).
	ErrRefreshFamilyRevoked = errors.New("the refresh token's family was revoked before its rotation committed")
)

// IssueRefreshTokenGrant redeems a validated refresh (RFC 6749 section 6). In order: it contains the
// family of a token that was already revoked, refuses a token whose issuing flow is switched off,
// then in ONE transaction claims the presented token, checks that the family is not recorded as
// revoked, and mints the new token set and inserts its child, and finally bumps the browser session
// a code-descended token is bound to.
//
// The claim and the insert share a transaction so that a revocation of the family cannot fall
// between them: it either commits before the check, which refuses the rotation and rolls the claim
// back, or after the insert, when it finds the child and revokes it too, or in the window between,
// where the child is born into a family that is already recorded and the validator refuses it (#132,
// #259). The session bump opens a transaction of its own and stays after the commit.
//
// A refusal is a *RefreshTokenReplayedError, ErrRefreshFlowDisabled, ErrRefreshTokenNotClaimed or
// ErrRefreshFamilyRevoked, which the token handler answers; anything else is a fault.
func (t *TokenIssuer) IssueRefreshTokenGrant(ctx context.Context, settings *models.Settings,
	input *RefreshTokenGrantInput) (*oauth.TokenResponse, *RefreshOutcome, error) {

	refreshToken := input.RefreshToken
	if refreshToken.Revoked {
		// The validation-time read observed this token already revoked, so it is a replay
		// CANDIDATE: rotation retired it and it came back. Contain the whole rotation family, since
		// a thief holding one member can otherwise keep rotating while the victim is locked out
		// (#128).
		//
		// Attempt containment even though the server cannot distinguish a malicious replay from a
		// legitimate concurrent duplicate whose lookup landed after the winner's claim. That is RFC
		// 9700 Section 4.14.2's strict model, and it is deliberate: no overlap window, because any
		// window leaves the defining theft scenario uncontained.
		//
		// The handler audits after it returns, so an audit row is never written for a containment
		// that rolled back.
		revokedCount, recorded, err := t.containRefreshTokenFamily(ctx, refreshToken.FirstRefreshTokenJti)
		if err != nil {
			return nil, nil, err
		}
		return nil, nil, &RefreshTokenReplayedError{FamilyRevokedCount: revokedCount, FamilyRecorded: recorded}
	}

	// A refresh is governed by the switch of the flow that ISSUED the token, not by the
	// authorization code flag alone. Until this landed every refresh was refused on
	// !AuthorizationCodeEnabled, so an ROPC-only client could never redeem the token ROPC handed
	// it, and turning ROPC off stopped nothing already issued (#250).
	//
	// It sits BELOW containment on purpose. A stolen token replayed while its flow is switched off
	// must still revoke its rotation family and still be audited; refusing first would leave the
	// family live and the theft unrecorded.
	//
	// It sits ABOVE MarkRefreshTokenAsRevoked on purpose too, so a token this refuses is not spent:
	// the operator may turn the switch back on, and a live token should still be live when they do.
	//
	// The ROPC arm resolves the global setting rather than reading only the per-client override,
	// because the password grant does. Otherwise turning the global switch off would block new
	// logins while inheriting clients kept refreshing indefinitely, which is not what the switch
	// says it does.
	if input.IsROPC {
		if !input.Client.IsResourceOwnerPasswordCredentialsEnabled(settings.ResourceOwnerPasswordCredentialsEnabled) {
			return nil, nil, ErrRefreshFlowDisabled
		}
	} else if !input.Client.AuthorizationCodeEnabled {
		return nil, nil, ErrRefreshFlowDisabled
	}

	// Atomically claim the row before minting anything. Until this landed the token was read
	// during validation and then written unconditionally, so two presentations of one refresh
	// token could both observe revoked = false and each mint a token set (#128).
	//
	// A false return does NOT mean specifically "another rotation claimed it". It means the row is
	// no longer live, which a concurrent rotation, a concurrent security revocation such as
	// revocation.RevokeUserAuthState, or the row having been deleted all produce.
	//
	// Refusing without any family cascade follows from that AMBIGUITY, not from the three cases
	// being individually harmless. One of them is a concurrent rotation whose freshly minted child a
	// cascade would destroy, and nothing here can tell which case this is, so containment must not
	// fire. Same reasoning as the authorization code's lost claim (#77): it protects the requests
	// whose lookup preceded the winning claim, so a legitimate double-submit does not tear down the
	// winner's mint in flight.
	//
	// A credential-change revocation is genuinely benign here, since it advanced the user's
	// generation and the validator rejects the whole family before this runs. A DELETED row is an
	// accepted residual: deletion is row-scoped and says nothing about descendants, so live family
	// members can outlive their deleted ancestor without being contained on this path. Containment
	// still fires on the next replay presented against any surviving member, because that request
	// reads its own row revoked.
	//
	// It does not protect EVERY concurrent duplicate. One whose lookup lands after the winner's
	// claim reads the row already revoked and takes the containment branch above instead. That is
	// the strict rotation policy, chosen deliberately: the server cannot tell a delayed legitimate
	// duplicate from a malicious replay from the token and the row alone.
	//
	// The claim is the first statement of the rotation's transaction, and every read and write after
	// it runs on that transaction. A lost claim or a revoked family leaves the body as an error, so
	// the helper rolls the transaction back: nothing is claimed and nothing is inserted.
	//
	// The body is safe to rerun after a deadlock (#301): the presented token is only read, every
	// token minted carries a fresh jti, and tokenResponse is whatever the attempt that committed
	// minted.
	var tokenResponse *oauth.TokenResponse
	err := t.database.RunInTransaction(ctx, func(tx *sql.Tx) error {
		claimed, err := t.database.MarkRefreshTokenAsRevoked(ctx, tx, refreshToken.Id)
		if err != nil {
			return err
		}
		if !claimed {
			slog.DebugContext(ctx, "refresh token was no longer live at claim time, rejecting",
				"grant_type", oidc.GrantTypeRefreshToken.String(),
				"refresh_token_id", refreshToken.Id)
			return ErrRefreshTokenNotClaimed
		}

		// The family's record, read on the rotation's own transaction and BELOW the claim. The
		// validator asked the same question at presentation, but a containment or a client made
		// public can commit between that read and this claim, and the live-row sweep it ran found no
		// child to revoke, because this rotation had not inserted one yet. The record is what that
		// sweep left behind for this check to find. Without it the rotation goes on to insert a live
		// child into a family the operator believes is revoked, and nothing but a record refuses it
		// (#132, #259). A revocation that commits after this read and before the insert leaves the
		// child born into a recorded family, which the validator refuses when it is presented.
		revoked, err := t.database.IsRefreshTokenFamilyRevoked(ctx, tx, refreshToken.FirstRefreshTokenJti)
		if err != nil {
			return err
		}
		if revoked {
			return ErrRefreshFamilyRevoked
		}

		if input.IsROPC {
			tokenResponse, err = t.mintROPCRefreshTokens(ctx, tx, settings, refreshToken, input.ScopeRequested)
		} else {
			tokenResponse, err = t.mintCodeRefreshTokens(ctx, tx, settings, &refreshToken.Code, refreshToken, input.ScopeRequested)
		}
		return err
	})
	if err != nil {
		return nil, nil, err
	}

	if input.IsROPC {
		// A password grant's token has no browser session to bump.
		return tokenResponse, &RefreshOutcome{}, nil
	}

	outcome := &RefreshOutcome{}
	if len(refreshToken.SessionIdentifier) > 0 {
		// No step-up happens on a refresh, so empty authentication methods and ACR level leave the
		// session's own. The address is left as recorded too: a session holds the latest address
		// its user's browser was seen from, and a refresh request often comes from the client's
		// server instead (#243).
		outcome.BumpedSession, err = t.sessions.BumpUserSession(ctx, refreshToken.SessionIdentifier,
			refreshToken.Code.ClientId, "", "", "")
		if err != nil {
			return nil, nil, err
		}
	}
	return tokenResponse, outcome, nil
}

// containRefreshTokenFamily records a rotation family as revoked and revokes every live member, in
// one transaction, and reports how many members it revoked and whether it wrote the record.
//
// The record is written first and in the same transaction as the sweep, so a family is never
// swept without a record: a rotation that claimed its parent and has not inserted its child holds
// no live row for the sweep to find, and only the record refuses the child when it arrives (#132).
// A replay of a token whose family is already recorded writes nothing and revokes nothing, which
// the handler reads as a repeated replay.
//
// Two containments of one new family can both read the record absent and the second insert then
// loses on the key. RunInTransactionRetryingConflict runs the loser once more, and it finds the
// record the winner committed.
func (t *TokenIssuer) containRefreshTokenFamily(ctx context.Context, firstRefreshTokenJti string) (int64, bool, error) {
	var revokedCount int64
	var recorded bool
	err := data.RunInTransactionRetryingConflict(ctx, t.database, func(tx *sql.Tx) error {
		var err error
		recorded, err = t.database.RecordRefreshTokenFamilyRevoked(ctx, tx, firstRefreshTokenJti, RevokedFamilyReasonReplay)
		if err != nil {
			return err
		}
		revokedCount, err = t.database.RevokeRefreshTokenFamily(ctx, tx, firstRefreshTokenJti)
		return err
	})
	if err != nil {
		return 0, false, err
	}
	return revokedCount, recorded, nil
}

// mintCodeRefreshTokens mints the token set for a claimed refresh token descended from an
// authorization code, and inserts its child. Every statement runs on tx, the rotation's own
// transaction: the reads because sqlitedb has one connection, which tx holds, and a read on nil
// would wait on it until the context expired, dropping the picture claim without an error (#437).
func (t *TokenIssuer) mintCodeRefreshTokens(ctx context.Context, tx *sql.Tx, settings *models.Settings,
	code *models.Code, parent *models.RefreshToken, scopeRequested string) (*oauth.TokenResponse, error) {

	err := t.database.CodeLoadClient(ctx, tx, code)
	if err != nil {
		return nil, err
	}

	scopeToUse := code.Scope
	if len(scopeRequested) > 0 {
		scopeToUse = scopeRequested
	}

	tokenExpirationInSeconds := tokenLifetimeSeconds(settings, &code.Client)

	var tokenResponse = oauth.TokenResponse{
		TokenType: TokenTypeBearer.String(),
		ExpiresIn: int64(tokenExpirationInSeconds),
	}

	privKey, keyIdentifier, err := t.loadSigningKey(ctx, tx)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()

	// access_token -----------------------------------------------------------------------

	err = t.database.CodeLoadUser(ctx, tx, code)
	if err != nil {
		return nil, err
	}

	err = t.database.UserLoadGroups(ctx, tx, &code.User)
	if err != nil {
		return nil, err
	}

	err = t.database.GroupsLoadAttributes(ctx, tx, code.User.Groups)
	if err != nil {
		return nil, err
	}

	err = t.database.UserLoadAttributes(ctx, tx, &code.User)
	if err != nil {
		return nil, err
	}

	// The PARENT refresh token is the authorizing credential here, not the code.
	accessTokenStr, err := t.generateAccessToken(ctx, tx, settings, code, scopeToUse, now, privKey, keyIdentifier, parent)
	if err != nil {
		return nil, err
	}
	tokenResponse.AccessToken = accessTokenStr
	tokenResponse.Scope = scopeToUse

	// id_token ---------------------------------------------------------------------------

	scopes := strings.Split(scopeToUse, " ")
	if slices.Contains(scopes, "openid") {
		idTokenStr, idTokenErr := t.generateIdToken(ctx, tx, settings, code, scopeToUse, now, privKey, keyIdentifier)
		if idTokenErr != nil {
			return nil, idTokenErr
		}
		tokenResponse.IdToken = idTokenStr
	}

	// refresh_token ----------------------------------------------------------------------

	// RFC 6749 Section 6: New refresh token scope MUST be identical to the original refresh token's scope
	originalRefreshTokenScope := parent.Scope
	refreshToken, refreshExpiresIn, err := t.generateRefreshToken(ctx, tx, settings, code, originalRefreshTokenScope, now, privKey, keyIdentifier, parent)
	if err != nil {
		return nil, err
	}
	tokenResponse.RefreshToken = refreshToken
	tokenResponse.RefreshExpiresIn = refreshExpiresIn

	return &tokenResponse, nil
}

// mintROPCRefreshTokens mints the token set for a claimed refresh token the password grant issued,
// and inserts its child. Unlike a code-descended token's, its user and client are on the token row.
func (t *TokenIssuer) mintROPCRefreshTokens(ctx context.Context, tx *sql.Tx, settings *models.Settings,
	parent *models.RefreshToken, scopeRequested string) (*oauth.TokenResponse, error) {

	// The token endpoint refuses a token with no instant before it gets here: without one there is
	// no auth_time this refresh could issue that OpenID Connect Core 1.0 section 12.2 allows (#125).
	if !parent.AuthenticatedAt.Valid {
		return nil, errs.New("the ROPC refresh token records no authentication instant")
	}

	// Load the User and Client from the refresh token
	err := t.database.RefreshTokenLoadUser(ctx, tx, parent)
	if err != nil {
		return nil, err
	}

	err = t.database.RefreshTokenLoadClient(ctx, tx, parent)
	if err != nil {
		return nil, err
	}

	scopeToUse := parent.Scope
	if len(scopeRequested) > 0 {
		scopeToUse = scopeRequested
	}

	tokenExpirationInSeconds := tokenLifetimeSeconds(settings, &parent.Client)

	var tokenResponse = oauth.TokenResponse{
		TokenType: TokenTypeBearer.String(),
		ExpiresIn: int64(tokenExpirationInSeconds),
	}

	privKey, keyIdentifier, err := t.loadSigningKey(ctx, tx)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()

	// Load user groups and attributes for token claims
	err = t.database.UserLoadGroups(ctx, tx, &parent.User)
	if err != nil {
		return nil, err
	}

	err = t.database.GroupsLoadAttributes(ctx, tx, parent.User.Groups)
	if err != nil {
		return nil, err
	}

	err = t.database.UserLoadAttributes(ctx, tx, &parent.User)
	if err != nil {
		return nil, err
	}

	// Create ROPCGrantInput for token generation. The instant is the parent's, so every token of
	// the family reports the password check that started it, not this refresh (#125).
	ropcInput := &ROPCGrantInput{
		Client:          &parent.Client,
		User:            &parent.User,
		Scope:           scopeToUse,
		AuthenticatedAt: parent.AuthenticatedAt.Time,
	}

	// access_token -----------------------------------------------------------------------

	// The parent refresh token authorizes this, not the reloaded user.
	accessTokenStr, err := t.generateROPCAccessToken(ctx, tx, settings, ropcInput, scopeToUse, now, privKey, keyIdentifier, parent)
	if err != nil {
		return nil, err
	}
	tokenResponse.AccessToken = accessTokenStr
	tokenResponse.Scope = scopeToUse

	// id_token ---------------------------------------------------------------------------

	scopes := strings.Split(scopeToUse, " ")
	if slices.Contains(scopes, "openid") {
		idTokenStr, idTokenErr := t.generateROPCIdToken(ctx, tx, settings, ropcInput, scopeToUse, now, privKey, keyIdentifier)
		if idTokenErr != nil {
			return nil, idTokenErr
		}
		tokenResponse.IdToken = idTokenStr
	}

	// refresh_token ----------------------------------------------------------------------

	// RFC 6749 Section 6: New refresh token scope MUST be identical to the original refresh token's scope
	originalRefreshTokenScope := parent.Scope
	refreshToken, refreshExpiresIn, err := t.generateRefreshTokenForROPC(ctx, tx, settings, ropcInput, originalRefreshTokenScope, now, privKey, keyIdentifier, parent)
	if err != nil {
		return nil, err
	}
	tokenResponse.RefreshToken = refreshToken
	tokenResponse.RefreshExpiresIn = refreshExpiresIn

	return &tokenResponse, nil
}
