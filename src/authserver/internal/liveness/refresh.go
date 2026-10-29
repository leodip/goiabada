package liveness

import (
	"context"
	"database/sql"
	"time"

	"github.com/leodip/goiabada/authserver/internal/issuance"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
)

// RefreshRefusal names why a refresh token is not live, or RefreshLive when it is. The refusals are
// declared in the order the check decides them, the first that applies being the one returned.
type RefreshRefusal int

const (
	// The zero RefreshRefusal comes with a fault: the check could not decide, so it is never live.
	_ RefreshRefusal = iota
	RefreshLive
	// RefreshUserDisabled is a token whose user is disabled, or gone, which loads as the zero user
	// (#137).
	RefreshUserDisabled
	// RefreshGenerationSuperseded is a token whose row is on a generation other than its user's
	// (#106).
	RefreshGenerationSuperseded
	// RefreshNoAuthenticationInstant is a password grant token issued before migration 000051,
	// which records no authentication instant to report as auth_time (#125).
	RefreshNoAuthenticationInstant
	// RefreshCodeRevoked is a token descended from a code marked revoked: its session was
	// terminated, its client became public or its user withdrew consent (#129).
	RefreshCodeRevoked
	// RefreshFamilyRevoked is a live row of a family recorded as revoked (#132, #259).
	RefreshFamilyRevoked
	// RefreshSessionNotFound is a session-bound token whose session no longer exists.
	RefreshSessionNotFound
	// RefreshSessionOfAnotherUser is a token whose session belongs to another user: the row's
	// session for a session-bound token, the code's for an offline one (#133).
	RefreshSessionOfAnotherUser
	// RefreshSessionExpired is a session-bound token whose session is past its idle timeout or its
	// maximum lifetime.
	RefreshSessionExpired
	// RefreshOfflineExpired is an offline token past its offline_access_max_lifetime.
	RefreshOfflineExpired
	// RefreshTokenRevoked is a token whose own row is revoked, of a grant nothing else refuses.
	RefreshTokenRevoked
)

// RefreshDatabase is what the refresh token check reads: the token's row with its code, user and
// client, the family's revocation record, and the session the grant is bound to.
type RefreshDatabase interface {
	CodeLoadUser(ctx context.Context, tx *sql.Tx, code *record.Code) error
	GetRefreshTokenByJti(ctx context.Context, tx *sql.Tx, jti string) (*record.RefreshToken, error)
	GetUserSessionBySessionIdentifier(ctx context.Context, tx *sql.Tx, sessionIdentifier string) (*record.UserSession, error)
	IsRefreshTokenFamilyRevoked(ctx context.Context, tx *sql.Tx, firstRefreshTokenJti string) (bool, error)
	RefreshTokenLoadClient(ctx context.Context, tx *sql.Tx, refreshToken *record.RefreshToken) error
	RefreshTokenLoadCode(ctx context.Context, tx *sql.Tx, refreshToken *record.RefreshToken) error
	RefreshTokenLoadUser(ctx context.Context, tx *sql.Tx, refreshToken *record.RefreshToken) error
}

// StoredRefreshToken is a refresh token's row with what it names, read from where its grant keeps
// it. A password grant's token carries no code, so its user, client and scope are on its own row;
// an authorization code's are on Row.Code, which FindRefreshToken loaded.
type StoredRefreshToken struct {
	Row *record.RefreshToken
	// IsROPC says the password grant minted the token: its row has no code.
	IsROPC   bool
	ClientId int64
	UserId   int64
	// User is the grant's user as loaded: the row's for the password grant, the code's otherwise.
	User  *record.User
	Scope string
}

// FindRefreshToken reads the row of a refresh token whose signature and expiry the caller has
// already verified, with the code, user and client it names. A jti with no row is answered nil and
// no error: the token is not live, and RFC 6749 section 5.2 and RFC 7662 answer it as any other
// dead token. A token without jti, which the auth server never signs, is a fault.
//
// The check is in two calls so a caller can do what is its own between them, and what it does
// first is match the token's client, ClientId, to the client presenting it. Nothing that tells a
// live token from a dead one is decided before that match: a public client_id is no secret, so a
// check above it would let anyone holding a stolen token learn what became of the grant by
// presenting it under any public client (#137).
func FindRefreshToken(ctx context.Context, database RefreshDatabase, token oauth.JwtToken) (*StoredRefreshToken, error) {
	jti := token.StringClaim("jti")
	if len(jti) == 0 {
		return nil, errs.New("the refresh token is invalid because it does not contain a jti claim")
	}

	row, err := database.GetRefreshTokenByJti(ctx, nil, jti)
	if err != nil {
		return nil, err
	}
	if row == nil {
		// Retention (DeleteExpiredRefreshTokens) makes this rare but cannot remove it: user
		// deletion, referential cascades and database restores all leave a signed token with no
		// row (#128).
		return nil, nil
	}

	if !row.CodeId.Valid {
		if err := database.RefreshTokenLoadUser(ctx, nil, row); err != nil {
			return nil, err
		}
		if err := database.RefreshTokenLoadClient(ctx, nil, row); err != nil {
			return nil, err
		}
		return &StoredRefreshToken{
			Row:      row,
			IsROPC:   true,
			ClientId: row.ClientId.Int64,
			UserId:   row.UserId.Int64,
			User:     &row.User,
			Scope:    row.Scope,
		}, nil
	}

	if err := database.RefreshTokenLoadCode(ctx, nil, row); err != nil {
		return nil, err
	}
	if err := database.CodeLoadUser(ctx, nil, &row.Code); err != nil {
		return nil, err
	}
	return &StoredRefreshToken{
		Row:      row,
		ClientId: row.Code.ClientId,
		UserId:   row.Code.UserId,
		User:     &row.Code.User,
		Scope:    row.Code.Scope,
	}, nil
}

// RefreshToken checks a refresh token FindRefreshToken read, against the state its grant stands for
// at now: the checks the refresh grant makes on a token's state, which introspection is to make
// too, so the two cannot disagree about a token (#676 decision 7). What belongs to a request stays
// with its caller: authenticating the client, matching it to the token, PKCE for a public client,
// and the scope a refresh may ask for. Whose token it is, ClientId, the caller matches to a client
// authentication has found to exist and be enabled, so the check reads no client of its own.
//
// The checks run in this order, and the first that refuses is the answer, nothing below it being
// read:
//
//  1. Read off what was loaded with the row, and reading nothing more: the user is enabled, the
//     row is on the user's generation, a password grant token records its authentication instant,
//     and a code-descended token's code is not revoked.
//  2. The family carries no revocation record.
//  3. A session-bound token's session exists, belongs to the user and is within its bounds; an
//     offline token is within its maximum lifetime and its code's session, while it exists,
//     belongs to the user.
//  4. The row itself is not revoked.
//
// The refresh grant answers some of these in its own order: it puts PKCE between 1 and 2, and a
// token refused only for its own row (4) is a replay, which it hands to the redemption to contain.
// That is why the row's revocation is decided last: every other refusal precedes it, so a replayed
// token of a grant something else ended is refused as that grant, as it always was.
//
// settings bound the session, and only a session-bound token that gets as far as its bounds needs
// them: a nil settings is ErrNoSettings there. Any error is a fault, never a refusal: the token's
// state could not be read, and a caller must not answer it as a dead token.
func RefreshToken(ctx context.Context, database RefreshDatabase, stored *StoredRefreshToken, token oauth.JwtToken,
	settings *record.Settings, now time.Time) (RefreshRefusal, error) {

	row := stored.Row

	if !stored.User.Enabled {
		return RefreshUserDisabled, nil
	}

	// The generation boundary (#106), read from the TOKEN row, not from any joined record (#106
	// decision 11(a)): row.AuthStateGeneration, NOT row.Code.AuthStateGeneration. The two
	// legitimately differ on the code shape: a self-service password change promotes the preserved
	// session's tokens to the new generation while their codes stay on the old one, so reading the
	// code here would reject exactly the tokens #106 decision 4 exists to keep working.
	if row.AuthStateGeneration != stored.User.AuthStateGeneration {
		return RefreshGenerationSuperseded, nil
	}

	// A password grant token issued before migration 000051 records no authentication instant, so
	// no refresh of it can issue the auth_time OpenID Connect Core 1.0 section 12.2 requires, the
	// time of the original authentication. Its client makes one password grant again, and the new
	// family records the instant (#125).
	if stored.IsROPC && !row.AuthenticatedAt.Valid {
		return RefreshNoAuthenticationInstant, nil
	}

	// The termination boundary (#129 decision 4). A rotated child inherits its parent's code_id, so
	// a marked code rejects every descendant of that grant, including one inserted after the
	// termination committed: the child is born already rejected rather than caught by a sweep.
	//
	// This is what reaches an OFFLINE token, which the session checks below never can. Its offline
	// branch checks only the max lifetime and deliberately does not consult the session's bounds,
	// because a session merely expiring must leave an offline grant working (decision 2).
	// Termination has to be a positive fact for exactly that reason.
	//
	// A password grant token is excluded because it has no grant origin to terminate: code_id is
	// NULL, there is no session, and row.Code is the zero value.
	if !stored.IsROPC && row.Code.Revoked {
		return RefreshCodeRevoked, nil
	}

	// A live token whose rotation family is recorded as revoked. The record is written by replay
	// containment and by a client made public, in the same transaction as the revocation, and it
	// outlives every member of the family, which is what makes it more than the live-row sweep it
	// accompanies: a rotation claims its parent and inserts its child in separate statements, so a
	// sweep that ran between them found no child to revoke, the child then committed live, and this
	// is the check that refuses it when it is presented. It is born refused, as #129 and #245 make a
	// code's child (#132, #259).
	//
	// Skipped for a token whose own row is revoked: the row answers for that one, last.
	if !row.Revoked {
		familyRevoked, err := database.IsRefreshTokenFamilyRevoked(ctx, nil, row.FirstRefreshTokenJti)
		if err != nil {
			return 0, err
		}
		if familyRevoked {
			return RefreshFamilyRevoked, nil
		}
	}

	switch token.StringClaim("typ") {
	case issuance.TokenTypeRefresh.String():
		session, err := database.GetUserSessionBySessionIdentifier(ctx, nil, row.SessionIdentifier)
		if err != nil {
			return 0, err
		}
		if session == nil {
			return RefreshSessionNotFound, nil
		}

		// The session has to belong to the grant's user. Without this a token bound to someone
		// else's session refreshes indefinitely and bumps that session as it goes, so the wrong
		// person's activity keeps the session alive and the wrong person's logout ends the grant
		// (#133). Only a code-descended token reaches it: a password grant token is typed Offline
		// unconditionally, because there is no browser session to bind to.
		//
		// Placed before the settings are needed: this comparison needs none.
		if session.UserId != stored.UserId {
			return RefreshSessionOfAnotherUser, nil
		}

		if settings == nil {
			return 0, ErrNoSettings
		}
		if !session.IsValid(now, settings.UserSessionIdleTimeoutInSeconds, settings.UserSessionMaxLifetimeInSeconds, nil) {
			return RefreshSessionExpired, nil
		}
	case issuance.TokenTypeOffline.String():
		// An offline token's lifetime is not linked to the user session, only to its max lifetime.
		maxLifetime := token.TimeClaim("offline_access_max_lifetime")
		if maxLifetime.IsZero() {
			return 0, errs.New("the refresh token is invalid because it does not contain an offline_access_max_lifetime claim")
		}
		if now.After(maxLifetime) {
			return RefreshOfflineExpired, nil
		}

		// The ownership boundary (#133), the half the session-bound branch cannot reach. An offline
		// grant is meant to outlive its session, which is why this branch otherwise never looks at
		// one, and that deliberate silence is what a grant cross-bound before the fix slips through:
		// it keeps rotating for the offline maximum lifetime, seeded at a year, re-copying the code's
		// acr each time.
		//
		// Read from the CODE, not from the token row. Only a session-bound token stores a session
		// identifier of its own, so the grant's session is the one its code was stamped with.
		//
		// Refuses only while the row is still there and its owner differs: absence is the ordinary
		// state of a healthy offline grant, so absence must not refuse. That is also the precise
		// limit of what this reaches, since the session sweep removes the evidence long before the
		// grant expires.
		//
		// Placed after the max-lifetime check so an already-expired token is refused without a
		// lookup, and a password grant token excluded because there was never a session to own it.
		if !stored.IsROPC && row.Code.SessionIdentifier != "" {
			codeSession, err := database.GetUserSessionBySessionIdentifier(ctx, nil, row.Code.SessionIdentifier)
			if err != nil {
				return 0, err
			}
			if codeSession != nil && codeSession.UserId != stored.UserId {
				return RefreshSessionOfAnotherUser, nil
			}
		}
	default:
		return 0, errs.New("the refresh token is invalid because it does not contain a valid typ claim")
	}

	if row.Revoked {
		return RefreshTokenRevoked, nil
	}
	return RefreshLive, nil
}
