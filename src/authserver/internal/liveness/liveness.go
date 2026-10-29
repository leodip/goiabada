// Package liveness decides whether an access token the auth server issued is still live: whether
// the user, the session and the authentication generation it stands for still hold. It reads the
// stored state and returns a verdict; what to answer and what to log are the caller's. The bearer
// guard in front of /userinfo and the admin and account APIs calls it, and introspection is to call
// the same check, so the two can never disagree about a token (#676 decision 1).
package liveness

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
)

// ErrNoSettings is the fault of a caller that passed no settings for a session-bound token: the
// session's idle and max-lifetime bounds cannot be measured without them, and skipping the
// measurement would let an expired session ride a still-valid JWT.
var ErrNoSettings = errors.New("no settings to measure the session's bounds against")

// Refusal names why a token is not live, or Live when it is.
type Refusal int

const (
	// The zero Refusal comes with a fault: the check could not decide, so the zero Verdict is
	// never live.
	_ Refusal = iota
	Live
	// BlankSubject is a user's token whose sub is empty or whitespace.
	BlankSubject
	// UserNotFound is a token whose subject no longer resolves to a user.
	UserNotFound
	// UserDisabled is a token of a disabled user (#106 decision 6).
	UserDisabled
	// TokenGenerationSuperseded is a token without sid whose own generation claim is behind, ahead
	// of or not a reading of its user's generation.
	TokenGenerationSuperseded
	// SessionNotFound is a token whose sid names a session that no longer exists.
	SessionNotFound
	// SessionOfAnotherUser is a token whose sid names a session of another user (#133).
	SessionOfAnotherUser
	// SessionExpired is a token whose session is past its idle timeout or its maximum lifetime.
	SessionExpired
	// SessionGenerationSuperseded is a token whose session is on a generation its user has left.
	SessionGenerationSuperseded
)

// Database is what the check reads: the token's user and the session its sid names.
type Database interface {
	GetUserBySubject(ctx context.Context, tx *sql.Tx, subject string) (*record.User, error)
	GetUserSessionBySessionIdentifier(ctx context.Context, tx *sql.Tx, sessionIdentifier string) (*record.UserSession, error)
}

// Verdict is the check's answer, with what it read on the way so a caller can log it: the user,
// once the subject resolved to one; the session identifier, once the check reached the token's
// session; and the session, once it was found.
type Verdict struct {
	Refusal           Refusal
	User              *record.User
	SessionIdentifier string
	Session           *record.UserSession
}

// Live reports whether the token is live.
func (v Verdict) Live() bool {
	return v.Refusal == Live
}

// Subject is the one reading of an access token's subject: trimmed, and false when nothing is left.
// The check looks the user up by it, and reqctx's accessors answer it to the per-subject rate
// limiter and the account handlers, so they cannot name different users for one token. They used
// to read it separately, the first two trimming and the handlers not, which agreed only because the
// auth server mints no subject with surrounding whitespace.
func Subject(token oauth.JwtToken) (string, bool) {
	subject := strings.TrimSpace(token.StringClaim("sub"))
	return subject, subject != ""
}

// AccessToken checks an access token whose signature, audience and expiry the caller has already
// verified, against the state it stands for at now.
//
// A token with no `auth_time` claim is a client's, from the client credentials grant, and is live:
// it has no user to check anything about. `auth_time`, not `sid`, is the "this is a user token"
// discriminator. sid is conditional: password-grant and offline tokens have none, so keying on it
// would let exactly those tokens past every check below.
//
// A user's token is checked for four things, and which apply depends on the token:
//
//  1. The account is still enabled. No handler under /api/v1/account/* checks this for itself, so
//     without it a disabled user keeps working access for the rest of their access token's
//     lifetime (#106 decision 6).
//  2. For a token carrying a `sid`, the session still exists and belongs to the token's own user.
//     The owner comparison backs up issuance rather than duplicating it: a ceremony can no longer
//     bind a grant to someone else's session, so anything refused for it was minted before the fix
//     (#133).
//  3. That session is within its idle and max-lifetime bounds. This is what makes deleting a
//     session take effect immediately despite the JWT remaining cryptographically valid.
//  4. The authentication generation still matches. This is the boundary that survives a
//     credential change: a token authenticated under generation N stops working once the user
//     advances to N+1 (#106 decision 11).
//
// The generation check is deliberately ASYMMETRIC, and it looks wrong until you know why:
//
//   - With a `sid`, the SESSION's generation decides and the token's own claim is IGNORED. That is
//     what lets a self-service password change preserve the caller's own session: the session is
//     promoted forward while the access tokens already issued from it still carry the old value.
//     Checking the claim too would sign that caller out, which is the thing decision 4 exists to
//     avoid.
//   - Without one (offline grants and the password grant), the token's own claim decides, since
//     there is no session to defer to.
//
// A token with no generation claim at all reads as generation 0, which is what keeps access tokens
// issued before that feature shipped working until their user's generation first advances (#106
// decision 15).
//
// settings bound the session, and only a session-bound token that gets as far as its bounds needs
// them: a nil settings is ErrNoSettings there, and a refusal decided before it stands without
// them. Any error is a fault, never a refusal: the token's state could not be read, and a caller
// must not answer it as a dead token.
func AccessToken(ctx context.Context, database Database, token oauth.JwtToken, settings *record.Settings,
	now time.Time) (Verdict, error) {

	if _, hasAuthTime := token.Claims["auth_time"]; !hasAuthTime {
		return Verdict{Refusal: Live}, nil
	}

	subject, hasSubject := Subject(token)
	if !hasSubject {
		return Verdict{Refusal: BlankSubject}, nil
	}

	user, err := database.GetUserBySubject(ctx, nil, subject)
	if err != nil {
		return Verdict{}, errs.Wrap(err, "failed to look up user for bearer token validation")
	}
	if user == nil {
		return Verdict{Refusal: UserNotFound}, nil
	}
	if !user.Enabled {
		return Verdict{Refusal: UserDisabled, User: user}, nil
	}

	sid := token.StringClaim("sid")
	if sid == "" {
		// Offline grant or password grant: no session to defer to, so the token's own generation
		// claim decides. A malformed claim is refused on !wellFormed, before the comparison, so it
		// can never collide with a stored generation.
		generation, wellFormed := tokenGeneration(token)
		if !wellFormed || generation != user.AuthStateGeneration {
			return Verdict{Refusal: TokenGenerationSuperseded, User: user}, nil
		}
		return Verdict{Refusal: Live, User: user}, nil
	}

	session, err := database.GetUserSessionBySessionIdentifier(ctx, nil, sid)
	if err != nil {
		return Verdict{User: user, SessionIdentifier: sid},
			errs.Wrap(err, "failed to look up user session for bearer token validation")
	}
	if session == nil {
		return Verdict{Refusal: SessionNotFound, User: user, SessionIdentifier: sid}, nil
	}

	// The session has to belong to the token's user. Nothing else here compares the two: the
	// lifetime check reads dates and the generation check reads a counter, so a token whose `sid`
	// names another user's session would otherwise be governed by that session in every respect,
	// ending when its owner's session ends and staying alive while its owner keeps using the browser
	// (#133).
	//
	// Placed before the settings are needed, not merely before the lifetime check it guards: this
	// comparison needs no settings, so a cross-bound token is refused even when missing settings
	// would otherwise make it a fault.
	if session.UserId != user.Id {
		return Verdict{Refusal: SessionOfAnotherUser, User: user, SessionIdentifier: sid, Session: session}, nil
	}

	if settings == nil {
		return Verdict{User: user, SessionIdentifier: sid, Session: session}, ErrNoSettings
	}
	if !session.IsValid(now, settings.UserSessionIdleTimeoutInSeconds, settings.UserSessionMaxLifetimeInSeconds, nil) {
		return Verdict{Refusal: SessionExpired, User: user, SessionIdentifier: sid, Session: session}, nil
	}

	// The SESSION's generation, not the token's. See the asymmetry note above: the token's own
	// claim is deliberately not consulted on this branch.
	if session.AuthStateGeneration != user.AuthStateGeneration {
		return Verdict{Refusal: SessionGenerationSuperseded, User: user, SessionIdentifier: sid, Session: session}, nil
	}

	return Verdict{Refusal: Live, User: user, SessionIdentifier: sid, Session: session}, nil
}

// tokenGeneration reads a token's authentication generation, reporting validity as a second
// return value rather than in band.
//
// An ABSENT claim is generation 0, and valid. That is what keeps access tokens issued before
// this feature shipped working until their user's generation first advances (#106 decision
// 15). Presence is tested against the raw claim map because IntClaim reports only whether
// a PRESENT claim parsed, so it returns (0, false) for both absent and malformed; conflating
// them would reject every legacy token.
//
// A malformed claim is (0, false), and callers must reject on !ok BEFORE comparing. Do not
// reintroduce an in-band sentinel such as -1: `auth_state_generation` is a signed
// BIGINT/INTEGER on all four engines with no nonnegative constraint, so any sentinel value a
// caller might compare against is also a value a user row can legitimately hold, and a user
// sitting on it would accept every malformed claim.
func tokenGeneration(token oauth.JwtToken) (int64, bool) {
	if _, present := token.Claims["auth_state_generation"]; !present {
		return 0, true
	}
	return token.IntClaim("auth_state_generation")
}
