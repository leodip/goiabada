// Package liveness decides whether a token the auth server issued is still live: whether the
// client, the user, the session, the authentication generation and the grant it stands for still
// hold, and, for an access token, whether it is one at all under RFC 9068 and, without a grant,
// whether its jti was revoked. It reads the stored state
// and returns a verdict; what to answer and what to log are the caller's. The bearer guard in front of /userinfo and the admin and account APIs calls
// AccessToken, the refresh grant calls RefreshToken, and revocation and introspection call the same
// checks, so they can never disagree about a token (#676 decisions 1 and 7).
package liveness

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/leodip/goiabada/authserver/internal/issuance"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
)

// ErrNoSettings is the fault of a caller that passed no settings where a check needs them: an
// access token's issuer cannot be compared without them, nor a session's idle and max-lifetime
// bounds measured, and skipping either would let a token the settings refuse ride a still-valid
// JWT.
var ErrNoSettings = errors.New("no settings to check the token against")

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
	// NotAnAccessTokenHeader is a token whose JOSE header typ is not at+jwt: an access token issued
	// before #676, or a token of another kind (RFC 9068 section 4).
	NotAnAccessTokenHeader
	// ForeignIssuer is a token whose iss is not exactly the configured issuer.
	ForeignIssuer
	// ClientNotFound is a token whose client_id names no client, or that carries none.
	ClientNotFound
	// ClientDisabled is a token whose client is disabled (#676 decision 6).
	ClientDisabled
	// GrantRevoked is a token whose grant_id names a grant that is no longer live: its refresh
	// token family is recorded as revoked or has no member left that is not (#676 decision 1).
	GrantRevoked
	// AccessTokenRevoked is a token without grant_id whose jti is stored as revoked, or that carries
	// no jti, which the auth server never signs (#676 decision 1).
	AccessTokenRevoked
)

// Database is what the check reads: the token's client, its user, the session its sid names, the
// grant its grant_id names and, for a token without one, whether its jti is stored as revoked.
type Database interface {
	GetClientByClientIdentifier(ctx context.Context, tx *sql.Tx, clientIdentifier string) (*record.Client, error)
	GetUserBySubject(ctx context.Context, tx *sql.Tx, subject string) (*record.User, error)
	GetUserSessionBySessionIdentifier(ctx context.Context, tx *sql.Tx, sessionIdentifier string) (*record.UserSession, error)
	IsRefreshTokenFamilyLive(ctx context.Context, tx *sql.Tx, firstRefreshTokenJti string) (bool, error)
	IsAccessTokenRevoked(ctx context.Context, tx *sql.Tx, jti string) (bool, error)
}

// Verdict is the check's answer, with what it read on the way so a caller can log it: the client,
// once the token's client_id resolved to one; the user, once the subject resolved to one; the session identifier, once the check reached the token's
// session; and the session, once it was found.
type Verdict struct {
	Refusal           Refusal
	Client            *record.Client
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
// First the token itself, as RFC 9068 section 4 asks of every resource server (#676 decisions 2 and
// 4): its JOSE header typ is at+jwt, and its iss is exactly the configured issuer. An access token
// issued before #676 carries the header typ JWT and is refused here, as is every token after the
// issuer setting changes. Neither refusal reads anything.
//
// Then its client (decision 6): the client its client_id names exists and is enabled, for a client's
// token as for a user's. A token from a disabled client is refused while the client stays disabled,
// and works again if it is re-enabled before the token expires; one from a deleted client never does.
//
// Last, once everything below has passed, its grant (decision 1): a token carrying grant_id is live
// only while its grant is, and a token without one only while its jti is not stored as revoked. See
// grantAccessToken and revokedAccessToken.
//
// A token with no `auth_time` claim is a client's, from the client credentials grant, and is live
// once its client is and its jti is not stored as revoked: it has no user to check anything about. `auth_time`, not `sid`, is the "this
// is a user token" discriminator. sid is conditional: password-grant and offline tokens have none,
// so keying on it would let exactly those tokens past every check below.
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
// A token with no generation claim at all reads as generation 0, as it did for the access tokens
// issued before that feature shipped (#106 decision 15).
//
// settings carry the issuer and bound the session, so every token that gets past its header needs
// them: a nil settings is ErrNoSettings. Any error is a fault, never a refusal: the token's state
// could not be read, and a caller must not answer it as a dead token.
func AccessToken(ctx context.Context, database Database, token oauth.JwtToken, settings *record.Settings,
	now time.Time) (Verdict, error) {

	if !hasAccessTokenHeader(token) {
		return Verdict{Refusal: NotAnAccessTokenHeader}, nil
	}
	if settings == nil {
		return Verdict{}, ErrNoSettings
	}
	// Exactly, as RFC 9068 section 4 and RFC 7519 section 4.1.1 compare it: StringOrURI values are
	// case-sensitive, and the issuer is a string the server writes, never a URL it normalizes.
	if token.StringClaim("iss") != settings.Issuer {
		return Verdict{Refusal: ForeignIssuer}, nil
	}

	clientIdentifier := token.StringClaim("client_id")
	if clientIdentifier == "" {
		return Verdict{Refusal: ClientNotFound}, nil
	}
	client, err := database.GetClientByClientIdentifier(ctx, nil, clientIdentifier)
	if err != nil {
		return Verdict{}, errs.Wrap(err, "failed to look up client for bearer token validation")
	}
	if client == nil {
		return Verdict{Refusal: ClientNotFound}, nil
	}
	if !client.Enabled {
		return Verdict{Refusal: ClientDisabled, Client: client}, nil
	}

	verdict, err := userAccessToken(ctx, database, token, settings, now)
	verdict.Client = client
	if err != nil || !verdict.Live() {
		return verdict, err
	}
	return grantAccessToken(ctx, database, token, verdict)
}

// grantAccessToken is AccessToken's last check, the grant (#676 decision 1), for a token everything
// else has passed, whose verdict so far is passed in. A token carrying grant_id lives only while its
// grant does: its refresh token family has no revocation record and still has a member that is not
// revoked. So withdrawing consent, making the client public, ending the session behind an offline
// grant and containing a replay each refuse the grant's access tokens at once, though the token
// carries no sid or its session is still there. A rotation keeps the grant live, and so does a
// credential change that preserves the caller's session, since its tokens are promoted, not
// revoked.
//
// A token without grant_id, a client's or one from the implicit flow, has no grant to check, and is
// judged by its own jti instead: see revokedAccessToken. One whose grant_id is present but empty or
// not a string is one the auth server never signs, and is refused without a read.
func grantAccessToken(ctx context.Context, database Database, token oauth.JwtToken, verdict Verdict) (Verdict, error) {
	if _, hasGrant := token.Claims["grant_id"]; !hasGrant {
		return revokedAccessToken(ctx, database, token, verdict)
	}
	grantId := token.StringClaim("grant_id")
	if grantId == "" {
		verdict.Refusal = GrantRevoked
		return verdict, nil
	}

	live, err := database.IsRefreshTokenFamilyLive(ctx, nil, grantId)
	if err != nil {
		verdict.Refusal = 0
		return verdict, errs.Wrap(err, "failed to look up the grant for bearer token validation")
	}
	if !live {
		verdict.Refusal = GrantRevoked
	}
	return verdict, nil
}

// revokedAccessToken is AccessToken's last check for a token without grant_id, whose verdict so far
// is passed in (#676 decision 1). Such a token, of the client credentials grant or the implicit
// flow, has no grant whose revocation could end it, so the revocation endpoint stores its jti
// instead, and the token is live only while its jti is not stored. A token carrying grant_id never
// reaches here: its grant already answers, so it costs no read of the stored jtis.
//
// One whose jti is absent, empty or not a string is one the auth server never signs, and is refused
// without a read: no revocation could ever store it.
func revokedAccessToken(ctx context.Context, database Database, token oauth.JwtToken, verdict Verdict) (Verdict, error) {
	jti := token.StringClaim("jti")
	if jti == "" {
		verdict.Refusal = AccessTokenRevoked
		return verdict, nil
	}

	revoked, err := database.IsAccessTokenRevoked(ctx, nil, jti)
	if err != nil {
		verdict.Refusal = 0
		return verdict, errs.Wrap(err, "failed to look up the revoked access token for bearer token validation")
	}
	if revoked {
		verdict.Refusal = AccessTokenRevoked
	}
	return verdict, nil
}

// userAccessToken is AccessToken's checks of the user, the session and the generation, for a token
// whose own checks and client have passed.
func userAccessToken(ctx context.Context, database Database, token oauth.JwtToken, settings *record.Settings,
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
	if session.UserId != user.Id {
		return Verdict{Refusal: SessionOfAnotherUser, User: user, SessionIdentifier: sid, Session: session}, nil
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

// hasAccessTokenHeader reports whether the token's JOSE header typ is at+jwt, which RFC 9068
// section 4 says a resource server MUST require, accepting application/at+jwt too. A typ is a media
// type, compared without regard to case (RFC 7515 section 4.1.9).
func hasAccessTokenHeader(token oauth.JwtToken) bool {
	typ, _ := token.Header["typ"].(string)
	return strings.EqualFold(typ, issuance.AccessTokenHeaderType) ||
		strings.EqualFold(typ, "application/"+issuance.AccessTokenHeaderType)
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
