package usersession

import (
	"cmp"
	"context"
	"database/sql"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/otpcredential"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/useragent"
	"github.com/leodip/goiabada/authserver/internal/uuid"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/hashutil"
)

// userSessionManagerDatabase is what the session manager needs: the session row and the clients
// it authorized, and the transaction that changes them together.
type userSessionManagerDatabase interface {
	AcquireUserRow(ctx context.Context, tx *sql.Tx, userId int64) error
	AcquireUserSessionRow(ctx context.Context, tx *sql.Tx, sessionIdentifier string) (bool, error)
	CreateUserSession(ctx context.Context, tx *sql.Tx, userSession *record.UserSession) error
	CreateUserSessionClient(ctx context.Context, tx *sql.Tx, userSessionClient *record.UserSessionClient) error
	DeleteUserSession(ctx context.Context, tx *sql.Tx, userSessionId int64) error
	GetUserById(ctx context.Context, tx *sql.Tx, userId int64) (*record.User, error)
	GetUserSessionBySessionIdentifier(ctx context.Context, tx *sql.Tx, sessionIdentifier string) (*record.UserSession, error)
	GetUserSessionsByUserId(ctx context.Context, tx *sql.Tx, userId int64) ([]record.UserSession, error)
	RunInTransaction(ctx context.Context, fn func(tx *sql.Tx) error) error
	UpdateUserSession(ctx context.Context, tx *sql.Tx, userSession *record.UserSession) error
	UpdateUserSessionClient(ctx context.Context, tx *sql.Tx, userSessionClient *record.UserSessionClient) error
	UserSessionLoadClients(ctx context.Context, tx *sql.Tx, userSession *record.UserSession) error
}

// sessionCleanupTimeout bounds AbandonUserSession's delete once it is detached from the caller's
// cancellation. Ten seconds, this repository's one value for a bounded wait on a dependency in the
// request path.
const sessionCleanupTimeout = 10 * time.Second

// Manager creates, bumps and judges the user sessions a browser signs in to. It touches no HTTP:
// the browser session the new session is bound to, and the device cookie, are written by the
// caller (authflow.Completion, through the handler's per-request adapter).
type Manager struct {
	database userSessionManagerDatabase
	// now is the clock HasValidUserSession judges a session against, a field so a test can fix
	// it, as sessionbackend's is.
	now func() time.Time
}

// NewManager builds the manager over the database.
func NewManager(database userSessionManagerDatabase) *Manager {
	return &Manager{
		database: database,
		now:      func() time.Time { return time.Now().UTC() },
	}
}

// HasValidUserSession reports whether userSession exists and may still be used: the two
// session lifetimes are the caller's settings, and requestedMaxAgeInSeconds is the client's
// max_age, nil when it sent none. It reads nothing from a context, so a caller that holds the
// settings passes the two values it means (#433).
func (u *Manager) HasValidUserSession(userSession *record.UserSession, idleTimeoutInSeconds int,
	maxLifetimeInSeconds int, requestedMaxAgeInSeconds *int64) bool {

	if userSession == nil {
		return false
	}
	return userSession.IsValid(u.now(), idleTimeoutInSeconds, maxLifetimeInSeconds, requestedMaxAgeInSeconds)
}

// Authentication is what a sign-in writes onto the session it creates or binds to.
type Authentication struct {
	// UserId is the user who signed in, and the row an OTPClaim is checked on.
	UserId int64
	// AuthMethods and AcrLevel are the methods the sign-in claims and the level it reached.
	AuthMethods string
	AcrLevel    record.AcrLevel
	// AuthTime, when set, becomes the session's auth_time: the instant of the credential the sign-in
	// last entered, a code's when it entered one after the password.
	AuthTime *time.Time
	// PasswordAuthTime, when set, becomes the session's password_auth_time: the instant the sign-in
	// verified the password. A new session requires it, and so does a replacing bind (#542).
	PasswordAuthTime *time.Time
	// OTPClaim is the sign-in's claim to a one-time code, checked on the user under the user's row
	// lock before anything is written (otpcredential.OTPClaim.Recheck).
	OTPClaim otpcredential.OTPClaim
	// AdoptedAuthTime is the auth_time the session the ceremony adopted held when
	// /auth/authorize adopted it, copied from the ceremony's AuthContext by the reuse arm.
	// The bind compares it with the session's current auth_time under the row lock and
	// refuses the ceremony when the two no longer match: a session a newer sign-in has
	// reached since the adoption is not one this ceremony may still write, however many of
	// its methods it merges back (#538). Nil on every bind that adopted no session.
	AdoptedAuthTime *time.Time
}

// ErrStaleAuthentication is returned by a bind that refused to write onto a session a newer
// authentication had already reached, the ordering rule of the reuse arm's single transaction
// (#538). A transaction alone serialises two binds, but it does not decide which of two concurrent
// sign-ins the session should describe. The instants do: a ceremony whose credential predates the
// session's current auth_time, or whose adopted session holds neither the auth_time it adopted nor
// the ceremony's own, writes nothing -- not its level, not its methods, not its auth_time -- and
// /auth/completed answers it as a ceremony the browser has replaced.
var ErrStaleAuthentication = errors.New("a newer authentication has already reached this session")

// SessionLimits is what the settings bound a user's sessions to when a sign-in starts a new one. The
// two lifetimes say which of the user's other sessions have expired, and MaxSessionsPerUser is how
// many sessions the user may hold once the new one is created, 0 for no limit (#564 decision 5).
type SessionLimits struct {
	IdleTimeoutInSeconds int
	MaxLifetimeInSeconds int
	MaxSessionsPerUser   int
}

// Removal is a session StartNewUserSession deleted, and why. Reason is the reason the caller's
// deleted_user_session event carries for it, one of audit's DeletedUserSessionReason values.
type Removal struct {
	Session record.UserSession
	Reason  string
}

// Device is the browser a sign-in starts a session on, as the HTTP side read it: the device cookie
// and the request's headers (#564 decision 4).
type Device struct {
	// Identifier is the device cookie's value, or a new one the caller minted. The session stores its
	// digest, never the value, and the same-device sweep compares digests.
	Identifier string
	// New is whether Identifier was minted for this sign-in, the browser presenting no device cookie
	// or one that does not parse. No earlier session can carry a new identifier, so the same-device
	// sweep matches nothing for it.
	New bool
	// Name, Type and OS are the display labels (useragent.Labels), shown to the user and never
	// compared (#281).
	Name string
	Type string
	OS   string
	// UserAgent is the raw User-Agent header, stored for display and bounded to the column's width
	// here (useragent.BoundRaw).
	UserAgent string
}

// StartNewUserSession creates a session for a completed authentication ceremony, in one
// transaction, and answers it. It writes nothing outside the database: binding the new session to
// the browser session (a conditional rotation of its identifier) and the device cookie are the
// caller's, after this returns, and a caller whose binding fails deletes the new row through
// AbandonUserSession.
//
// authStateGeneration comes from the AuthContext, so it is the generation the ceremony
// authenticated under rather than the user's current value. A ceremony that began before
// a credential change therefore produces a session on the superseded generation, which
// is rejected rather than silently carried forward (#106 decision 11).
//
// otpConfigGeneration is the same shape: the user's OTP configuration generation as this
// ceremony observed it when it answered the level 2 question. Nil means the ceremony
// observed nothing, which writes 0, and for a brand new session that means it owes a
// level 2 re-prompt whenever the user's counter is already above 0. That is the
// fail-closed direction and the only one a nil can safely take (#242).
//
// authentication.AuthTime is the instant this ceremony's last credential was accepted, captured by
// authflow.PasswordSubmission and overwritten by authflow.OTPSubmission. It becomes the session's
// AuthTime and so the auth_time claim, which OIDC Core 1.0 section 3.1.2.1 makes max_age's reference
// point: "the last time the End-User was actively authenticated by the OP". The browser owns the
// hops between the credential and this call, so the clock read here would be no such instant
// (#252 decision 8). Started and LastAccessed stay on now: they measure the session's own life.
// Nil or zero is refused before anything is written, never replaced by now. So is a nil or zero
// authentication.PasswordAuthTime, what a removal of the authenticator lowers auth_time to (#542).
// authentication.OTPClaim is checked on the user under the user's row lock, first in the
// transaction, so a session is never created claiming a code from an authenticator a removal took
// away meanwhile (otpcredential.OTPClaim.Recheck).
//
// device is the browser, recorded on the session by its identifier's digest and its labels, and
// refused when it has no identifier, whose digest every such browser would share. ipAddress is the
// browser's address as the caller read it, the session's one recorded address.
//
// The transaction deletes, besides creating the row:
//   - replacing, the session this sign-in replaces for the same user (the one the browser's cookie
//     named), or nil. A session of another user is refused: the cross-user handover terminates it
//     with revocation first and passes nil. A re-login replaces a session and revokes nothing: the
//     replaced session's bound refresh tokens stop, its offline grants survive (#133, #243).
//   - the user's other sessions recorded with the same device identifier.
//   - when the user would hold more than limits.MaxSessionsPerUser sessions with the new one, as
//     many of their other sessions as it takes (sessionsOverCap), reported as session_cap (#564
//     decision 5).
//
// Every row removed comes back with its reason, so the caller can audit each, and only when the
// transaction committed: every failure rolled them back.
func (u *Manager) StartNewUserSession(ctx context.Context, clientId int64, authentication Authentication,
	authStateGeneration int64, otpConfigGeneration *int64, device Device, ipAddress string,
	replacing *record.UserSession, limits SessionLimits) (*record.UserSession, []Removal, error) {

	userId := authentication.UserId
	if authentication.AuthTime == nil || authentication.AuthTime.IsZero() {
		return nil, nil, errs.New("no credential instant captured; refusing to mint a session whose auth_time would be invented")
	}
	if authentication.PasswordAuthTime == nil || authentication.PasswordAuthTime.IsZero() {
		return nil, nil, errs.New("no password instant captured; refusing to mint a session whose password_auth_time would be invented")
	}
	if device.Identifier == "" {
		return nil, nil, errs.New("no device identifier given; refusing to record a device every such browser would share")
	}
	if replacing != nil && replacing.UserId != userId {
		return nil, nil, errs.Errorf("refusing to replace user session %v: it belongs to user %v, not %v",
			replacing.Id, replacing.UserId, userId)
	}

	utcNow := time.Now().UTC()

	observedOtpConfigGeneration := int64(0)
	if otpConfigGeneration != nil {
		observedOtpConfigGeneration = *otpConfigGeneration
	}

	// The identifier is minted here, outside the transaction, so a rerun excludes the same row from
	// the sweep.
	userSession := &record.UserSession{
		SessionIdentifier: uuid.New(),
		Started:           utcNow,
		LastAccessed:      utcNow,
		IpAddress:         ipAddress,
		AuthMethods:       authentication.AuthMethods,
		AcrLevel:          authentication.AcrLevel,
		AuthTime:          authentication.AuthTime.UTC(),
		PasswordAuthTime:  authentication.PasswordAuthTime.UTC(),
		UserId:            userId,
		DeviceName:        device.Name,
		DeviceType:        device.Type,
		DeviceOS:          device.OS,
		UserAgent:         useragent.BoundRaw(device.UserAgent),
		DeviceId:          deviceDigest(device.Identifier),

		AuthStateGeneration: authStateGeneration,
		OtpConfigGeneration: observedOtpConfigGeneration,
	}

	userSession.Clients = append(userSession.Clients, record.UserSessionClient{
		Started:      utcNow,
		LastAccessed: utcNow,
		ClientId:     clientId,
	})

	// One transaction, opened through RunInTransaction, which reruns the body after a deadlock
	// abort (#301). Each attempt collects its removals afresh and they are copied out only once the
	// transaction answered nil, so an aborted attempt's deletions, which never happened, are not
	// reported (#198).
	var removed []Removal
	err := u.database.RunInTransaction(ctx, func(tx *sql.Tx) error {
		var removedThisAttempt []Removal

		if claimErr := authentication.OTPClaim.Recheck(ctx, u.database, tx, userId); claimErr != nil {
			return claimErr
		}

		if createUserSessionErr := u.database.CreateUserSession(ctx, tx, userSession); createUserSessionErr != nil {
			return createUserSessionErr
		}

		// The association belongs to the row created just above, whose id no other caller holds, so
		// it cannot lose the (session, client) key to a concurrent insert (#249).
		for _, client := range userSession.Clients {
			client.UserSessionId = userSession.Id
			if createUserSessionClientErr := u.database.CreateUserSessionClient(ctx, tx, &client); createUserSessionClientErr != nil {
				return createUserSessionClientErr
			}
		}

		allUserSessions, getUserSessionsErr := u.database.GetUserSessionsByUserId(ctx, tx, userId)
		if getUserSessionsErr != nil {
			return getUserSessionsErr
		}

		// The same device is the same device identifier, compared by its digest; the User-Agent and
		// the address are recorded and never compared, since two browsers can send the same pair
		// (#564 decision 4). An empty stored identifier matches nothing. replacing is matched in this
		// read rather than deleted blindly, so a row already gone is not reported, and a row both
		// replaced and on this device is removed and reported once, as replaced (#564 decision 7).
		var kept []record.UserSession
		for _, us := range allUserSessions {
			if us.SessionIdentifier == userSession.SessionIdentifier {
				continue
			}
			var reason string
			switch {
			case replacing != nil && us.Id == replacing.Id:
				reason = audit.DeletedUserSessionReplacedBySignIn
			case !device.New && us.DeviceId != "" && us.DeviceId == userSession.DeviceId:
				reason = audit.DeletedUserSessionSameDevice
			default:
				kept = append(kept, us)
				continue
			}
			if deleteUserSessionErr := u.database.DeleteUserSession(ctx, tx, us.Id); deleteUserSessionErr != nil {
				return deleteUserSessionErr
			}
			removedThisAttempt = append(removedThisAttempt, Removal{Session: us, Reason: reason})
		}

		// The cap counts what the two rules above left, and the new session, which is not among kept
		// and so is never chosen (#564 decision 5).
		for _, us := range sessionsOverCap(kept, utcNow, limits) {
			if deleteUserSessionErr := u.database.DeleteUserSession(ctx, tx, us.Id); deleteUserSessionErr != nil {
				return deleteUserSessionErr
			}
			removedThisAttempt = append(removedThisAttempt, Removal{Session: us, Reason: audit.DeletedUserSessionSessionCap})
		}
		removed = removedThisAttempt
		return nil
	})
	if err != nil {
		// ceiling: RunInTransaction cannot always tell whether a failed commit landed. When it did,
		// the row exists with no cookie naming it until the background worker's idle sweep removes
		// it, and the rows it swept are gone without their audit events; reporting them here would
		// audit deletions that may have rolled back. Revisit if the row ever becomes reachable by
		// something other than the cookie (#198).
		return nil, nil, err
	}

	return userSession, removed, nil
}

// sessionsOverCap is which of others, the user's sessions besides the one a sign-in just created,
// go so that the user holds no more than limits.MaxSessionsPerUser sessions with the new one
// counted, and none when the cap is 0, no limit (#564 decision 5). Every stored session counts,
// expired ones the background job has not removed yet included.
//
// Expired sessions go first, those whose idle timeout or max lifetime has passed at now, and then
// the least recently accessed, the lower id breaking a tie, in that order within each group. Least
// recently accessed alone could end a session in use and keep a dead one, since a session past its
// max lifetime can have been used more recently than a valid one.
//
// No lock is taken for it: two sign-ins of one user committing at once can each count the other's
// session as not yet there, and leave the user one over the cap until their next sign-in. The cap
// is a housekeeping bound, and taking the user's row on every sign-in to make it exact buys nothing
// a user would notice.
func sessionsOverCap(others []record.UserSession, now time.Time, limits SessionLimits) []record.UserSession {
	if limits.MaxSessionsPerUser <= 0 {
		return nil
	}
	excess := len(others) + 1 - limits.MaxSessionsPerUser
	if excess <= 0 {
		return nil
	}

	expired := func(us *record.UserSession) bool {
		return !us.IsValid(now, limits.IdleTimeoutInSeconds, limits.MaxLifetimeInSeconds, nil)
	}
	candidates := slices.Clone(others)
	slices.SortStableFunc(candidates, func(a, b record.UserSession) int {
		if aExpired, bExpired := expired(&a), expired(&b); aExpired != bExpired {
			if aExpired {
				return -1
			}
			return 1
		}
		if c := a.LastAccessed.Compare(b.LastAccessed); c != 0 {
			return c
		}
		return cmp.Compare(a.Id, b.Id)
	})
	return candidates[:excess]
}

// AbandonUserSession deletes userSession, which StartNewUserSession committed, when binding it to
// the browser session failed, and returns cause unchanged: the ceremony failed for that reason and
// the caller must be told that one, not what this cleanup did. A cleanup that fails in turn is
// joined onto cause, so errors.Is still finds the original and the record says the row survived.
//
// The binding cannot join StartNewUserSession's transaction: RunInTransaction reruns its body after
// a deadlock abort, and a rerun of the rotation would write Set-Cookie twice. So it runs after the
// commit and is compensated here. Without this the row stayed, named by no cookie, in the admin
// console's session list until its idle timeout (#198).
//
// The delete runs on ctx's values but not its cancellation, because a disconnected client is both
// what cancels the request's context and why a browser-session write fails; it keeps the request id
// on its records, and is bounded by sessionCleanupTimeout since nothing else stops it (#386).
//
// ceiling: the rows StartNewUserSession swept committed with the new one, so a user whose binding
// fails is left with neither the session this ceremony created nor the ones it replaced, and signs
// in again. Revisit if the browser session store gains a two-phase write (#198).
func (u *Manager) AbandonUserSession(ctx context.Context, userSession *record.UserSession, cause error) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), sessionCleanupTimeout)
	defer cancel()

	if err := u.database.DeleteUserSession(ctx, nil, userSession.Id); err != nil {
		return errs.Join(cause, errs.Wrap(err,
			"unable to delete the user session left behind by a failed browser session write"))
	}
	return cause
}

// deviceDigest is what a session stores of a device identifier: its SHA-256, so a database read
// does not hand out a value a browser could present.
func deviceDigest(identifier string) string {
	return hashutil.HashString(identifier)
}

// BumpUserSession updates an existing session's last accessed time and client list.
// It also handles ACR/AMR step-up authentication scenarios.
//
// Step-up authentication occurs when a user with an existing session (e.g., password-only)
// accesses a client that requires a higher authentication level (e.g., password + OTP).
// In this case, the session's AuthMethods and AcrLevel must be upgraded to reflect
// the stronger authentication that was actually performed.
//
// **A bump only ever raises.** It never lowers the session's level and never drops a method from
// its methods. That is right for what calls it: SSO reuse, a step-up and a refresh all extend the
// authentication the session already holds. A ceremony that authenticated afresh over the session
// (prompt=login, an id_token_hint naming someone else, a restart: Level1AuthCompleted) is a
// different thing, a new authentication that replaces the session's, and /auth/completed's reuse arm
// binds it with BindUserSession's replace, from what the ceremony performed (#537). Until #537
// this function replaced the methods on any difference, so such a ceremony left a session at level
// 3 with amr "pwd", every later token from it contradicting itself (#239 F4).
//
// The token endpoint and prompt=none pass no methods and no level: a refresh steps nothing up, and
// prompt=none reuses the session only when it already holds the level asked for, so the session's
// own values were all either could pass, and writing them back could only undo a change committed
// since they were read (#542).
//
// Parameters:
//   - authMethods: The authentication methods used in the current auth flow (e.g., "pwd otp").
//     A method it lists that the session's lacks is added; nothing is removed.
//   - acrLevel: The target ACR level for the current auth flow.
//     The session's ACR is only upgraded (never downgraded) to maintain security guarantees.
//   - ipAddress: The browser's address as the caller read it, which replaces the one recorded.
//     Empty leaves the recorded address as it is, which is what the token endpoint passes: a
//     refresh request comes from the client's server as often as from the user's browser.
//
// The session, its associations, the decision between inserting an association and updating it, and
// every write are one transaction, and the transaction is rerun once when an insert lost the
// (session, client) key to a concurrent bump (migration 000055, #249). Two bumps of one session for
// one client that overlap both read the client as absent and both insert; the engine refuses the
// second, and on PostgreSQL that refusal aborts the transaction, so the loser runs again and its
// second attempt reads the association the winner committed and updates it. That only works if
// nothing the attempt decided from was read before the transaction opened, which is why the session
// and its associations are read in the body: a rerun that reused the first attempt's copy would
// decide "absent" again and insert the same pair a second time. The body is otherwise safe to run
// twice, since it builds every value it writes from what it has just read.
//
// **The session's row is taken before it is read** (AcquireUserSessionRow), and that is what makes
// writing the whole row back safe. Read without it, a removal of the user's authenticator lowering
// the session between the read and the write was undone: the write put back the otp and the level
// the removal had just taken away (#542). With it, a removal that got there first has committed by
// the time the read runs, and one that arrives later waits for this write and then lowers it.
func (u *Manager) BumpUserSession(ctx context.Context, sessionIdentifier string, clientId int64,
	authMethods string, acrLevel record.AcrLevel, ipAddress string) (*record.UserSession, error) {
	return u.bindUserSession(ctx, sessionIdentifier, clientId,
		Authentication{AuthMethods: authMethods, AcrLevel: acrLevel}, false, ipAddress)
}

// BindUserSession binds a completed sign-in to the session the browser arrived with, which is
// /auth/completed's reuse arm. It is BumpUserSession with what only a sign-in brings:
//
//   - replace writes the sign-in's level, methods and password instant over the session's, rather
//     than raising them, for a ceremony that authenticated afresh (#537), and requires
//     authentication.PasswordAuthTime;
//   - authentication.AuthTime, when set, becomes the session's auth_time;
//   - authentication.OTPClaim is checked on the user under the user's row lock, first in the
//     transaction (otpcredential.OTPClaim.Recheck), and the session must be authentication.UserId's.
//
// All of it is one transaction under the session's row, where the replacement and the auth_time
// used to be a second whole-row write after the bump's, unlocked and outside its transaction, which
// could undo a removal's lowering as the bump's own write could (#542).
//
// A bind whose sign-in predates the session's current authentication, or whose adopted session
// holds neither the auth_time it adopted nor the ceremony's own, writes nothing and returns
// ErrStaleAuthentication (#538).
func (u *Manager) BindUserSession(ctx context.Context, sessionIdentifier string, clientId int64,
	authentication Authentication, replace bool, ipAddress string) (*record.UserSession, error) {
	if replace && (authentication.PasswordAuthTime == nil || authentication.PasswordAuthTime.IsZero()) {
		return nil, errs.New("no password instant captured; refusing to replace a session's authentication with a password_auth_time that would be invented")
	}
	return u.bindUserSession(ctx, sessionIdentifier, clientId, authentication, replace, ipAddress)
}

// AuthenticationIsStale answers, from the session row as it is now, whether the ordering rule would
// refuse a bind of authentication (#538). It locks nothing and writes nothing, and a session that is
// gone is not stale here: the bind answers that itself.
//
// /auth/completed's reuse arm asks it before it rotates the browser session's identifier, so a
// ceremony the bind would refuse rotates nothing. The bind asks again under the row lock, for a
// sign-in that lands between the two.
func (u *Manager) AuthenticationIsStale(ctx context.Context, sessionIdentifier string,
	authentication Authentication) (bool, error) {
	userSession, err := u.database.GetUserSessionBySessionIdentifier(ctx, nil, sessionIdentifier)
	if err != nil {
		return false, err
	}
	if userSession == nil {
		return false, nil
	}
	return staleAuthentication(userSession, authentication), nil
}

func (u *Manager) bindUserSession(ctx context.Context, sessionIdentifier string, clientId int64,
	authentication Authentication, replace bool, ipAddress string) (*record.UserSession, error) {

	authMethods := authentication.AuthMethods
	acrLevel := authentication.AcrLevel

	var bumped *record.UserSession
	err := data.RunInTransactionRetryingConflict(ctx, u.database, func(tx *sql.Tx) error {
		if claimErr := authentication.OTPClaim.Recheck(ctx, u.database, tx, authentication.UserId); claimErr != nil {
			return claimErr
		}

		live, err := u.database.AcquireUserSessionRow(ctx, tx, sessionIdentifier)
		if err != nil {
			return err
		}
		if !live {
			return errs.New("can't bump user session because user session is nil")
		}

		userSession, err := u.database.GetUserSessionBySessionIdentifier(ctx, tx, sessionIdentifier)
		if err != nil {
			return err
		}
		if userSession == nil {
			return errs.New("can't bump user session because user session is nil")
		}
		if authentication.UserId != 0 && userSession.UserId != authentication.UserId {
			return errs.Errorf("refusing to bind user session %v of user %v to a sign-in of user %v",
				userSession.Id, userSession.UserId, authentication.UserId)
		}

		// The ordering rule (#538). Two ceremonies can complete on the same session: one whose
		// /auth/completed request stalled after loading its context, and a second that runs a
		// whole prompt=login or step-up while the first waits. The transaction above already makes
		// the two writes serial, one whole bind at a time; what it cannot decide is which sign-in
		// the session should describe when both wrote. The instants decide, and there are two of
		// them. A ceremony whose credential was accepted before the session's current auth_time is
		// an older authentication, and its bind writes nothing -- not the level or the methods a
		// step-up would raise, not the level and methods a prompt=login would replace them with,
		// and not an auth_time that moves backwards. A session with no auth_time yet (a legacy row,
		// or one this transaction is the first to stamp) has no newer authentication to lose, so it
		// takes the write.
		//
		// The comparison reads the row this transaction locked, so a concurrent bind answering
		// the same question waits on AcquireUserSessionRow and then reads the auth_time the
		// winner committed: the older ceremony loses, the newer one wins, whichever arrives
		// second, which is the whole of what the ordering adds to the serialisation.
		//
		// The second instant is the one the ceremony adopted the session at: a bind built on an
		// authentication the row no longer holds, adopted at /auth/authorize and since replaced by
		// a newer sign-in, writes nothing either, for the same reason (#538, the SSO case).
		if staleAuthentication(userSession, authentication) {
			return errs.WithStack(ErrStaleAuthentication)
		}

		err = u.database.UserSessionLoadClients(ctx, tx, userSession)
		if err != nil {
			return err
		}

		utcNow := time.Now().UTC()
		userSession.LastAccessed = utcNow

		// The latest address the browser was seen from, not a history. Appending every new one
		// made the column grow without bound until the update failed past its 512 bytes on
		// MySQL, PostgreSQL and SQL Server, and every later bump of the session with it; and the
		// substring test deciding what was new read 10.0.0.1 as already present in 10.0.0.12
		// (#243).
		if ipAddress != "" {
			userSession.IpAddress = ipAddress
		}

		if replace {
			// A new authentication replaces the session's, as /auth/completed's decideCompletion
			// explains: the level it was asked for, the methods it performed and when it entered
			// the password, never merged with what the session held before (#537, #542).
			userSession.AcrLevel = acrLevel
			userSession.AuthMethods = authMethods
			userSession.PasswordAuthTime = authentication.PasswordAuthTime.UTC()
		} else {
			// Handle step-up authentication: add the methods the current auth flow used that the
			// session lacks, e.g. "otp" when the user just completed OTP over a pwd-only session.
			// Merged, never replaced, so a flow listing fewer methods than the session cannot
			// shrink them (#537).
			if raisesAuthMethods(userSession.AuthMethods, authMethods) {
				userSession.AuthMethods = mergeAuthMethods(userSession.AuthMethods, authMethods)
			}

			// Handle step-up authentication: upgrade ACR level if a higher level was achieved.
			// We only upgrade, never downgrade, because once a user has proven a higher level
			// of authentication in this session, that security guarantee should be preserved.
			// Example: User logged in with pwd+otp (level2), then visits a level1 client.
			// The session should remain at level2 because that's what was actually achieved.
			if acrLevel != "" && shouldUpgradeAcrLevel(userSession.AcrLevel, acrLevel) {
				userSession.AcrLevel = acrLevel
			}
		}

		if authentication.AuthTime != nil {
			userSession.AuthTime = authentication.AuthTime.UTC()
		}

		// append client if not already present
		clientFound := false
		for _, c := range userSession.Clients {
			if c.ClientId == clientId {
				clientFound = true
				break
			}
		}
		if !clientFound {
			userSession.Clients = append(userSession.Clients, record.UserSessionClient{
				Started:      utcNow,
				LastAccessed: utcNow,
				ClientId:     clientId,
			})
		} else {
			// update last accessed
			for i, c := range userSession.Clients {
				if c.ClientId == clientId {
					userSession.Clients[i].LastAccessed = utcNow
					break
				}
			}
		}

		// The insert-versus-update decision comes from client.Id on a copy, so an attempt that
		// inserted leaves the slice as it found it.
		if updateUserSessionErr := u.database.UpdateUserSession(ctx, tx, userSession); updateUserSessionErr != nil {
			return updateUserSessionErr
		}

		for _, client := range userSession.Clients {
			if client.Id > 0 {
				// update
				if updateUserSessionClientErr := u.database.UpdateUserSessionClient(ctx, tx, &client); updateUserSessionClientErr != nil {
					return updateUserSessionClientErr
				}
			} else {
				// insert new
				client.UserSessionId = userSession.Id
				if createUserSessionClientErr := u.database.CreateUserSessionClient(ctx, tx, &client); createUserSessionClientErr != nil {
					return createUserSessionClientErr
				}
			}
		}

		// Set by the attempt that wrote, so a rerun's session replaces a first attempt's and a
		// failed commit returns nothing at all.
		bumped = userSession
		return nil
	})
	if err != nil {
		return nil, err
	}

	return bumped, nil
}

// staleAuthentication answers whether authentication is an older authentication than the one
// userSession's row already records, under the lock the caller's transaction holds on it, and so
// must not be written onto the session (#538). Two comparisons run, and either refusing is enough.
//
// The first is the instant the sign-in claims: AuthTime, the credential the ceremony last accepted.
// A bind that carries none claims no authentication of its own, so by this comparison alone it is
// never stale. A session whose auth_time is zero -- a legacy row, or one no bind has stamped yet --
// has no newer authentication for an arriving one to be older than, so every sign-in takes it.
//
// The second is the instant the ceremony adopted the session at: AdoptedAuthTime, copied from the
// adopted session's auth_time when /auth/authorize adopted it. When the session's current auth_time
// is neither that nor the ceremony's own credential instant, a newer sign-in has reached the session
// since the adoption, and the methods such a bind merges back and the level it raises the session to
// would describe the older sign-in rather than the one the session holds now, which is what #538
// refuses. The ceremony's own instant counts because a ceremony that adopted the session and then
// entered a code moved auth_time to that code with its own first bind: a second bind of the same
// ceremony, a reload of /auth/completed after a step that failed once the bind had committed, finds
// its own authentication there and is current.
//
// Equal instants are current, not stale, in the first comparison too, for the same second bind: a
// bind carrying the session's own auth_time is the sign-in the session already describes.
//
// Equal means equal at the auth_time column's precision, a microsecond on every engine
// (sameInstant). The instants a ceremony carries are the clock's, to the nanosecond, while the row
// holds what the engine kept of the same instant, so a ceremony's own instant and the row it wrote
// differ below a microsecond, in either direction when an engine rounds rather than truncates.
//
// The instants authflow.PasswordSubmission and authflow.OTPSubmission stamp come from the auth server instance's clock, so
// the first comparison assumes the instances of one deployment share a synchronized clock, as NTP
// keeps them. A host minutes adrift can refuse a genuinely later sign-in, and the user's next
// sign-in that enters a credential is stamped by the same slow clock, so it can be refused again
// until the gap has passed. The second comparison reads no clock at all.
func staleAuthentication(session *record.UserSession, authentication Authentication) bool {
	// The instant this sign-in claims, AuthTime, the credential the ceremony last accepted.
	claimed := time.Time{}
	if authentication.AuthTime != nil {
		claimed = authentication.AuthTime.UTC()
	}

	// The authentication this ceremony was built on, when it adopted a session at
	// /auth/authorize: if the session's auth_time has moved since, to anything but this
	// ceremony's own credential, a newer sign-in owns it now, and a ceremony built on an
	// authentication the session no longer holds must start again, even though it entered no
	// credential of its own. It applies whenever the field is set, including an SSO ceremony
	// that then stepped up.
	if authentication.AdoptedAuthTime != nil {
		holdsAdopted := sameInstant(session.AuthTime, *authentication.AdoptedAuthTime)
		holdsOwn := !claimed.IsZero() && sameInstant(session.AuthTime, claimed)
		if !holdsAdopted && !holdsOwn {
			return true
		}
	}

	if claimed.IsZero() {
		return false
	}

	if session.AuthTime.IsZero() {
		return false
	}
	return claimed.Before(session.AuthTime) && !sameInstant(claimed, session.AuthTime)
}

// authTimePrecision is the precision of the user_sessions.auth_time column on every engine:
// datetime(6) on MySQL, timestamp(6) on PostgreSQL, datetime2(6) on SQL Server, and SQLite holds
// at least as much.
const authTimePrecision = time.Microsecond

// sameInstant reports whether a and b are the same instant at the auth_time column's precision,
// within a microsecond of each other whichever way an engine reduced the one it stored.
func sameInstant(a, b time.Time) bool {
	return a.Sub(b).Abs() < authTimePrecision
}

// WillRaisePrivilege reports whether bumping a session with these values would raise its
// authentication methods or its ACR level, which is the privilege change decision 6 of
// #266 rotates the browser session identifier at.
//
// It exists so the decision can be taken BEFORE BumpUserSession runs. BumpUserSession
// opens its own transaction and commits before it returns, so a rotation attempted
// afterwards has a window in which the pre-step-up identifier names a session that is
// already at the higher level, which is exactly the carryover rotation exists to stop.
// Deciding first and rotating first means a failure between the two leaves a fresh
// identifier on a session that has not been raised yet, which is the safe direction.
//
// It is built from the same two predicates BumpUserSession applies, so the decider and
// the writer cannot drift apart.
func WillRaisePrivilege(userSession *record.UserSession, authMethods string, acrLevel record.AcrLevel) bool {
	if userSession == nil {
		return false
	}
	return raisesAuthMethods(userSession.AuthMethods, authMethods) ||
		(acrLevel != "" && shouldUpgradeAcrLevel(userSession.AcrLevel, acrLevel))
}

// raisesAuthMethods reports whether incoming lists a method current lacks, which is the only change
// a bump makes to a session's methods. An empty incoming value means the ceremony recorded none,
// which changes nothing, and so does one listing fewer methods than the session: "pwd" over a
// "pwd otp" session is not a raise.
//
// It answered true on any difference until #537, so a bump with "pwd" replaced a session's
// "pwd otp" and WillRaisePrivilege counted that drop as a privilege raise.
func raisesAuthMethods(current, incoming string) bool {
	have := strings.Fields(current)
	for _, method := range strings.Fields(incoming) {
		if !slices.Contains(have, method) {
			return true
		}
	}
	return false
}

// mergeAuthMethods is current with every method of incoming it lacks appended, in incoming's
// order, space-separated as AuthContext.AuthMethods and the session column store them. Appending
// keeps amr in the order the methods were used: a session's methods came first.
func mergeAuthMethods(current, incoming string) string {
	merged := strings.Fields(current)
	for _, method := range strings.Fields(incoming) {
		if !slices.Contains(merged, method) {
			merged = append(merged, method)
		}
	}
	return strings.Join(merged, " ")
}

// shouldUpgradeAcrLevel determines if the session's ACR level should be upgraded.
// Returns true if newAcr represents a stronger authentication level than currentAcr.
//
// This is used during step-up authentication: when a user with a level1 session
// authenticates with OTP for a level2 client, the session's ACR should be upgraded.
//
// Uses record.AcrLevel.IsHigherThan() as the single source of truth for ACR comparison.
// A level outside the three answers false on either side, which IsHigherThan alone does not:
// an unrecognized current level has priority 0, so any known level would be higher than it,
// and a session row carrying a value this server never wrote would be raised rather than
// left as found. Priority 0 is what marks the value unrecognized (#433).
func shouldUpgradeAcrLevel(currentAcr, newAcr record.AcrLevel) bool {
	if currentAcr.Priority() == 0 || newAcr.Priority() == 0 {
		return false // Unknown ACR, fail safe
	}

	return newAcr.IsHigherThan(currentAcr)
}
