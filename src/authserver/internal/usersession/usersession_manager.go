package usersession

import (
	"context"
	"database/sql"
	"net/http"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/sessionkeys"
	"github.com/leodip/goiabada/authserver/internal/useragent"
	"github.com/leodip/goiabada/authserver/internal/uuid"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/sessionstore"
)

// userSessionManagerDatabase is what the session manager needs: the session row and the clients
// it authorized, and the transaction that changes them together.
type userSessionManagerDatabase interface {
	CreateUserSession(ctx context.Context, tx *sql.Tx, userSession *record.UserSession) error
	CreateUserSessionClient(ctx context.Context, tx *sql.Tx, userSessionClient *record.UserSessionClient) error
	DeleteUserSession(ctx context.Context, tx *sql.Tx, userSessionId int64) error
	GetUserSessionBySessionIdentifier(ctx context.Context, tx *sql.Tx, sessionIdentifier string) (*record.UserSession, error)
	GetUserSessionsByUserId(ctx context.Context, tx *sql.Tx, userId int64) ([]record.UserSession, error)
	RunInTransaction(ctx context.Context, fn func(tx *sql.Tx) error) error
	UpdateUserSession(ctx context.Context, tx *sql.Tx, userSession *record.UserSession) error
	UpdateUserSessionClient(ctx context.Context, tx *sql.Tx, userSessionClient *record.UserSessionClient) error
	UserSessionLoadClients(ctx context.Context, tx *sql.Tx, userSession *record.UserSession) error
}

// sessionCleanupTimeout bounds the compensating delete once abandonUserSession has detached it
// from the caller's cancellation. Ten seconds, matching every other bounded wait on a dependency
// in this repository's request path rather than introducing a value nobody chose against the
// others.
const sessionCleanupTimeout = 10 * time.Second

// userSessionStore is what the manager calls on the browser session store. Regenerate is in
// it, so a store that cannot rotate does not compile here, where it used to fall back to a
// plain save that bound the new user session to the identifier the browser arrived with (#431).
type userSessionStore interface {
	Get(r *http.Request, name string) (*sessionstore.Session, error)
	Regenerate(w http.ResponseWriter, r *http.Request, session *sessionstore.Session) error
}

// Manager creates, bumps and judges the user sessions a browser signs in to.
type Manager struct {
	sessionStore userSessionStore
	sessionName  string
	database     userSessionManagerDatabase
	// now is the clock HasValidUserSession judges a session against, a field so a test can fix
	// it, as sessionbackend's is.
	now func() time.Time
}

func NewManager(sessionStore userSessionStore, sessionName string, database userSessionManagerDatabase) *Manager {
	return &Manager{
		sessionStore: sessionStore,
		sessionName:  sessionName,
		database:     database,
		now:          func() time.Time { return time.Now().UTC() },
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

// StartNewUserSession creates a session for a completed authentication ceremony.
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
// authenticatedAt is the instant this ceremony's last credential was accepted, captured by
// the password handler and overwritten by the OTP handler. It becomes the session's AuthTime
// and so the auth_time claim, which OIDC Core 3.1.2.1 makes max_age's reference point: "the
// last time the End-User was actively authenticated by the OP". Reading the clock here
// instead would name the moment this function ran, and the browser owns the hop between the
// two -- a tab left sitting after the password was accepted and resumed hours later would
// mint a session claiming the user had just authenticated, so a relying party asking for a
// fresh sign-in with max_age would be told it got one (#252 decision 8). Started and
// LastAccessed stay on now: they measure the session's own life, not the credential's.
// Nil or zero is refused, before anything is written: a session with no credential instant
// has nothing true to put in auth_time, and falling back to now would recreate the false
// freshness this parameter exists to remove, one broken caller away. The one caller cannot
// produce it, because /auth/completed refuses to mint a session without Level1AuthCompleted
// and only the password handler sets that, alongside authenticatedAt; the refusal is what
// makes that invariant fail closed rather than an argument in a comment.
//
// ipAddress is the browser's address as the caller read it, and becomes the session's one
// recorded address. replacing is the session this sign-in replaces for the same user, the one the
// browser's cookie named, or nil; it is deleted with the same-device sweep's rows, and every row
// removed is returned so the caller can audit each. A replaced session's refresh tokens that are
// bound to it stop, as they do when it expires, and its offline grants survive: a re-login
// replaces a session and revokes nothing (#133, #243). A session of another user is not this
// function's to end: the cross-user handover terminates it with revocation first and passes nil.
//
// The removals come back only when their deletion committed: with the session on success, and
// alongside the error when the browser session write after the commit fails, since the rows are
// gone either way and each is owed its audit event. Every other failure rolled them back and
// returns none.
func (u *Manager) StartNewUserSession(w http.ResponseWriter, r *http.Request,
	userId int64, clientId int64, authMethods string, acrLevel record.AcrLevel,
	authStateGeneration int64, otpConfigGeneration *int64,
	authenticatedAt *time.Time, ipAddress string,
	replacing *record.UserSession) (*record.UserSession, []record.UserSession, error) {

	if authenticatedAt == nil || authenticatedAt.IsZero() {
		return nil, nil, errs.New("no credential instant captured; refusing to mint a session whose auth_time would be invented")
	}
	if replacing != nil && replacing.UserId != userId {
		return nil, nil, errs.Errorf("refusing to replace user session %v: it belongs to user %v, not %v",
			replacing.Id, replacing.UserId, userId)
	}
	authTime := authenticatedAt.UTC()

	utcNow := time.Now().UTC()

	observedOtpConfigGeneration := int64(0)
	if otpConfigGeneration != nil {
		observedOtpConfigGeneration = *otpConfigGeneration
	}

	// One parse of the request for all three display labels. They are derived from the
	// Sec-CH-UA* Client Hints when the browser sends them and from the User-Agent otherwise,
	// and nothing below reads them back: the sweep keys on UserAgent and IpAddress (#281).
	deviceName, deviceType, deviceOS := useragent.Labels(r)

	userSession := &record.UserSession{
		SessionIdentifier: uuid.New(),
		Started:           utcNow,
		LastAccessed:      utcNow,
		IpAddress:         ipAddress,
		AuthMethods:       authMethods,
		AcrLevel:          acrLevel,
		AuthTime:          authTime,
		UserId:            userId,
		DeviceName:        deviceName,
		DeviceType:        deviceType,
		DeviceOS:          deviceOS,
		UserAgent:         useragent.BoundRaw(r.UserAgent()),

		AuthStateGeneration: authStateGeneration,
		OtpConfigGeneration: observedOtpConfigGeneration,
	}

	userSession.Clients = append(userSession.Clients, record.UserSessionClient{
		Started:      utcNow,
		LastAccessed: utcNow,
		ClientId:     clientId,
	})

	// The browser session is read before anything is written. It is a memoised per-request read
	// that /auth/completed has already resolved by this point, so it consults no backend and
	// writes nothing here; taking it first is what makes an unreadable cookie a refusal with an
	// empty database rather than one leaving a session row behind (#198).
	sess, err := u.sessionStore.Get(r, u.sessionName)
	if err != nil {
		return nil, nil, errs.Wrap(err, "unable to get the session")
	}

	// The session row, its client associations, the read of this user's other sessions and the
	// same-device sweep below are one transaction, opened through RunInTransaction so a deadlock
	// reruns the body (#301). The body is safe to rerun: the id CreateUserSession assigns is
	// reassigned by the next attempt, the association loop ranges by value, so nothing an attempt
	// wrote onto a copy is read by the attempt after it, and the identifier the sweep excludes
	// itself by is minted above rather than inside, so it survives a rerun. A rolled-back attempt
	// undoes its own deletions and the attempt after it re-reads, which is why the rows it removed
	// are collected into a fresh slice on every attempt and copied out only once RunInTransaction
	// has answered nil: an aborted attempt's deletions never happened, and an attempt that deletes
	// a different set from the one before it reports its own.
	//
	// The sweep is in here rather than after the commit because a failure between the two left a
	// committed session row that no cookie named, sometimes having already deleted the session the
	// browser did have (#198). Only the browser-store write below is left after the commit, and it
	// is compensated rather than prevented: see abandonUserSession.
	var removed []record.UserSession
	err = u.database.RunInTransaction(r.Context(), func(tx *sql.Tx) error {
		var removedThisAttempt []record.UserSession

		if createUserSessionErr := u.database.CreateUserSession(r.Context(), tx, userSession); createUserSessionErr != nil {
			return createUserSessionErr
		}

		// The associations belong to the session row created just above, whose id no other caller
		// holds, so this insert cannot lose the (session, client) key to a concurrent one and needs
		// no rerun on it. Only a bump, which writes to a session that already exists, can (#249).
		for _, client := range userSession.Clients {
			client.UserSessionId = userSession.Id
			if createUserSessionClientErr := u.database.CreateUserSessionClient(r.Context(), tx, &client); createUserSessionClientErr != nil {
				return createUserSessionClientErr
			}
		}

		allUserSessions, getUserSessionsErr := u.database.GetUserSessionsByUserId(r.Context(), tx, userId)
		if getUserSessionsErr != nil {
			return getUserSessionsErr
		}

		// Delete this user's other sessions from the same device: same raw User-Agent header,
		// same address. Nothing here reads DeviceName, DeviceType or DeviceOS, which are a
		// parser's guess at a browser name and now display only. Keying on them meant a coarser
		// label collapsed two machines behind one address into one device, and a change of parser
		// or of label format silently changed which sessions superseded which. The header is
		// compared as sent, bounded by useragent.BoundRaw on both sides, so the comparison is between
		// two values cut at the same point (#281).
		//
		// Two consequences of pre-upgrade rows carrying an empty header, both accepted rather than
		// worked around: a login that sends a header does not match one, so a legacy row survives
		// this login and expires on its own by idle timeout or max lifetime; and a client that
		// sends no header matches every legacy row on its address, which is how a header-less
		// client is treated today in any case.
		//
		// The address is compared whole, one address to one address. It used to be a substring
		// test against a comma-joined history, so 10.0.0.1 was found in 10.0.0.12, and a history
		// that outgrew the 512-byte column failed every later bump of that session. A session now
		// holds the latest address its browser was seen from (#243).
		//
		// replacing is the other reason a row goes: the session this browser's cookie named, which
		// this sign-in supersedes wherever it was last seen. Without it a max_age or prompt=login
		// sign-in from a new address left the old session behind, still listed and still bumped by
		// its refresh tokens, with no browser able to reach it (#243). It is matched in this read
		// rather than deleted blindly, so a row already gone is not reported as one this sign-in
		// removed, and a row that is both replacing and a sweep match is removed and reported once.
		for _, us := range allUserSessions {
			if us.SessionIdentifier == userSession.SessionIdentifier {
				continue
			}
			isReplaced := replacing != nil && us.Id == replacing.Id
			isSameDevice := us.UserAgent == userSession.UserAgent && us.IpAddress == ipAddress
			if !isReplaced && !isSameDevice {
				continue
			}
			if deleteUserSessionErr := u.database.DeleteUserSession(r.Context(), tx, us.Id); deleteUserSessionErr != nil {
				return deleteUserSessionErr
			}
			removedThisAttempt = append(removedThisAttempt, us)
		}
		removed = removedThisAttempt
		return nil
	})
	if err != nil {
		// ceiling: this cannot always tell whether the commit happened. RunInTransaction's
		// contract says a commit that fails for a reason the engine did not declare may have
		// landed anyway, in which case the ceremony answers an error over a row that exists and
		// no cookie names -- #198's shape, arriving through the helper rather than through a
		// step of this ceremony.
		//
		// Nothing here can close it, and a compensating read is not the answer: a read that
		// finds no row is not proof the commit rolled back, because the commit may still be
		// completing while it runs. What bounds the window is the background worker's idle
		// sweep, which removes the row at the configured idle timeout. So the cost is an entry
		// in the admin console's session list until then, with nothing ever issued against it.
		// The same unknown decides the removals: none is reported here, so a commit that landed
		// anyway leaves the rows it swept gone without their audit events, where reporting them
		// would audit deletions that may have rolled back.
		// Revisit only if the row ever becomes reachable by something other than the cookie.
		return nil, nil, err
	}

	sess.Values[sessionkeys.SessionIdentifier] = userSession.SessionIdentifier

	// The browser session's identifier is replaced as the user session is bound to it, so
	// no identifier that existed before this ceremony can name the session the ceremony
	// produced.
	//
	// This is the property a cookie store gave for free and a server-side one has to add.
	// A cookie store is structurally immune to session fixation because the cookie IS the
	// state: an attacker's planted copy stays the attacker's own stale state. A row is
	// not, because a planted identifier names a row the victim's sign-in then fills in,
	// and the attacker is signed in as the victim. Rotating here is what puts that
	// immunity back, and it covers a different user signing in on the same browser for
	// free, being the same code path (#266).
	//
	// The identifier is written into the session before the rotation rather than after
	// so that the whole sign-in reaches the browser as one Set-Cookie carrying the
	// authenticated expiry. Nothing is persisted under the new identifier until
	// Regenerate runs, and the row it deletes never held the identifier, so the ordering
	// changes no outcome an attacker could use.
	//
	// A failure here comes after the commit, so the rows the sweep removed are gone whatever
	// abandonUserSession manages, and they go back to the caller beside the error to be audited.
	if regenerateErr := u.sessionStore.Regenerate(w, r, sess); regenerateErr != nil {
		return nil, removed, u.abandonUserSession(r.Context(), userSession, errs.Wrap(regenerateErr, "unable to rotate the browser session identifier"))
	}

	return userSession, removed, nil
}

// abandonUserSession deletes the session row the transaction above committed, after the browser
// store write that was to bind it to a cookie failed, and returns cause unchanged: the ceremony
// failed for that reason and the caller must be told that one, not what this cleanup did.
//
// It is the compensation for the single step that cannot join the transaction. RunInTransaction
// reruns its body when the engine aborts it as a deadlock victim, and a rerun of Regenerate
// would write Set-Cookie twice, so the browser-store write stays after the commit. Without
// this, the row stayed: no browser held a cookie naming it, nothing was ever issued against it,
// and it sat in the admin console's session list until its own idle timeout expired (#198).
//
// A cleanup that fails in turn is joined onto cause rather than replacing it, so errors.Is still
// finds the original and the record still says the row survived.
//
// ceiling: the same-device sweep commits with the row, so undoing the row here cannot bring back
// the sessions it superseded, and a user whose cookie write fails is left with neither the session
// this ceremony created nor the one it replaced -- they sign in again. Closing that needs the
// browser-store write staged inside the transaction, which it cannot be while a rerun can double
// the Set-Cookie. Revisit if the store gains a two-phase write that can be prepared before the
// commit and completed after it (#198).
func (u *Manager) abandonUserSession(ctx context.Context, userSession *record.UserSession, cause error) error {
	// The caller's VALUES, deliberately not the caller's cancellation, because the cancellation
	// and the failure this compensates for are the same event: net/http cancels a request's
	// context the instant the client disconnects, and a disconnected client is exactly why a
	// browser-store write fails. Inheriting it would abandon the delete in the one case the
	// compensation exists for, leaving #198's orphan behind and reporting nothing but the
	// rotation error. WithoutCancel rather than a fresh root so the delete's own record still
	// carries the request id, bounded because a detached context has no other stop signal and
	// ten seconds is this repository's one value for a bounded wait on a dependency
	// (#386 decision 6, and final review round 1 finding 9).
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), sessionCleanupTimeout)
	defer cancel()

	if err := u.database.DeleteUserSession(ctx, nil, userSession.Id); err != nil {
		return errs.Join(cause, errs.Wrap(err,
			"unable to delete the user session left behind by a failed browser session write"))
	}
	return cause
}

// BumpUserSession updates an existing session's last accessed time and client list.
// It also handles ACR/AMR step-up authentication scenarios.
//
// Step-up authentication occurs when a user with an existing session (e.g., password-only)
// accesses a client that requires a higher authentication level (e.g., password + OTP).
// In this case, the session's AuthMethods and AcrLevel must be upgraded to reflect
// the stronger authentication that was actually performed.
//
// Parameters:
//   - authMethods: The authentication methods used in the current auth flow (e.g., "pwd otp").
//     If this differs from the session's current AuthMethods, the session is updated.
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
func (u *Manager) BumpUserSession(ctx context.Context, sessionIdentifier string, clientId int64,
	authMethods string, acrLevel record.AcrLevel, ipAddress string) (*record.UserSession, error) {

	var bumped *record.UserSession
	err := data.RunInTransactionRetryingConflict(ctx, u.database, func(tx *sql.Tx) error {
		userSession, err := u.database.GetUserSessionBySessionIdentifier(ctx, tx, sessionIdentifier)
		if err != nil {
			return err
		}
		if userSession == nil {
			return errs.New("can't bump user session because user session is nil")
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

		// Handle step-up authentication: update AuthMethods if new methods were used.
		// The authMethods parameter contains all methods used in the current auth flow
		// (e.g., "pwd otp" if the user just completed OTP after having a pwd-only session).
		if raisesAuthMethods(userSession.AuthMethods, authMethods) {
			userSession.AuthMethods = authMethods
		}

		// Handle step-up authentication: upgrade ACR level if a higher level was achieved.
		// We only upgrade, never downgrade, because once a user has proven a higher level
		// of authentication in this session, that security guarantee should be preserved.
		// Example: User logged in with pwd+otp (level2), then visits a level1 client.
		// The session should remain at level2 because that's what was actually achieved.
		if acrLevel != "" && shouldUpgradeAcrLevel(userSession.AcrLevel, acrLevel) {
			userSession.AcrLevel = acrLevel
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

// raisesAuthMethods reports whether a bump would replace the session's recorded methods.
// An empty incoming value means the ceremony recorded none, which changes nothing.
func raisesAuthMethods(current, incoming string) bool {
	return incoming != "" && incoming != current
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
