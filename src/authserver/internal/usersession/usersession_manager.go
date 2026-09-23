package usersession

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/leodip/goiabada/authserver/internal/constants"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/useragent"
	"github.com/leodip/goiabada/authserver/internal/uuidutil"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/sessionstore"
)

// userSessionManagerDatabase is what the session manager needs: the session row and the clients
// it authorized, and the transaction that changes them together.
type userSessionManagerDatabase interface {
	CreateUserSession(ctx context.Context, tx *sql.Tx, userSession *models.UserSession) error
	CreateUserSessionClient(ctx context.Context, tx *sql.Tx, userSessionClient *models.UserSessionClient) error
	DeleteUserSession(ctx context.Context, tx *sql.Tx, userSessionId int64) error
	GetUserSessionBySessionIdentifier(ctx context.Context, tx *sql.Tx, sessionIdentifier string) (*models.UserSession, error)
	GetUserSessionsByUserId(ctx context.Context, tx *sql.Tx, userId int64) ([]models.UserSession, error)
	RunInTransaction(ctx context.Context, fn func(tx *sql.Tx) error) error
	UpdateUserSession(ctx context.Context, tx *sql.Tx, userSession *models.UserSession) error
	UpdateUserSessionClient(ctx context.Context, tx *sql.Tx, userSessionClient *models.UserSessionClient) error
	UserSessionLoadClients(ctx context.Context, tx *sql.Tx, userSession *models.UserSession) error
}

// sessionCleanupTimeout bounds the compensating delete once abandonUserSession has detached it
// from the caller's cancellation. Ten seconds, matching every other bounded wait on a dependency
// in this repository's request path rather than introducing a value nobody chose against the
// others.
const sessionCleanupTimeout = 10 * time.Second

type UserSessionManager struct {
	sessionStore sessionstore.Store
	sessionName  string
	database     userSessionManagerDatabase
}

func NewUserSessionManager(sessionStore sessionstore.Store, sessionName string, database userSessionManagerDatabase) *UserSessionManager {
	return &UserSessionManager{
		sessionStore: sessionStore,
		sessionName:  sessionName,
		database:     database,
	}
}

func (u *UserSessionManager) HasValidUserSession(ctx context.Context, userSession *models.UserSession, requestedMaxAgeInSeconds *int) bool {

	settings := ctx.Value(constants.ContextKeySettings).(*models.Settings)

	isValid := false
	if userSession != nil {
		isValid = userSession.IsValid(settings.UserSessionIdleTimeoutInSeconds,
			settings.UserSessionMaxLifetimeInSeconds, requestedMaxAgeInSeconds)
	}

	return isValid
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
func (u *UserSessionManager) StartNewUserSession(w http.ResponseWriter, r *http.Request,
	userId int64, clientId int64, authMethods string, acrLevel string,
	authStateGeneration int64, otpConfigGeneration *int64,
	authenticatedAt *time.Time) (*models.UserSession, error) {

	if authenticatedAt == nil || authenticatedAt.IsZero() {
		return nil, errs.New("StartNewUserSession: no credential instant captured; refusing to mint a session whose auth_time would be invented")
	}
	authTime := authenticatedAt.UTC()

	utcNow := time.Now().UTC()

	observedOtpConfigGeneration := int64(0)
	if otpConfigGeneration != nil {
		observedOtpConfigGeneration = *otpConfigGeneration
	}

	ipWithoutPort, _, _ := net.SplitHostPort(r.RemoteAddr)
	if len(ipWithoutPort) == 0 {
		ipWithoutPort = r.RemoteAddr
	}

	// One parse of the request for all three display labels. They are derived from the
	// Sec-CH-UA* Client Hints when the browser sends them and from the User-Agent otherwise,
	// and nothing below reads them back: the sweep keys on UserAgent and IpAddress (#281).
	deviceName, deviceType, deviceOS := useragent.Labels(r)

	userSession := &models.UserSession{
		SessionIdentifier: uuidutil.New(),
		Started:           utcNow,
		LastAccessed:      utcNow,
		IpAddress:         ipWithoutPort,
		AuthMethods:       authMethods,
		AcrLevel:          acrLevel,
		AuthTime:          authTime,
		UserId:            userId,
		DeviceName:        deviceName,
		DeviceType:        deviceType,
		DeviceOS:          deviceOS,
		UserAgent:         useragent.Raw(r),

		AuthStateGeneration: authStateGeneration,
		OtpConfigGeneration: observedOtpConfigGeneration,
	}

	userSession.Clients = append(userSession.Clients, models.UserSessionClient{
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
		return nil, errs.Wrap(err, "unable to get the session")
	}

	// The session row, its client associations, the read of this user's other sessions and the
	// same-device sweep below are one transaction, opened through RunInTransaction so a deadlock
	// reruns the body (#301). The body is safe to rerun: the id CreateUserSession assigns is
	// reassigned by the next attempt, the association loop ranges by value, so nothing an attempt
	// wrote onto a copy is read by the attempt after it, and the identifier the sweep excludes
	// itself by is minted above rather than inside, so it survives a rerun. A rolled-back attempt
	// undoes its own deletions and the attempt after it re-reads.
	//
	// The sweep is in here rather than after the commit because a failure between the two left a
	// committed session row that no cookie named, sometimes having already deleted the session the
	// browser did have (#198). Only the browser-store write below is left after the commit, and it
	// is compensated rather than prevented: see abandonUserSession.
	err = u.database.RunInTransaction(r.Context(), func(tx *sql.Tx) error {
		if createUserSessionErr := u.database.CreateUserSession(r.Context(), tx, userSession); createUserSessionErr != nil {
			return createUserSessionErr
		}

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
		// compared as sent, bounded by useragent.Bound on both sides, so the comparison is between
		// two values cut at the same point (#281).
		//
		// Two consequences of pre-upgrade rows carrying an empty header, both accepted rather than
		// worked around: a login that sends a header does not match one, so a legacy row survives
		// this login and expires on its own by idle timeout or max lifetime; and a client that
		// sends no header matches every legacy row on its address, which is how a header-less
		// client is treated today in any case.
		for _, us := range allUserSessions {
			if us.SessionIdentifier != userSession.SessionIdentifier &&
				us.UserAgent == userSession.UserAgent &&
				us.IpAddress == ipWithoutPort {
				if deleteUserSessionErr := u.database.DeleteUserSession(r.Context(), tx, us.Id); deleteUserSessionErr != nil {
					return deleteUserSessionErr
				}
			}
		}
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
		// Revisit only if the row ever becomes reachable by something other than the cookie.
		return nil, err
	}

	sess.Values[constants.SessionKeySessionIdentifier] = userSession.SessionIdentifier

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
	if regenerator, ok := u.sessionStore.(sessionstore.Regenerator); ok {
		if regenerateErr := regenerator.Regenerate(w, r, sess); regenerateErr != nil {
			return nil, u.abandonUserSession(r.Context(), userSession, errs.Wrap(regenerateErr, "unable to rotate the browser session identifier"))
		}
		return userSession, nil
	}

	err = u.sessionStore.Save(r, w, sess)
	if err != nil {
		return nil, u.abandonUserSession(r.Context(), userSession, err)
	}

	return userSession, nil
}

// abandonUserSession deletes the session row the transaction above committed, after the browser
// store write that was to bind it to a cookie failed, and returns cause unchanged: the ceremony
// failed for that reason and the caller must be told that one, not what this cleanup did.
//
// It is the compensation for the single step that cannot join the transaction. RunInTransaction
// reruns its body when the engine aborts it as a deadlock victim, and a rerun of Regenerate or
// Save would write Set-Cookie twice, so the browser-store write stays after the commit. Without
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
func (u *UserSessionManager) abandonUserSession(ctx context.Context, userSession *models.UserSession, cause error) error {
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
func (u *UserSessionManager) BumpUserSession(r *http.Request, sessionIdentifier string, clientId int64,
	authMethods string, acrLevel string) (*models.UserSession, error) {

	userSession, err := u.database.GetUserSessionBySessionIdentifier(r.Context(), nil, sessionIdentifier)
	if err != nil {
		return nil, err
	}

	if userSession != nil {

		err = u.database.UserSessionLoadClients(r.Context(), nil, userSession)
		if err != nil {
			return nil, err
		}

		utcNow := time.Now().UTC()
		userSession.LastAccessed = utcNow

		// concatenate any new IP address
		ipWithoutPort, _, _ := net.SplitHostPort(r.RemoteAddr)
		if len(ipWithoutPort) == 0 {
			ipWithoutPort = r.RemoteAddr
		}

		if !strings.Contains(userSession.IpAddress, ipWithoutPort) {
			userSession.IpAddress = fmt.Sprintf("%v,%v", userSession.IpAddress, ipWithoutPort)
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
			userSession.Clients = append(userSession.Clients, models.UserSessionClient{
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

		// The session update and its association write land in one transaction, opened through
		// RunInTransaction so a deadlock reruns the body (#301). userSession was read before the
		// transaction opened and the body only reads it: the insert-versus-update decision comes
		// from client.Id on a copy, so an attempt that inserted leaves the slice as it found it
		// and the rerun decides the same way.
		err = u.database.RunInTransaction(r.Context(), func(tx *sql.Tx) error {
			if updateUserSessionErr := u.database.UpdateUserSession(r.Context(), tx, userSession); updateUserSessionErr != nil {
				return updateUserSessionErr
			}

			for _, client := range userSession.Clients {
				if client.Id > 0 {
					// update
					if updateUserSessionClientErr := u.database.UpdateUserSessionClient(r.Context(), tx, &client); updateUserSessionClientErr != nil {
						return updateUserSessionClientErr
					}
				} else {
					// insert new
					client.UserSessionId = userSession.Id
					if createUserSessionClientErr := u.database.CreateUserSessionClient(r.Context(), tx, &client); createUserSessionClientErr != nil {
						return createUserSessionClientErr
					}
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}

		return userSession, nil
	}

	return nil, errs.New("Unexpected: can't bump user session because user session is nil")
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
func WillRaisePrivilege(userSession *models.UserSession, authMethods, acrLevel string) bool {
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
// Uses models.AcrLevel.IsHigherThan() as the single source of truth for ACR comparison.
func shouldUpgradeAcrLevel(currentAcr, newAcr string) bool {
	currentLevel, err := models.AcrLevelFromString(currentAcr)
	if err != nil {
		return false // Unknown current ACR, fail safe
	}

	newLevel, err := models.AcrLevelFromString(newAcr)
	if err != nil {
		return false // Unknown new ACR, fail safe
	}

	return newLevel.IsHigherThan(currentLevel)
}
