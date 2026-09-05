package user

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/leodip/goiabada/core/useragent"
	"github.com/pkg/errors"
)

type UserSessionManager struct {
	codeIssuer   *oauth.CodeIssuer
	sessionStore sessions.Store
	sessionName  string
	database     data.Database
}

func NewUserSessionManager(codeIssuer *oauth.CodeIssuer, sessionStore sessions.Store, sessionName string, database data.Database) *UserSessionManager {
	return &UserSessionManager{
		codeIssuer:   codeIssuer,
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
func (u *UserSessionManager) StartNewUserSession(w http.ResponseWriter, r *http.Request,
	userId int64, clientId int64, authMethods string, acrLevel string,
	authStateGeneration int64, otpConfigGeneration *int64) (*models.UserSession, error) {

	utcNow := time.Now().UTC()

	observedOtpConfigGeneration := int64(0)
	if otpConfigGeneration != nil {
		observedOtpConfigGeneration = *otpConfigGeneration
	}

	ipWithoutPort, _, _ := net.SplitHostPort(r.RemoteAddr)
	if len(ipWithoutPort) == 0 {
		ipWithoutPort = r.RemoteAddr
	}

	userSession := &models.UserSession{
		SessionIdentifier: uuid.New().String(),
		Started:           utcNow,
		LastAccessed:      utcNow,
		IpAddress:         ipWithoutPort,
		AuthMethods:       authMethods,
		AcrLevel:          acrLevel,
		AuthTime:          utcNow,
		UserId:            userId,
		DeviceName:        useragent.GetDeviceName(r),
		DeviceType:        useragent.GetDeviceType(r),
		DeviceOS:          useragent.GetDeviceOS(r),

		AuthStateGeneration: authStateGeneration,
		OtpConfigGeneration: observedOtpConfigGeneration,
	}

	userSession.Clients = append(userSession.Clients, models.UserSessionClient{
		Started:      utcNow,
		LastAccessed: utcNow,
		ClientId:     clientId,
	})

	tx, err := u.database.BeginTransaction()
	if err != nil {
		return nil, err
	}
	defer u.database.RollbackTransaction(tx) //nolint:errcheck

	// THE USER'S ROW FIRST, and it is not optional here even though nothing below names it.
	// CreateUserSession's insert takes a shared lock on the parent users row through
	// user_sessions.user_id without naming it, and the shared client acquisition on the next line
	// must be taken by a transaction that ALREADY holds everything above clients. Lock queues are
	// fair, so a shared holder that afterwards reaches upward can close a cycle with a queued
	// exclusive request without upgrading anything: measured on MySQL as this transaction holding
	// the client shared and waiting for the users row, an issuance holding the users row and
	// waiting for the client, and a client deletion queued exclusively behind both (#139).
	if err := u.database.AcquireUserRow(tx, userId); err != nil {
		return nil, err
	}

	// The client's row, shared. commondb.DeleteClient takes it exclusively and then reads the
	// sessions associated with the client so it can take their rows too, and that list is complete
	// only because every transaction that writes an association row takes this lock first. This is
	// one of the three that do (#139).
	if err := u.database.AcquireClientRowShared(tx, clientId); err != nil {
		return nil, err
	}

	err = u.database.CreateUserSession(tx, userSession)
	if err != nil {
		return nil, err
	}

	for _, client := range userSession.Clients {
		client.UserSessionId = userSession.Id
		err = u.database.CreateUserSessionClient(tx, &client)
		if err != nil {
			return nil, err
		}
	}

	err = u.database.CommitTransaction(tx)
	if err != nil {
		return nil, err
	}

	allUserSessions, err := u.database.GetUserSessionsByUserId(nil, userId)
	if err != nil {
		return nil, err
	}

	// delete other sessions from this same device & ip
	for _, us := range allUserSessions {
		if us.SessionIdentifier != userSession.SessionIdentifier &&
			us.DeviceName == userSession.DeviceName &&
			us.DeviceType == userSession.DeviceType &&
			us.DeviceOS == userSession.DeviceOS &&
			us.IpAddress == ipWithoutPort {
			err = u.database.DeleteUserSession(nil, us.Id)
			if err != nil {
				return nil, err
			}
		}
	}

	sess, err := u.sessionStore.Get(r, u.sessionName)
	if err != nil {
		return nil, errors.Wrap(err, "unable to get the session")
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
		if err := regenerator.Regenerate(w, r, sess); err != nil {
			return nil, errors.Wrap(err, "unable to rotate the browser session identifier")
		}
		return userSession, nil
	}

	err = u.sessionStore.Save(r, w, sess)
	if err != nil {
		return nil, err
	}

	return userSession, nil
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

	userSession, err := u.database.GetUserSessionBySessionIdentifier(nil, sessionIdentifier)
	if err != nil {
		return nil, err
	}

	if userSession != nil {

		err = u.database.UserSessionLoadClients(nil, userSession)
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

		tx, err := u.database.BeginTransaction()
		if err != nil {
			return nil, err
		}
		defer u.database.RollbackTransaction(tx) //nolint:errcheck

		// The client's row, shared, above the session row this transaction is about to write.
		// commondb.DeleteClient takes it exclusively and then reads the sessions associated with
		// the client, and that list is closed by this lock rather than by a re-read (#139).
		//
		// Taken UNCONDITIONALLY rather than only when the association below is an insert. The
		// insert-versus-update decision is made from userSession.Clients, which was read before
		// this transaction opened and can be stale, so a bump that believes it is only updating
		// can still be the one that inserts.
		//
		// No AcquireUserRow above it, and the absence is deliberate rather than an omission: this
		// transaction takes no lock on the users row at all. UpdateUserSession is a full-row
		// update, but UserSession.UserId is dont-update, so its foreign key is not in the SET list
		// and SQL Server has nothing to re-check.
		if err := u.database.AcquireClientRowShared(tx, clientId); err != nil {
			return nil, err
		}

		err = u.database.UpdateUserSession(tx, userSession)
		if err != nil {
			return nil, err
		}

		for _, client := range userSession.Clients {
			if client.Id > 0 {
				// update
				err = u.database.UpdateUserSessionClient(tx, &client)
				if err != nil {
					return nil, err
				}
			} else {
				// insert new
				client.UserSessionId = userSession.Id
				err = u.database.CreateUserSessionClient(tx, &client)
				if err != nil {
					return nil, err
				}
			}
		}

		err = u.database.CommitTransaction(tx)
		if err != nil {
			return nil, err
		}

		return userSession, nil
	}

	return nil, errors.WithStack(errors.New("Unexpected: can't bump user session because user session is nil"))
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
// Uses enums.AcrLevel.IsHigherThan() as the single source of truth for ACR comparison.
func shouldUpgradeAcrLevel(currentAcr, newAcr string) bool {
	currentLevel, err := enums.AcrLevelFromString(currentAcr)
	if err != nil {
		return false // Unknown current ACR, fail safe
	}

	newLevel, err := enums.AcrLevelFromString(newAcr)
	if err != nil {
		return false // Unknown new ACR, fail safe
	}

	return newLevel.IsHigherThan(currentLevel)
}
