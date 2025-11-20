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
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
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

func (u *UserSessionManager) StartNewUserSession(w http.ResponseWriter, r *http.Request,
	userId int64, clientId int64, authMethods string, acrLevel string) (*models.UserSession, error) {

	utcNow := time.Now().UTC()

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
	err = u.sessionStore.Save(r, w, sess)
	if err != nil {
		return nil, err
	}

	return userSession, nil
}

func (u *UserSessionManager) BumpUserSession(r *http.Request, sessionIdentifier string, clientId int64) (*models.UserSession, error) {

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
