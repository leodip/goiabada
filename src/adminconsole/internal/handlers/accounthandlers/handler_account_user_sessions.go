package accounthandlers

import (
	"encoding/json"
	"net/http"
	"sort"
	"time"

	"github.com/pkg/errors"

	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
)

func HandleAccountSessionsGet(
	httpHelper handlers.HttpHelper,
	database data.Database,
) http.HandlerFunc {

	type sessionInfo struct {
		UserSessionId             int64
		IsCurrent                 bool
		StartedAt                 string
		DurationSinceStarted      string
		LastAcessedAt             string
		DurationSinceLastAccessed string
		IpAddress                 string
		DeviceName                string
		DeviceType                string
		DeviceOS                  string
		Clients                   []string
	}

	return func(w http.ResponseWriter, r *http.Request) {

		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)

		var jwtInfo oauth.JwtInfo
		if r.Context().Value(constants.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		}

		sub, err := jwtInfo.IdToken.Claims.GetSubject()
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		user, err := database.GetUserBySubject(nil, sub)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		userSessions, err := database.GetUserSessionsByUserId(nil, user.Id)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		err = database.UserSessionsLoadClients(nil, userSessions)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		sessionIdentifier := ""
		if r.Context().Value(constants.ContextKeySessionIdentifier) != nil {
			sessionIdentifier = r.Context().Value(constants.ContextKeySessionIdentifier).(string)
		}

		sessionInfoArr := []sessionInfo{}
		for _, us := range userSessions {
			if !us.IsValid(settings.UserSessionIdleTimeoutInSeconds, settings.UserSessionMaxLifetimeInSeconds, nil) {
				continue
			}

			err = database.UserSessionClientsLoadClients(nil, us.Clients)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			usi := sessionInfo{
				UserSessionId:             us.Id,
				StartedAt:                 us.Started.Format(time.RFC1123),
				DurationSinceStarted:      time.Now().UTC().Sub(us.Started).Round(time.Second).String(),
				LastAcessedAt:             us.LastAccessed.Format(time.RFC1123),
				DurationSinceLastAccessed: time.Now().UTC().Sub(us.LastAccessed).Round(time.Second).String(),
				IpAddress:                 us.IpAddress,
				DeviceName:                us.DeviceName,
				DeviceType:                us.DeviceType,
				DeviceOS:                  us.DeviceOS,
			}

			for _, usc := range us.Clients {
				usi.Clients = append(usi.Clients, usc.Client.ClientIdentifier)
			}

			if us.SessionIdentifier == sessionIdentifier {
				usi.IsCurrent = true
			}
			sessionInfoArr = append(sessionInfoArr, usi)
		}

		sort.Slice(sessionInfoArr, func(i, j int) bool {
			return sessionInfoArr[i].UserSessionId > sessionInfoArr[j].UserSessionId
		})

		bind := map[string]interface{}{
			"sessions":  sessionInfoArr,
			"csrfField": csrf.TemplateField(r),
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_user_sessions.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAccountSessionsEndSesssionPost(
	httpHelper handlers.HttpHelper,
	authHelper handlers.AuthHelper,
	database data.Database,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		var jwtInfo oauth.JwtInfo
		if r.Context().Value(constants.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		}

		sub, err := jwtInfo.IdToken.Claims.GetSubject()
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}
		user, err := database.GetUserBySubject(nil, sub)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		var data map[string]interface{}
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&data); err != nil {
			httpHelper.JsonError(w, r, errors.Wrap(err, "could not decode request body"))
			return
		}

		userSessionId, ok := data["userSessionId"].(float64)
		if !ok || userSessionId == 0 {
			httpHelper.JsonError(w, r, errors.WithStack(errors.New("could not find user session id to revoke")))
			return
		}

		allUserSessions, err := database.GetUserSessionsByUserId(nil, user.Id)
		if err != nil {
			httpHelper.JsonError(w, r, errors.WithStack(errors.New("could not fetch user sessions from db")))
			return
		}

		for _, us := range allUserSessions {
			if us.Id == int64(userSessionId) {
				err := database.DeleteUserSession(nil, us.Id)
				if err != nil {
					httpHelper.JsonError(w, r, err)
					return
				}

				auditLogger.Log(constants.AuditDeletedUserSession, map[string]interface{}{
					"userSessionId": us.Id,
					"loggedInUser":  authHelper.GetLoggedInSubject(r),
				})

				result := struct {
					Success bool
				}{
					Success: true,
				}
				httpHelper.EncodeJson(w, r, result)
				return
			}
		}
	}
}
