package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"time"

	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/dtos"
	"github.com/leodip/goiabada/internal/entities"
)

func (s *Server) handleAccountSessionsGet() http.HandlerFunc {

	type sessionInfo struct {
		UserSessionId             uint
		IsCurrent                 bool
		StartedAt                 string
		DurationSinceStarted      string
		LastAcessedAt             string
		DurationSinceLastAccessed string
		IpAddress                 string
		DeviceName                string
		DeviceType                string
		DeviceOS                  string
	}

	return func(w http.ResponseWriter, r *http.Request) {

		settings := r.Context().Value(common.ContextKeySettings).(*entities.Settings)

		var jwtInfo dtos.JwtInfo
		if r.Context().Value(common.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(common.ContextKeyJwtInfo).(dtos.JwtInfo)
		}

		sub, err := jwtInfo.IdTokenClaims.GetSubject()
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		user, err := s.database.GetUserBySubject(sub)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		userSessions, err := s.database.GetUserSessionsByUserId(user.Id)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		sessionIdentifier := ""
		if r.Context().Value(common.ContextKeySessionIdentifier) != nil {
			sessionIdentifier = r.Context().Value(common.ContextKeySessionIdentifier).(string)
		}

		sessionInfoArr := []sessionInfo{}
		for _, us := range userSessions {
			if !us.IsValid(settings.UserSessionIdleTimeoutInSeconds, settings.UserSessionMaxLifetimeInSeconds, nil) {
				continue
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

		err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/account_user_sessions.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAccountSessionsEndSesssionPost() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		var jwtInfo dtos.JwtInfo
		if r.Context().Value(common.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(common.ContextKeyJwtInfo).(dtos.JwtInfo)
		}

		sub, err := jwtInfo.IdTokenClaims.GetSubject()
		if err != nil {
			s.jsonError(w, r, err)
			return
		}
		user, err := s.database.GetUserBySubject(sub)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		var data map[string]interface{}
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&data); err != nil {
			s.jsonError(w, r, err)
			return
		}

		userSessionId, ok := data["userSessionId"].(float64)
		if !ok || userSessionId == 0 {
			s.jsonError(w, r, errors.New("could not find user session id to revoke"))
			return
		}

		allUserSessions, err := s.database.GetUserSessionsByUserId(user.Id)
		if err != nil {
			s.jsonError(w, r, errors.New("could not fetch user sessions from db"))
			return
		}

		for _, us := range allUserSessions {
			if us.Id == uint(userSessionId) {
				err := s.database.DeleteUserSession(us.Id)
				if err != nil {
					s.jsonError(w, r, err)
					return
				}

				result := struct {
					Success bool
				}{
					Success: true,
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(result)
				return
			}
		}
	}
}
