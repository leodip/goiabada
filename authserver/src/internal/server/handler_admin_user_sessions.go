package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/entities"
)

func (s *Server) handleAdminUserSessionsGet() http.HandlerFunc {

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

		idStr := chi.URLParam(r, "userId")
		if len(idStr) == 0 {
			s.internalServerError(w, r, errors.New("userId is required"))
			return
		}

		id, err := strconv.ParseUint(idStr, 10, 64)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		user, err := s.database.GetUserById(uint(id))
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		if user == nil {
			s.internalServerError(w, r, errors.New("user not found"))
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
			"user":      user,
			"sessions":  sessionInfoArr,
			"page":      r.URL.Query().Get("page"),
			"query":     r.URL.Query().Get("query"),
			"csrfField": csrf.TemplateField(r),
		}

		err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_sessions.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAdminUserSessionsPost() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "userId")
		if len(idStr) == 0 {
			s.jsonError(w, r, errors.New("userId is required"))
			return
		}

		id, err := strconv.ParseUint(idStr, 10, 64)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}
		user, err := s.database.GetUserById(uint(id))
		if err != nil {
			s.jsonError(w, r, err)
			return
		}
		if user == nil {
			s.jsonError(w, r, errors.New("user not found"))
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
