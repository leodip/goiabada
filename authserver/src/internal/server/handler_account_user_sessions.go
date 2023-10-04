package server

import (
	"net/http"
	"time"

	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/dtos"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/enums"
)

func (s *Server) handleAccountSessionsGet() http.HandlerFunc {

	type sessionInfo struct {
		UserSessionID uint
		IsCurrent     bool
		StartedAt     string
		LastAcessedAt string
		IpAddress     string
		DeviceName    string
		DeviceType    string
		DeviceOS      string
	}

	return func(w http.ResponseWriter, r *http.Request) {

		settings := r.Context().Value(common.ContextKeySettings).(*entities.Settings)

		requiresAuth := true

		var jwtInfo dtos.JwtInfo
		if r.Context().Value(common.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(common.ContextKeyJwtInfo).(dtos.JwtInfo)
			acrLevel := jwtInfo.GetIdTokenAcrLevel()
			if acrLevel != nil && (*acrLevel == enums.AcrLevel2 || *acrLevel == enums.AcrLevel3) {
				requiresAuth = false
			}
		}

		if requiresAuth {
			s.redirToAuthorize(w, r, "account-management", r.RequestURI)
			return
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

		userSessions, err := s.database.GetUserSessionsByUserID(user.ID)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		sess, err := s.sessionStore.Get(r, common.SessionName)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		sessionIdentifier := ""
		if sess.Values[common.SessionKeySessionIdentifier] != nil {
			sessionIdentifier = sess.Values[common.SessionKeySessionIdentifier].(string)
		}

		sessionInfoArr := []sessionInfo{}
		for _, us := range userSessions {
			if !us.IsValid(settings.UserSessionIdleTimeoutInSeconds, settings.UserSessionMaxLifetimeInSeconds, nil) {
				continue
			}
			usi := sessionInfo{
				UserSessionID: us.ID,
				StartedAt:     us.Started.Format(time.RFC1123),
				LastAcessedAt: us.LastAccessed.Format(time.RFC1123),
				IpAddress:     us.IpAddress,
				DeviceName:    us.DeviceName,
				DeviceType:    us.DeviceType,
				DeviceOS:      us.DeviceOS,
			}

			if us.SessionIdentifier == sessionIdentifier {
				usi.IsCurrent = true
			}
			sessionInfoArr = append(sessionInfoArr, usi)
		}

		bind := map[string]interface{}{
			"sessions":  sessionInfoArr,
			"csrfField": csrf.TemplateField(r),
		}

		err = s.renderTemplate(w, r, "/layouts/account_layout.html", "/account_sessions.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAccountSessionsEndSesssionPost() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		requiresAuth := true

		var jwtInfo dtos.JwtInfo
		if r.Context().Value(common.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(common.ContextKeyJwtInfo).(dtos.JwtInfo)
			acrLevel := jwtInfo.GetIdTokenAcrLevel()
			if acrLevel != nil && (*acrLevel == enums.AcrLevel2 || *acrLevel == enums.AcrLevel3) {
				requiresAuth = false
			}
		}

		if requiresAuth {
			s.redirToAuthorize(w, r, "account-management", r.RequestURI)
			return
		}

	}
}
