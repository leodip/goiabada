package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/dtos"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleAccountManageConsentsGet() http.HandlerFunc {

	type consentInfo struct {
		ConsentId         uint
		Client            string
		ClientDescription string
		GrantedAt         string
		Scope             string
	}

	return func(w http.ResponseWriter, r *http.Request) {

		var jwtInfo dtos.JwtInfo
		if r.Context().Value(common.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(common.ContextKeyJwtInfo).(dtos.JwtInfo)
		}

		if !s.isAuthorizedToAccessResource(jwtInfo, []string{"authserver:account"}) {
			s.redirToAuthorize(w, r, "system-website", lib.GetBaseUrl()+r.RequestURI)
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

		userConsents, err := s.database.GetUserConsents(user.ID)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		consentInfoArr := []consentInfo{}
		for _, c := range userConsents {
			ci := consentInfo{
				ConsentId:         c.ID,
				Client:            c.Client.ClientIdentifier,
				ClientDescription: c.Client.Description,
				GrantedAt:         c.UpdatedAt.Format(time.RFC1123),
				Scope:             c.Scope,
			}
			consentInfoArr = append(consentInfoArr, ci)
		}

		bind := map[string]interface{}{
			"consents":  consentInfoArr,
			"csrfField": csrf.TemplateField(r),
		}

		err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/account_manage_consents.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAccountManageConsentsRevokePost() http.HandlerFunc {

	type revokeConsentResult struct {
		RequiresAuth        bool
		RevokedSuccessfully bool
	}

	return func(w http.ResponseWriter, r *http.Request) {

		result := revokeConsentResult{
			RequiresAuth: true,
		}

		var jwtInfo dtos.JwtInfo
		if r.Context().Value(common.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(common.ContextKeyJwtInfo).(dtos.JwtInfo)
		}

		if s.isAuthorizedToAccessResource(jwtInfo, []string{"authserver:account"}) {
			result.RequiresAuth = false
		} else {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(result)
			return
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

		consentId, ok := data["consentId"].(float64)
		if !ok || consentId == 0 {
			s.jsonError(w, r, errors.New("could not find consent id to revoke"))
			return
		}

		userConsents, err := s.database.GetUserConsents(user.ID)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		found := false
		for _, c := range userConsents {
			if c.ID == uint(consentId) {
				found = true
				break
			}
		}

		if !found {
			s.jsonError(w, r, fmt.Errorf("unable to revoke consent with id %v because it doesn't belong to user id %v", consentId, user.ID))
			return
		} else {

			err := s.database.DeleteUserConsent(uint(consentId))
			if err != nil {
				s.jsonError(w, r, err)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(revokeConsentResult{
				RevokedSuccessfully: true,
			})
			return
		}
	}
}
