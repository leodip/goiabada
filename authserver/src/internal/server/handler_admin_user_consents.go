package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/common"
)

func (s *Server) handleAdminUserConsentsGet() http.HandlerFunc {

	type consentInfo struct {
		ConsentId         uint
		Client            string
		ClientDescription string
		GrantedAt         string
		Scope             string
	}

	return func(w http.ResponseWriter, r *http.Request) {

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

		userConsents, err := s.database.GetConsentsByUserId(user.Id)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		consentInfoArr := []consentInfo{}
		for _, c := range userConsents {
			ci := consentInfo{
				ConsentId:         c.Id,
				Client:            c.Client.ClientIdentifier,
				ClientDescription: c.Client.Description,
				GrantedAt:         c.GrantedAt.Format(time.RFC1123),
				Scope:             c.Scope,
			}
			consentInfoArr = append(consentInfoArr, ci)
		}

		sess, err := s.sessionStore.Get(r, common.SessionName)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		savedSuccessfully := sess.Flashes("savedSuccessfully")
		if savedSuccessfully != nil {
			err = sess.Save(r, w)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}
		}

		bind := map[string]interface{}{
			"user":              user,
			"consents":          consentInfoArr,
			"page":              r.URL.Query().Get("page"),
			"query":             r.URL.Query().Get("query"),
			"savedSuccessfully": len(savedSuccessfully) > 0,
			"csrfField":         csrf.TemplateField(r),
		}

		err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_consents.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAdminUserConsentsPost() http.HandlerFunc {

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

		consentId, ok := data["consentId"].(float64)
		if !ok || consentId == 0 {
			s.jsonError(w, r, errors.New("could not find consent id to revoke"))
			return
		}

		userConsents, err := s.database.GetConsentsByUserId(user.Id)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		found := false
		for _, c := range userConsents {
			if c.Id == uint(consentId) {
				found = true
				break
			}
		}

		if !found {
			s.jsonError(w, r, fmt.Errorf("unable to revoke consent with id %v because it doesn't belong to user id %v", consentId, user.Id))
			return
		} else {

			err := s.database.DeleteUserConsent(uint(consentId))
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
