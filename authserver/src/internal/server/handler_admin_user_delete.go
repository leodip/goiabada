package server

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleAdminUserDeleteGet() http.HandlerFunc {

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

		bind := map[string]interface{}{
			"user":      user,
			"page":      r.URL.Query().Get("page"),
			"query":     r.URL.Query().Get("query"),
			"csrfField": csrf.TemplateField(r),
		}

		err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_delete.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAdminUserDeletePost() http.HandlerFunc {

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

		err = s.database.DeleteUser(user)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		lib.LogAudit(constants.AuditDeletedUser, map[string]interface{}{
			"userId":       user.Id,
			"loggedInUser": s.getLoggedInSubject(r),
		})

		http.Redirect(w, r, fmt.Sprintf("%v/admin/users/?page=%v&query=%v", lib.GetBaseUrl(),
			r.URL.Query().Get("page"), r.URL.Query().Get("query")), http.StatusFound)
	}
}
