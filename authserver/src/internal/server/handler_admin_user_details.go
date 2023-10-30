package server

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleAdminUserDetailsGet() http.HandlerFunc {

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

		sess, err := s.sessionStore.Get(r, common.SessionName)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		userDetailsSavedSuccessfully := sess.Flashes("userDetailsSavedSuccessfully")
		err = sess.Save(r, w)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		bind := map[string]interface{}{
			"user":                         user,
			"page":                         r.URL.Query().Get("page"),
			"query":                        r.URL.Query().Get("query"),
			"userDetailsSavedSuccessfully": len(userDetailsSavedSuccessfully) > 0,
			"csrfField":                    csrf.TemplateField(r),
		}

		err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_details.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAdminUserDetailsPost() http.HandlerFunc {

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

		user.Enabled = r.FormValue("enabled") == "on"
		_, err = s.database.UpdateUser(user)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		sess, err := s.sessionStore.Get(r, common.SessionName)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		sess.AddFlash("true", "userDetailsSavedSuccessfully")
		err = sess.Save(r, w)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("%v/admin/users/%v/details?page=%v&query=%v", lib.GetBaseUrl(), user.Id,
			r.URL.Query().Get("page"), r.URL.Query().Get("query")), http.StatusFound)
	}
}
