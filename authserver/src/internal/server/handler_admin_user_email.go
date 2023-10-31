package server

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/dtos"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleAdminUserEmailGet() http.HandlerFunc {

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

		userEmailSavedSuccessfully := sess.Flashes("userEmailSavedSuccessfully")
		err = sess.Save(r, w)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		bind := map[string]interface{}{
			"user":                       user,
			"page":                       r.URL.Query().Get("page"),
			"query":                      r.URL.Query().Get("query"),
			"userEmailSavedSuccessfully": len(userEmailSavedSuccessfully) > 0,
			"csrfField":                  csrf.TemplateField(r),
		}

		err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_email.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAdminUserEmailPost(emailValidator emailValidator,
	inputSanitizer inputSanitizer) http.HandlerFunc {

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

		email := &dtos.UserEmail{
			Email:             strings.ToLower(strings.TrimSpace(r.FormValue("email"))),
			EmailConfirmation: strings.ToLower(strings.TrimSpace(r.FormValue("email"))),
			EmailVerified:     user.EmailVerified,
			Subject:           user.Subject.String(),
		}
		err = emailValidator.ValidateEmailUpdate(r.Context(), email)
		if err != nil {
			if valError, ok := err.(*customerrors.ValidationError); ok {

				dtos.AssignEmailToUser(user, email)

				bind := map[string]interface{}{
					"user":      user,
					"page":      r.URL.Query().Get("page"),
					"query":     r.URL.Query().Get("query"),
					"csrfField": csrf.TemplateField(r),
					"error":     valError.Description,
				}

				err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_email.html", bind)
				if err != nil {
					s.internalServerError(w, r, err)
					return
				}
				return
			} else {
				s.internalServerError(w, r, err)
				return
			}
		}

		user.Email = inputSanitizer.Sanitize(email.Email)
		user.EmailVerified = r.FormValue("emailVerified") == "on"
		user.EmailVerificationCodeEncrypted = nil
		user.EmailVerificationCodeIssuedAt = nil

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

		sess.AddFlash("true", "userEmailSavedSuccessfully")
		err = sess.Save(r, w)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("%v/admin/users/%v/email?page=%v&query=%v", lib.GetBaseUrl(), user.Id,
			r.URL.Query().Get("page"), r.URL.Query().Get("query")), http.StatusFound)
	}
}
