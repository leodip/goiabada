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
	core_validators "github.com/leodip/goiabada/internal/core/validators"
	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleAdminUserPhoneGet() http.HandlerFunc {

	phoneCountries := lib.GetPhoneCountries()

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

		phoneNumberCountry := ""
		phoneNumber := ""

		if len(user.PhoneNumber) > 0 {
			parts := strings.SplitN(user.PhoneNumber, " ", 2)
			if len(parts) == 2 {
				phoneNumberCountry = parts[0]
				phoneNumber = parts[1]
			}
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
			"user":                user,
			"phoneCountries":      phoneCountries,
			"phoneNumberCountry":  phoneNumberCountry,
			"phoneNumber":         phoneNumber,
			"phoneNumberVerified": user.PhoneNumberVerified,
			"page":                r.URL.Query().Get("page"),
			"query":               r.URL.Query().Get("query"),
			"savedSuccessfully":   len(savedSuccessfully) > 0,
			"csrfField":           csrf.TemplateField(r),
		}

		err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_phone.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAdminUserPhonePost(phoneValidator phoneValidator,
	inputSanitizer inputSanitizer) http.HandlerFunc {

	phoneCountries := lib.GetPhoneCountries()

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

		input := &core_validators.ValidatePhoneInput{
			PhoneNumberCountry: r.FormValue("phoneCountry"),
			PhoneNumber:        strings.TrimSpace(r.FormValue("phoneNumber")),
		}

		err = phoneValidator.ValidatePhone(r.Context(), input)
		if err != nil {
			if valError, ok := err.(*customerrors.ValidationError); ok {
				bind := map[string]interface{}{
					"phoneNumberCountry":  input.PhoneNumberCountry,
					"phoneNumber":         input.PhoneNumber,
					"phoneNumberVerified": r.FormValue("phoneNumberVerified") == "on",
					"phoneCountries":      phoneCountries,
					"page":                r.URL.Query().Get("page"),
					"query":               r.URL.Query().Get("query"),
					"csrfField":           csrf.TemplateField(r),
					"error":               valError.Description,
				}

				err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_phone.html", bind)
				if err != nil {
					s.internalServerError(w, r, err)
				}
				return
			} else {
				s.internalServerError(w, r, err)
				return
			}
		}

		user.PhoneNumber = fmt.Sprintf("%v %v", input.PhoneNumberCountry, input.PhoneNumber)
		user.PhoneNumberVerified = r.FormValue("phoneNumberVerified") == "on"

		if len(strings.TrimSpace(user.PhoneNumber)) == 0 {
			user.PhoneNumberVerified = false
		}

		_, err = s.database.SaveUser(user)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		sess, err := s.sessionStore.Get(r, common.SessionName)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		sess.AddFlash("true", "savedSuccessfully")
		err = sess.Save(r, w)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("%v/admin/users/%v/phone?page=%v&query=%v", lib.GetBaseUrl(), user.Id,
			r.URL.Query().Get("page"), r.URL.Query().Get("query")), http.StatusFound)
	}
}
