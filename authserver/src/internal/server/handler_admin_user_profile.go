package server

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/common"
	core_validators "github.com/leodip/goiabada/internal/core/validators"
	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/enums"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleAdminUserProfileGet() http.HandlerFunc {

	timezones := lib.GetTimeZones()
	locales := lib.GetLocales()

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

		savedSuccessfully := sess.Flashes("savedSuccessfully")
		err = sess.Save(r, w)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		bind := map[string]interface{}{
			"user":              user,
			"timezones":         timezones,
			"locales":           locales,
			"page":              r.URL.Query().Get("page"),
			"query":             r.URL.Query().Get("query"),
			"savedSuccessfully": len(savedSuccessfully) > 0,
			"csrfField":         csrf.TemplateField(r),
		}

		err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_profile.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAdminUserProfilePost(profileValidator profileValidator,
	inputSanitizer inputSanitizer) http.HandlerFunc {

	timezones := lib.GetTimeZones()
	locales := lib.GetLocales()

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

		zoneInfoValue := r.FormValue("zoneInfo")
		zoneInfoCountry := ""
		zoneInfo := ""

		if zoneInfoValue != "" {
			zoneInfoParts := strings.Split(zoneInfoValue, "___")
			if len(zoneInfoParts) != 2 {
				s.internalServerError(w, r, errors.New("invalid zoneInfo"))
				return
			}
			zoneInfoCountry = zoneInfoParts[0]
			zoneInfo = zoneInfoParts[1]
		}

		input := &core_validators.ValidateProfileInput{
			Username:            strings.TrimSpace(r.FormValue("username")),
			GivenName:           strings.TrimSpace(r.FormValue("givenName")),
			MiddleName:          strings.TrimSpace(r.FormValue("middleName")),
			FamilyName:          strings.TrimSpace(r.FormValue("familyName")),
			Nickname:            strings.TrimSpace(r.FormValue("nickname")),
			Website:             strings.TrimSpace(r.FormValue("website")),
			Gender:              r.FormValue("gender"),
			DateOfBirth:         strings.TrimSpace(r.FormValue("dateOfBirth")),
			ZoneInfoCountryName: zoneInfoCountry,
			ZoneInfo:            zoneInfo,
			Locale:              r.FormValue("locale"),
			Subject:             user.Subject.String(),
		}

		user.Username = input.Username
		user.GivenName = input.GivenName
		user.MiddleName = input.MiddleName
		user.FamilyName = input.FamilyName
		user.Nickname = input.Nickname
		user.Website = input.Website
		if len(input.Gender) > 0 {
			i, err := strconv.Atoi(input.Gender)
			if err == nil {
				user.Gender = enums.Gender(i).String()
			}
		} else {
			user.Gender = ""
		}

		if len(input.DateOfBirth) > 0 {
			layout := "2006-01-02"
			parsedTime, err := time.Parse(layout, input.DateOfBirth)
			if err == nil {
				user.BirthDate = &parsedTime
			}
		} else {
			user.BirthDate = nil
		}

		user.ZoneInfoCountryName = input.ZoneInfoCountryName
		user.ZoneInfo = input.ZoneInfo
		user.Locale = input.Locale

		err = profileValidator.ValidateProfile(r.Context(), input)

		if err != nil {
			if valError, ok := err.(*customerrors.ValidationError); ok {

				bind := map[string]interface{}{
					"user":      user,
					"timezones": timezones,
					"locales":   locales,
					"page":      r.URL.Query().Get("page"),
					"query":     r.URL.Query().Get("query"),
					"csrfField": csrf.TemplateField(r),
					"error":     valError.Description,
				}

				err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_profile.html", bind)
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

		user.Username = inputSanitizer.Sanitize(user.Username)
		user.GivenName = inputSanitizer.Sanitize(user.GivenName)
		user.MiddleName = inputSanitizer.Sanitize(user.MiddleName)
		user.FamilyName = inputSanitizer.Sanitize(user.FamilyName)
		user.Nickname = inputSanitizer.Sanitize(user.Nickname)

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

		sess.AddFlash("true", "savedSuccessfully")
		err = sess.Save(r, w)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("%v/admin/users/%v/profile?page=%v&query=%v", lib.GetBaseUrl(), user.Id,
			r.URL.Query().Get("page"), r.URL.Query().Get("query")), http.StatusFound)
	}
}
