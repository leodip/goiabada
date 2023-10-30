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
	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/dtos"
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

		userProfileSavedSuccessfully := sess.Flashes("userProfileSavedSuccessfully")
		err = sess.Save(r, w)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		bind := map[string]interface{}{
			"user":                         user,
			"timezones":                    timezones,
			"locales":                      locales,
			"page":                         r.URL.Query().Get("page"),
			"query":                        r.URL.Query().Get("query"),
			"userProfileSavedSuccessfully": len(userProfileSavedSuccessfully) > 0,
			"csrfField":                    csrf.TemplateField(r),
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

		profile := &dtos.UserProfile{
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

		err = profileValidator.ValidateProfile(r.Context(), profile)
		if err != nil {
			if valError, ok := err.(*customerrors.ValidationError); ok {

				dtos.AssignProfileToUser(user, profile)

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

		user.Username = strings.TrimSpace(inputSanitizer.Sanitize(profile.Username))
		user.GivenName = strings.TrimSpace(inputSanitizer.Sanitize(profile.GivenName))
		user.MiddleName = strings.TrimSpace(inputSanitizer.Sanitize(profile.MiddleName))
		user.FamilyName = strings.TrimSpace(inputSanitizer.Sanitize(profile.FamilyName))
		user.Nickname = strings.TrimSpace(inputSanitizer.Sanitize(profile.Nickname))
		user.Website = profile.Website

		if len(profile.Gender) > 0 {
			i, _ := strconv.Atoi(profile.Gender)
			user.Gender = enums.Gender(i).String()
		} else {
			user.Gender = ""
		}

		if len(profile.DateOfBirth) > 0 {
			layout := "2006-01-02"
			parsedTime, _ := time.Parse(layout, profile.DateOfBirth)
			user.BirthDate = &parsedTime
		} else {
			user.BirthDate = nil
		}

		user.ZoneInfoCountryName = profile.ZoneInfoCountryName
		user.ZoneInfo = profile.ZoneInfo
		user.Locale = profile.Locale

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

		sess.AddFlash("true", "userProfileSavedSuccessfully")
		err = sess.Save(r, w)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("%v/admin/users/%v/profile?page=%v&query=%v", lib.GetBaseUrl(), user.Id,
			r.URL.Query().Get("page"), r.URL.Query().Get("query")), http.StatusFound)
	}
}
