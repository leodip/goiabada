package server

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/dtos"
	"github.com/leodip/goiabada/internal/enums"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleAccountProfileGet() http.HandlerFunc {

	timezones := lib.GetTimeZones()
	locales := lib.GetLocales()

	return func(w http.ResponseWriter, r *http.Request) {

		var jwtInfo dtos.JwtInfo
		if r.Context().Value(common.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(common.ContextKeyJwtInfo).(dtos.JwtInfo)
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

		sess, err := s.sessionStore.Get(r, common.SessionName)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		profileSavedSuccessfully := sess.Flashes("profileSavedSuccessfully")
		err = sess.Save(r, w)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		bind := map[string]interface{}{
			"user":                     user,
			"timezones":                timezones,
			"locales":                  locales,
			"profileSavedSuccessfully": len(profileSavedSuccessfully) > 0,
			"csrfField":                csrf.TemplateField(r),
		}

		err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/account_profile.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAccountProfilePost(profileValidator profileValidator, inputSanitizer inputSanitizer) http.HandlerFunc {

	timezones := lib.GetTimeZones()
	locales := lib.GetLocales()

	return func(w http.ResponseWriter, r *http.Request) {

		var jwtInfo dtos.JwtInfo
		if r.Context().Value(common.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(common.ContextKeyJwtInfo).(dtos.JwtInfo)
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

		zoneInfoValue := r.FormValue("zoneInfo")
		zoneInfoCountryName := ""
		zoneInfo := ""

		if zoneInfoValue != "" {
			zoneInfoParts := strings.Split(zoneInfoValue, "___")
			if len(zoneInfoParts) != 2 {
				s.internalServerError(w, r, errors.New("invalid zoneInfo"))
				return
			}
			zoneInfoCountryName = zoneInfoParts[0]
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
			ZoneInfoCountryName: zoneInfoCountryName,
			ZoneInfo:            zoneInfo,
			Locale:              r.FormValue("locale"),
			Subject:             sub,
		}

		err = profileValidator.ValidateProfile(r.Context(), profile)
		if err != nil {
			if valError, ok := err.(*customerrors.ValidationError); ok {
				dtos.AssignProfileToUser(user, profile)

				bind := map[string]interface{}{
					"user":      user,
					"timezones": timezones,
					"locales":   locales,
					"csrfField": csrf.TemplateField(r),
					"error":     valError.Description,
				}

				err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/account_profile.html", bind)
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
		sess.AddFlash("true", "profileSavedSuccessfully")
		err = sess.Save(r, w)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		http.Redirect(w, r, lib.GetBaseUrl()+"/account/profile", http.StatusFound)
	}
}
