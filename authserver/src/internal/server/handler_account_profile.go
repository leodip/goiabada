package server

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/constants"
	core_validators "github.com/leodip/goiabada/internal/core/validators"
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

		sub, err := jwtInfo.IdToken.Claims.GetSubject()
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
			"timezones":         timezones,
			"locales":           locales,
			"savedSuccessfully": len(savedSuccessfully) > 0,
			"csrfField":         csrf.TemplateField(r),
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

		sub, err := jwtInfo.IdToken.Claims.GetSubject()
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

		input := &core_validators.ValidateProfileInput{
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

		user.Username = inputSanitizer.Sanitize(user.Username)
		user.GivenName = inputSanitizer.Sanitize(user.GivenName)
		user.MiddleName = inputSanitizer.Sanitize(user.MiddleName)
		user.FamilyName = inputSanitizer.Sanitize(user.FamilyName)
		user.Nickname = inputSanitizer.Sanitize(user.Nickname)

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

		lib.LogAudit(constants.AuditUpdatedUserProfile, map[string]interface{}{
			"userId":       user.Id,
			"loggedInUser": s.getLoggedInSubject(r),
		})

		http.Redirect(w, r, lib.GetBaseUrl()+"/account/profile", http.StatusFound)
	}
}
