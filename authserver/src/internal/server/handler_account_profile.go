package server

import (
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

		if !s.isAuthorizedToAccessAccountPages(jwtInfo) {
			s.redirToAuthorize(w, r, "account-management", lib.GetBaseUrl()+r.RequestURI)
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

		accountProfile := dtos.AccountProfileFromUser(user)

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
			"profileSavedSuccessfully": len(profileSavedSuccessfully) > 0,
			"accountProfile":           accountProfile,
			"timezones":                timezones,
			"locales":                  locales,
			"csrfField":                csrf.TemplateField(r),
		}

		err = s.renderTemplate(w, r, "/layouts/account_layout.html", "/account_profile.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAccountProfilePost(profileValidator profileValidator) http.HandlerFunc {

	timezones := lib.GetTimeZones()
	locales := lib.GetLocales()

	return func(w http.ResponseWriter, r *http.Request) {

		var jwtInfo dtos.JwtInfo
		if r.Context().Value(common.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(common.ContextKeyJwtInfo).(dtos.JwtInfo)
		}

		if !s.isAuthorizedToAccessAccountPages(jwtInfo) {
			s.redirToAuthorize(w, r, "account-management", lib.GetBaseUrl()+r.RequestURI)
			return
		}

		sub, err := jwtInfo.IdTokenClaims.GetSubject()
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		accountProfile := &dtos.AccountProfile{
			Username:    strings.TrimSpace(r.FormValue("username")),
			GivenName:   strings.TrimSpace(r.FormValue("givenName")),
			MiddleName:  strings.TrimSpace(r.FormValue("middleName")),
			FamilyName:  strings.TrimSpace(r.FormValue("familyName")),
			Nickname:    strings.TrimSpace(r.FormValue("nickname")),
			Website:     strings.TrimSpace(r.FormValue("website")),
			Gender:      r.FormValue("gender"),
			DateOfBirth: strings.TrimSpace(r.FormValue("dateOfBirth")),
			ZoneInfo:    r.FormValue("zoneInfo"),
			Locale:      r.FormValue("locale"),
			Subject:     sub,
		}

		err = profileValidator.ValidateProfile(r.Context(), accountProfile)
		if err != nil {
			if valError, ok := err.(*customerrors.ValidationError); ok {
				bind := map[string]interface{}{
					"accountProfile": accountProfile,
					"timezones":      timezones,
					"locales":        locales,
					"csrfField":      csrf.TemplateField(r),
					"error":          valError.Description,
				}

				err = s.renderTemplate(w, r, "/layouts/account_layout.html", "/account_profile.html", bind)
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

		user, err := s.database.GetUserBySubject(sub)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		user.Username = accountProfile.Username
		user.GivenName = accountProfile.GivenName
		user.MiddleName = accountProfile.MiddleName
		user.FamilyName = accountProfile.FamilyName
		user.Nickname = accountProfile.Nickname
		user.Website = accountProfile.Website

		if len(accountProfile.Gender) > 0 {
			i, _ := strconv.Atoi(accountProfile.Gender)
			user.Gender = enums.Gender(i).String()
		} else {
			user.Gender = ""
		}

		if len(accountProfile.DateOfBirth) > 0 {
			layout := "2006-01-02"
			parsedTime, _ := time.Parse(layout, accountProfile.DateOfBirth)
			user.BirthDate = &parsedTime
		} else {
			user.BirthDate = nil
		}

		user.ZoneInfo = accountProfile.ZoneInfo
		user.Locale = accountProfile.Locale

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
