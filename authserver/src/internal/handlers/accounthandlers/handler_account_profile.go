package accounthandlers

import (
	"database/sql"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/data"
	"github.com/leodip/goiabada/internal/enums"
	"github.com/leodip/goiabada/internal/handlers"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/leodip/goiabada/internal/security"
	"github.com/leodip/goiabada/internal/validators"
)

func HandleAccountProfileGet(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	database data.Database,
) http.HandlerFunc {

	timezones := lib.GetTimeZones()
	locales := lib.GetLocales()

	return func(w http.ResponseWriter, r *http.Request) {

		var jwtInfo security.JwtInfo
		if r.Context().Value(constants.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(constants.ContextKeyJwtInfo).(security.JwtInfo)
		}

		sub, err := jwtInfo.IdToken.Claims.GetSubject()
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		user, err := database.GetUserBySubject(nil, sub)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		sess, err := httpSession.Get(r, constants.SessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		savedSuccessfully := sess.Flashes("savedSuccessfully")
		if savedSuccessfully != nil {
			err = sess.Save(r, w)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
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

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_profile.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAccountProfilePost(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	authHelper handlers.AuthHelper,
	database data.Database,
	profileValidator handlers.ProfileValidator,
	inputSanitizer handlers.InputSanitizer,
) http.HandlerFunc {

	timezones := lib.GetTimeZones()
	locales := lib.GetLocales()

	return func(w http.ResponseWriter, r *http.Request) {

		var jwtInfo security.JwtInfo
		if r.Context().Value(constants.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(constants.ContextKeyJwtInfo).(security.JwtInfo)
		}

		sub, err := jwtInfo.IdToken.Claims.GetSubject()
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		user, err := database.GetUserBySubject(nil, sub)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		zoneInfoValue := r.FormValue("zoneInfo")
		zoneInfoCountryName := ""
		zoneInfo := ""

		if zoneInfoValue != "" {
			zoneInfoParts := strings.Split(zoneInfoValue, "___")
			if len(zoneInfoParts) != 2 {
				httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("invalid zoneInfo")))
				return
			}
			zoneInfoCountryName = zoneInfoParts[0]
			zoneInfo = zoneInfoParts[1]
		}

		input := &validators.ValidateProfileInput{
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
			if err == nil && enums.IsGenderValid(i) {
				user.Gender = enums.Gender(i).String()
			}
		} else {
			user.Gender = ""
		}

		if len(input.DateOfBirth) > 0 {
			layout := "2006-01-02"
			parsedTime, err := time.Parse(layout, input.DateOfBirth)
			if err == nil {
				user.BirthDate = sql.NullTime{Time: parsedTime, Valid: true}
			}
		} else {
			user.BirthDate = sql.NullTime{Valid: false}
		}

		user.ZoneInfoCountryName = input.ZoneInfoCountryName
		user.ZoneInfo = input.ZoneInfo
		user.Locale = input.Locale

		err = profileValidator.ValidateProfile(r.Context(), input)

		if err != nil {
			if valError, ok := err.(*customerrors.ErrorDetail); ok {

				bind := map[string]interface{}{
					"user":      user,
					"timezones": timezones,
					"locales":   locales,
					"csrfField": csrf.TemplateField(r),
					"error":     valError.GetDescription(),
				}

				err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_profile.html", bind)
				if err != nil {
					httpHelper.InternalServerError(w, r, err)
					return
				}
				return
			} else {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		user.Username = inputSanitizer.Sanitize(user.Username)
		user.GivenName = inputSanitizer.Sanitize(user.GivenName)
		user.MiddleName = inputSanitizer.Sanitize(user.MiddleName)
		user.FamilyName = inputSanitizer.Sanitize(user.FamilyName)
		user.Nickname = inputSanitizer.Sanitize(user.Nickname)

		err = database.UpdateUser(nil, user)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		sess, err := httpSession.Get(r, constants.SessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		sess.AddFlash("true", "savedSuccessfully")
		err = sess.Save(r, w)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		lib.LogAudit(constants.AuditUpdatedUserProfile, map[string]interface{}{
			"userId":       user.Id,
			"loggedInUser": authHelper.GetLoggedInSubject(r),
		})

		http.Redirect(w, r, lib.GetBaseUrl()+"/account/profile", http.StatusFound)
	}
}