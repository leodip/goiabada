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
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/locales"
	"github.com/leodip/goiabada/core/timezones"
	"github.com/leodip/goiabada/core/validators"
)

func HandleAccountProfileGet(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	authHelper handlers.AuthHelper,
	database data.Database,
) http.HandlerFunc {

	timezones := timezones.Get()
	locales := locales.Get()

	return func(w http.ResponseWriter, r *http.Request) {

		loggedInSubject := authHelper.GetLoggedInSubject(r)
		if strings.TrimSpace(loggedInSubject) == "" {
			http.Redirect(w, r, config.Get().BaseURL+"/unauthorized", http.StatusFound)
			return
		}
		user, err := database.GetUserBySubject(nil, loggedInSubject)
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
			err = httpSession.Save(r, w, sess)
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
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {

	timezones := timezones.Get()
	locales := locales.Get()

	return func(w http.ResponseWriter, r *http.Request) {

		loggedInSubject := authHelper.GetLoggedInSubject(r)
		if strings.TrimSpace(loggedInSubject) == "" {
			http.Redirect(w, r, config.Get().BaseURL+"/unauthorized", http.StatusFound)
			return
		}
		user, err := database.GetUserBySubject(nil, loggedInSubject)
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
			Subject:             loggedInSubject,
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

		err = profileValidator.ValidateProfile(input)

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
		err = httpSession.Save(r, w, sess)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		auditLogger.Log(constants.AuditUpdatedUserProfile, map[string]interface{}{
			"userId":       user.Id,
			"loggedInUser": authHelper.GetLoggedInSubject(r),
		})

		http.Redirect(w, r, config.Get().BaseURL+"/account/profile", http.StatusFound)
	}
}
