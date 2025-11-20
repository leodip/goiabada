package adminuserhandlers

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/locales"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/timezones"
)

func HandleAdminUserProfileGet(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	apiClient apiclient.ApiClient,
) http.HandlerFunc {

	timezones := timezones.Get()
	locales := locales.Get()

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "userId")
		if len(idStr) == 0 {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("userId is required")))
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		// Get JWT info from context to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
			return
		}

		user, err := apiClient.GetUserById(jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if user == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("user not found")))
			return
		}

		sess, err := httpSession.Get(r, constants.AdminConsoleSessionName)
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
			"page":              r.URL.Query().Get("page"),
			"query":             r.URL.Query().Get("query"),
			"savedSuccessfully": len(savedSuccessfully) > 0,
			"csrfField":         csrf.TemplateField(r),
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_profile.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminUserProfilePost(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	apiClient apiclient.ApiClient,
) http.HandlerFunc {

	timezones := timezones.Get()
	locales := locales.Get()

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "userId")
		if len(idStr) == 0 {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("userId is required")))
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		// Get JWT info from context to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
			return
		}

		// Parse zoneInfo form value
		zoneInfoValue := r.FormValue("zoneInfo")
		zoneInfoCountry := ""
		zoneInfo := ""

		if zoneInfoValue != "" {
			zoneInfoParts := strings.Split(zoneInfoValue, "___")
			if len(zoneInfoParts) != 2 {
				httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("invalid zoneInfo")))
				return
			}
			zoneInfoCountry = zoneInfoParts[0]
			zoneInfo = zoneInfoParts[1]
		}

		// Create update request
		request := &api.UpdateUserProfileRequest{
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
		}

		// Call the profile update API
		user, err := apiClient.UpdateUserProfile(jwtInfo.TokenResponse.AccessToken, id, request)
		if err != nil {
			// Handle validation errors by showing them in the form
			handlers.HandleAPIErrorWithCallback(httpHelper, w, r, err, func(errorMessage string) {
				// Get user data for form display
				user, userErr := apiClient.GetUserById(jwtInfo.TokenResponse.AccessToken, id)
				if userErr != nil {
					httpHelper.InternalServerError(w, r, userErr)
					return
				}

				// Update user fields with form values for display
				user.Username = request.Username
				user.GivenName = request.GivenName
				user.MiddleName = request.MiddleName
				user.FamilyName = request.FamilyName
				user.Nickname = request.Nickname
				user.Website = request.Website
				user.ZoneInfoCountryName = request.ZoneInfoCountryName
				user.ZoneInfo = request.ZoneInfo
				user.Locale = request.Locale

				// Handle gender display
				if len(request.Gender) > 0 {
					i, err := strconv.Atoi(request.Gender)
					if err == nil {
						user.Gender = enums.Gender(i).String()
					}
				} else {
					user.Gender = ""
				}

				// Handle date of birth display
				if len(request.DateOfBirth) > 0 {
					layout := "2006-01-02"
					parsedTime, err := time.Parse(layout, request.DateOfBirth)
					if err == nil {
						user.BirthDate = sql.NullTime{Time: parsedTime, Valid: true}
					}
				} else {
					user.BirthDate = sql.NullTime{Valid: false}
				}

				bind := map[string]interface{}{
					"user":      user,
					"timezones": timezones,
					"locales":   locales,
					"page":      r.URL.Query().Get("page"),
					"query":     r.URL.Query().Get("query"),
					"csrfField": csrf.TemplateField(r),
					"error":     errorMessage,
				}

				err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_profile.html", bind)
				if err != nil {
					httpHelper.InternalServerError(w, r, err)
					return
				}
			})
			return
		}

		// Set success flash message
		sess, err := httpSession.Get(r, constants.AdminConsoleSessionName)
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

		// Redirect to the profile page
		http.Redirect(w, r, fmt.Sprintf("%v/admin/users/%v/profile?page=%v&query=%v", config.GetAdminConsole().BaseURL, user.Id,
			r.URL.Query().Get("page"), r.URL.Query().Get("query")), http.StatusFound)
	}
}
