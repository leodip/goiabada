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

func HandleAccountProfileGet(
    httpHelper handlers.HttpHelper,
    httpSession sessions.Store,
    apiClient apiclient.ApiClient,
) http.HandlerFunc {

	timezones := timezones.Get()
	locales := locales.Get()

	return func(w http.ResponseWriter, r *http.Request) {

        // Get JWT info to extract access token
        jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
        if !ok {
            httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
            return
        }

        user, err := apiClient.GetAccountProfile(jwtInfo.TokenResponse.AccessToken)
        if err != nil {
            handlers.HandleAPIError(httpHelper, w, r, err)
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
    apiClient apiclient.ApiClient,
) http.HandlerFunc {

	timezones := timezones.Get()
	locales := locales.Get()

	return func(w http.ResponseWriter, r *http.Request) {

        // Get access token
        jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
        if !ok {
            httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
            return
        }

        // Load current profile (for successful render or error rebound)
        user, err := apiClient.GetAccountProfile(jwtInfo.TokenResponse.AccessToken)
        if err != nil {
            handlers.HandleAPIError(httpHelper, w, r, err)
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

        // Build API request
        request := &api.UpdateUserProfileRequest{
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
        }

        // Call API to update
        updatedUser, err := apiClient.UpdateAccountProfile(jwtInfo.TokenResponse.AccessToken, request)
        if err != nil {
            // Render validation error retaining input
            handlers.HandleAPIErrorWithCallback(httpHelper, w, r, err, func(errorMessage string) {
                // reflect submitted values onto user for display
                user.Username = request.Username
                user.GivenName = request.GivenName
                user.MiddleName = request.MiddleName
                user.FamilyName = request.FamilyName
                user.Nickname = request.Nickname
                user.Website = request.Website
                user.ZoneInfoCountryName = request.ZoneInfoCountryName
                user.ZoneInfo = request.ZoneInfo
                user.Locale = request.Locale

                if len(request.Gender) > 0 {
                    if i, err := strconv.Atoi(request.Gender); err == nil {
                        user.Gender = enums.Gender(i).String()
                    }
                } else {
                    user.Gender = ""
                }

                if len(request.DateOfBirth) > 0 {
                    layout := "2006-01-02"
                    if parsed, err := time.Parse(layout, request.DateOfBirth); err == nil {
                        user.BirthDate = sql.NullTime{Time: parsed, Valid: true}
                    }
                } else {
                    user.BirthDate = sql.NullTime{Valid: false}
                }

                bind := map[string]interface{}{
                    "user":      user,
                    "timezones": timezones,
                    "locales":   locales,
                    "csrfField": csrf.TemplateField(r),
                    "error":     errorMessage,
                }

                if err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_profile.html", bind); err != nil {
                    httpHelper.InternalServerError(w, r, err)
                    return
                }
            })
            return
        }

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

        _ = updatedUser // we don't need it here besides success confirmation

        http.Redirect(w, r, config.GetAdminConsole().BaseURL+"/account/profile", http.StatusFound)
    }
}
