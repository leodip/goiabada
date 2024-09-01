package accounthandlers

import (
	"net/http"
	"sort"
	"strings"

	"github.com/biter777/countries"
	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/oauth"

	"github.com/leodip/goiabada/core/validators"
)

func HandleAccountAddressGet(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	database data.Database,
) http.HandlerFunc {

	countries := countries.AllInfo()
	sort.Slice(countries, func(i, j int) bool {
		return countries[i].Name < countries[j].Name
	})

	return func(w http.ResponseWriter, r *http.Request) {

		var jwtInfo oauth.JwtInfo
		if r.Context().Value(constants.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
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

		address := struct {
			AddressLine1      string
			AddressLine2      string
			AddressLocality   string
			AddressRegion     string
			AddressPostalCode string
			AddressCountry    string
		}{
			AddressLine1:      user.AddressLine1,
			AddressLine2:      user.AddressLine2,
			AddressLocality:   user.AddressLocality,
			AddressRegion:     user.AddressRegion,
			AddressPostalCode: user.AddressPostalCode,
			AddressCountry:    user.AddressCountry,
		}

		bind := map[string]interface{}{
			"user":              user,
			"address":           address,
			"countries":         countries,
			"savedSuccessfully": len(savedSuccessfully) > 0,
			"csrfField":         csrf.TemplateField(r),
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_address.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAccountAddressPost(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	authHelper handlers.AuthHelper,
	database data.Database,
	addressValidator handlers.AddressValidator,
	inputSanitizer handlers.InputSanitizer,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {

	countries := countries.AllInfo()
	sort.Slice(countries, func(i, j int) bool {
		return countries[i].Name < countries[j].Name
	})

	return func(w http.ResponseWriter, r *http.Request) {

		var jwtInfo oauth.JwtInfo
		if r.Context().Value(constants.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
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

		input := &validators.ValidateAddressInput{
			AddressLine1:      strings.TrimSpace(r.FormValue("addressLine1")),
			AddressLine2:      strings.TrimSpace(r.FormValue("addressLine2")),
			AddressLocality:   strings.TrimSpace(r.FormValue("addressLocality")),
			AddressRegion:     strings.TrimSpace(r.FormValue("addressRegion")),
			AddressPostalCode: strings.TrimSpace(r.FormValue("addressPostalCode")),
			AddressCountry:    strings.TrimSpace(r.FormValue("addressCountry")),
		}

		err = addressValidator.ValidateAddress(r.Context(), input)
		if err != nil {
			if valError, ok := err.(*customerrors.ErrorDetail); ok {
				bind := map[string]interface{}{
					"user":      user,
					"address":   input,
					"countries": countries,
					"csrfField": csrf.TemplateField(r),
					"error":     valError.GetDescription(),
				}

				err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_address.html", bind)
				if err != nil {
					httpHelper.InternalServerError(w, r, err)
				}
				return
			} else {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		user.AddressLine1 = inputSanitizer.Sanitize(input.AddressLine1)
		user.AddressLine2 = inputSanitizer.Sanitize(input.AddressLine2)
		user.AddressLocality = inputSanitizer.Sanitize(input.AddressLocality)
		user.AddressRegion = inputSanitizer.Sanitize(input.AddressRegion)
		user.AddressPostalCode = inputSanitizer.Sanitize(input.AddressPostalCode)
		user.AddressCountry = inputSanitizer.Sanitize(input.AddressCountry)

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

		auditLogger.Log(constants.AuditUpdatedUserAddress, map[string]interface{}{
			"userId":       user.Id,
			"loggedInUser": authHelper.GetLoggedInSubject(r),
		})

		http.Redirect(w, r, config.Get().BaseURL+"/account/address", http.StatusFound)
	}
}
