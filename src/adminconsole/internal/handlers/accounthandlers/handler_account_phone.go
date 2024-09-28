package accounthandlers

import (
	"net/http"
	"strings"

	"github.com/pkg/errors"

	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/phonecountries"
	"github.com/leodip/goiabada/core/validators"
)

func HandleAccountPhoneGet(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	authHelper handlers.AuthHelper,
	database data.Database,
) http.HandlerFunc {

	phoneCountries := phonecountries.Get()

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
			"selectedPhoneCountryUniqueId": user.PhoneNumberCountryUniqueId,
			"phoneNumber":                  user.PhoneNumber,
			"phoneCountries":               phoneCountries,
			"savedSuccessfully":            len(savedSuccessfully) > 0,
			"csrfField":                    csrf.TemplateField(r),
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_phone.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAccountPhonePost(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	authHelper handlers.AuthHelper,
	database data.Database,
	phoneValidator handlers.PhoneValidator,
	inputSanitizer handlers.InputSanitizer,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {

	phoneCountries := phonecountries.Get()

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

		input := &validators.ValidatePhoneInput{
			PhoneCountryUniqueId: r.FormValue("phoneCountryUniqueId"),
			PhoneNumber:          strings.TrimSpace(r.FormValue("phoneNumber")),
		}

		err = phoneValidator.ValidatePhone(r.Context(), input)
		if err != nil {
			if valError, ok := err.(*customerrors.ErrorDetail); ok {
				bind := map[string]interface{}{
					"selectedPhoneCountryUniqueId": input.PhoneCountryUniqueId,
					"phoneNumber":                  input.PhoneNumber,
					"phoneCountries":               phoneCountries,
					"csrfField":                    csrf.TemplateField(r),
					"error":                        valError.GetDescription(),
				}

				err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_phone.html", bind)
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

		var phoneCountry phonecountries.PhoneCountry
		found := false
		for _, c := range phoneCountries {
			if c.UniqueId == input.PhoneCountryUniqueId {
				found = true
				phoneCountry = c
				break
			}
		}

		if !found && len(input.PhoneCountryUniqueId) > 0 {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("Phone country is invalid: "+input.PhoneCountryUniqueId)))
			return
		}

		user.PhoneNumberCountryUniqueId = input.PhoneCountryUniqueId
		user.PhoneNumberCountryCallingCode = phoneCountry.CallingCode
		user.PhoneNumber = inputSanitizer.Sanitize(input.PhoneNumber)
		user.PhoneNumberVerified = false

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

		auditLogger.Log(constants.AuditUpdatedUserPhone, map[string]interface{}{
			"userId":       user.Id,
			"loggedInUser": authHelper.GetLoggedInSubject(r),
		})

		http.Redirect(w, r, config.Get().BaseURL+"/account/phone", http.StatusFound)
	}
}
