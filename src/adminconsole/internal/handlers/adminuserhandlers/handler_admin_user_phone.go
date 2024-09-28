package adminuserhandlers

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	"github.com/go-chi/chi/v5"
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

func HandleAdminUserPhoneGet(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	database data.Database,
) http.HandlerFunc {

	phoneCountries := phonecountries.Get()

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
		user, err := database.GetUserById(nil, id)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if user == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("user not found")))
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
			"user":                         user,
			"phoneCountries":               phoneCountries,
			"selectedPhoneCountryUniqueId": user.PhoneNumberCountryUniqueId,
			"phoneNumber":                  user.PhoneNumber,
			"phoneNumberVerified":          user.PhoneNumberVerified,
			"page":                         r.URL.Query().Get("page"),
			"query":                        r.URL.Query().Get("query"),
			"savedSuccessfully":            len(savedSuccessfully) > 0,
			"csrfField":                    csrf.TemplateField(r),
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_phone.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminUserPhonePost(
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
		user, err := database.GetUserById(nil, id)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if user == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("user not found")))
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
					"phoneNumberVerified":          r.FormValue("phoneNumberVerified") == "on",
					"phoneCountries":               phoneCountries,
					"page":                         r.URL.Query().Get("page"),
					"query":                        r.URL.Query().Get("query"),
					"csrfField":                    csrf.TemplateField(r),
					"error":                        valError.GetDescription(),
				}

				err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_phone.html", bind)
				if err != nil {
					httpHelper.InternalServerError(w, r, err)
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
		user.PhoneNumberVerified = r.FormValue("phoneNumberVerified") == "on"

		if len(strings.TrimSpace(user.PhoneNumber)) == 0 {
			user.PhoneNumberVerified = false
		}

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

		http.Redirect(w, r, fmt.Sprintf("%v/admin/users/%v/phone?page=%v&query=%v", config.Get().BaseURL, user.Id,
			r.URL.Query().Get("page"), r.URL.Query().Get("query")), http.StatusFound)
	}
}
