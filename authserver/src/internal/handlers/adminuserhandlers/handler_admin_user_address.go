package adminuserhandlers

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	"github.com/biter777/countries"
	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/data"
	"github.com/leodip/goiabada/internal/handlers"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/leodip/goiabada/internal/validators"
)

func HandleAdminUserAddressGet(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	database data.Database,
) http.HandlerFunc {

	countries := countries.AllInfo()
	sort.Slice(countries, func(i, j int) bool {
		return countries[i].Name < countries[j].Name
	})

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
			"page":              r.URL.Query().Get("page"),
			"query":             r.URL.Query().Get("query"),
			"savedSuccessfully": len(savedSuccessfully) > 0,
			"csrfField":         csrf.TemplateField(r),
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_address.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminUserAddressPost(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	authHelper handlers.AuthHelper,
	database data.Database,
	addressValidator handlers.AddressValidator,
	inputSanitizer handlers.InputSanitizer,
) http.HandlerFunc {

	countries := countries.AllInfo()
	sort.Slice(countries, func(i, j int) bool {
		return countries[i].Name < countries[j].Name
	})

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
			if valError, ok := err.(*customerrors.ValidationError); ok {

				bind := map[string]interface{}{
					"user":      user,
					"address":   input,
					"countries": countries,
					"page":      r.URL.Query().Get("page"),
					"query":     r.URL.Query().Get("query"),
					"error":     valError.Description,
					"csrfField": csrf.TemplateField(r),
				}

				err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_address.html", bind)
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

		lib.LogAudit(constants.AuditUpdatedUserAddress, map[string]interface{}{
			"userId":       user.Id,
			"loggedInUser": authHelper.GetLoggedInSubject(r),
		})

		http.Redirect(w, r, fmt.Sprintf("%v/admin/users/%v/address?page=%v&query=%v", lib.GetBaseUrl(), user.Id,
			r.URL.Query().Get("page"), r.URL.Query().Get("query")), http.StatusFound)
	}
}
