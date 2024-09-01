package adminuserhandlers

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"

	"github.com/pkg/errors"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/hashutil"
)

func HandleAdminUserAuthenticationGet(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	database data.Database,
) http.HandlerFunc {

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

		bind := map[string]interface{}{
			"user":              user,
			"otpEnabled":        user.OTPEnabled,
			"page":              r.URL.Query().Get("page"),
			"query":             r.URL.Query().Get("query"),
			"savedSuccessfully": len(savedSuccessfully) > 0,
			"csrfField":         csrf.TemplateField(r),
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_authentication.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminUserAuthenticationPost(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	authHelper handlers.AuthHelper,
	database data.Database,
	passwordValidator handlers.PasswordValidator,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {

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

		renderError := func(message string) {
			bind := map[string]interface{}{
				"user":       user,
				"otpEnabled": r.FormValue("otpEnabled") == "on",
				"page":       r.URL.Query().Get("page"),
				"query":      r.URL.Query().Get("query"),
				"csrfField":  csrf.TemplateField(r),
				"error":      message,
			}

			err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_authentication.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		newPassword := r.FormValue("newPassword")
		if len(newPassword) > 0 {
			err = passwordValidator.ValidatePassword(r.Context(), newPassword)
			if err != nil {
				renderError(err.Error())
				return
			}

			passwordHash, err := hashutil.HashPassword(newPassword)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
			user.PasswordHash = passwordHash
			user.ForgotPasswordCodeEncrypted = nil
			user.ForgotPasswordCodeIssuedAt = sql.NullTime{Valid: false}
		}

		if user.OTPEnabled {
			otpEnabled := r.FormValue("otpEnabled") == "on"
			if !otpEnabled {
				user.OTPEnabled = false
				user.OTPSecret = ""
			}
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
		err = sess.Save(r, w)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		auditLogger.Log(constants.AuditUpdatedUserAuthentication, map[string]interface{}{
			"userId":       user.Id,
			"loggedInUser": authHelper.GetLoggedInSubject(r),
		})

		http.Redirect(w, r, fmt.Sprintf("%v/admin/users/%v/authentication?page=%v&query=%v", config.Get().BaseURL, user.Id,
			r.URL.Query().Get("page"), r.URL.Query().Get("query")), http.StatusFound)
	}
}
