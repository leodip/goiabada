package adminuserhandlers

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/models"
)

func HandleAdminUserAttributesAddGet(
	httpHelper handlers.HttpHelper,
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

		bind := map[string]interface{}{
			"user":                 user,
			"includeInAccessToken": true,
			"includeInIdToken":     true,
			"page":                 r.URL.Query().Get("page"),
			"query":                r.URL.Query().Get("query"),
			"csrfField":            csrf.TemplateField(r),
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_attributes_add.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminUserAttributesAddPost(
	httpHelper handlers.HttpHelper,
	authHelper handlers.AuthHelper,
	database data.Database,
	identifierValidator handlers.IdentifierValidator,
	inputSanitizer handlers.InputSanitizer,
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
				"user":                 user,
				"attributeKey":         r.FormValue("attributeKey"),
				"attributeValue":       r.FormValue("attributeValue"),
				"includeInAccessToken": r.FormValue("includeInAccessToken") == "on",
				"includeInIdToken":     r.FormValue("includeInIdToken") == "on",
				"error":                message,
				"page":                 r.URL.Query().Get("page"),
				"query":                r.URL.Query().Get("query"),
				"csrfField":            csrf.TemplateField(r),
			}

			err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_attributes_add.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		attrKey := strings.TrimSpace(r.FormValue("attributeKey"))
		attrValue := strings.TrimSpace(r.FormValue("attributeValue"))

		if len(attrKey) == 0 {
			renderError("Attribute key is required")
			return
		}

		err = identifierValidator.ValidateIdentifier(attrKey, false)
		if err != nil {
			renderError(err.Error())
			return
		}

		const maxLengthAttrValue = 250
		if len(attrValue) > maxLengthAttrValue {
			renderError("The attribute value cannot exceed a maximum length of " + strconv.Itoa(maxLengthAttrValue) + " characters. Please make the value shorter.")
			return
		}

		includeInAccessToken := r.FormValue("includeInAccessToken") == "on"
		includeInIdToken := r.FormValue("includeInIdToken") == "on"

		userAttribute := &models.UserAttribute{
			Key:                  attrKey,
			Value:                inputSanitizer.Sanitize(attrValue),
			IncludeInAccessToken: includeInAccessToken,
			IncludeInIdToken:     includeInIdToken,
			UserId:               user.Id,
		}
		err = database.CreateUserAttribute(nil, userAttribute)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		auditLogger.Log(constants.AuditAddedUserAttribute, map[string]interface{}{
			"userId":          user.Id,
			"userAttributeId": userAttribute.Id,
			"loggedInUser":    authHelper.GetLoggedInSubject(r),
		})

		http.Redirect(w, r, fmt.Sprintf("%v/admin/users/%v/attributes?page=%v&query=%v", config.Get().BaseURL, user.Id,
			r.URL.Query().Get("page"), r.URL.Query().Get("query")), http.StatusFound)
	}
}
