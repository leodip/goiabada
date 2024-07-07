package adminuserhandlers

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/pkg/errors"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/data"
	"github.com/leodip/goiabada/internal/handlers"
	"github.com/leodip/goiabada/internal/lib"
)

func HandleAdminUserAttributesEditGet(
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

		idStr = chi.URLParam(r, "attributeId")
		if len(idStr) == 0 {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("attributeId is required")))
			return
		}

		id, err = strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		attribute, err := database.GetUserAttributeById(nil, id)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if attribute == nil || attribute.UserId != user.Id {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("attribute not found")))
			return
		}

		bind := map[string]interface{}{
			"user":      user,
			"attribute": attribute,
			"page":      r.URL.Query().Get("page"),
			"query":     r.URL.Query().Get("query"),
			"csrfField": csrf.TemplateField(r),
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_attributes_edit.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminUserAttributesEditPost(
	httpHelper handlers.HttpHelper,
	authHelper handlers.AuthHelper,
	database data.Database,
	identifierValidator handlers.IdentifierValidator,
	inputSanitizer handlers.InputSanitizer,
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

		idStr = chi.URLParam(r, "attributeId")
		if len(idStr) == 0 {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("attributeId is required")))
			return
		}

		id, err = strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		attribute, err := database.GetUserAttributeById(nil, id)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if attribute == nil || attribute.UserId != user.Id {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("attribute not found")))
			return
		}

		attribute.Key = r.FormValue("attributeKey")
		attribute.Value = r.FormValue("attributeValue")
		attribute.IncludeInAccessToken = r.FormValue("includeInAccessToken") == "on"
		attribute.IncludeInIdToken = r.FormValue("includeInIdToken") == "on"

		renderError := func(message string) {
			bind := map[string]interface{}{
				"user":      user,
				"attribute": attribute,
				"error":     message,
				"csrfField": csrf.TemplateField(r),
			}

			err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_attributes_edit.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		if len(attribute.Key) == 0 {
			renderError("Attribute key is required")
			return
		}

		err = identifierValidator.ValidateIdentifier(attribute.Key, false)
		if err != nil {
			renderError(err.Error())
			return
		}

		const maxLengthAttrValue = 250
		if len(attribute.Value) > maxLengthAttrValue {
			renderError("The attribute value cannot exceed a maximum length of " + strconv.Itoa(maxLengthAttrValue) + " characters. Please make the value shorter.")
			return
		}

		attribute.Value = inputSanitizer.Sanitize(attribute.Value)
		err = database.UpdateUserAttribute(nil, attribute)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		lib.LogAudit(constants.AuditUpdatedUserAttribute, map[string]interface{}{
			"userId":          user.Id,
			"userAttributeId": attribute.Id,
			"loggedInUser":    authHelper.GetLoggedInSubject(r),
		})

		http.Redirect(w, r, fmt.Sprintf("%v/admin/users/%v/attributes?page=%v&query=%v", lib.GetBaseUrl(), user.Id,
			r.URL.Query().Get("page"), r.URL.Query().Get("query")), http.StatusFound)
	}
}
