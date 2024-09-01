package admingrouphandlers

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/pkg/errors"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/models"
)

func HandleAdminGroupAttributesAddGet(
	httpHelper handlers.HttpHelper,
	database data.Database,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "groupId")
		if len(idStr) == 0 {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("groupId is required")))
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		group, err := database.GetGroupById(nil, id)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if group == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("group not found")))
			return
		}

		bind := map[string]interface{}{
			"groupId":              group.Id,
			"groupIdentifier":      group.GroupIdentifier,
			"includeInAccessToken": true,
			"includeInIdToken":     true,
			"description":          group.Description,
			"csrfField":            csrf.TemplateField(r),
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_groups_attributes_add.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminGroupAttributesAddPost(
	httpHelper handlers.HttpHelper,
	authHelper handlers.AuthHelper,
	database data.Database,
	identifierValidator handlers.IdentifierValidator,
	inputSanitizer handlers.InputSanitizer,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "groupId")
		if len(idStr) == 0 {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("groupId is required")))
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		group, err := database.GetGroupById(nil, id)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if group == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("group not found")))
			return
		}

		renderError := func(message string) {
			bind := map[string]interface{}{
				"groupId":              group.Id,
				"groupIdentifier":      group.GroupIdentifier,
				"attributeKey":         r.FormValue("attributeKey"),
				"attributeValue":       r.FormValue("attributeValue"),
				"includeInAccessToken": r.FormValue("includeInAccessToken") == "on",
				"includeInIdToken":     r.FormValue("includeInIdToken") == "on",
				"error":                message,
				"csrfField":            csrf.TemplateField(r),
			}

			err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_groups_attributes_add.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		attrKey := r.FormValue("attributeKey")
		attrValue := r.FormValue("attributeValue")

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

		groupAttribute := &models.GroupAttribute{
			Key:                  attrKey,
			Value:                inputSanitizer.Sanitize(attrValue),
			IncludeInAccessToken: includeInAccessToken,
			IncludeInIdToken:     includeInIdToken,
			GroupId:              group.Id,
		}
		err = database.CreateGroupAttribute(nil, groupAttribute)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		auditLogger.Log(constants.AuditAddedGroupAttribute, map[string]interface{}{
			"groupAttributeId": groupAttribute.Id,
			"groupId":          group.Id,
			"groupIdentifier":  group.GroupIdentifier,
			"loggedInUser":     authHelper.GetLoggedInSubject(r),
		})

		http.Redirect(w, r, fmt.Sprintf("/admin/groups/%v/attributes", group.Id), http.StatusFound)
	}
}
