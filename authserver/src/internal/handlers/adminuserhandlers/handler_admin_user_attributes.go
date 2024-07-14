package adminuserhandlers

import (
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

func HandleAdminUserAttributesGet(
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

		attributes, err := database.GetUserAttributesByUserId(nil, user.Id)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		bind := map[string]interface{}{
			"user":       user,
			"attributes": attributes,
			"page":       r.URL.Query().Get("page"),
			"query":      r.URL.Query().Get("query"),
			"csrfField":  csrf.TemplateField(r),
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_attributes.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminUserAttributesRemovePost(
	httpHelper handlers.HttpHelper,
	authHelper handlers.AuthHelper,
	database data.Database,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "userId")
		if len(idStr) == 0 {
			httpHelper.JsonError(w, r, errors.WithStack(errors.New("userId is required")), http.StatusInternalServerError)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.JsonError(w, r, err, http.StatusInternalServerError)
			return
		}
		user, err := database.GetUserById(nil, id)
		if err != nil {
			httpHelper.JsonError(w, r, err, http.StatusInternalServerError)
			return
		}
		if user == nil {
			httpHelper.JsonError(w, r, errors.WithStack(errors.New("user not found")), http.StatusInternalServerError)
			return
		}

		attributes, err := database.GetUserAttributesByUserId(nil, user.Id)
		if err != nil {
			httpHelper.JsonError(w, r, err, http.StatusInternalServerError)
			return
		}

		attributeIdStr := chi.URLParam(r, "attributeId")
		if len(attributeIdStr) == 0 {
			httpHelper.JsonError(w, r, errors.WithStack(errors.New("attribute id is required")), http.StatusInternalServerError)
			return
		}

		attributeId, err := strconv.ParseInt(attributeIdStr, 10, 64)
		if err != nil {
			httpHelper.JsonError(w, r, err, http.StatusInternalServerError)
			return
		}

		found := false
		for _, attribute := range attributes {
			if attribute.Id == attributeId {
				found = true
				break
			}
		}

		if !found {
			httpHelper.JsonError(w, r, errors.WithStack(errors.New("attribute not found")), http.StatusInternalServerError)
			return
		}

		err = database.DeleteUserAttribute(nil, attributeId)
		if err != nil {
			httpHelper.JsonError(w, r, err, http.StatusInternalServerError)
			return
		}

		lib.LogAudit(constants.AuditDeleteUserAttribute, map[string]interface{}{
			"userId":          user.Id,
			"userAttributeId": attributeId,
			"loggedInUser":    authHelper.GetLoggedInSubject(r),
		})

		result := struct {
			Success bool
		}{
			Success: true,
		}
		httpHelper.EncodeJson(w, r, result)
	}
}
