package admingrouphandlers

import (
	"net/http"
	"strconv"

	"github.com/pkg/errors"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
)

func HandleAdminGroupAttributesGet(
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

		attributes, err := database.GetGroupAttributesByGroupId(nil, group.Id)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		bind := map[string]interface{}{
			"groupId":         group.Id,
			"groupIdentifier": group.GroupIdentifier,
			"description":     group.Description,
			"attributes":      attributes,
			"csrfField":       csrf.TemplateField(r),
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_groups_attributes.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminGroupAttributesRemovePost(
	httpHelper handlers.HttpHelper,
	authHelper handlers.AuthHelper,
	database data.Database,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "groupId")
		if len(idStr) == 0 {
			httpHelper.JsonError(w, r, errors.WithStack(errors.New("groupId is required")))
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}
		group, err := database.GetGroupById(nil, id)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}
		if group == nil {
			httpHelper.JsonError(w, r, errors.WithStack(errors.New("group not found")))
			return
		}

		attributes, err := database.GetGroupAttributesByGroupId(nil, group.Id)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		attributeIdStr := chi.URLParam(r, "attributeId")
		if len(attributeIdStr) == 0 {
			httpHelper.JsonError(w, r, errors.WithStack(errors.New("attribute id is required")))
			return
		}

		attributeId, err := strconv.ParseInt(attributeIdStr, 10, 64)
		if err != nil {
			httpHelper.JsonError(w, r, err)
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
			httpHelper.JsonError(w, r, errors.WithStack(errors.New("attribute not found")))
			return
		}

		err = database.DeleteGroupAttribute(nil, attributeId)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		auditLogger.Log(constants.AuditDeleteGroupAttribute, map[string]interface{}{
			"groupAttributeId": attributeId,
			"groupId":          group.Id,
			"groupIdentifier":  group.GroupIdentifier,
			"loggedInUser":     authHelper.GetLoggedInSubject(r),
		})

		result := struct {
			Success bool
		}{
			Success: true,
		}
		httpHelper.EncodeJson(w, r, result)
	}
}
