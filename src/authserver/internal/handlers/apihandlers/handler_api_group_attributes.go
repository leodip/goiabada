package apihandlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/authserver/internal/handlers"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/validators"
)

func HandleAPIGroupAttributesGet(
	database data.Database,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "id")
		if idStr == "" {
			writeJSONError(w, "Group ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid group ID", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Verify group exists
		group, err := database.GetGroupById(nil, id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error getting group by ID for attributes"), "groupId", id)
			return
		}
		if group == nil {
			writeJSONError(w, "Group not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Get group attributes
		attributes, err := database.GetGroupAttributesByGroupId(nil, id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error getting group attributes by group ID"), "groupId", id)
			return
		}

		response := api.GetGroupAttributesResponse{
			Attributes: api.ToGroupAttributeResponses(attributes),
		}

		// Ensure we never return a nil slice
		if response.Attributes == nil {
			response.Attributes = []api.GroupAttributeResponse{}
		}

		writeJSON(w, r, http.StatusOK, response)
	}
}

func HandleAPIGroupAttributeGet(
	database data.Database,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "id")
		if idStr == "" {
			writeJSONError(w, "Group attribute ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid group attribute ID", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		if id < 0 {
			writeJSONError(w, "Group attribute not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Get group attribute
		attribute, err := database.GetGroupAttributeById(nil, id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error getting group attribute by ID"), "attributeId", id)
			return
		}
		if attribute == nil {
			writeJSONError(w, "Group attribute not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		response := api.GetGroupAttributeResponse{
			Attribute: *api.ToGroupAttributeResponse(attribute),
		}

		writeJSON(w, r, http.StatusOK, response)
	}
}

func HandleAPIGroupAttributeCreatePost(
	authHelper handlers.AuthHelper,
	database data.Database,
	identifierValidator *validators.IdentifierValidator,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		var createReq api.CreateGroupAttributeRequest
		err := json.NewDecoder(r.Body).Decode(&createReq)
		if err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST", http.StatusBadRequest)
			return
		}

		// Validate required fields
		if createReq.Key == "" {
			writeJSONError(w, "Attribute key is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		if createReq.GroupId <= 0 {
			writeJSONError(w, "Group ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Validate key format
		err = identifierValidator.ValidateIdentifier(createReq.Key, false)
		if err != nil {
			writeValidationError(w, r, err)
			return
		}

		// Validate value length
		const maxLengthAttrValue = 250
		if len(createReq.Value) > maxLengthAttrValue {
			writeJSONError(w, "The attribute value cannot exceed a maximum length of "+strconv.Itoa(maxLengthAttrValue)+" characters", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		if err := validators.ValidateNoAngleBrackets(createReq.Value, i18n.ErrCodeAttributeValueAngleBrackets); err != nil {
			writeValidationError(w, r, err)
			return
		}

		// Verify group exists
		group, err := database.GetGroupById(nil, createReq.GroupId)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}
		if group == nil {
			writeJSONError(w, "Group not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Create group attribute
		groupAttribute := &models.GroupAttribute{
			Key:                  createReq.Key,
			Value:                createReq.Value,
			IncludeInIdToken:     createReq.IncludeInIdToken,
			IncludeInAccessToken: createReq.IncludeInAccessToken,
			GroupId:              createReq.GroupId,
		}

		err = database.CreateGroupAttribute(nil, groupAttribute)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error creating group attribute"), "groupId", groupAttribute.GroupId, "key", groupAttribute.Key)
			return
		}

		// Audit log
		auditLogger.Log(constants.AuditAddedGroupAttribute, map[string]interface{}{
			"groupAttributeId": groupAttribute.Id,
			"groupId":          group.Id,
			"groupIdentifier":  group.GroupIdentifier,
			"loggedInUser":     authHelper.GetLoggedInSubject(r),
		})

		// Return created attribute
		response := api.CreateGroupAttributeResponse{
			Attribute: *api.ToGroupAttributeResponse(groupAttribute),
		}

		writeJSON(w, r, http.StatusCreated, response)
	}
}

func HandleAPIGroupAttributeUpdatePut(
	authHelper handlers.AuthHelper,
	database data.Database,
	identifierValidator *validators.IdentifierValidator,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "id")
		if idStr == "" {
			writeJSONError(w, "Group attribute ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid group attribute ID", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		if id < 0 {
			writeJSONError(w, "Group attribute not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Get existing attribute
		attribute, err := database.GetGroupAttributeById(nil, id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error getting group attribute by ID"), "attributeId", id)
			return
		}
		if attribute == nil {
			writeJSONError(w, "Group attribute not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		var updateReq api.UpdateGroupAttributeRequest
		err = json.NewDecoder(r.Body).Decode(&updateReq)
		if err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST", http.StatusBadRequest)
			return
		}

		// Validate required fields
		if updateReq.Key == "" {
			writeJSONError(w, "Attribute key is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Validate key format
		err = identifierValidator.ValidateIdentifier(updateReq.Key, false)
		if err != nil {
			writeValidationError(w, r, err)
			return
		}

		// Validate value length
		const maxLengthAttrValue = 250
		if len(updateReq.Value) > maxLengthAttrValue {
			writeJSONError(w, "The attribute value cannot exceed a maximum length of "+strconv.Itoa(maxLengthAttrValue)+" characters", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		if err := validators.ValidateNoAngleBrackets(updateReq.Value, i18n.ErrCodeAttributeValueAngleBrackets); err != nil {
			writeValidationError(w, r, err)
			return
		}

		// Get group for audit log
		group, err := database.GetGroupById(nil, attribute.GroupId)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		// Update attribute
		attribute.Key = updateReq.Key
		attribute.Value = updateReq.Value
		attribute.IncludeInIdToken = updateReq.IncludeInIdToken
		attribute.IncludeInAccessToken = updateReq.IncludeInAccessToken

		err = database.UpdateGroupAttribute(nil, attribute)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error updating group attribute"), "attributeId", attribute.Id, "groupId", attribute.GroupId, "key", attribute.Key)
			return
		}

		// Audit log
		auditLogger.Log(constants.AuditUpdatedGroupAttribute, map[string]interface{}{
			"groupAttributeId": attribute.Id,
			"groupId":          attribute.GroupId,
			"groupIdentifier":  group.GroupIdentifier,
			"loggedInUser":     authHelper.GetLoggedInSubject(r),
		})

		// Return updated attribute
		response := api.UpdateGroupAttributeResponse{
			Attribute: *api.ToGroupAttributeResponse(attribute),
		}

		writeJSON(w, r, http.StatusOK, response)
	}
}

func HandleAPIGroupAttributeDelete(
	authHelper handlers.AuthHelper,
	database data.Database,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "id")
		if idStr == "" {
			writeJSONError(w, "Group attribute ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid group attribute ID", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		if id < 0 {
			writeJSONError(w, "Group attribute not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Get existing attribute for audit log
		attribute, err := database.GetGroupAttributeById(nil, id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error getting group attribute by ID"), "attributeId", id)
			return
		}
		if attribute == nil {
			writeJSONError(w, "Group attribute not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Get group for audit log
		group, err := database.GetGroupById(nil, attribute.GroupId)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		// Delete attribute
		err = database.DeleteGroupAttribute(nil, id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error deleting group attribute"), "attributeId", id, "groupId", attribute.GroupId, "key", attribute.Key)
			return
		}

		// Audit log
		auditLogger.Log(constants.AuditDeleteGroupAttribute, map[string]interface{}{
			"groupAttributeId": id,
			"groupId":          attribute.GroupId,
			"groupIdentifier":  group.GroupIdentifier,
			"loggedInUser":     authHelper.GetLoggedInSubject(r),
		})

		// Return success response
		response := api.SuccessResponse{
			Success: true,
		}

		writeJSON(w, r, http.StatusOK, response)
	}
}
