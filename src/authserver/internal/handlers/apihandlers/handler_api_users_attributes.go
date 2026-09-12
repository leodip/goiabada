package apihandlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/authserver/internal/handlers"
	"github.com/leodip/goiabada/authserver/internal/middleware"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/validators"
)

// HandleAPIUserAttributesGet - GET /api/v1/admin/users/{id}/attributes
func HandleAPIUserAttributesGet(
	database data.Database,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authentication and authorization handled by middleware

		// Get user ID from URL parameter
		userIdStr := chi.URLParam(r, "id")
		if userIdStr == "" {
			writeJSONError(w, "User ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		userId, err := strconv.ParseInt(userIdStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid user ID", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Check if user exists
		user, err := database.GetUserById(nil, userId)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}
		if user == nil {
			writeJSONError(w, "User not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Get user attributes
		attributes, err := database.GetUserAttributesByUserId(nil, userId)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		// Create response
		response := api.GetUserAttributesResponse{
			Attributes: api.ToUserAttributeResponses(attributes),
		}

		// Set content type and encode response
		writeJSON(w, r, http.StatusOK, response)
	}
}

// HandleAPIUserAttributeGet - GET /api/v1/admin/user-attributes/{id}
func HandleAPIUserAttributeGet(
	database data.Database,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authentication and authorization handled by middleware

		// Get attribute ID from URL parameter
		attributeIdStr := chi.URLParam(r, "id")
		if attributeIdStr == "" {
			writeJSONError(w, "Attribute ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		attributeId, err := strconv.ParseInt(attributeIdStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid attribute ID", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Get user attribute from database
		attribute, err := database.GetUserAttributeById(nil, attributeId)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}
		if attribute == nil {
			writeJSONError(w, "Attribute not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Create response
		response := api.GetUserAttributeResponse{
			Attribute: *api.ToUserAttributeResponse(attribute),
		}

		// Set content type and encode response
		writeJSON(w, r, http.StatusOK, response)
	}
}

// HandleAPIUserAttributeCreatePost - POST /api/v1/admin/user-attributes
func HandleAPIUserAttributeCreatePost(
	database data.Database,
	identifierValidator *validators.IdentifierValidator,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authentication and authorization handled by middleware

		// Decode the request body
		var req api.CreateUserAttributeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}

		// Validate required fields
		if req.Key == "" {
			writeJSONError(w, "Attribute key is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Validate user exists
		user, err := database.GetUserById(nil, req.UserId)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}
		if user == nil {
			writeJSONError(w, "User not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Validate attribute key
		err = identifierValidator.ValidateIdentifier(req.Key, false)
		if err != nil {
			writeValidationError(w, r, err)
			return
		}

		// Validate attribute value length
		const maxLengthAttrValue = 250
		if len(req.Value) > maxLengthAttrValue {
			writeJSONError(w, "The attribute value cannot exceed a maximum length of 250 characters", "VALUE_TOO_LONG", http.StatusBadRequest)
			return
		}

		if err := validators.ValidateNoAngleBrackets(req.Value, i18n.ErrCodeAttributeValueAngleBrackets); err != nil {
			writeValidationError(w, r, err)
			return
		}

		// Create user attribute
		userAttribute := &models.UserAttribute{
			Key:                  req.Key,
			Value:                req.Value,
			IncludeInAccessToken: req.IncludeInAccessToken,
			IncludeInIdToken:     req.IncludeInIdToken,
			UserId:               req.UserId,
		}

		err = database.CreateUserAttribute(nil, userAttribute)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		// Get logged in user from access token
		jwtToken, ok := middleware.GetValidatedToken(r)
		var loggedInUser string
		if ok {
			loggedInUser = jwtToken.GetStringClaim("sub")
		}

		// Log audit event
		auditLogger.Log(r.Context(), constants.AuditAddedUserAttribute, map[string]interface{}{
			"userId":          user.Id,
			"userAttributeId": userAttribute.Id,
			"loggedInUser":    loggedInUser,
		})

		// Create response
		response := api.CreateUserAttributeResponse{
			Attribute: *api.ToUserAttributeResponse(userAttribute),
		}

		// Set content type and encode response
		writeJSON(w, r, http.StatusCreated, response)
	}
}

// HandleAPIUserAttributeUpdatePut - PUT /api/v1/admin/user-attributes/{id}
func HandleAPIUserAttributeUpdatePut(
	database data.Database,
	identifierValidator *validators.IdentifierValidator,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authentication and authorization handled by middleware

		// Get attribute ID from URL parameter
		attributeIdStr := chi.URLParam(r, "id")
		if attributeIdStr == "" {
			writeJSONError(w, "Attribute ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		attributeId, err := strconv.ParseInt(attributeIdStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid attribute ID", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Decode the request body
		var req api.UpdateUserAttributeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}

		// Get existing attribute
		attribute, err := database.GetUserAttributeById(nil, attributeId)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}
		if attribute == nil {
			writeJSONError(w, "Attribute not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Validate required fields
		if req.Key == "" {
			writeJSONError(w, "Attribute key is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Validate attribute key
		err = identifierValidator.ValidateIdentifier(req.Key, false)
		if err != nil {
			writeValidationError(w, r, err)
			return
		}

		// Validate attribute value length
		const maxLengthAttrValue = 250
		if len(req.Value) > maxLengthAttrValue {
			writeJSONError(w, "The attribute value cannot exceed a maximum length of 250 characters", "VALUE_TOO_LONG", http.StatusBadRequest)
			return
		}

		if err := validators.ValidateNoAngleBrackets(req.Value, i18n.ErrCodeAttributeValueAngleBrackets); err != nil {
			writeValidationError(w, r, err)
			return
		}

		// Update attribute fields
		attribute.Key = req.Key
		attribute.Value = req.Value
		attribute.IncludeInAccessToken = req.IncludeInAccessToken
		attribute.IncludeInIdToken = req.IncludeInIdToken

		// Update attribute in database
		err = database.UpdateUserAttribute(nil, attribute)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		// Get logged in user from access token
		jwtToken, ok := middleware.GetValidatedToken(r)
		var loggedInUser string
		if ok {
			loggedInUser = jwtToken.GetStringClaim("sub")
		}

		// Log audit event
		auditLogger.Log(r.Context(), constants.AuditUpdatedUserAttribute, map[string]interface{}{
			"userId":          attribute.UserId,
			"userAttributeId": attribute.Id,
			"loggedInUser":    loggedInUser,
		})

		// Create response
		response := api.GetUserAttributeResponse{
			Attribute: *api.ToUserAttributeResponse(attribute),
		}

		// Set content type and encode response
		writeJSON(w, r, http.StatusOK, response)
	}
}

// HandleAPIUserAttributeDelete - DELETE /api/v1/admin/user-attributes/{id}
func HandleAPIUserAttributeDelete(
	database data.Database,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authentication and authorization handled by middleware

		// Get attribute ID from URL parameter
		attributeIdStr := chi.URLParam(r, "id")
		if attributeIdStr == "" {
			writeJSONError(w, "Attribute ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		attributeId, err := strconv.ParseInt(attributeIdStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid attribute ID", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Check if attribute exists before deleting
		attribute, err := database.GetUserAttributeById(nil, attributeId)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}
		if attribute == nil {
			writeJSONError(w, "Attribute not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Delete attribute from database
		err = database.DeleteUserAttribute(nil, attributeId)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		// Get logged in user from access token
		jwtToken, ok := middleware.GetValidatedToken(r)
		var loggedInUser string
		if ok {
			loggedInUser = jwtToken.GetStringClaim("sub")
		}

		// Log audit event
		auditLogger.Log(r.Context(), constants.AuditDeleteUserAttribute, map[string]interface{}{
			"userId":          attribute.UserId,
			"userAttributeId": attributeId,
			"loggedInUser":    loggedInUser,
		})

		// Create response
		response := api.SuccessResponse{
			Success: true,
		}

		// Set content type and encode response
		writeJSON(w, r, http.StatusOK, response)
	}
}
