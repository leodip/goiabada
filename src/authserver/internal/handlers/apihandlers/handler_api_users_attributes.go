package apihandlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/authserver/internal/handlers"
	"github.com/leodip/goiabada/authserver/internal/middleware"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/inputsanitizer"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/validators"
)

// HandleAPIUserAttributesGet - GET /api/v1/admin/users/{id}/attributes
func HandleAPIUserAttributesGet(
	httpHelper handlers.HttpHelper,
	database data.Database,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authentication and authorization handled by middleware

		// Get user ID from URL parameter
		userIdStr := chi.URLParam(r, "id")
		if userIdStr == "" {
			writeJSONError(w, "User ID is required", "USER_ID_REQUIRED", http.StatusBadRequest)
			return
		}

		userId, err := strconv.ParseInt(userIdStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid user ID", "INVALID_USER_ID", http.StatusBadRequest)
			return
		}

		// Check if user exists
		user, err := database.GetUserById(nil, userId)
		if err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}
		if user == nil {
			writeJSONError(w, "User not found", "USER_NOT_FOUND", http.StatusNotFound)
			return
		}

		// Get user attributes
		attributes, err := database.GetUserAttributesByUserId(nil, userId)
		if err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}

		// Create response
		response := UserAttributesResponse{
			Attributes: attributes,
		}

		// Set content type and encode response
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			writeJSONError(w, "Failed to encode response", "ENCODING_ERROR", http.StatusInternalServerError)
			return
		}
	}
}

// HandleAPIUserAttributeGet - GET /api/v1/admin/user-attributes/{id}
func HandleAPIUserAttributeGet(
	httpHelper handlers.HttpHelper,
	database data.Database,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authentication and authorization handled by middleware

		// Get attribute ID from URL parameter
		attributeIdStr := chi.URLParam(r, "id")
		if attributeIdStr == "" {
			writeJSONError(w, "Attribute ID is required", "ATTRIBUTE_ID_REQUIRED", http.StatusBadRequest)
			return
		}

		attributeId, err := strconv.ParseInt(attributeIdStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid attribute ID", "INVALID_ATTRIBUTE_ID", http.StatusBadRequest)
			return
		}

		// Get user attribute from database
		attribute, err := database.GetUserAttributeById(nil, attributeId)
		if err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}
		if attribute == nil {
			writeJSONError(w, "Attribute not found", "ATTRIBUTE_NOT_FOUND", http.StatusNotFound)
			return
		}

		// Create response
		response := UserAttributeResponse{
			Attribute: attribute,
		}

		// Set content type and encode response
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			writeJSONError(w, "Failed to encode response", "ENCODING_ERROR", http.StatusInternalServerError)
			return
		}
	}
}

// HandleAPIUserAttributeCreatePost - POST /api/v1/admin/user-attributes
func HandleAPIUserAttributeCreatePost(
	httpHelper handlers.HttpHelper,
	database data.Database,
	identifierValidator *validators.IdentifierValidator,
	inputSanitizer *inputsanitizer.InputSanitizer,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authentication and authorization handled by middleware

		// Decode the request body
		var req CreateUserAttributeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}

		// Validate required fields
		if req.Key == "" {
			writeJSONError(w, "Attribute key is required", "KEY_REQUIRED", http.StatusBadRequest)
			return
		}

		// Validate user exists
		user, err := database.GetUserById(nil, req.UserId)
		if err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}
		if user == nil {
			writeJSONError(w, "User not found", "USER_NOT_FOUND", http.StatusNotFound)
			return
		}

		// Validate attribute key
		err = identifierValidator.ValidateIdentifier(req.Key, false)
		if err != nil {
			writeValidationError(w, err)
			return
		}

		// Validate attribute value length
		const maxLengthAttrValue = 250
		if len(req.Value) > maxLengthAttrValue {
			writeJSONError(w, "The attribute value cannot exceed a maximum length of 250 characters", "VALUE_TOO_LONG", http.StatusBadRequest)
			return
		}

		// Create user attribute
		userAttribute := &models.UserAttribute{
			Key:                  req.Key,
			Value:                inputSanitizer.Sanitize(req.Value),
			IncludeInAccessToken: req.IncludeInAccessToken,
			IncludeInIdToken:     req.IncludeInIdToken,
			UserId:               req.UserId,
		}

		err = database.CreateUserAttribute(nil, userAttribute)
		if err != nil {
			writeJSONError(w, "Failed to create user attribute", "USER_ATTRIBUTE_CREATION_FAILED", http.StatusInternalServerError)
			return
		}

		// Get logged in user from access token
		jwtToken, ok := middleware.GetValidatedToken(r)
		var loggedInUser string
		if ok {
			loggedInUser = jwtToken.GetStringClaim("sub")
		}

		// Log audit event
		auditLogger.Log(constants.AuditAddedUserAttribute, map[string]interface{}{
			"userId":          user.Id,
			"userAttributeId": userAttribute.Id,
			"loggedInUser":    loggedInUser,
		})

		// Create response
		response := UserAttributeResponse{
			Attribute: userAttribute,
		}

		// Set content type and encode response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		if err := json.NewEncoder(w).Encode(response); err != nil {
			writeJSONError(w, "Failed to encode response", "ENCODING_ERROR", http.StatusInternalServerError)
			return
		}
	}
}

// HandleAPIUserAttributeUpdatePut - PUT /api/v1/admin/user-attributes/{id}
func HandleAPIUserAttributeUpdatePut(
	httpHelper handlers.HttpHelper,
	database data.Database,
	identifierValidator *validators.IdentifierValidator,
	inputSanitizer *inputsanitizer.InputSanitizer,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authentication and authorization handled by middleware

		// Get attribute ID from URL parameter
		attributeIdStr := chi.URLParam(r, "id")
		if attributeIdStr == "" {
			writeJSONError(w, "Attribute ID is required", "ATTRIBUTE_ID_REQUIRED", http.StatusBadRequest)
			return
		}

		attributeId, err := strconv.ParseInt(attributeIdStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid attribute ID", "INVALID_ATTRIBUTE_ID", http.StatusBadRequest)
			return
		}

		// Decode the request body
		var req UpdateUserAttributeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}

		// Get existing attribute
		attribute, err := database.GetUserAttributeById(nil, attributeId)
		if err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}
		if attribute == nil {
			writeJSONError(w, "Attribute not found", "ATTRIBUTE_NOT_FOUND", http.StatusNotFound)
			return
		}

		// Validate required fields
		if req.Key == "" {
			writeJSONError(w, "Attribute key is required", "KEY_REQUIRED", http.StatusBadRequest)
			return
		}

		// Validate attribute key
		err = identifierValidator.ValidateIdentifier(req.Key, false)
		if err != nil {
			writeValidationError(w, err)
			return
		}

		// Validate attribute value length
		const maxLengthAttrValue = 250
		if len(req.Value) > maxLengthAttrValue {
			writeJSONError(w, "The attribute value cannot exceed a maximum length of 250 characters", "VALUE_TOO_LONG", http.StatusBadRequest)
			return
		}

		// Update attribute fields
		attribute.Key = req.Key
		attribute.Value = inputSanitizer.Sanitize(req.Value)
		attribute.IncludeInAccessToken = req.IncludeInAccessToken
		attribute.IncludeInIdToken = req.IncludeInIdToken

		// Update attribute in database
		err = database.UpdateUserAttribute(nil, attribute)
		if err != nil {
			writeJSONError(w, "Failed to update user attribute", "USER_ATTRIBUTE_UPDATE_FAILED", http.StatusInternalServerError)
			return
		}

		// Get logged in user from access token
		jwtToken, ok := middleware.GetValidatedToken(r)
		var loggedInUser string
		if ok {
			loggedInUser = jwtToken.GetStringClaim("sub")
		}

		// Log audit event
		auditLogger.Log(constants.AuditUpdatedUserAttribute, map[string]interface{}{
			"userId":          attribute.UserId,
			"userAttributeId": attribute.Id,
			"loggedInUser":    loggedInUser,
		})

		// Create response
		response := UserAttributeResponse{
			Attribute: attribute,
		}

		// Set content type and encode response
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			writeJSONError(w, "Failed to encode response", "ENCODING_ERROR", http.StatusInternalServerError)
			return
		}
	}
}

// HandleAPIUserAttributeDelete - DELETE /api/v1/admin/user-attributes/{id}
func HandleAPIUserAttributeDelete(
	httpHelper handlers.HttpHelper,
	database data.Database,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authentication and authorization handled by middleware

		// Get attribute ID from URL parameter
		attributeIdStr := chi.URLParam(r, "id")
		if attributeIdStr == "" {
			writeJSONError(w, "Attribute ID is required", "ATTRIBUTE_ID_REQUIRED", http.StatusBadRequest)
			return
		}

		attributeId, err := strconv.ParseInt(attributeIdStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid attribute ID", "INVALID_ATTRIBUTE_ID", http.StatusBadRequest)
			return
		}

		// Check if attribute exists before deleting
		attribute, err := database.GetUserAttributeById(nil, attributeId)
		if err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}
		if attribute == nil {
			writeJSONError(w, "Attribute not found", "ATTRIBUTE_NOT_FOUND", http.StatusNotFound)
			return
		}

		// Delete attribute from database
		err = database.DeleteUserAttribute(nil, attributeId)
		if err != nil {
			writeJSONError(w, "Failed to delete user attribute", "USER_ATTRIBUTE_DELETE_FAILED", http.StatusInternalServerError)
			return
		}

		// Get logged in user from access token
		jwtToken, ok := middleware.GetValidatedToken(r)
		var loggedInUser string
		if ok {
			loggedInUser = jwtToken.GetStringClaim("sub")
		}

		// Log audit event
		auditLogger.Log(constants.AuditDeleteUserAttribute, map[string]interface{}{
			"userId":          attribute.UserId,
			"userAttributeId": attributeId,
			"loggedInUser":    loggedInUser,
		})

		// Create response
		response := SuccessResponse{
			Success: true,
		}

		// Set content type and encode response
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			writeJSONError(w, "Failed to encode response", "ENCODING_ERROR", http.StatusInternalServerError)
			return
		}
	}
}
