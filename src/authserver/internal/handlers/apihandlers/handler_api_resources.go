package apihandlers

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"

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

func HandleAPIResourcesGet(
	database data.Database,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resources, err := database.GetAllResources(nil)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error getting all resources"))
			return
		}

		// Sort resources by identifier for consistent ordering
		sort.Slice(resources, func(i, j int) bool {
			return resources[i].ResourceIdentifier < resources[j].ResourceIdentifier
		})

		response := api.GetResourcesResponse{
			Resources: api.ToResourceResponses(resources),
		}

		writeJSON(w, r, http.StatusOK, response)
	}
}

// HandleAPIResourceCreatePost - POST /api/v1/admin/resources
func HandleAPIResourceCreatePost(
	authHelper handlers.AuthHelper,
	database data.Database,
	identifierValidator *validators.IdentifierValidator,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var createReq api.CreateResourceRequest
		if err := json.NewDecoder(r.Body).Decode(&createReq); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}

		// Validate resource identifier is present
		if strings.TrimSpace(createReq.ResourceIdentifier) == "" {
			writeJSONError(w, "Resource identifier is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Validate description length
		const maxLengthDescription = 100
		if len(createReq.Description) > maxLengthDescription {
			writeJSONError(w, "The description cannot exceed a maximum length of "+strconv.Itoa(maxLengthDescription)+" characters", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		if err := validators.ValidateNoAngleBrackets(createReq.Description, i18n.ErrCodeDescriptionAngleBrackets); err != nil {
			writeValidationError(w, r, err)
			return
		}

		// Validate identifier format
		if err := identifierValidator.ValidateIdentifier(createReq.ResourceIdentifier, true); err != nil {
			writeValidationError(w, r, err)
			return
		}

		// Check uniqueness
		existing, err := database.GetResourceByResourceIdentifier(nil, createReq.ResourceIdentifier)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error checking resource by identifier"), "resourceIdentifier", createReq.ResourceIdentifier)
			return
		}
		if existing != nil {
			writeJSONError(w, "The resource identifier is already in use", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Create resource
		resource := &models.Resource{
			ResourceIdentifier: strings.TrimSpace(createReq.ResourceIdentifier),
			Description:        strings.TrimSpace(createReq.Description),
		}
		if err := database.CreateResource(nil, resource); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error creating resource"), "resourceIdentifier", resource.ResourceIdentifier)
			return
		}

		// Audit log
		auditLogger.Log(constants.AuditCreatedResource, map[string]interface{}{
			"resourceId":         resource.Id,
			"resourceIdentifier": resource.ResourceIdentifier,
			"loggedInUser":       authHelper.GetLoggedInSubject(r),
		})

		// Response
		response := api.CreateResourceResponse{
			Resource: *api.ToResourceResponse(resource),
		}
		writeJSON(w, r, http.StatusCreated, response)
	}
}

// HandleAPIResourceGet - GET /api/v1/admin/resources/{id}
func HandleAPIResourceGet(
	database data.Database,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idStr := chi.URLParam(r, "id")
		if idStr == "" {
			writeJSONError(w, "Resource ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid resource ID", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		resource, err := database.GetResourceById(nil, id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error getting resource by ID"), "resourceId", id)
			return
		}
		if resource == nil {
			writeJSONError(w, "Resource not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		response := api.GetResourceResponse{
			Resource: *api.ToResourceResponse(resource),
		}
		writeJSON(w, r, http.StatusOK, response)
	}
}

// HandleAPIResourceUpdatePut - PUT /api/v1/admin/resources/{id}
func HandleAPIResourceUpdatePut(
	authHelper handlers.AuthHelper,
	database data.Database,
	identifierValidator *validators.IdentifierValidator,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idStr := chi.URLParam(r, "id")
		if idStr == "" {
			writeJSONError(w, "Resource ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid resource ID", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		resource, err := database.GetResourceById(nil, id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error getting resource by ID for update"), "resourceId", id)
			return
		}
		if resource == nil {
			writeJSONError(w, "Resource not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		var updateReq api.UpdateResourceRequest
		if err := json.NewDecoder(r.Body).Decode(&updateReq); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}

		// Validate identifier present
		if strings.TrimSpace(updateReq.ResourceIdentifier) == "" {
			writeJSONError(w, "Resource identifier is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Validate description length
		const maxLengthDescription = 100
		if len(updateReq.Description) > maxLengthDescription {
			writeJSONError(w, "The description cannot exceed a maximum length of "+strconv.Itoa(maxLengthDescription)+" characters", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		if err := validators.ValidateNoAngleBrackets(updateReq.Description, i18n.ErrCodeDescriptionAngleBrackets); err != nil {
			writeValidationError(w, r, err)
			return
		}

		// Validate identifier format
		if err := identifierValidator.ValidateIdentifier(updateReq.ResourceIdentifier, true); err != nil {
			writeValidationError(w, r, err)
			return
		}

		// Uniqueness check (excluding this resource)
		existing, err := database.GetResourceByResourceIdentifier(nil, updateReq.ResourceIdentifier)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error checking resource by identifier for update"), "resourceIdentifier", updateReq.ResourceIdentifier, "resourceId", resource.Id)
			return
		}
		if existing != nil && existing.Id != resource.Id {
			writeJSONError(w, "The resource identifier is already in use", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Apply changes
		trimmedResourceIdentifier := strings.TrimSpace(updateReq.ResourceIdentifier)

		// System-level resource protection: block identifier changes
		if resource.IsSystemLevelResource() && trimmedResourceIdentifier != resource.ResourceIdentifier {
			writeJSONError(w, "The identifier of a system-level resource cannot be changed.", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		resource.ResourceIdentifier = trimmedResourceIdentifier
		resource.Description = strings.TrimSpace(updateReq.Description)

		if err := database.UpdateResource(nil, resource); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error updating resource"), "resourceId", resource.Id, "resourceIdentifier", resource.ResourceIdentifier)
			return
		}

		// Audit
		auditLogger.Log(constants.AuditUpdatedResource, map[string]interface{}{
			"resourceId":         resource.Id,
			"resourceIdentifier": resource.ResourceIdentifier,
			"loggedInUser":       authHelper.GetLoggedInSubject(r),
		})

		// Response
		response := api.UpdateResourceResponse{
			Resource: *api.ToResourceResponse(resource),
		}
		writeJSON(w, r, http.StatusOK, response)
	}
}

// HandleAPIResourceDelete - DELETE /api/v1/admin/resources/{id}
func HandleAPIResourceDelete(
	authHelper handlers.AuthHelper,
	database data.Database,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idStr := chi.URLParam(r, "id")
		if idStr == "" {
			writeJSONError(w, "Resource ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid resource ID", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		resource, err := database.GetResourceById(nil, id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error getting resource by ID for deletion"), "resourceId", id)
			return
		}
		if resource == nil {
			writeJSONError(w, "Resource not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		if resource.IsSystemLevelResource() {
			writeJSONError(w, "Trying to delete a system level resource", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		if err := database.DeleteResource(nil, resource.Id); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: Database error deleting resource"), "resourceId", resource.Id, "resourceIdentifier", resource.ResourceIdentifier)
			return
		}

		auditLogger.Log(constants.AuditDeletedResource, map[string]interface{}{
			"resourceId":         resource.Id,
			"resourceIdentifier": resource.ResourceIdentifier,
			"loggedInUser":       authHelper.GetLoggedInSubject(r),
		})

		resp := api.SuccessResponse{Success: true}
		writeJSON(w, r, http.StatusOK, resp)
	}
}
