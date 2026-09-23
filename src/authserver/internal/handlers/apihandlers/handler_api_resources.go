package apihandlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/authserver/internal/accountvalidation"
	"github.com/leodip/goiabada/authserver/internal/apimapping"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/validators"
)

// resourcesDatabase is what the resource endpoints need: the resource row.
type resourcesDatabase interface {
	CreateResource(ctx context.Context, tx *sql.Tx, resource *models.Resource) error
	DeleteResource(ctx context.Context, tx *sql.Tx, resourceId int64) error
	GetAllResources(ctx context.Context, tx *sql.Tx) ([]models.Resource, error)
	GetResourceById(ctx context.Context, tx *sql.Tx, resourceId int64) (*models.Resource, error)
	GetResourceByResourceIdentifier(ctx context.Context, tx *sql.Tx, resourceIdentifier string) (*models.Resource, error)
	UpdateResource(ctx context.Context, tx *sql.Tx, resource *models.Resource) error
}

func HandleAPIResourcesGet(
	database resourcesDatabase,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resources, err := database.GetAllResources(r.Context(), nil)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting all resources"))
			return
		}

		// Sort resources by identifier for consistent ordering
		sort.Slice(resources, func(i, j int) bool {
			return resources[i].ResourceIdentifier < resources[j].ResourceIdentifier
		})

		response := api.GetResourcesResponse{
			Resources: apimapping.ToResourceResponses(resources),
		}

		writeJSON(w, r, http.StatusOK, response)
	}
}

// HandleAPIResourceCreatePost - POST /api/v1/admin/resources
func HandleAPIResourceCreatePost(
	database resourcesDatabase,
	identifierValidator *validators.IdentifierValidator,
	auditLogger AuditLogger,
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

		if err := accountvalidation.ValidateNoAngleBrackets(createReq.Description, i18n.ErrCodeDescriptionAngleBrackets); err != nil {
			writeValidationError(w, r, err)
			return
		}

		// Validate identifier format
		if err := identifierValidator.ValidateIdentifier(createReq.ResourceIdentifier, true); err != nil {
			writeValidationError(w, r, err)
			return
		}

		// Check uniqueness
		existing, err := database.GetResourceByResourceIdentifier(r.Context(), nil, createReq.ResourceIdentifier)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error checking resource by identifier"), "resource_identifier", createReq.ResourceIdentifier)
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
		if err := database.CreateResource(r.Context(), nil, resource); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error creating resource"), "resource_identifier", resource.ResourceIdentifier)
			return
		}

		// Audit log
		auditLogger.Log(r.Context(), audit.AuditCreatedResource, map[string]interface{}{
			"resourceId":         resource.Id,
			"resourceIdentifier": resource.ResourceIdentifier,
			"loggedInUser":       callerSubject(r),
		})

		// Response
		response := api.CreateResourceResponse{
			Resource: *apimapping.ToResourceResponse(resource),
		}
		writeJSON(w, r, http.StatusCreated, response)
	}
}

// HandleAPIResourceGet - GET /api/v1/admin/resources/{id}
func HandleAPIResourceGet(
	database resourcesDatabase,
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

		resource, err := database.GetResourceById(r.Context(), nil, id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting resource by ID"), "resource_id", id)
			return
		}
		if resource == nil {
			writeJSONError(w, "Resource not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		response := api.GetResourceResponse{
			Resource: *apimapping.ToResourceResponse(resource),
		}
		writeJSON(w, r, http.StatusOK, response)
	}
}

// HandleAPIResourceUpdatePut - PUT /api/v1/admin/resources/{id}
func HandleAPIResourceUpdatePut(
	database resourcesDatabase,
	identifierValidator *validators.IdentifierValidator,
	auditLogger AuditLogger,
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

		resource, err := database.GetResourceById(r.Context(), nil, id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting resource by ID for update"), "resource_id", id)
			return
		}
		if resource == nil {
			writeJSONError(w, "Resource not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		var updateReq api.UpdateResourceRequest
		if decodeErr := json.NewDecoder(r.Body).Decode(&updateReq); decodeErr != nil {
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

		if validateNoAngleBracketsErr := accountvalidation.ValidateNoAngleBrackets(updateReq.Description, i18n.ErrCodeDescriptionAngleBrackets); validateNoAngleBracketsErr != nil {
			writeValidationError(w, r, validateNoAngleBracketsErr)
			return
		}

		// Validate identifier format
		if validateIdentifierErr := identifierValidator.ValidateIdentifier(updateReq.ResourceIdentifier, true); validateIdentifierErr != nil {
			writeValidationError(w, r, validateIdentifierErr)
			return
		}

		// Uniqueness check (excluding this resource)
		existing, err := database.GetResourceByResourceIdentifier(r.Context(), nil, updateReq.ResourceIdentifier)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error checking resource by identifier for update"), "resource_identifier", updateReq.ResourceIdentifier, "resource_id", resource.Id)
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

		if err := database.UpdateResource(r.Context(), nil, resource); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error updating resource"), "resource_id", resource.Id, "resource_identifier", resource.ResourceIdentifier)
			return
		}

		// Audit
		auditLogger.Log(r.Context(), audit.AuditUpdatedResource, map[string]interface{}{
			"resourceId":         resource.Id,
			"resourceIdentifier": resource.ResourceIdentifier,
			"loggedInUser":       callerSubject(r),
		})

		// Response
		response := api.UpdateResourceResponse{
			Resource: *apimapping.ToResourceResponse(resource),
		}
		writeJSON(w, r, http.StatusOK, response)
	}
}

// HandleAPIResourceDelete - DELETE /api/v1/admin/resources/{id}
func HandleAPIResourceDelete(
	database resourcesDatabase,
	auditLogger AuditLogger,
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

		resource, err := database.GetResourceById(r.Context(), nil, id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting resource by ID for deletion"), "resource_id", id)
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

		if err := database.DeleteResource(r.Context(), nil, resource.Id); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error deleting resource"), "resource_id", resource.Id, "resource_identifier", resource.ResourceIdentifier)
			return
		}

		auditLogger.Log(r.Context(), audit.AuditDeletedResource, map[string]interface{}{
			"resourceId":         resource.Id,
			"resourceIdentifier": resource.ResourceIdentifier,
			"loggedInUser":       callerSubject(r),
		})

		resp := api.SuccessResponse{Success: true}
		writeJSON(w, r, http.StatusOK, resp)
	}
}
