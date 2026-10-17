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
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/inputvalidation"
)

// resourcesDatabase is what the resource endpoints need: the resource row, and the client row
// an identifier may not name (#151).
type resourcesDatabase interface {
	CreateResource(ctx context.Context, tx *sql.Tx, resource *record.Resource) error
	DeleteResource(ctx context.Context, tx *sql.Tx, resourceId int64) error
	GetAllResources(ctx context.Context, tx *sql.Tx) ([]record.Resource, error)
	GetClientByClientIdentifier(ctx context.Context, tx *sql.Tx, clientIdentifier string) (*record.Client, error)
	GetResourceById(ctx context.Context, tx *sql.Tx, resourceId int64) (*record.Resource, error)
	GetResourceByResourceIdentifier(ctx context.Context, tx *sql.Tx, resourceIdentifier string) (*record.Resource, error)
	UpdateResource(ctx context.Context, tx *sql.Tx, resource *record.Resource) error
}

func HandleResourcesGet(
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

// HandleResourceCreatePost - POST /api/v1/admin/resources
func HandleResourceCreatePost(
	database resourcesDatabase,
	identifierValidator *inputvalidation.IdentifierValidator,
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
			writeLocalizedError(w, r, i18n.NewLocalizedError(i18n.ErrCodeResourceIdentifierRequired, nil), "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Validate description length
		const maxLengthDescription = 100
		if inputvalidation.TextLength(createReq.Description) > maxLengthDescription {
			writeLocalizedError(w, r, i18n.NewLocalizedError(i18n.ErrCodeResourceDescriptionTooLong, map[string]any{"max": maxLengthDescription}), "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		if err := accountvalidation.ValidateNoAngleBrackets(createReq.Description, i18n.ErrCodeDescriptionAngleBrackets); err != nil {
			writeValidationError(w, r, err)
			return
		}

		// Validate identifier format
		if err := identifierValidator.Validate(createReq.ResourceIdentifier, true); err != nil {
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
			writeLocalizedError(w, r, i18n.NewLocalizedError(i18n.ErrCodeResourceIdentifierInUse, nil), "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// A resource identifier may not name a client either. The two namespaces are separate
		// tables with separate uniqueness checks, and a string held by both makes an access
		// token's aud resolvable as a client, which is how a session-bound access token passed
		// every ID-token-hint check in #109's logout (#151). Under concurrency the check is
		// advisory: no index spans the two tables, so this create and a client create naming the
		// same string, overlapping, can both commit; the startup warning reports such a pair.
		clashingClient, err := database.GetClientByClientIdentifier(r.Context(), nil, createReq.ResourceIdentifier)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error checking client by resource identifier"), "resource_identifier", createReq.ResourceIdentifier)
			return
		}
		if clashingClient != nil {
			writeLocalizedError(w, r, i18n.NewLocalizedError(i18n.ErrCodeResourceIdentifierNamesClient, nil), "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Create resource
		resource := &record.Resource{
			ResourceIdentifier: strings.TrimSpace(createReq.ResourceIdentifier),
			Description:        strings.TrimSpace(createReq.Description),
		}
		if err := database.CreateResource(r.Context(), nil, resource); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error creating resource"), "resource_identifier", resource.ResourceIdentifier)
			return
		}

		// Audit log
		auditLogger.Log(r.Context(), audit.EventCreatedResource, map[string]interface{}{
			"resource_id":         resource.Id,
			"resource_identifier": resource.ResourceIdentifier,
			"logged_in_user":      callerSubject(r),
		})

		// Response
		response := api.CreateResourceResponse{
			Resource: *apimapping.ToResourceResponse(resource),
		}
		writeJSON(w, r, http.StatusCreated, response)
	}
}

// HandleResourceGet - GET /api/v1/admin/resources/{id}
func HandleResourceGet(
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

// HandleResourceUpdatePut - PUT /api/v1/admin/resources/{id}
func HandleResourceUpdatePut(
	database resourcesDatabase,
	identifierValidator *inputvalidation.IdentifierValidator,
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
			writeLocalizedError(w, r, i18n.NewLocalizedError(i18n.ErrCodeResourceIdentifierRequired, nil), "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Validate description length
		const maxLengthDescription = 100
		if inputvalidation.TextLength(updateReq.Description) > maxLengthDescription {
			writeLocalizedError(w, r, i18n.NewLocalizedError(i18n.ErrCodeResourceDescriptionTooLong, map[string]any{"max": maxLengthDescription}), "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		if validateNoAngleBracketsErr := accountvalidation.ValidateNoAngleBrackets(updateReq.Description, i18n.ErrCodeDescriptionAngleBrackets); validateNoAngleBracketsErr != nil {
			writeValidationError(w, r, validateNoAngleBracketsErr)
			return
		}

		// Validate identifier format
		if validateIdentifierErr := identifierValidator.Validate(updateReq.ResourceIdentifier, true); validateIdentifierErr != nil {
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
			writeLocalizedError(w, r, i18n.NewLocalizedError(i18n.ErrCodeResourceIdentifierInUse, nil), "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Apply changes
		trimmedResourceIdentifier := strings.TrimSpace(updateReq.ResourceIdentifier)

		// System-level resource protection: block identifier changes
		if resource.IsSystemLevelResource() && trimmedResourceIdentifier != resource.ResourceIdentifier {
			writeLocalizedError(w, r, i18n.NewLocalizedError(i18n.ErrCodeResourceSystemLevelIdentifierFixed, nil), "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// A new identifier may not name a client either (#151). The check fires only when the
		// request actually changes the identifier, so a row that already holds a collision,
		// from before this check existed, keeps its other edits: renaming either side is a
		// breaking change for the integrations using it.
		if trimmedResourceIdentifier != resource.ResourceIdentifier {
			clashingClient, err := database.GetClientByClientIdentifier(r.Context(), nil, trimmedResourceIdentifier)
			if err != nil {
				writeInternalServerError(w, r, errs.Wrap(err, "database error checking client by resource identifier for update"), "resource_identifier", updateReq.ResourceIdentifier, "resource_id", resource.Id)
				return
			}
			if clashingClient != nil {
				writeLocalizedError(w, r, i18n.NewLocalizedError(i18n.ErrCodeResourceIdentifierNamesClient, nil), "VALIDATION_ERROR", http.StatusBadRequest)
				return
			}
		}

		resource.ResourceIdentifier = trimmedResourceIdentifier
		resource.Description = strings.TrimSpace(updateReq.Description)

		if err := database.UpdateResource(r.Context(), nil, resource); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error updating resource"), "resource_id", resource.Id, "resource_identifier", resource.ResourceIdentifier)
			return
		}

		// Audit
		auditLogger.Log(r.Context(), audit.EventUpdatedResource, map[string]interface{}{
			"resource_id":         resource.Id,
			"resource_identifier": resource.ResourceIdentifier,
			"logged_in_user":      callerSubject(r),
		})

		// Response
		response := api.UpdateResourceResponse{
			Resource: *apimapping.ToResourceResponse(resource),
		}
		writeJSON(w, r, http.StatusOK, response)
	}
}

// HandleResourceDelete - DELETE /api/v1/admin/resources/{id}
func HandleResourceDelete(
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
			writeLocalizedError(w, r, i18n.NewLocalizedError(i18n.ErrCodeResourceSystemLevelDeleteNotAllowed, nil), "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		if err := database.DeleteResource(r.Context(), nil, resource.Id); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error deleting resource"), "resource_id", resource.Id, "resource_identifier", resource.ResourceIdentifier)
			return
		}

		auditLogger.Log(r.Context(), audit.EventDeletedResource, map[string]interface{}{
			"resource_id":         resource.Id,
			"resource_identifier": resource.ResourceIdentifier,
			"logged_in_user":      callerSubject(r),
		})

		resp := api.SuccessResponse{Success: true}
		writeJSON(w, r, http.StatusOK, resp)
	}
}
