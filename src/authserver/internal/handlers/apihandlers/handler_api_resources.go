package apihandlers

import (
    "encoding/json"
    "log/slog"
    "net/http"
    "sort"
    "strconv"
    "strings"

    "github.com/go-chi/chi/v5"
    "github.com/leodip/goiabada/authserver/internal/handlers"
    "github.com/leodip/goiabada/core/api"
    "github.com/leodip/goiabada/core/constants"
    "github.com/leodip/goiabada/core/data"
    "github.com/leodip/goiabada/core/handlerhelpers"
    "github.com/leodip/goiabada/core/inputsanitizer"
    "github.com/leodip/goiabada/core/models"
    "github.com/leodip/goiabada/core/validators"
)

func HandleAPIResourcesGet(
    httpHelper *handlerhelpers.HttpHelper,
    database data.Database,
) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        resources, err := database.GetAllResources(nil)
        if err != nil {
            slog.Error("AuthServer API: Database error getting all resources", "error", err)
            writeJSONError(w, "Failed to retrieve resources", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }

        // Sort resources by identifier for consistent ordering
        sort.Slice(resources, func(i, j int) bool {
            return resources[i].ResourceIdentifier < resources[j].ResourceIdentifier
        })

        response := api.GetResourcesResponse{
            Resources: api.ToResourceResponses(resources),
        }

        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)
        json.NewEncoder(w).Encode(response)
    }
}

// HandleAPIResourceCreatePost - POST /api/v1/admin/resources
func HandleAPIResourceCreatePost(
    httpHelper handlers.HttpHelper,
    authHelper handlers.AuthHelper,
    database data.Database,
    identifierValidator *validators.IdentifierValidator,
    inputSanitizer *inputsanitizer.InputSanitizer,
    auditLogger handlers.AuditLogger,
) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        var createReq api.CreateResourceRequest
        if err := json.NewDecoder(r.Body).Decode(&createReq); err != nil {
            writeJSONError(w, "Invalid request body", "INVALID_REQUEST", http.StatusBadRequest)
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

        // Validate identifier format
        if err := identifierValidator.ValidateIdentifier(createReq.ResourceIdentifier, true); err != nil {
            writeValidationError(w, err)
            return
        }

        // Check uniqueness
        existing, err := database.GetResourceByResourceIdentifier(nil, createReq.ResourceIdentifier)
        if err != nil {
            slog.Error("AuthServer API: Database error checking resource by identifier", "error", err, "resourceIdentifier", createReq.ResourceIdentifier)
            writeJSONError(w, "Failed to check resource existence", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }
        if existing != nil {
            writeJSONError(w, "The resource identifier is already in use", "VALIDATION_ERROR", http.StatusBadRequest)
            return
        }

        // Create resource
        resource := &models.Resource{
            ResourceIdentifier: strings.TrimSpace(inputSanitizer.Sanitize(createReq.ResourceIdentifier)),
            Description:        strings.TrimSpace(inputSanitizer.Sanitize(createReq.Description)),
        }
        if err := database.CreateResource(nil, resource); err != nil {
            slog.Error("AuthServer API: Database error creating resource", "error", err, "resourceIdentifier", resource.ResourceIdentifier)
            writeJSONError(w, "Failed to create resource", "INTERNAL_ERROR", http.StatusInternalServerError)
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
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusCreated)
        httpHelper.EncodeJson(w, r, response)
    }
}

// HandleAPIResourceGet - GET /api/v1/admin/resources/{id}
func HandleAPIResourceGet(
    httpHelper handlers.HttpHelper,
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
            slog.Error("AuthServer API: Database error getting resource by ID", "error", err, "resourceId", id)
            writeJSONError(w, "Failed to get resource", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }
        if resource == nil {
            writeJSONError(w, "Resource not found", "NOT_FOUND", http.StatusNotFound)
            return
        }

        response := api.GetResourceResponse{
            Resource: *api.ToResourceResponse(resource),
        }
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)
        httpHelper.EncodeJson(w, r, response)
    }
}

// HandleAPIResourceUpdatePut - PUT /api/v1/admin/resources/{id}
func HandleAPIResourceUpdatePut(
    httpHelper handlers.HttpHelper,
    authHelper handlers.AuthHelper,
    database data.Database,
    identifierValidator *validators.IdentifierValidator,
    inputSanitizer *inputsanitizer.InputSanitizer,
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
            slog.Error("AuthServer API: Database error getting resource by ID for update", "error", err, "resourceId", id)
            writeJSONError(w, "Failed to get resource", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }
        if resource == nil {
            writeJSONError(w, "Resource not found", "NOT_FOUND", http.StatusNotFound)
            return
        }

        // System-level resources cannot be modified
        if resource.IsSystemLevelResource() {
            writeJSONError(w, "cannot update settings for a system level resource", "VALIDATION_ERROR", http.StatusBadRequest)
            return
        }

        var updateReq api.UpdateResourceRequest
        if err := json.NewDecoder(r.Body).Decode(&updateReq); err != nil {
            writeJSONError(w, "Invalid request body", "INVALID_REQUEST", http.StatusBadRequest)
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

        // Validate identifier format
        if err := identifierValidator.ValidateIdentifier(updateReq.ResourceIdentifier, true); err != nil {
            writeValidationError(w, err)
            return
        }

        // Uniqueness check (excluding this resource)
        existing, err := database.GetResourceByResourceIdentifier(nil, updateReq.ResourceIdentifier)
        if err != nil {
            slog.Error("AuthServer API: Database error checking resource by identifier for update", "error", err, "resourceIdentifier", updateReq.ResourceIdentifier, "resourceId", resource.Id)
            writeJSONError(w, "Failed to check resource existence", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }
        if existing != nil && existing.Id != resource.Id {
            writeJSONError(w, "The resource identifier is already in use", "VALIDATION_ERROR", http.StatusBadRequest)
            return
        }

        // Apply changes
        resource.ResourceIdentifier = strings.TrimSpace(inputSanitizer.Sanitize(updateReq.ResourceIdentifier))
        resource.Description = strings.TrimSpace(inputSanitizer.Sanitize(updateReq.Description))

        if err := database.UpdateResource(nil, resource); err != nil {
            slog.Error("AuthServer API: Database error updating resource", "error", err, "resourceId", resource.Id, "resourceIdentifier", resource.ResourceIdentifier)
            writeJSONError(w, "Failed to update resource", "INTERNAL_ERROR", http.StatusInternalServerError)
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
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)
        httpHelper.EncodeJson(w, r, response)
    }
}
