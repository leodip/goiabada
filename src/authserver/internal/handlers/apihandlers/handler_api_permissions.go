package apihandlers

import (
    "encoding/json"
    "fmt"
    "log/slog"
    "net/http"
    "slices"
    "strconv"
    "strings"

    "github.com/go-chi/chi/v5"
    "github.com/leodip/goiabada/core/api"
    "github.com/leodip/goiabada/core/constants"
    "github.com/leodip/goiabada/core/data"
    "github.com/leodip/goiabada/core/inputsanitizer"
    "github.com/leodip/goiabada/core/models"
    "github.com/leodip/goiabada/core/validators"
    srvhandlers "github.com/leodip/goiabada/authserver/internal/handlers"
)

func HandleAPIPermissionsByResourceGet(
    database data.Database,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resourceIdStr := chi.URLParam(r, "resourceId")
		if len(resourceIdStr) == 0 {
			writeJSONError(w, "Resource ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		resourceId, err := strconv.ParseInt(resourceIdStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid resource ID format", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		permissions, err := database.GetPermissionsByResourceId(nil, resourceId)
		if err != nil {
			slog.Error("AuthServer API: Database error getting permissions", "error", err, "resourceId", resourceId)
			writeJSONError(w, "Database error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}

		// Ensure permissions is never nil
		if permissions == nil {
			permissions = []models.Permission{}
		}

		// Load resource information for each permission if we have any
		if len(permissions) > 0 {
			err = database.PermissionsLoadResources(nil, permissions)
			if err != nil {
				writeJSONError(w, "Failed to load resource information", "INTERNAL_ERROR", http.StatusInternalServerError)
				return
			}

			// Filter out the userinfo permission if the resource is authserver
			if permissions[0].Resource.ResourceIdentifier == constants.AuthServerResourceIdentifier {
				permissions = slices.DeleteFunc(permissions, func(p models.Permission) bool {
					return p.PermissionIdentifier == constants.UserinfoPermissionIdentifier
				})
			}
		}

		response := api.GetPermissionsByResourceResponse{
			Permissions: api.ToPermissionResponses(permissions),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(response)
	}
}

// HandleAPIResourcePermissionsPut - PUT /api/v1/admin/resources/{resourceId}/permissions
// Replaces the full set of permission definitions for a resource.
func HandleAPIResourcePermissionsPut(
    database data.Database,
    authHelper srvhandlers.AuthHelper,
    identifierValidator *validators.IdentifierValidator,
    inputSanitizer *inputsanitizer.InputSanitizer,
    auditLogger srvhandlers.AuditLogger,
) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        resourceIdStr := chi.URLParam(r, "resourceId")
        if len(resourceIdStr) == 0 {
            writeJSONError(w, "Resource ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
            return
        }

        resourceId, err := strconv.ParseInt(resourceIdStr, 10, 64)
        if err != nil {
            writeJSONError(w, "Invalid resource ID format", "VALIDATION_ERROR", http.StatusBadRequest)
            return
        }

        resource, err := database.GetResourceById(nil, resourceId)
        if err != nil {
            slog.Error("AuthServer API: Database error getting resource by ID for permissions update", "error", err, "resourceId", resourceId)
            writeJSONError(w, "Database error", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }
        if resource == nil {
            writeJSONError(w, "Resource not found", "NOT_FOUND", http.StatusNotFound)
            return
        }
        if resource.IsSystemLevelResource() {
            writeJSONError(w, "System level resources cannot be modified", "VALIDATION_ERROR", http.StatusBadRequest)
            return
        }

        var req api.UpdateResourcePermissionsRequest
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
            writeJSONError(w, "Invalid request body", "VALIDATION_ERROR", http.StatusBadRequest)
            return
        }

        // Deduplicate identifiers and validate entries
        seenIdentifiers := map[string]bool{}
        for i := range req.Permissions {
            // Trim inputs
            rawIdentifier := strings.TrimSpace(req.Permissions[i].PermissionIdentifier)
            rawDescription := strings.TrimSpace(req.Permissions[i].Description)

            // Explicitly forbid HTML angle brackets in description
            if strings.ContainsAny(rawDescription, "<>") {
                writeJSONError(w, "The description contains invalid characters, as we do not permit the use of HTML in the description.", "VALIDATION_ERROR", http.StatusBadRequest)
                return
            }

            // Sanitize description and enforce that it must not change (no HTML allowed)
            sanitizedDescription := inputSanitizer.Sanitize(rawDescription)
            if sanitizedDescription != rawDescription {
                writeJSONError(w, "The description contains invalid characters, as we do not permit the use of HTML in the description.", "VALIDATION_ERROR", http.StatusBadRequest)
                return
            }

            // Sanitize identifier (defensive) then validate format
            sanitizedIdentifier := inputSanitizer.Sanitize(rawIdentifier)

            if len(sanitizedIdentifier) == 0 {
                writeJSONError(w, "Permission identifier is required", "VALIDATION_ERROR", http.StatusBadRequest)
                return
            }

            if err := identifierValidator.ValidateIdentifier(sanitizedIdentifier, true); err != nil {
                writeValidationError(w, err)
                return
            }

            const maxLengthDescription = 100
            if len(sanitizedDescription) > maxLengthDescription {
                writeJSONError(w, fmt.Sprintf("The description cannot exceed a maximum length of %d characters.", maxLengthDescription), "VALIDATION_ERROR", http.StatusBadRequest)
                return
            }

            if seenIdentifiers[sanitizedIdentifier] {
                writeJSONError(w, fmt.Sprintf("Permission %s is duplicated.", sanitizedIdentifier), "VALIDATION_ERROR", http.StatusBadRequest)
                return
            }
            seenIdentifiers[sanitizedIdentifier] = true

            // Persist sanitized values back on request for subsequent operations
            req.Permissions[i].PermissionIdentifier = sanitizedIdentifier
            req.Permissions[i].Description = sanitizedDescription
        }

        // Load existing permissions once
        existing, err := database.GetPermissionsByResourceId(nil, resource.Id)
        if err != nil {
            slog.Error("AuthServer API: Database error getting existing permissions", "error", err, "resourceId", resource.Id)
            writeJSONError(w, "Database error", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }

        // Build a map for uniqueness checks
        existingById := map[int64]models.Permission{}
        existingByIdentifier := map[string]models.Permission{}
        for _, p := range existing {
            existingById[p.Id] = p
            existingByIdentifier[p.PermissionIdentifier] = p
        }

        // First update existing permissions (Id > 0)
        for _, p := range req.Permissions {
            if p.Id > 0 {
                cur, ok := existingById[p.Id]
                if !ok {
                    writeJSONError(w, "Permission not found", "NOT_FOUND", http.StatusNotFound)
                    return
                }
                // If changing identifier, ensure no conflict with another permission
                if other, exists := existingByIdentifier[p.PermissionIdentifier]; exists && other.Id != cur.Id {
                    writeJSONError(w, fmt.Sprintf("Permission identifier %s is already in use.", p.PermissionIdentifier), "VALIDATION_ERROR", http.StatusBadRequest)
                    return
                }

                cur.PermissionIdentifier = p.PermissionIdentifier
                cur.Description = p.Description
                if err := database.UpdatePermission(nil, &cur); err != nil {
                    slog.Error("AuthServer API: Database error updating permission", "error", err, "permissionId", cur.Id)
                    writeJSONError(w, "Failed to update permission", "INTERNAL_ERROR", http.StatusInternalServerError)
                    return
                }
                // reflect change in maps
                existingByIdentifier[p.PermissionIdentifier] = cur
                existingById[p.Id] = cur
            }
        }

        // Then create new permissions (Id <= 0)
        for _, p := range req.Permissions {
            if p.Id <= 0 {
                if _, exists := existingByIdentifier[p.PermissionIdentifier]; exists {
                    writeJSONError(w, fmt.Sprintf("Permission identifier %s is already in use.", p.PermissionIdentifier), "VALIDATION_ERROR", http.StatusBadRequest)
                    return
                }
                perm := &models.Permission{
                    ResourceId:           resource.Id,
                    PermissionIdentifier: p.PermissionIdentifier,
                    Description:          p.Description,
                }
                if err := database.CreatePermission(nil, perm); err != nil {
                    slog.Error("AuthServer API: Database error creating permission", "error", err, "resourceId", resource.Id)
                    writeJSONError(w, "Failed to create permission", "INTERNAL_ERROR", http.StatusInternalServerError)
                    return
                }
                existingByIdentifier[perm.PermissionIdentifier] = *perm
                existingById[perm.Id] = *perm
            }
        }

        // Delete any permissions that are no longer present (by identifier set)
        // Reload current permissions to be safe
        current, err := database.GetPermissionsByResourceId(nil, resource.Id)
        if err != nil {
            slog.Error("AuthServer API: Database error getting current permissions for deletion", "error", err, "resourceId", resource.Id)
            writeJSONError(w, "Database error", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }
        desiredIdentifiers := map[string]bool{}
        for _, p := range req.Permissions {
            desiredIdentifiers[p.PermissionIdentifier] = true
        }
        for _, existingPerm := range current {
            if !desiredIdentifiers[existingPerm.PermissionIdentifier] {
                if err := database.DeletePermission(nil, existingPerm.Id); err != nil {
                    slog.Error("AuthServer API: Database error deleting permission", "error", err, "permissionId", existingPerm.Id)
                    writeJSONError(w, "Failed to delete permission", "INTERNAL_ERROR", http.StatusInternalServerError)
                    return
                }
            }
        }

        // Audit consolidated update
        auditLogger.Log(constants.AuditUpdatedResourcePermissions, map[string]interface{}{
            "resourceId":   resource.Id,
            "loggedInUser": authHelper.GetLoggedInSubject(r),
        })

        // Respond success
        resp := api.SuccessResponse{Success: true}
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)
        _ = json.NewEncoder(w).Encode(resp)
    }
}

// Note: The previous validation endpoint [/resources/validate-permission] was removed.
