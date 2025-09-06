package apihandlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"slices"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/handlerhelpers"
	"github.com/leodip/goiabada/core/models"
)

func HandleAPIPermissionsByResourceGet(
	httpHelper *handlerhelpers.HttpHelper,
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
		json.NewEncoder(w).Encode(response)
	}
}