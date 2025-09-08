package apihandlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"sort"

	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/handlerhelpers"
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