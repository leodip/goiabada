package apihandlers

import (
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/handlers"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/data"
)

func HandleAPIGroupsGet(
	httpHelper handlers.HttpHelper,
	database data.Database,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		groups, err := database.GetAllGroups(nil)
		if err != nil {
			writeJSONError(w, "Failed to get groups", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}

		response := api.GetGroupsResponse{
			Groups: api.ToGroupResponses(groups),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		httpHelper.EncodeJson(w, r, response)
	}
}