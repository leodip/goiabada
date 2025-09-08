package apihandlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/leodip/goiabada/authserver/internal/handlers"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/data"
)

func HandleAPIUsersSearchGet(
	httpHelper handlers.HttpHelper,
	database data.Database,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authentication and authorization handled by middleware
		// Token is available in context if needed via GetValidatedToken(r)

		// Parse query parameters
		pageStr := r.URL.Query().Get("page")
		sizeStr := r.URL.Query().Get("size")
		query := r.URL.Query().Get("query")
		annotateGroupMembershipStr := r.URL.Query().Get("annotateGroupMembership")

		// Default values
		page := 1
		size := 10

		// Parse page
		if pageStr != "" {
			if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
				page = p
			}
		}

		// Parse size with reasonable limits
		if sizeStr != "" {
			if s, err := strconv.Atoi(sizeStr); err == nil && s > 0 && s <= 200 {
				size = s
			}
		}

		// Search users
		users, total, err := database.SearchUsersPaginated(nil, query, page, size)
		if err != nil {
			slog.Error("AuthServer API: failed to search users", "error", err, "query", query, "page", page)
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}

		// Handle group membership annotation if requested
		if annotateGroupMembershipStr != "" {
			annotateGroupId, err := strconv.ParseInt(annotateGroupMembershipStr, 10, 64)
			if err != nil {
				writeJSONError(w, "Invalid annotateGroupMembership value", "VALIDATION_ERROR", http.StatusBadRequest)
				return
			}

			// Verify group exists
			group, err := database.GetGroupById(nil, annotateGroupId)
			if err != nil {
				slog.Error("AuthServer API: failed to get group by ID", "error", err, "groupId", annotateGroupId, "query", query, "page", page)
				writeJSONError(w, "Failed to get group", "INTERNAL_ERROR", http.StatusInternalServerError)
				return
			}
			if group == nil {
				writeJSONError(w, "Group not found", "NOT_FOUND", http.StatusNotFound)
				return
			}

			// Load groups for all users to check membership
			err = database.UsersLoadGroups(nil, users)
			if err != nil {
				slog.Error("AuthServer API: failed to load user groups", "error", err, "userCount", len(users), "query", query, "page", page)
				writeJSONError(w, "Failed to load user groups", "INTERNAL_ERROR", http.StatusInternalServerError)
				return
			}

			// Create annotated response
			annotatedUsers := make([]api.UserWithGroupMembershipResponse, len(users))
			for i, user := range users {
				inGroup := false
				for _, userGroup := range user.Groups {
					if userGroup.Id == annotateGroupId {
						inGroup = true
						break
					}
				}
				annotatedUsers[i] = api.UserWithGroupMembershipResponse{
					UserResponse: *api.ToUserResponse(&user),
					InGroup:      inGroup,
				}
			}

			annotatedResponse := api.SearchUsersWithGroupAnnotationResponse{
				Users: annotatedUsers,
				Total: total,
				Page:  page,
				Size:  size,
				Query: query,
			}

			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(annotatedResponse); err != nil {
				writeJSONError(w, "Failed to encode response", "ENCODING_ERROR", http.StatusInternalServerError)
				return
			}
			return
		}

		// Create standard response
		response := api.SearchUsersResponse{
			Users: api.ToUserResponses(users),
			Total: total,
			Page:  page,
			Size:  size,
			Query: query,
		}

		// Set content type and encode response
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			writeJSONError(w, "Failed to encode response", "ENCODING_ERROR", http.StatusInternalServerError)
			return
		}
	}
}