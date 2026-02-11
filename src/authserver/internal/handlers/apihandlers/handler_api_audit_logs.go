package apihandlers

import (
	"log/slog"
	"net/http"
	"strconv"

	"github.com/leodip/goiabada/authserver/internal/handlers"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/data"
)

func HandleAPIAuditLogsGet(
	httpHelper handlers.HttpHelper,
	database data.Database,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authentication and authorization handled by middleware
		// Requires scopesSettingsRead permission

		// Parse query parameters
		pageStr := r.URL.Query().Get("page")
		sizeStr := r.URL.Query().Get("size")
		auditEvent := r.URL.Query().Get("auditEvent")

		// Default values
		page := 1
		size := 20

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

		// Get audit logs
		auditLogs, total, err := database.GetAuditLogsPaginated(nil, page, size, auditEvent)
		if err != nil {
			slog.Error("AuthServer API: failed to get audit logs", "error", err, "page", page, "size", size, "auditEvent", auditEvent)
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}

		// Convert to response format
		auditLogResponses := make([]api.AuditLogResponse, len(auditLogs))
		for i, log := range auditLogs {
			auditLogResponses[i] = api.AuditLogResponse{
				Id:         log.Id,
				CreatedAt:  log.CreatedAt.Format("2006-01-02T15:04:05Z07:00"), // ISO 8601
				AuditEvent: log.AuditEvent,
				Details:    log.Details, // JSON string
			}
		}

		response := api.GetAuditLogsResponse{
			AuditLogs: auditLogResponses,
			Total:     total,
			Page:      page,
			Size:      size,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		httpHelper.EncodeJson(w, r, response)
	}
}
