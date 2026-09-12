package apihandlers

import (
	"net/http"
	"strconv"

	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/logging"
)

func HandleAPIAuditLogsGet(
	database data.Database,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authentication and authorization handled by middleware
		// Requires scopesSettingsRead permission

		// Parse query parameters
		pageStr := r.URL.Query().Get("page")
		sizeStr := r.URL.Query().Get("size")
		auditEvent := r.URL.Query().Get("auditEvent")
		// Exact match, as auditEvent is: the id an operator holds came off one log record, so
		// a prefix or a fold would list a different request's events under it (#328).
		requestId := r.URL.Query().Get("requestId")

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
		auditLogs, total, err := database.GetAuditLogsPaginated(nil, page, size, auditEvent, requestId)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "AuthServer API: failed to get audit logs"), "page", page, "size", size, "audit_event", auditEvent,
				// Not request_id: that name is the handler's own, injected from the context.
				// This is what the caller asked to filter by, and it is client-chosen, so it
				// is bounded and escaped the way every other such value on a record is (#328).
				"filter_request_id", logging.FieldForLog(requestId))
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
				RequestId:  log.RequestId,
			}
		}

		response := api.GetAuditLogsResponse{
			AuditLogs: auditLogResponses,
			Total:     total,
			Page:      page,
			Size:      size,
		}

		writeJSON(w, r, http.StatusOK, response)
	}
}
