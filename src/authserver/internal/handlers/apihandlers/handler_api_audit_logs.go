package apihandlers

import (
	"context"
	"database/sql"
	"net/http"
	"strconv"

	"github.com/leodip/goiabada/authserver/internal/apimapping"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/logging"
)

// auditLogsDatabase is what the audit log endpoint needs: one page of records.
type auditLogsDatabase interface {
	GetAuditLogsPaginated(ctx context.Context, tx *sql.Tx, page int, pageSize int, filter record.AuditLogFilter) ([]record.AuditLog, int, error)
}

func HandleAuditLogsGet(
	database auditLogsDatabase,
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

		// The user filter lists the rows about that user or made by them. A value that is not a
		// positive integer is refused rather than ignored as page and size are: ignored, it
		// would list every user's events under a filter the caller believes is set (#780
		// decision 3). An empty value is refused too: only an absent parameter sets no filter.
		var userId int64
		if query := r.URL.Query(); query.Has("userId") {
			id, err := strconv.ParseInt(query.Get("userId"), 10, 64)
			if err != nil || id <= 0 {
				writeJSONError(w, "Invalid userId value", "VALIDATION_ERROR", http.StatusBadRequest)
				return
			}
			userId = id
		}

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
		auditLogs, total, err := database.GetAuditLogsPaginated(r.Context(), nil, page, size,
			record.AuditLogFilter{AuditEvent: auditEvent, RequestId: requestId, UserId: userId})
		if err != nil {
			// Both filter values are client-chosen, so both go on the record through
			// FieldForLog: without it a multi-kilobyte auditEvent lands whole, carrying
			// whatever control characters or line separators it was sent with, which is the
			// log injection this tree closed for every other client-chosen scalar (#159).
			// filter_request_id and not request_id because that name is the handler's own,
			// injected from the context; this is what the caller asked to filter by (#328).
			writeInternalServerError(w, r, errs.Wrap(err, "failed to get audit logs"),
				"page", page, "size", size,
				"audit_event", logging.FieldForLog(auditEvent),
				"filter_request_id", logging.FieldForLog(requestId),
				"filter_user_id", userId)
			return
		}

		// Convert to response format
		auditLogResponses := make([]api.AuditLogResponse, len(auditLogs))
		for i := range auditLogs {
			auditLogResponses[i] = apimapping.ToAuditLogResponse(&auditLogs[i])
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
