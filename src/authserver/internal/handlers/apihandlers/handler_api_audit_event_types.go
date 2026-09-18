package apihandlers

import (
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/core/api"
)

// HandleAPIAuditEventTypesGet - GET /api/v1/admin/audit-logs/event-types
//
// Serves the catalog of audit event names the auditEvent filter on GET /api/v1/admin/audit-logs
// accepts. The admin console's audit log viewer fills its filter dropdown from this rather than
// compiling the names in, so an audit event added here reaches that dropdown without the admin
// console being rebuilt (#351).
//
// The catalog is a declared list, so this handler has no failure of its own. It still declares
// 500 in openapi.yaml, because writeJSON buffers and answers 500 if the encode fails, and a
// generated client with no branch for it would meet that as an unmodelled error.
func HandleAPIAuditEventTypesGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authentication and authorization handled by middleware.
		// Requires scopesSettingsRead, the same read scope GET /api/v1/admin/audit-logs carries.

		response := api.GetAuditEventTypesResponse{
			AuditEventTypes: audit.AuditEventTypes,
		}

		writeJSON(w, r, http.StatusOK, response)
	}
}
