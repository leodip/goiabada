package accounthandlers

import (
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/middleware"
)

// maxAuditedClientIPLength bounds the client IP an emailed-link refusal writes to its audit entry.
const maxAuditedClientIPLength = 100

// auditedClientIP is the client IP both emailed-link flows record on a refused link, read through
// the module's one reader and truncated.
//
// Truncated because httpmw.RealIP resolves the IP from a forwarded header in a proxied
// deployment, so an audit entry naming it is a sink for a value that originates outside the
// process. One helper for both flows, so the reset and activation entries cannot bound the same
// value differently (#435).
func auditedClientIP(r *http.Request) string {
	clientIP := middleware.ClientIP(r)
	if len(clientIP) > maxAuditedClientIPLength {
		clientIP = clientIP[:maxAuditedClientIPLength]
	}
	return clientIP
}
