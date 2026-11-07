package apihandlers

import (
	"context"
	"database/sql"
	"net/http"
	"time"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
)

// accountExportDatabase is what the account's own download reads: the caller's row by subject, and
// every part the administrator's export reads.
type accountExportDatabase interface {
	userExportDatabase

	GetUserBySubject(ctx context.Context, tx *sql.Tx, subject string) (*record.User, error)
}

// HandleAccountExportGet - GET /api/v1/account/export
//
// The caller's own data, as the administrator's download of them answers it, byte for byte but for
// the instant it was made (#782 decision 3): the document buildUserExport builds, which names no
// administrator who acted (decision 2) and leaves out the attributes no app receives (decision 8),
// written by writeUserExport, with five minutes to send it. Routes.go mounts
// RequireAdminConsoleClient, the step-up guard and the account_export tier in front of it, in that
// order. Once the answer has been sent, whether or not the caller received all of it,
// exported_own_user_data is written; a refused or failed download writes nothing (decision 4).
//
// baseURL is the auth server's own, which a legal document acceptance's address is built from.
func HandleAccountExportGet(database accountExportDatabase, auditLogger AuditLogger, baseURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		extendWriteDeadline(w, r, userExportWriteTimeout)

		_, subject, ok := accountCaller(w, r)
		if !ok {
			return
		}

		settings, ok := reqctx.SettingsFrom(r.Context())
		if !ok {
			writeInternalServerError(w, r, reqctx.ErrNoSettings)
			return
		}

		user, err := database.GetUserBySubject(r.Context(), nil, subject)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}
		if user == nil {
			writeJSONError(w, "User not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		document, err := buildUserExport(r.Context(), database, user, settings, baseURL, time.Now())
		if err != nil {
			writeInternalServerError(w, r, err, "user_id", user.Id)
			return
		}
		if !writeUserExport(w, r, document) {
			return
		}

		auditLogger.Log(r.Context(), audit.EventExportedOwnUserData, map[string]interface{}{
			"user_id":        user.Id,
			"logged_in_user": subject,
		})
	}
}
