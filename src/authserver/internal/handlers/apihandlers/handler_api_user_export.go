package apihandlers

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/internal/userexport"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
)

// The export of everything held about one user (#781): one JSON document, built whole by
// userexport.Build, named for download and sent as every admin API answer is, buffered, so any
// failure is a clean 500 (decision 5). Only a token reaching both the users and the settings
// domain gets here, since the document holds the user's audit events (decision 1); routes.go
// mounts that check.

// userExportWriteTimeout is how long the export's answer has to reach the caller, in place of the
// listener's 60 seconds: 30,000 audit events are 12.6 MB as JSON, and a slow connection still
// finishes (decision 5).
const userExportWriteTimeout = 5 * time.Minute

// userExportDatabase is what the export reads.
type userExportDatabase interface {
	GetUserById(ctx context.Context, tx *sql.Tx, userId int64) (*record.User, error)
}

// HandleUserExportGet - GET /api/v1/admin/users/{id}/export
func HandleUserExportGet(database userExportDatabase, auditLogger AuditLogger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		extendWriteDeadline(w, r, userExportWriteTimeout)

		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid user ID format", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		settings, ok := reqctx.SettingsFrom(r.Context())
		if !ok {
			writeInternalServerError(w, r, reqctx.ErrNoSettings)
			return
		}

		user, err := database.GetUserById(r.Context(), nil, id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting user by ID for the export"), "user_id", id)
			return
		}
		if user == nil {
			writeJSONError(w, "User not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		document := userexport.Build(user, settings.Issuer, time.Now())
		if !writeUserExport(w, r, document) {
			return
		}

		// Once the answer has been sent, whether or not the caller received all of it: the data
		// has left the server either way (decision 8).
		auditLogger.Log(r.Context(), audit.EventExportedUserData, map[string]interface{}{
			"user_id":        user.Id,
			"logged_in_user": callerSubject(r),
		})
	}
}

// writeUserExport answers the document as a file to save: JSON, gzip-compressed when the request
// accepts gzip, named user-<id>-<date>.json. The whole body is encoded and compressed before the
// header, so a failure is the API's 500 rather than a cut file. ok false means a 500 was answered.
func writeUserExport(w http.ResponseWriter, r *http.Request, document api.UserExportResponse) (ok bool) {
	var body bytes.Buffer
	if err := json.NewEncoder(&body).Encode(document); err != nil {
		writeInternalServerError(w, r, errs.Wrap(err, "unable to encode the user export"), "user_id", document.Identifiers.Id)
		return false
	}

	header := w.Header()
	header.Add("Vary", "Accept-Encoding")
	if acceptsGzip(r) {
		var compressed bytes.Buffer
		zw := gzip.NewWriter(&compressed)
		_, err := zw.Write(body.Bytes())
		if err == nil {
			err = zw.Close()
		}
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "unable to compress the user export"), "user_id", document.Identifiers.Id)
			return false
		}
		body = compressed
		header.Set("Content-Encoding", "gzip")
	}

	header.Set("Content-Type", "application/json")
	header.Set("Content-Disposition", `attachment; filename="`+userexport.FileName(document.Identifiers.Id, document.ExportedAt)+`"`)
	header.Set("Content-Length", strconv.Itoa(body.Len()))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body.Bytes())
	return true
}

// extendWriteDeadline gives this answer until timeout from now to be written, past the listener's
// write timeout. A writer that takes no deadline, as a test's recorder does, keeps the listener's;
// any other failure is logged, and the answer still goes out under the listener's bound.
func extendWriteDeadline(w http.ResponseWriter, r *http.Request, timeout time.Duration) {
	err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(timeout))
	if err != nil && !errors.Is(err, http.ErrNotSupported) {
		slog.WarnContext(r.Context(), "unable to extend the write deadline", "error", err)
	}
}

// acceptsGzip reports whether the request's Accept-Encoding allows a gzip-coded answer, read as RFC
// 9110 section 12.5.3 defines the field: each member is a coding with an optional weight, a weight
// of 0 makes that coding not acceptable, and "*" stands for any coding the field does not name.
// Section 8.4.1.3 has a recipient treat x-gzip as gzip. No field, or one naming neither gzip nor
// "*", leaves gzip out: an answer is sent plain unless the caller asked for gzip. A weight that is
// not a number is read as 0, so a malformed field never earns a compressed answer.
func acceptsGzip(r *http.Request) bool {
	gzipWeight, anyWeight := -1.0, -1.0
	for _, line := range r.Header.Values("Accept-Encoding") {
		for _, member := range strings.Split(line, ",") {
			coding, parameters, _ := strings.Cut(member, ";")
			coding = strings.ToLower(strings.TrimSpace(coding))
			weight := 1.0
			for _, parameter := range strings.Split(parameters, ";") {
				name, value, found := strings.Cut(parameter, "=")
				if !found || !strings.EqualFold(strings.TrimSpace(name), "q") {
					continue
				}
				parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
				if err != nil {
					parsed = 0
				}
				weight = parsed
			}
			switch coding {
			case "gzip", "x-gzip":
				gzipWeight = max(gzipWeight, weight)
			case "*":
				anyWeight = max(anyWeight, weight)
			}
		}
	}
	if gzipWeight >= 0 {
		return gzipWeight > 0
	}
	return anyWeight > 0
}
