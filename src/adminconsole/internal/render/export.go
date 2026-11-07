package render

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
)

// exportWriteTimeout is how long a user's export has to reach the browser, in place of the
// listener's 60 seconds: the auth server's own bound on writing it, since the console copies the
// answer on as it arrives (#781 decision 5).
const exportWriteTimeout = 5 * time.Minute

// LiftExportWriteDeadline and ServeExport are the one pass-through both downloads of a user's
// export share, the administrator's from a user's header and the user's own from Your data (#781
// decisions 5 and 7, #782 decision 3), so the two answers cannot drift apart. A handler lifts the
// deadline first, asks the auth server for the export, sends a failure to its classifier with
// nothing written, and hands a success to ServeExport.

// LiftExportWriteDeadline gives the answer five minutes to be written, in place of the listener's
// 60 seconds. It is called before the export is asked for, since the listener's bound runs from the
// request's arrival: on HTTP/2 its timer resets the stream once it fires, written to or not. A
// writer that takes no deadline, as a test's recorder does, keeps the listener's; any other failure
// is logged, and the answer still goes out under the listener's bound.
func LiftExportWriteDeadline(w http.ResponseWriter, r *http.Request) {
	err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(exportWriteTimeout))
	if err != nil && !errors.Is(err, http.ErrNotSupported) {
		slog.WarnContext(r.Context(), "unable to extend the write deadline", "error", err)
	}
}

// ServeExport copies the auth server's answer to the browser untouched, still compressed, with its
// Content-Encoding, so the browser unpacks it, its Content-Disposition, which names the file, and
// its Content-Length, under Cache-Control: no-store; the console never decodes or holds it whole.
// It closes the export's body. Once the copy has started the status is sent, so a copy cut short is
// only logged: the auth server writes the export's audit event either way, since the data has left
// it.
func ServeExport(w http.ResponseWriter, r *http.Request, export *apiclient.UserExport) {
	defer func() { _ = export.Body.Close() }()

	header := w.Header()
	header.Set("Cache-Control", "no-store")
	header.Set("Content-Type", export.ContentType)
	header.Set("Content-Disposition", export.ContentDisposition)
	if export.ContentEncoding != "" {
		header.Set("Content-Encoding", export.ContentEncoding)
	}
	if export.ContentLength != "" {
		header.Set("Content-Length", export.ContentLength)
	}
	w.WriteHeader(http.StatusOK)

	if _, err := io.Copy(w, export.Body); err != nil {
		slog.WarnContext(r.Context(), "user export copy ended early", "error", err)
	}
}
