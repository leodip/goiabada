package adminuserhandlers

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
)

// userExportWriteTimeout is how long the export has to reach the browser, in place of the
// listener's 60 seconds: the auth server's own bound on writing it, since the console copies the
// answer on as it arrives (#781 decision 5).
const userExportWriteTimeout = 5 * time.Minute

// userExportAPI is what the user header's Download data button needs: the user's export.
type userExportAPI interface {
	GetUserExport(ctx context.Context, accessToken string, userId int64) (*apiclient.UserExport, error)
}

// HandleExportPost answers the Download data form with the user's export, their data as one JSON
// document the browser saves (#781 decision 7). The auth server's answer is copied
// to the browser untouched, still compressed, with its Content-Encoding, so the browser unpacks it,
// and its Content-Disposition, which names the file; the console never decodes or holds it whole
// (decision 5). It is a form's POST rather than a link because the origin check covers unsafe
// methods only, and the session cookie rides another site's link: a forged download would put the
// person's data on the administrator's disk and audit an export in the administrator's name.
//
// A failed call goes through the API error classifier, before anything is written. Once the copy
// has started the status is sent, so a copy cut short is only logged; the auth server writes the
// export's audit event either way, since the data has left it.
func HandleExportPost(
	httpHelper HttpHelper,
	apiClient userExportAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		extendWriteDeadline(w, r, userExportWriteTimeout)

		id, err := strconv.ParseInt(r.PathValue("userId"), 10, 64)
		if err != nil {
			httpHelper.NotFound(w, r)
			return
		}

		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		export, err := apiClient.GetUserExport(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}
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
			slog.WarnContext(r.Context(), "user export copy ended early", "error", err, "user_id", id)
		}
	}
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
