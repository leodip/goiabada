package adminclienthandlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/core/api"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/constants"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/core/errs"
)

// clientLogoAPI is what the client logo page needs: the client, and the logo it reads, uploads
// and deletes.
type clientLogoAPI interface {
	DeleteClientLogo(ctx context.Context, accessToken string, clientId int64) error
	GetClientById(ctx context.Context, accessToken string, clientId int64) (*api.ClientResponse, error)
	GetClientLogo(ctx context.Context, accessToken string, clientId int64) (*apiclient.ClientLogoInfo, error)
	UploadClientLogo(ctx context.Context, accessToken string, clientId int64, logoData []byte, filename string) (*apiclient.ClientLogoUploadResponse, error)
}

// The error surface here answers through the console's shared JSON writers rather than the
// hand-rolled {"success": false, "error": <message>} these handlers wrote until #279, which put an
// internal message on the wire at 500 with nothing in the log, answered 401 for the middleware
// invariant the other 100 sites answer 500 for, and rendered the HTML 500 page into a fetch() that
// was about to call response.json(). The success bodies are unchanged.
func HandleAdminClientLogoGet(
	httpHelper handlers.HttpHelper,
	apiClient clientLogoAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "clientId")
		if len(idStr) == 0 {
			httpHelper.NotFound(w, r)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.NotFound(w, r)
			return
		}

		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauthclient.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errs.New("no JWT info found in context"))
			return
		}

		clientResp, err := apiClient.GetClientById(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if clientResp == nil {
			httpHelper.NotFound(w, r)
			return
		}

		var logoUrl string
		logoInfo, err := apiClient.GetClientLogo(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			// The page renders without the logo, but not past a 401: the administrator's session
			// has ended, and nothing on the page would work (#427 decision 17).
			if handlers.IsSessionEnded(err) {
				handlers.HandleAPIError(httpHelper, w, r, err)
				return
			}
			slog.WarnContext(r.Context(), "unable to fetch the client logo info", "error", err, "client_id", id)
		} else if logoInfo != nil && logoInfo.HasLogo {
			logoUrl = fmt.Sprintf("%s?t=%d", logoInfo.LogoUrl, time.Now().UnixNano())
		}

		bind := map[string]interface{}{
			"client":  clientResp,
			"logoUrl": logoUrl,
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_logo.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminClientLogoPost(
	httpHelper handlers.HttpHelper,
	apiClient clientLogoAPI,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauthclient.JwtInfo)
		if !ok {
			httpHelper.JsonError(w, r, errs.New("no JWT info found in context"))
			return
		}

		clientIdStr := chi.URLParam(r, "clientId")
		clientId, err := strconv.ParseInt(clientIdStr, 10, 64)
		if err != nil {
			handlers.JsonNotFound(httpHelper, w, r)
			return
		}

		// The body is bounded before it gets here, by uploadBodyLimit in the server's
		// request-body table (#426). The argument is not a limit: it is how much of the form is
		// held in memory before the rest spills to temporary files.
		//nolint:gosec // G120: bounded by uploadBodyLimit, as above; G120 flags every multipart parse
		if parseFormErr := r.ParseMultipartForm(10 << 20); parseFormErr != nil {
			handlers.JsonBadRequestBody(httpHelper, w, r)
			return
		}

		file, header, err := r.FormFile("picture")
		if err != nil {
			handlers.JsonBadRequestBody(httpHelper, w, r)
			return
		}
		defer func() { _ = file.Close() }()

		logoData, err := io.ReadAll(file)
		if err != nil {
			httpHelper.JsonError(w, r, errs.Wrap(err, "failed to read logo data"))
			return
		}

		response, err := apiClient.UploadClientLogo(r.Context(), jwtInfo.TokenResponse.AccessToken, clientId, logoData, header.Filename)
		if err != nil {
			handlers.HandleAPIErrorJson(httpHelper, w, r, err)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success":    true,
			"pictureUrl": response.PictureUrl,
		})
	}
}

func HandleAdminClientLogoDelete(
	httpHelper handlers.HttpHelper,
	apiClient clientLogoAPI,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauthclient.JwtInfo)
		if !ok {
			httpHelper.JsonError(w, r, errs.New("no JWT info found in context"))
			return
		}

		clientIdStr := chi.URLParam(r, "clientId")
		clientId, err := strconv.ParseInt(clientIdStr, 10, 64)
		if err != nil {
			handlers.JsonNotFound(httpHelper, w, r)
			return
		}

		err = apiClient.DeleteClientLogo(r.Context(), jwtInfo.TokenResponse.AccessToken, clientId)
		if err != nil {
			handlers.HandleAPIErrorJson(httpHelper, w, r, err)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
		})
	}
}
