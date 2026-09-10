package adminclienthandlers

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
)

// The error surface here answers through the console's shared JSON writers rather than the
// hand-rolled {"success": false, "error": <message>} these handlers wrote until #279, which put an
// internal message on the wire at 500 with nothing in the log, answered 401 for the middleware
// invariant the other 100 sites answer 500 for, and rendered the HTML 500 page into a fetch() that
// was about to call response.json(). The success bodies are unchanged.
func HandleAdminClientLogoGet(
	httpHelper handlers.HttpHelper,
	apiClient apiclient.ApiClient,
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

		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errs.New("no JWT info found in context"))
			return
		}

		clientResp, err := apiClient.GetClientById(jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if clientResp == nil {
			httpHelper.NotFound(w, r)
			return
		}

		var logoUrl string
		logoInfo, err := apiClient.GetClientLogo(jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			slog.Warn("Failed to fetch client logo info", "error", err, "clientId", id)
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
	apiClient apiclient.ApiClient,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
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

		if err := r.ParseMultipartForm(10 << 20); err != nil {
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

		response, err := apiClient.UploadClientLogo(jwtInfo.TokenResponse.AccessToken, clientId, logoData, header.Filename)
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
	apiClient apiclient.ApiClient,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
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

		err = apiClient.DeleteClientLogo(jwtInfo.TokenResponse.AccessToken, clientId)
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
