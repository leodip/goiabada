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
	"github.com/gorilla/csrf"
	"github.com/pkg/errors"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/oauth"
)

func HandleAdminClientLogoGet(
	httpHelper handlers.HttpHelper,
	apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "clientId")
		if len(idStr) == 0 {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("clientId is required")))
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
			return
		}

		clientResp, err := apiClient.GetClientById(jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if clientResp == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New(fmt.Sprintf("client %v not found", id))))
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
			"client":   clientResp,
			"logoUrl":  logoUrl,
			"csrfField": csrf.TemplateField(r),
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
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "Unauthorized",
			})
			return
		}

		clientIdStr := chi.URLParam(r, "clientId")
		clientId, err := strconv.ParseInt(clientIdStr, 10, 64)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "Invalid client ID",
			})
			return
		}

		if err := r.ParseMultipartForm(10 << 20); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "Failed to parse form: " + err.Error(),
			})
			return
		}

		file, header, err := r.FormFile("picture")
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "No picture file provided",
			})
			return
		}
		defer func() { _ = file.Close() }()

		logoData, err := io.ReadAll(file)
		if err != nil {
			httpHelper.InternalServerError(w, r, errors.Wrap(err, "failed to read logo data"))
			return
		}

		response, err := apiClient.UploadClientLogo(jwtInfo.TokenResponse.AccessToken, clientId, logoData, header.Filename)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			if apiErr, ok := err.(*apiclient.APIError); ok {
				w.WriteHeader(apiErr.StatusCode)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false,
					"error":   apiErr.Message,
				})
			} else {
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false,
					"error":   err.Error(),
				})
			}
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
	apiClient apiclient.ApiClient,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "Unauthorized",
			})
			return
		}

		clientIdStr := chi.URLParam(r, "clientId")
		clientId, err := strconv.ParseInt(clientIdStr, 10, 64)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "Invalid client ID",
			})
			return
		}

		err = apiClient.DeleteClientLogo(jwtInfo.TokenResponse.AccessToken, clientId)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			if apiErr, ok := err.(*apiclient.APIError); ok {
				w.WriteHeader(apiErr.StatusCode)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false,
					"error":   apiErr.Message,
				})
			} else {
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false,
					"error":   err.Error(),
				})
			}
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
		})
	}
}
