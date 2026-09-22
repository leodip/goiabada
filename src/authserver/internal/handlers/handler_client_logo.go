package handlers

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/authserver/internal/models"
)

// clientLogoDatabase is what the client logo page needs: the client and its logo.
type clientLogoDatabase interface {
	GetClientByClientIdentifier(ctx context.Context, tx *sql.Tx, clientIdentifier string) (*models.Client, error)
	GetClientLogoByClientId(ctx context.Context, tx *sql.Tx, clientId int64) (*models.ClientLogo, error)
}

func HandleClientLogoGet(
	httpHelper HttpHelper,
	database clientLogoDatabase,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		clientIdentifier := chi.URLParam(r, "clientIdentifier")
		if len(clientIdentifier) == 0 {
			http.NotFound(w, r)
			return
		}

		client, err := database.GetClientByClientIdentifier(r.Context(), nil, clientIdentifier)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		if client == nil {
			http.NotFound(w, r)
			return
		}

		clientLogo, err := database.GetClientLogoByClientId(r.Context(), nil, client.Id)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		if clientLogo == nil {
			http.NotFound(w, r)
			return
		}

		// Compute ETag from content hash (truncated SHA-256)
		hash := sha256.Sum256(clientLogo.Logo)
		etag := fmt.Sprintf("\"%x\"", hash[:8])

		// Check If-None-Match header
		ifNoneMatch := r.Header.Get("If-None-Match")
		if ifNoneMatch != "" {
			entries := strings.Split(ifNoneMatch, ",")
			for _, entry := range entries {
				entry = strings.TrimSpace(entry)
				// Strip weak tag prefix
				entry = strings.TrimPrefix(entry, "W/")
				if entry == etag || entry == "*" {
					w.Header().Set("ETag", etag)
					w.Header().Set("Cache-Control", "public, max-age=300, must-revalidate")
					w.WriteHeader(http.StatusNotModified)
					return
				}
			}
		}

		w.Header().Set("Content-Type", clientLogo.ContentType)
		w.Header().Set("ETag", etag)
		w.Header().Set("Cache-Control", "public, max-age=300, must-revalidate")
		w.Header().Set("Content-Length", strconv.Itoa(len(clientLogo.Logo)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(clientLogo.Logo)
	}
}
