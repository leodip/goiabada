package handlers

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/leodip/goiabada/authserver/internal/record"
)

// clientLogoDatabase is what the client logo page needs: the client and its logo.
type clientLogoDatabase interface {
	GetClientByClientIdentifier(ctx context.Context, tx *sql.Tx, clientIdentifier string) (*record.Client, error)
	GetClientLogoByClientID(ctx context.Context, tx *sql.Tx, clientID int64) (*record.ClientLogo, error)
}

// HandleClientLogoGet answers a client's logo, to anyone, kept five minutes and revalidated by its
// ETag. A client that does not exist, or one with no logo, is not found, and that answer is no-store
// (ResourceNotFound).
func HandleClientLogoGet(
	pageRenderer PageRenderer,
	database clientLogoDatabase,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		clientIdentifier := r.PathValue("clientIdentifier")
		if len(clientIdentifier) == 0 {
			ResourceNotFound(w, r)
			return
		}

		client, err := database.GetClientByClientIdentifier(r.Context(), nil, clientIdentifier)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}

		if client == nil {
			ResourceNotFound(w, r)
			return
		}

		clientLogo, err := database.GetClientLogoByClientID(r.Context(), nil, client.ID)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}

		if clientLogo == nil {
			ResourceNotFound(w, r)
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
		//nolint:gosec // G705: image bytes under the image content type the upload validated, and nosniff is set at the root
		_, _ = w.Write(clientLogo.Logo)
	}
}
