package handlers

import (
	"context"
	"database/sql"
	"net/http"
	"strconv"

	"github.com/leodip/goiabada/authserver/internal/record"
)

// brandAssetDatabase is what a brand asset's public answer needs: the asset with its bytes.
type brandAssetDatabase interface {
	GetBrandAssetById(ctx context.Context, tx *sql.Tx, assetId int64) (*record.BrandAsset, error)
}

// HandleBrandAssetGet answers a brand asset's bytes, at brandasset.Route, to anyone, as a static
// file is answered (#813 decision 2): under the type its upload was validated as, with nosniff,
// kept for a year when the request names its current fingerprint and five minutes otherwise, as a
// brand's stylesheet is. An asset that does not exist is not found. Whether a brand uses the
// asset is not asked: its URL is only ever published by a brand or by the upload's own answer.
//
// A font is answered with Access-Control-Allow-Origin naming fontOrigin, the admin console's
// origin, so the console's pages may draw it: a browser loads a font from another origin only when
// the serving origin grants it (the Fetch Standard's CORS protocol). The grant names that one
// origin, carries no credentials and is on a font's answer alone, so no other site may use an
// operator's typeface from this server (decision 8). An empty fontOrigin grants nothing.
func HandleBrandAssetGet(pageRenderer PageRenderer, database brandAssetDatabase, fontOrigin string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		assetId, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil || assetId <= 0 {
			http.NotFound(w, r)
			return
		}

		asset, err := database.GetBrandAssetById(r.Context(), nil, assetId)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}
		if asset == nil {
			http.NotFound(w, r)
			return
		}

		cache := brandStylesheetOtherCache
		if fingerprints := r.URL.Query()["v"]; len(fingerprints) == 1 && fingerprints[0] == asset.Fingerprint {
			cache = brandStylesheetCurrentCache
		}
		header := w.Header()
		header.Set("Content-Type", asset.ContentType)
		header.Set("X-Content-Type-Options", "nosniff")
		header.Set("Cache-Control", cache)
		header.Set("Content-Length", strconv.Itoa(len(asset.Content)))
		if asset.Kind == record.BrandAssetKindFont && fontOrigin != "" {
			header.Set("Access-Control-Allow-Origin", fontOrigin)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(asset.Content)
	}
}
