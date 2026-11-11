package apihandlers

import (
	"context"
	"database/sql"
	"net/http"
	"strconv"

	"github.com/leodip/goiabada/authserver/internal/apimapping"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/brandasset"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
)

// The admin API's brand assets (#813 decisions 1 and 10), in the settings domain: a file uploaded
// as an asset of a named kind is stored at once, attached to no brand, and answered with its id
// and URL; a brand's create and update name the asset each slot holds by that id. An asset no
// brand names is deleted by the cleanup worker's sweep once it is a day old, which is the only
// thing that deletes one.

// brandAssetsDatabase is what the brand asset endpoints need: an asset stored, and an asset read
// without its bytes.
type brandAssetsDatabase interface {
	CreateBrandAsset(ctx context.Context, tx *sql.Tx, asset *record.BrandAsset) error
	GetBrandAssetsByIds(ctx context.Context, tx *sql.Tx, assetIds []int64) ([]record.BrandAsset, error)
}

// HandleBrandAssetPost - POST /api/v1/admin/brand-assets/{logo,favicon,background,font}, one route
// per kind, each with its row in the request-body table: the file in the multipart field "file",
// held to its kind's rules (#813 decision 3) and stored as it came, with the type it was validated
// as, its fingerprint and its pixel size.
func HandleBrandAssetPost(database brandAssetsDatabase, auditLogger AuditLogger, baseURL string, kind record.BrandAssetKind) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data, ok := readUploadedBrandAsset(w, r, kind)
		if !ok {
			return
		}

		info, err := brandasset.Validate(kind, data)
		if err != nil {
			writeValidationError(w, r, err)
			return
		}

		asset := &record.BrandAsset{
			Kind:        kind,
			ContentType: info.ContentType,
			Fingerprint: brandasset.Fingerprint(data),
			Width:       info.Width,
			Height:      info.Height,
			Content:     data,
		}
		if err := database.CreateBrandAsset(r.Context(), nil, asset); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error storing a brand asset"), "kind", string(kind))
			return
		}

		auditLogger.Log(r.Context(), audit.EventUploadedBrandAsset, map[string]interface{}{
			"brand_asset_id": asset.Id,
			"kind":           string(kind),
			"logged_in_user": callerSubject(r),
		})

		writeJSON(w, r, http.StatusCreated, api.CreateBrandAssetResponse{BrandAsset: apimapping.ToBrandAssetResponse(asset, baseURL)})
	}
}

// HandleBrandAssetGet - GET /api/v1/admin/brand-assets/{id}: a stored asset without its bytes,
// attached or not, so the brand editor can draw one uploaded and not yet saved.
func HandleBrandAssetGet(database brandAssetsDatabase, baseURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil || id <= 0 {
			writeJSONError(w, "Invalid brand asset ID", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		assets, err := database.GetBrandAssetsByIds(r.Context(), nil, []int64{id})
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting a brand asset by ID"), "brand_asset_id", id)
			return
		}
		if len(assets) == 0 {
			writeJSONError(w, "Brand asset not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		writeJSON(w, r, http.StatusOK, api.GetBrandAssetResponse{BrandAsset: apimapping.ToBrandAssetResponse(&assets[0], baseURL)})
	}
}
