package commondb

import (
	"context"
	"database/sql"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// brandAssetColumns is the brand_assets table as scanBrandAsset reads it, the bytes included.
var brandAssetColumns = columnList{
	sqlite:   "id, created_at, kind, content_type, fingerprint, width, height, content",
	mysql:    "id, created_at, kind, content_type, fingerprint, width, height, content",
	postgres: "id, created_at, kind, content_type, fingerprint, width, height, content",
	mssql:    "id, created_at, kind, content_type, fingerprint, width, height, content",
}

// brandAssetInfoColumns is the brand_assets table as scanBrandAssetInfo reads it: every column but
// the bytes, which a brand's answer and its pages never load (#813 decision 2).
var brandAssetInfoColumns = columnList{
	sqlite:   "id, created_at, kind, content_type, fingerprint, width, height",
	mysql:    "id, created_at, kind, content_type, fingerprint, width, height",
	postgres: "id, created_at, kind, content_type, fingerprint, width, height",
	mssql:    "id, created_at, kind, content_type, fingerprint, width, height",
}

// scanBrandAsset reads one row selected with brandAssetColumns.
func scanBrandAsset(row rowScanner, asset *record.BrandAsset) error {
	return row.Scan(
		&asset.Id,
		&asset.CreatedAt,
		&asset.Kind,
		&asset.ContentType,
		&asset.Fingerprint,
		&asset.Width,
		&asset.Height,
		&asset.Content,
	)
}

// scanBrandAssetInfo reads one row selected with brandAssetInfoColumns, leaving Content nil.
func scanBrandAssetInfo(row rowScanner, asset *record.BrandAsset) error {
	return row.Scan(
		&asset.Id,
		&asset.CreatedAt,
		&asset.Kind,
		&asset.ContentType,
		&asset.Fingerprint,
		&asset.Width,
		&asset.Height,
	)
}

var insertBrandAsset = statement{
	sqlite:   "INSERT INTO brand_assets (created_at, kind, content_type, fingerprint, width, height, content) VALUES (?, ?, ?, ?, ?, ?, ?)",
	mysql:    "INSERT INTO brand_assets (created_at, kind, content_type, fingerprint, width, height, content) VALUES (?, ?, ?, ?, ?, ?, ?)",
	postgres: "INSERT INTO brand_assets (created_at, kind, content_type, fingerprint, width, height, content) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
	mssql:    "INSERT INTO brand_assets (created_at, kind, content_type, fingerprint, width, height, content) OUTPUT INSERTED.id VALUES (@p1, @p2, @p3, @p4, @p5, @p6, @p7)",
}

var selectBrandAssetById = statement{
	sqlite:   "SELECT " + brandAssetColumns.sqlite + " FROM brand_assets WHERE id = ?",
	mysql:    "SELECT " + brandAssetColumns.mysql + " FROM brand_assets WHERE id = ?",
	postgres: "SELECT " + brandAssetColumns.postgres + " FROM brand_assets WHERE id = $1",
	mssql:    "SELECT " + brandAssetColumns.mssql + " FROM brand_assets WHERE id = @p1",
}

// selectBrandAssetInfosWhere is completed by an IN list of asset ids.
var selectBrandAssetInfosWhere = statement{
	sqlite:   "SELECT " + brandAssetInfoColumns.sqlite + " FROM brand_assets WHERE ",
	mysql:    "SELECT " + brandAssetInfoColumns.mysql + " FROM brand_assets WHERE ",
	postgres: "SELECT " + brandAssetInfoColumns.postgres + " FROM brand_assets WHERE ",
	mssql:    "SELECT " + brandAssetInfoColumns.mssql + " FROM brand_assets WHERE ",
}

// deleteUnattachedBrandAssets deletes the assets created before its one argument that no slot of
// any brand names.
var deleteUnattachedBrandAssets = statement{
	sqlite: "DELETE FROM brand_assets WHERE created_at < ? AND NOT EXISTS (SELECT 1 FROM brands WHERE " +
		"brands.logo_asset_id = brand_assets.id OR brands.dark_logo_asset_id = brand_assets.id OR " +
		"brands.favicon_asset_id = brand_assets.id OR brands.background_asset_id = brand_assets.id OR " +
		"brands.regular_font_asset_id = brand_assets.id OR brands.bold_font_asset_id = brand_assets.id)",
	mysql: "DELETE FROM brand_assets WHERE created_at < ? AND NOT EXISTS (SELECT 1 FROM brands WHERE " +
		"brands.logo_asset_id = brand_assets.id OR brands.dark_logo_asset_id = brand_assets.id OR " +
		"brands.favicon_asset_id = brand_assets.id OR brands.background_asset_id = brand_assets.id OR " +
		"brands.regular_font_asset_id = brand_assets.id OR brands.bold_font_asset_id = brand_assets.id)",
	postgres: "DELETE FROM brand_assets WHERE created_at < $1 AND NOT EXISTS (SELECT 1 FROM brands WHERE " +
		"brands.logo_asset_id = brand_assets.id OR brands.dark_logo_asset_id = brand_assets.id OR " +
		"brands.favicon_asset_id = brand_assets.id OR brands.background_asset_id = brand_assets.id OR " +
		"brands.regular_font_asset_id = brand_assets.id OR brands.bold_font_asset_id = brand_assets.id)",
	mssql: "DELETE FROM brand_assets WHERE created_at < @p1 AND NOT EXISTS (SELECT 1 FROM brands WHERE " +
		"brands.logo_asset_id = brand_assets.id OR brands.dark_logo_asset_id = brand_assets.id OR " +
		"brands.favicon_asset_id = brand_assets.id OR brands.background_asset_id = brand_assets.id OR " +
		"brands.regular_font_asset_id = brand_assets.id OR brands.bold_font_asset_id = brand_assets.id)",
}

func (d *Database) CreateBrandAsset(ctx context.Context, tx *sql.Tx, asset *record.BrandAsset) error {

	originalCreatedAt := asset.CreatedAt
	asset.CreatedAt = time.Now().UTC()

	id, err := d.insert(ctx, tx, insertBrandAsset, "brand asset",
		asset.CreatedAt, asset.Kind, asset.ContentType, asset.Fingerprint, asset.Width, asset.Height, asset.Content)
	if err != nil {
		asset.CreatedAt = originalCreatedAt
		return err
	}

	asset.Id = id
	return nil
}

func (d *Database) GetBrandAssetById(ctx context.Context, tx *sql.Tx, assetId int64) (*record.BrandAsset, error) {
	return queryOne(ctx, d, tx, selectBrandAssetById.text(d.Dialect), []any{assetId}, scanBrandAsset, "brand asset")
}

func (d *Database) GetBrandAssetsByIds(ctx context.Context, tx *sql.Tx, assetIds []int64) ([]record.BrandAsset, error) {

	if len(assetIds) == 0 {
		return nil, nil
	}

	var assets []record.BrandAsset

	err := forEachIdBatch(assetIds, func(batch []int64) error {
		query := selectBrandAssetInfosWhere.text(d.Dialect) + inList(d.Dialect, "id", 1, len(batch))
		var err error
		assets, err = queryAll(ctx, d, tx, assets, query, int64Args(batch), scanBrandAssetInfo, "brand asset")
		return err
	})
	if err != nil {
		return nil, err
	}

	return assets, nil
}

// DeleteUnattachedBrandAssets is the sweep's one statement (#813 decision 2). An asset a slot names
// is protected twice: by the NOT EXISTS, and by the slot's foreign key, which refuses the deletion
// of an asset a brand write attaches while the statement runs, failing the sweep rather than
// leaving the slot naming nothing; the next sweep deletes the others.
func (d *Database) DeleteUnattachedBrandAssets(ctx context.Context, tx *sql.Tx, createdBefore time.Time) (int, error) {

	result, err := d.ExecSQL(ctx, tx, deleteUnattachedBrandAssets.text(d.Dialect), createdBefore.UTC())
	if err != nil {
		return 0, errs.Wrap(err, "unable to delete unattached brand assets")
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return 0, errs.Wrap(err, "unable to get rows affected when deleting unattached brand assets")
	}

	return int(deleted), nil
}
