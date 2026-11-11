package commondb

import (
	"context"
	"database/sql"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// brandColumns is the brands table as scanBrand reads it.
var brandColumns = columnList{
	sqlite: "id, created_at, updated_at, name, appearance, theme, corners, font, background_fit, hide_app_name, " +
		"logo_asset_id, dark_logo_asset_id, favicon_asset_id, background_asset_id, regular_font_asset_id, bold_font_asset_id",
	mysql: "id, created_at, updated_at, name, appearance, theme, corners, font, background_fit, hide_app_name, " +
		"logo_asset_id, dark_logo_asset_id, favicon_asset_id, background_asset_id, regular_font_asset_id, bold_font_asset_id",
	postgres: "id, created_at, updated_at, name, appearance, theme, corners, font, background_fit, hide_app_name, " +
		"logo_asset_id, dark_logo_asset_id, favicon_asset_id, background_asset_id, regular_font_asset_id, bold_font_asset_id",
	mssql: "id, created_at, updated_at, name, appearance, theme, corners, font, background_fit, hide_app_name, " +
		"logo_asset_id, dark_logo_asset_id, favicon_asset_id, background_asset_id, regular_font_asset_id, bold_font_asset_id",
}

// qualifiedBrandColumns is brandColumns named by table, for the read joining the settings row.
var qualifiedBrandColumns = columnList{
	sqlite: "brands.id, brands.created_at, brands.updated_at, brands.name, brands.appearance, brands.theme, brands.corners, brands.font, brands.background_fit, brands.hide_app_name, " +
		"brands.logo_asset_id, brands.dark_logo_asset_id, brands.favicon_asset_id, brands.background_asset_id, brands.regular_font_asset_id, brands.bold_font_asset_id",
	mysql: "brands.id, brands.created_at, brands.updated_at, brands.name, brands.appearance, brands.theme, brands.corners, brands.font, brands.background_fit, brands.hide_app_name, " +
		"brands.logo_asset_id, brands.dark_logo_asset_id, brands.favicon_asset_id, brands.background_asset_id, brands.regular_font_asset_id, brands.bold_font_asset_id",
	postgres: "brands.id, brands.created_at, brands.updated_at, brands.name, brands.appearance, brands.theme, brands.corners, brands.font, brands.background_fit, brands.hide_app_name, " +
		"brands.logo_asset_id, brands.dark_logo_asset_id, brands.favicon_asset_id, brands.background_asset_id, brands.regular_font_asset_id, brands.bold_font_asset_id",
	mssql: "brands.id, brands.created_at, brands.updated_at, brands.name, brands.appearance, brands.theme, brands.corners, brands.font, brands.background_fit, brands.hide_app_name, " +
		"brands.logo_asset_id, brands.dark_logo_asset_id, brands.favicon_asset_id, brands.background_asset_id, brands.regular_font_asset_id, brands.bold_font_asset_id",
}

// scanBrand reads one row selected with brandColumns or qualifiedBrandColumns.
func scanBrand(row rowScanner, brand *record.Brand) error {
	return row.Scan(
		&brand.Id,
		&brand.CreatedAt,
		&brand.UpdatedAt,
		&brand.Name,
		&brand.Appearance,
		&brand.Theme,
		&brand.Corners,
		&brand.Font,
		&brand.BackgroundFit,
		&brand.HideAppName,
		&brand.LogoAssetId,
		&brand.DarkLogoAssetId,
		&brand.FaviconAssetId,
		&brand.BackgroundAssetId,
		&brand.RegularFontAssetId,
		&brand.BoldFontAssetId,
	)
}

var insertBrand = statement{
	sqlite: "INSERT INTO brands (created_at, updated_at, name, appearance, theme, corners, font, background_fit, hide_app_name, " +
		"logo_asset_id, dark_logo_asset_id, favicon_asset_id, background_asset_id, regular_font_asset_id, bold_font_asset_id) " +
		"VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
	mysql: "INSERT INTO brands (created_at, updated_at, name, appearance, theme, corners, font, background_fit, hide_app_name, " +
		"logo_asset_id, dark_logo_asset_id, favicon_asset_id, background_asset_id, regular_font_asset_id, bold_font_asset_id) " +
		"VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
	postgres: "INSERT INTO brands (created_at, updated_at, name, appearance, theme, corners, font, background_fit, hide_app_name, " +
		"logo_asset_id, dark_logo_asset_id, favicon_asset_id, background_asset_id, regular_font_asset_id, bold_font_asset_id) " +
		"VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) RETURNING id",
	mssql: "INSERT INTO brands (created_at, updated_at, name, appearance, theme, corners, font, background_fit, hide_app_name, " +
		"logo_asset_id, dark_logo_asset_id, favicon_asset_id, background_asset_id, regular_font_asset_id, bold_font_asset_id) OUTPUT INSERTED.id " +
		"VALUES (@p1, @p2, @p3, @p4, @p5, @p6, @p7, @p8, @p9, @p10, @p11, @p12, @p13, @p14, @p15)",
}

// updateBrand writes the whole row but created_at, which is dont-update.
var updateBrand = statement{
	sqlite: "UPDATE brands SET updated_at = ?, name = ?, appearance = ?, theme = ?, corners = ?, font = ?, background_fit = ?, " +
		"hide_app_name = ?, logo_asset_id = ?, dark_logo_asset_id = ?, favicon_asset_id = ?, background_asset_id = ?, regular_font_asset_id = ?, bold_font_asset_id = ? WHERE id = ?",
	mysql: "UPDATE brands SET updated_at = ?, name = ?, appearance = ?, theme = ?, corners = ?, font = ?, background_fit = ?, " +
		"hide_app_name = ?, logo_asset_id = ?, dark_logo_asset_id = ?, favicon_asset_id = ?, background_asset_id = ?, regular_font_asset_id = ?, bold_font_asset_id = ? WHERE id = ?",
	postgres: "UPDATE brands SET updated_at = $1, name = $2, appearance = $3, theme = $4, corners = $5, font = $6, background_fit = $7, " +
		"hide_app_name = $8, logo_asset_id = $9, dark_logo_asset_id = $10, favicon_asset_id = $11, background_asset_id = $12, regular_font_asset_id = $13, bold_font_asset_id = $14 WHERE id = $15",
	mssql: "UPDATE brands SET updated_at = @p1, name = @p2, appearance = @p3, theme = @p4, corners = @p5, font = @p6, background_fit = @p7, " +
		"hide_app_name = @p8, logo_asset_id = @p9, dark_logo_asset_id = @p10, favicon_asset_id = @p11, background_asset_id = @p12, regular_font_asset_id = @p13, bold_font_asset_id = @p14 WHERE id = @p15",
}

var selectBrandById = statement{
	sqlite:   "SELECT " + brandColumns.sqlite + " FROM brands WHERE id = ?",
	mysql:    "SELECT " + brandColumns.mysql + " FROM brands WHERE id = ?",
	postgres: "SELECT " + brandColumns.postgres + " FROM brands WHERE id = $1",
	mssql:    "SELECT " + brandColumns.mssql + " FROM brands WHERE id = @p1",
}

var selectAllBrands = statement{
	sqlite:   "SELECT " + brandColumns.sqlite + " FROM brands ORDER BY id",
	mysql:    "SELECT " + brandColumns.mysql + " FROM brands ORDER BY id",
	postgres: "SELECT " + brandColumns.postgres + " FROM brands ORDER BY id",
	mssql:    "SELECT " + brandColumns.mssql + " FROM brands ORDER BY id",
}

// selectDefaultBrand is the brand the settings row points at, which an empty pointer joins to none.
var selectDefaultBrand = statement{
	sqlite: "SELECT " + qualifiedBrandColumns.sqlite + " FROM brands " +
		"INNER JOIN settings ON settings.default_brand_id = brands.id WHERE settings.id = ?",
	mysql: "SELECT " + qualifiedBrandColumns.mysql + " FROM brands " +
		"INNER JOIN settings ON settings.default_brand_id = brands.id WHERE settings.id = ?",
	postgres: "SELECT " + qualifiedBrandColumns.postgres + " FROM brands " +
		"INNER JOIN settings ON settings.default_brand_id = brands.id WHERE settings.id = $1",
	mssql: "SELECT " + qualifiedBrandColumns.mssql + " FROM brands " +
		"INNER JOIN settings ON settings.default_brand_id = brands.id WHERE settings.id = @p1",
}

var selectDefaultBrandId = statement{
	sqlite:   "SELECT default_brand_id FROM settings WHERE id = ?",
	mysql:    "SELECT default_brand_id FROM settings WHERE id = ?",
	postgres: "SELECT default_brand_id FROM settings WHERE id = $1",
	mssql:    "SELECT default_brand_id FROM settings WHERE id = @p1",
}

// updateDefaultBrandId binds the pointer, the time, then the settings row's id.
var updateDefaultBrandId = statement{
	sqlite:   "UPDATE settings SET default_brand_id = ?, updated_at = ? WHERE id = ?",
	mysql:    "UPDATE settings SET default_brand_id = ?, updated_at = ? WHERE id = ?",
	postgres: "UPDATE settings SET default_brand_id = $1, updated_at = $2 WHERE id = $3",
	mssql:    "UPDATE settings SET default_brand_id = @p1, updated_at = @p2 WHERE id = @p3",
}

var deleteBrand = statement{
	sqlite:   "DELETE FROM brands WHERE id = ?",
	mysql:    "DELETE FROM brands WHERE id = ?",
	postgres: "DELETE FROM brands WHERE id = $1",
	mssql:    "DELETE FROM brands WHERE id = @p1",
}

func (d *Database) CreateBrand(ctx context.Context, tx *sql.Tx, brand *record.Brand) error {

	now := time.Now().UTC()

	originalCreatedAt := brand.CreatedAt
	originalUpdatedAt := brand.UpdatedAt
	brand.CreatedAt = sql.NullTime{Time: now, Valid: true}
	brand.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	id, err := d.insert(ctx, tx, insertBrand, "brand",
		brand.CreatedAt, brand.UpdatedAt, brand.Name, brand.Appearance, brand.Theme,
		brand.Corners, brand.Font, brand.BackgroundFit, brand.HideAppName,
		brand.LogoAssetId, brand.DarkLogoAssetId, brand.FaviconAssetId,
		brand.BackgroundAssetId, brand.RegularFontAssetId, brand.BoldFontAssetId)
	if err != nil {
		brand.CreatedAt = originalCreatedAt
		brand.UpdatedAt = originalUpdatedAt
		return err
	}

	brand.Id = id
	return nil
}

func (d *Database) UpdateBrand(ctx context.Context, tx *sql.Tx, brand *record.Brand) error {

	if brand.Id == 0 {
		return errs.New("can't update brand with id 0")
	}

	originalUpdatedAt := brand.UpdatedAt
	brand.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	_, err := d.ExecSQL(ctx, tx, updateBrand.text(d.Dialect),
		brand.UpdatedAt, brand.Name, brand.Appearance, brand.Theme,
		brand.Corners, brand.Font, brand.BackgroundFit, brand.HideAppName,
		brand.LogoAssetId, brand.DarkLogoAssetId, brand.FaviconAssetId,
		brand.BackgroundAssetId, brand.RegularFontAssetId, brand.BoldFontAssetId,
		brand.Id)
	if err != nil {
		brand.UpdatedAt = originalUpdatedAt
		return errs.Wrap(err, "unable to update brand")
	}

	return nil
}

func (d *Database) GetBrandById(ctx context.Context, tx *sql.Tx, brandId int64) (*record.Brand, error) {
	return queryOne(ctx, d, tx, selectBrandById.text(d.Dialect), []any{brandId}, scanBrand, "brand")
}

func (d *Database) GetAllBrands(ctx context.Context, tx *sql.Tx) ([]record.Brand, error) {
	return queryAll(ctx, d, tx, nil, selectAllBrands.text(d.Dialect), nil, scanBrand, "brand")
}

func (d *Database) GetDefaultBrand(ctx context.Context, tx *sql.Tx) (*record.Brand, error) {
	return queryOne(ctx, d, tx, selectDefaultBrand.text(d.Dialect), []any{int64(initialSettingsId)}, scanBrand, "brand")
}

// MakeBrandDefault moves the settings row's pointer to brandId, under the settings row's lock (#810
// decision 1).
//
// WHAT THE LOCK BUYS. DeleteBrand reads the pointer under the same lock before it deletes, so a
// move and a deletion of the brand it moves to are serialized: whichever takes the row second reads
// what the first committed. The move then finds the brand gone and answers ErrBrandNotFound, or the
// deletion finds the brand is the default and refuses it. Without the lock the deletion reads the
// pointer as it stood before the move and the foreign key refuses one of the two with an engine
// error instead. The brand is read after the lock is taken, so it is read as the deletions before
// it committed it; the foreign key still refuses a pointer to a brand that is gone.
//
// The pointer is read on the row this transaction has just written, so it is the committed one on
// every engine, MySQL's REPEATABLE READ included.
func (d *Database) MakeBrandDefault(ctx context.Context, tx *sql.Tx, brandId int64) (int64, error) {

	if tx == nil {
		return 0, errs.New("making a brand the default requires a transaction: the settings row's lock lasts as long as it does")
	}

	if err := d.AcquireSettingsRow(ctx, tx, initialSettingsId); err != nil {
		return 0, err
	}

	current, err := d.readDefaultBrandId(ctx, tx)
	if err != nil {
		return 0, err
	}
	if current.Valid && current.Int64 == brandId {
		return brandId, nil
	}

	brand, err := d.GetBrandById(ctx, tx, brandId)
	if err != nil {
		return 0, err
	}
	if brand == nil {
		return 0, errs.WithStack(data.ErrBrandNotFound)
	}

	result, err := d.ExecSQL(ctx, tx, updateDefaultBrandId.text(d.Dialect),
		brandId, time.Now().UTC(), initialSettingsId)
	if err != nil {
		return 0, errs.Wrap(err, "unable to make the brand the default")
	}
	written, err := result.RowsAffected()
	if err != nil {
		return 0, errs.Wrap(err, "unable to get rows affected when making a brand the default")
	}
	if written == 0 {
		return 0, errs.New("there is no settings row to make a brand the default on")
	}

	return current.Int64, nil
}

// DeleteBrand deletes a brand that is not the default, reading the pointer under the settings
// row's lock, for the reason MakeBrandDefault gives (#810 decision 1).
//
// Under that same lock it first puts every client given the brand back on the default, and answers
// how many it moved (#812 decision 1). SetClientBrand takes the lock too, so an assignment of the
// brand either committed before and is moved and counted here, or comes after and finds the brand
// gone. The default brand is refused before any client is touched. A brand that is not there moves
// no client, since the foreign key lets none name it.
func (d *Database) DeleteBrand(ctx context.Context, tx *sql.Tx, brandId int64) (int, error) {

	if tx == nil {
		return 0, errs.New("deleting a brand requires a transaction: the settings row's lock lasts as long as it does")
	}

	if err := d.AcquireSettingsRow(ctx, tx, initialSettingsId); err != nil {
		return 0, err
	}

	current, err := d.readDefaultBrandId(ctx, tx)
	if err != nil {
		return 0, err
	}
	if current.Valid && current.Int64 == brandId {
		return 0, errs.WithStack(data.ErrDefaultBrandNotDeletable)
	}

	moved, err := d.clearBrandFromClients(ctx, tx, brandId)
	if err != nil {
		return 0, err
	}

	result, err := d.ExecSQL(ctx, tx, deleteBrand.text(d.Dialect), brandId)
	if err != nil {
		return 0, errs.Wrap(err, "unable to delete brand")
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return 0, errs.Wrap(err, "unable to get rows affected when deleting a brand")
	}
	if deleted == 0 {
		return 0, errs.WithStack(data.ErrBrandNotFound)
	}

	return moved, nil
}

// readDefaultBrandId reads the settings row's pointer. A missing row reads as an empty pointer:
// there is no default to move from or to protect.
func (d *Database) readDefaultBrandId(ctx context.Context, tx *sql.Tx) (sql.NullInt64, error) {
	var id sql.NullInt64
	rows, err := d.QuerySQL(ctx, tx, selectDefaultBrandId.text(d.Dialect), int64(initialSettingsId))
	if err != nil {
		return id, errs.Wrap(err, "unable to read the default brand")
	}
	defer func() { _ = rows.Close() }()

	if rows.Next() {
		if err := rows.Scan(&id); err != nil {
			return id, errs.Wrap(err, "unable to scan the default brand")
		}
	}
	if err := rows.Err(); err != nil {
		return id, errs.Wrap(err, "unable to read the default brand")
	}
	return id, nil
}
