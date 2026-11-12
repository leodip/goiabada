package apihandlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/leodip/goiabada/authserver/internal/accountvalidation"
	"github.com/leodip/goiabada/authserver/internal/apimapping"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/brandasset"
	"github.com/leodip/goiabada/authserver/internal/brandthemes"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/inputvalidation"
)

// The admin API's brands (#810), in the settings domain: a brand is a name, an appearance and one
// of the built-in themes, with its kit's choices (#813 decision 10), and the one the settings row
// points at is the default, which a client with no brand of its own is drawn in (decisions 1 and 5;
// #812 decision 1). Every brand answer says how many clients are drawn in it (#812 decision 3). The
// last write of a brand wins, as for resources and groups.

// brandsDatabase is what the brand endpoints need: the brands, the default pointer, the count of
// clients drawn in each, the assets the brands' slots name, read without their bytes, and the
// transaction the pointer's writes take the settings row's lock in.
type brandsDatabase interface {
	CreateBrand(ctx context.Context, tx *sql.Tx, brand *record.Brand) error
	UpdateBrand(ctx context.Context, tx *sql.Tx, brand *record.Brand) error
	GetBrandById(ctx context.Context, tx *sql.Tx, brandId int64) (*record.Brand, error)
	GetAllBrands(ctx context.Context, tx *sql.Tx) ([]record.Brand, error)
	GetDefaultBrand(ctx context.Context, tx *sql.Tx) (*record.Brand, error)
	MakeBrandDefault(ctx context.Context, tx *sql.Tx, brandId int64) (int64, error)
	DeleteBrand(ctx context.Context, tx *sql.Tx, brandId int64) (int, error)
	CountClientsPerBrand(ctx context.Context, tx *sql.Tx) (map[int64]int, error)
	brandasset.SlotsReader
	RunInTransaction(ctx context.Context, fn func(tx *sql.Tx) error) error
}

// brandFields are what a create and an update name: every field of a brand, each slot by the id of
// the asset it holds, nil for an empty slot, and the footer links and the support contact.
type brandFields struct {
	name, appearance, theme, corners, font, backgroundFit string
	hideAppName                                           bool
	logo, darkLogo, favicon, background, regularFont      *api.BrandAssetRef
	boldFont                                              *api.BrandAssetRef
	footer                                                brandFooterFields
}

func createBrandFields(req api.CreateBrandRequest) brandFields {
	return brandFields{
		name: req.Name, appearance: req.Appearance, theme: req.Theme,
		corners: req.Corners, font: req.Font, backgroundFit: req.BackgroundFit, hideAppName: req.HideAppName,
		logo: req.Logo, darkLogo: req.DarkLogo, favicon: req.Favicon, background: req.Background,
		regularFont: req.RegularFont, boldFont: req.BoldFont,
		footer: brandFooterFields{footerLinks: req.FooterLinks, supportEmail: req.SupportEmail,
			supportURL: req.SupportUrl, supportPhone: req.SupportPhone},
	}
}

func updateBrandFields(req api.UpdateBrandRequest) brandFields {
	return createBrandFields(api.CreateBrandRequest(req))
}

// slotOf is the slot a reference fills: the asset id it names, or an empty slot for none.
func slotOf(ref *api.BrandAssetRef) sql.NullInt64 {
	if ref == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: ref.Id, Valid: true}
}

// validateBrand holds a create's or an update's fields to #810 decision 5 and #813 decision 10, and
// answers them as stored, each slot naming the asset id the request names: the name trimmed, required, at most
// record.BrandNameMaxLength characters and without angle brackets; the appearance, the theme, the
// corners, the font and the background fit each one of their keys, exactly. A missing choice is
// refused as an unknown one, so a misspelt field name is reported and never becomes a default. The
// hide-app-name switch is taken as sent, false when absent. Then the footer links and the support
// contact are held to validateBrandFooter's rules (#814).
func validateBrand(fields brandFields) (record.Brand, error) {
	name := strings.TrimSpace(fields.name)
	if name == "" {
		return record.Brand{}, i18n.NewLocalizedError(i18n.ErrCodeBrandNameRequired, nil)
	}
	if inputvalidation.TextLength(name) > record.BrandNameMaxLength {
		return record.Brand{}, i18n.NewLocalizedError(i18n.ErrCodeBrandNameTooLong,
			map[string]any{"max": record.BrandNameMaxLength})
	}
	if err := accountvalidation.ValidateNoAngleBrackets(name, i18n.ErrCodeBrandNameAngleBrackets); err != nil {
		return record.Brand{}, err
	}
	if !record.BrandAppearance(fields.appearance).IsValid() {
		return record.Brand{}, i18n.NewLocalizedError(i18n.ErrCodeBrandAppearanceInvalid, nil)
	}
	if _, ok := brandthemes.StylesheetOf(fields.theme); !ok {
		return record.Brand{}, i18n.NewLocalizedError(i18n.ErrCodeBrandThemeInvalid, nil)
	}
	if !record.BrandCorners(fields.corners).IsValid() {
		return record.Brand{}, i18n.NewLocalizedError(i18n.ErrCodeBrandCornersInvalid, nil)
	}
	if !record.BrandFont(fields.font).IsValid() {
		return record.Brand{}, i18n.NewLocalizedError(i18n.ErrCodeBrandFontInvalid, nil)
	}
	if !record.BrandBackgroundFit(fields.backgroundFit).IsValid() {
		return record.Brand{}, i18n.NewLocalizedError(i18n.ErrCodeBrandBackgroundFitInvalid, nil)
	}
	brand := record.NewBrand(name, record.BrandAppearance(fields.appearance), fields.theme)
	brand.Corners = record.BrandCorners(fields.corners)
	brand.Font = record.BrandFont(fields.font)
	brand.BackgroundFit = record.BrandBackgroundFit(fields.backgroundFit)
	brand.HideAppName = fields.hideAppName
	brand.LogoAssetId = slotOf(fields.logo)
	brand.DarkLogoAssetId = slotOf(fields.darkLogo)
	brand.FaviconAssetId = slotOf(fields.favicon)
	brand.BackgroundAssetId = slotOf(fields.background)
	brand.RegularFontAssetId = slotOf(fields.regularFont)
	brand.BoldFontAssetId = slotOf(fields.boldFont)
	if err := validateBrandFooter(fields.footer, &brand); err != nil {
		return record.Brand{}, err
	}
	return brand, nil
}

// brandSlotRules are the six slots in slot order, each with the kind of asset it holds and its
// refusal: both logo slots hold a logo, and both font slots a font (#813 decision 3).
var brandSlotRules = []struct {
	slot func(brand *record.Brand) sql.NullInt64
	kind record.BrandAssetKind
	code string
}{
	{func(b *record.Brand) sql.NullInt64 { return b.LogoAssetId }, record.BrandAssetKindLogo, i18n.ErrCodeBrandLogoAssetInvalid},
	{func(b *record.Brand) sql.NullInt64 { return b.DarkLogoAssetId }, record.BrandAssetKindLogo, i18n.ErrCodeBrandDarkLogoAssetInvalid},
	{func(b *record.Brand) sql.NullInt64 { return b.FaviconAssetId }, record.BrandAssetKindFavicon, i18n.ErrCodeBrandFaviconAssetInvalid},
	{func(b *record.Brand) sql.NullInt64 { return b.BackgroundAssetId }, record.BrandAssetKindBackground, i18n.ErrCodeBrandBackgroundAssetInvalid},
	{func(b *record.Brand) sql.NullInt64 { return b.RegularFontAssetId }, record.BrandAssetKindFont, i18n.ErrCodeBrandRegularFontAssetInvalid},
	{func(b *record.Brand) sql.NullInt64 { return b.BoldFontAssetId }, record.BrandAssetKindFont, i18n.ErrCodeBrandBoldFontAssetInvalid},
}

// validateBrandSlots holds the slots brand is written with to #813 decisions 5, 7 and 10, and answers
// the assets they name, read without their bytes. A dark logo is drawn in place of the logo, so it is
// refused without one; the uploaded font is drawn from the regular font file, so it is refused while
// that slot is empty, a bold file alone included; and a bold file is refused without a regular one.
// Then each filled slot must name a stored asset of its kind, or the write is refused at that slot,
// an asset since swept being none. A refusal is an *i18n.LocalizedError; a read that fails is not.
func validateBrandSlots(ctx context.Context, assets brandasset.SlotsReader, brand *record.Brand) (brandasset.Slots, error) {
	switch {
	case brand.DarkLogoAssetId.Valid && !brand.LogoAssetId.Valid:
		return brandasset.Slots{}, i18n.NewLocalizedError(i18n.ErrCodeBrandDarkLogoLogoRequired, nil)
	case brand.Font == record.BrandFontUploaded && !brand.RegularFontAssetId.Valid:
		return brandasset.Slots{}, i18n.NewLocalizedError(i18n.ErrCodeBrandUploadedFontRegularRequired, nil)
	case brand.BoldFontAssetId.Valid && !brand.RegularFontAssetId.Valid:
		return brandasset.Slots{}, i18n.NewLocalizedError(i18n.ErrCodeBrandBoldFontRegularRequired, nil)
	}

	ids := brandasset.SlotIds(brand)
	if len(ids) == 0 {
		return brandasset.Slots{}, nil
	}
	stored, err := assets.GetBrandAssetsByIds(ctx, nil, ids)
	if err != nil {
		return brandasset.Slots{}, errs.Wrap(err, "database error reading the assets a brand's slots name")
	}
	for _, rule := range brandSlotRules {
		slot := rule.slot(brand)
		if !slot.Valid {
			continue
		}
		found := slices.ContainsFunc(stored, func(asset record.BrandAsset) bool {
			return asset.Id == slot.Int64 && asset.Kind == rule.kind
		})
		if !found {
			return brandasset.Slots{}, i18n.NewLocalizedError(rule.code, nil)
		}
	}
	return brandasset.SlotsOf(brand, stored), nil
}

// writeBrandSlotsError answers a write whose slots validateBrandSlots refused or could not read.
func writeBrandSlotsError(w http.ResponseWriter, r *http.Request, err error) {
	var localized *i18n.LocalizedError
	if errors.As(err, &localized) {
		writeValidationError(w, r, err)
		return
	}
	writeInternalServerError(w, r, err)
}

// readBrandSlots reads the assets brand's slots name, answering the request when it cannot: an answer
// without them would read back as a brand with empty slots.
func readBrandSlots(w http.ResponseWriter, r *http.Request, assets brandasset.SlotsReader, brand *record.Brand) (brandasset.Slots, bool) {
	slots, err := brandasset.ReadSlots(r.Context(), assets, nil, brand)
	if err != nil {
		writeInternalServerError(w, r, err, "brand_id", brand.Id)
		return brandasset.Slots{}, false
	}
	return slots, true
}

// brandNameTaken answers a brand write the engine refused on the name's unique key: the name was
// another brand's, whether it was when the request came or a write committed meanwhile took it. It
// reports whether it answered.
func brandNameTaken(w http.ResponseWriter, r *http.Request, err error) bool {
	if !errors.Is(err, data.ErrUniqueViolation) {
		return false
	}
	writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeBrandNameInUse, nil))
	return true
}

// brandSlotSwept answers a brand write the engine refused after its slots were checked, when the
// asset a slot names is no longer stored: the sweep deleted it between the check and the write, and
// the slot's foreign key refused the write. Such a write is refused at that slot, as an id naming no
// asset is (#813 decision 10). It reports whether it answered; a write whose slots all still hold
// their assets, or whose slots cannot be read again, failed for another reason and is the caller's
// to answer.
func brandSlotSwept(w http.ResponseWriter, r *http.Request, assets brandasset.SlotsReader, brand *record.Brand) bool {
	if len(brandasset.SlotIds(brand)) == 0 {
		return false
	}
	_, err := validateBrandSlots(r.Context(), assets, brand)
	var localized *i18n.LocalizedError
	if !errors.As(err, &localized) {
		return false
	}
	writeValidationError(w, r, err)
	return true
}

// brandId reads the {id} path value, answering the request when it is not an id.
func brandId(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeJSONError(w, "Invalid brand ID", "VALIDATION_ERROR", http.StatusBadRequest)
		return 0, false
	}
	return id, true
}

func writeBrandNotFound(w http.ResponseWriter) {
	writeJSONError(w, "Brand not found", "NOT_FOUND", http.StatusNotFound)
}

// loadBrand reads the brand the path names, answering the request when it cannot.
func loadBrand(w http.ResponseWriter, r *http.Request, database brandsDatabase) (*record.Brand, bool) {
	id, ok := brandId(w, r)
	if !ok {
		return nil, false
	}
	brand, err := database.GetBrandById(r.Context(), nil, id)
	if err != nil {
		writeInternalServerError(w, r, errs.Wrap(err, "database error getting brand by ID"), "brand_id", id)
		return nil, false
	}
	if brand == nil {
		writeBrandNotFound(w)
		return nil, false
	}
	return brand, true
}

// defaultBrandId reads the id of the default brand, 0 when the settings row points at none,
// answering the request when it cannot.
func defaultBrandId(w http.ResponseWriter, r *http.Request, database brandsDatabase) (int64, bool) {
	brand, err := database.GetDefaultBrand(r.Context(), nil)
	if err != nil {
		writeInternalServerError(w, r, errs.Wrap(err, "database error getting the default brand"))
		return 0, false
	}
	if brand == nil {
		return 0, true
	}
	return brand.Id, true
}

// brandClientCounts reads how many clients each brand draws, by brand id, answering the request
// when it cannot: a count that cannot be read fails the answer (#812 decision 3). A brand no client
// is drawn in is absent, and reads as 0.
func brandClientCounts(w http.ResponseWriter, r *http.Request, database brandsDatabase) (map[int64]int, bool) {
	counts, err := database.CountClientsPerBrand(r.Context(), nil)
	if err != nil {
		writeInternalServerError(w, r, errs.Wrap(err, "database error counting the clients of each brand"))
		return nil, false
	}
	return counts, true
}

// HandleBrandsGet - GET /api/v1/admin/brands
func HandleBrandsGet(database brandsDatabase, baseURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		brands, err := database.GetAllBrands(r.Context(), nil)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting all brands"))
			return
		}
		defaultId, ok := defaultBrandId(w, r, database)
		if !ok {
			return
		}
		counts, ok := brandClientCounts(w, r, database)
		if !ok {
			return
		}

		// Every brand's assets are read at once, without their bytes, and none when no slot is filled.
		var ids []int64
		for i := range brands {
			for _, id := range brandasset.SlotIds(&brands[i]) {
				if !slices.Contains(ids, id) {
					ids = append(ids, id)
				}
			}
		}
		var assets []record.BrandAsset
		if len(ids) > 0 {
			assets, err = database.GetBrandAssetsByIds(r.Context(), nil, ids)
			if err != nil {
				writeInternalServerError(w, r, errs.Wrap(err, "database error reading the assets of the brands' slots"))
				return
			}
		}

		slices.SortFunc(brands, func(a, b record.Brand) int { return strings.Compare(a.Name, b.Name) })

		response := api.GetBrandsResponse{Brands: make([]api.BrandResponse, 0, len(brands))}
		for i := range brands {
			response.Brands = append(response.Brands, apimapping.ToBrandResponse(&brands[i], brandasset.SlotsOf(&brands[i], assets), baseURL,
				brands[i].Id == defaultId, counts[brands[i].Id]))
		}
		writeJSON(w, r, http.StatusOK, response)
	}
}

// HandleBrandCreatePost - POST /api/v1/admin/brands
func HandleBrandCreatePost(database brandsDatabase, auditLogger AuditLogger, baseURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req api.CreateBrandRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}
		brand, err := validateBrand(createBrandFields(req))
		if err != nil {
			writeValidationError(w, r, err)
			return
		}
		slots, err := validateBrandSlots(r.Context(), database, &brand)
		if err != nil {
			writeBrandSlotsError(w, r, err)
			return
		}

		if err := database.CreateBrand(r.Context(), nil, &brand); err != nil {
			if !brandNameTaken(w, r, err) && !brandSlotSwept(w, r, database, &brand) {
				writeInternalServerError(w, r, errs.Wrap(err, "database error creating brand"))
			}
			return
		}

		details := map[string]interface{}{
			"brand_id":       brand.Id,
			"brand_name":     brand.Name,
			"logged_in_user": callerSubject(r),
		}
		brandFooterAudit(&brand, details)
		auditLogger.Log(r.Context(), audit.EventCreatedBrand, details)

		// A brand just created is never the default, the pointer names a brand that existed, and no
		// client can have been given it yet: it draws no client.
		writeJSON(w, r, http.StatusCreated, api.CreateBrandResponse{Brand: apimapping.ToBrandResponse(&brand, slots, baseURL, false, 0)})
	}
}

// HandleBrandGet - GET /api/v1/admin/brands/{id}
func HandleBrandGet(database brandsDatabase, baseURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		brand, ok := loadBrand(w, r, database)
		if !ok {
			return
		}
		defaultId, ok := defaultBrandId(w, r, database)
		if !ok {
			return
		}
		counts, ok := brandClientCounts(w, r, database)
		if !ok {
			return
		}
		slots, ok := readBrandSlots(w, r, database, brand)
		if !ok {
			return
		}
		writeJSON(w, r, http.StatusOK, api.GetBrandResponse{Brand: apimapping.ToBrandResponse(brand, slots, baseURL, brand.Id == defaultId, counts[brand.Id])})
	}
}

// HandleBrandUpdatePut - PUT /api/v1/admin/brands/{id}
func HandleBrandUpdatePut(database brandsDatabase, auditLogger AuditLogger, baseURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		brand, ok := loadBrand(w, r, database)
		if !ok {
			return
		}

		var req api.UpdateBrandRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}
		fields, err := validateBrand(updateBrandFields(req))
		if err != nil {
			writeValidationError(w, r, err)
			return
		}

		// An update is a full replace: every field, each slot included, takes what the request
		// names, and a slot it leaves out is emptied (#813 decision 10). The asset a slot named
		// before is left unattached unless another slot names it, for the sweep.
		fields.Id = brand.Id
		fields.CreatedAt = brand.CreatedAt
		fields.UpdatedAt = brand.UpdatedAt
		brand = &fields
		slots, err := validateBrandSlots(r.Context(), database, brand)
		if err != nil {
			writeBrandSlotsError(w, r, err)
			return
		}
		if err := database.UpdateBrand(r.Context(), nil, brand); err != nil {
			if !brandNameTaken(w, r, err) && !brandSlotSwept(w, r, database, brand) {
				writeInternalServerError(w, r, errs.Wrap(err, "database error updating brand"), "brand_id", brand.Id)
			}
			return
		}

		details := map[string]interface{}{
			"brand_id":       brand.Id,
			"brand_name":     brand.Name,
			"appearance":     string(brand.Appearance),
			"theme":          brand.Theme,
			"corners":        string(brand.Corners),
			"font":           string(brand.Font),
			"background_fit": string(brand.BackgroundFit),
			"hide_app_name":  brand.HideAppName,
			"logged_in_user": callerSubject(r),
		}
		// Each filled slot by the id of the asset it holds after the save; an empty one is left out.
		if brand.LogoAssetId.Valid {
			details["logo_asset_id"] = brand.LogoAssetId.Int64
		}
		if brand.DarkLogoAssetId.Valid {
			details["dark_logo_asset_id"] = brand.DarkLogoAssetId.Int64
		}
		if brand.FaviconAssetId.Valid {
			details["favicon_asset_id"] = brand.FaviconAssetId.Int64
		}
		if brand.BackgroundAssetId.Valid {
			details["background_asset_id"] = brand.BackgroundAssetId.Int64
		}
		if brand.RegularFontAssetId.Valid {
			details["regular_font_asset_id"] = brand.RegularFontAssetId.Int64
		}
		if brand.BoldFontAssetId.Valid {
			details["bold_font_asset_id"] = brand.BoldFontAssetId.Int64
		}
		brandFooterAudit(brand, details)
		auditLogger.Log(r.Context(), audit.EventUpdatedBrand, details)

		defaultId, ok := defaultBrandId(w, r, database)
		if !ok {
			return
		}
		counts, ok := brandClientCounts(w, r, database)
		if !ok {
			return
		}
		writeJSON(w, r, http.StatusOK, api.UpdateBrandResponse{Brand: apimapping.ToBrandResponse(brand, slots, baseURL, brand.Id == defaultId, counts[brand.Id])})
	}
}

// HandleBrandDelete - DELETE /api/v1/admin/brands/{id}
//
// The deletion runs in a transaction because DeleteBrand reads the default pointer under the
// settings row's lock: the default is refused there, before any client is touched, and a change of
// default committed meanwhile is the one it reads (decision 1). Under that lock it moves the
// brand's clients to the default and answers how many, which deleted_brand records as client_count
// (#812 decisions 1 and 3).
func HandleBrandDelete(database brandsDatabase, auditLogger AuditLogger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		brand, ok := loadBrand(w, r, database)
		if !ok {
			return
		}

		var moved int
		err := database.RunInTransaction(r.Context(), func(tx *sql.Tx) error {
			var deleteErr error
			moved, deleteErr = database.DeleteBrand(r.Context(), tx, brand.Id)
			return deleteErr
		})
		switch {
		case errors.Is(err, data.ErrDefaultBrandNotDeletable):
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeBrandDefaultDeleteNotAllowed, nil))
			return
		case errors.Is(err, data.ErrBrandNotFound):
			writeBrandNotFound(w)
			return
		case err != nil:
			writeInternalServerError(w, r, errs.Wrap(err, "database error deleting brand"), "brand_id", brand.Id)
			return
		}

		auditLogger.Log(r.Context(), audit.EventDeletedBrand, map[string]interface{}{
			"brand_id":       brand.Id,
			"brand_name":     brand.Name,
			"client_count":   moved,
			"logged_in_user": callerSubject(r),
		})

		writeJSON(w, r, http.StatusOK, api.SuccessResponse{Success: true})
	}
}

// HandleBrandMakeDefaultPost - POST /api/v1/admin/brands/{id}/make-default
//
// MakeBrandDefault moves the pointer under the settings row's lock and reads the brand under it,
// so a brand deleted meanwhile is not found rather than made the default (decision 1). The brand,
// the one it replaces, the assets its slots name and the count of clients each brand draws are
// read in the same transaction, after the move, for the answer and the audit event, so a read that
// fails rolls the move back rather than answer an error for a change that was made. A brand that
// already is the default is answered as it is, and nothing is recorded.
func HandleBrandMakeDefaultPost(database brandsDatabase, auditLogger AuditLogger, baseURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := brandId(w, r)
		if !ok {
			return
		}

		var brand, previous *record.Brand
		var previousId int64
		var slots brandasset.Slots
		var counts map[int64]int
		err := database.RunInTransaction(r.Context(), func(tx *sql.Tx) error {
			brand, previous, slots, counts = nil, nil, brandasset.Slots{}, nil
			var err error
			previousId, err = database.MakeBrandDefault(r.Context(), tx, id)
			if err != nil {
				return err
			}
			brand, err = database.GetBrandById(r.Context(), tx, id)
			if err != nil {
				return errs.Wrap(err, "database error getting the brand made the default")
			}
			if brand == nil {
				return errs.WithStack(data.ErrBrandNotFound)
			}
			if previousId != id && previousId != 0 {
				previous, err = database.GetBrandById(r.Context(), tx, previousId)
				if err != nil {
					return errs.Wrap(err, "database error getting the previous default brand")
				}
			}
			slots, err = brandasset.ReadSlots(r.Context(), database, tx, brand)
			if err != nil {
				return err
			}
			counts, err = database.CountClientsPerBrand(r.Context(), tx)
			if err != nil {
				return errs.Wrap(err, "database error counting the clients of each brand")
			}
			return nil
		})
		switch {
		case errors.Is(err, data.ErrBrandNotFound):
			writeBrandNotFound(w)
			return
		case err != nil:
			writeInternalServerError(w, r, errs.Wrap(err, "database error making a brand the default"), "brand_id", id)
			return
		}

		if previousId != id {
			// The pointer was empty, or named a brand gone since: the old brand is named as none.
			previousName := ""
			if previous != nil {
				previousName = previous.Name
			}
			auditLogger.Log(r.Context(), audit.EventUpdatedDefaultBrand, map[string]interface{}{
				"brand_id":       brand.Id,
				"brand_name":     brand.Name,
				"old_brand_id":   previousId,
				"old_brand_name": previousName,
				"logged_in_user": callerSubject(r),
			})
		}

		writeJSON(w, r, http.StatusOK, api.MakeBrandDefaultResponse{Brand: apimapping.ToBrandResponse(brand, slots, baseURL, true, counts[brand.Id])})
	}
}

// HandleBrandThemesGet - GET /api/v1/admin/brand-themes
//
// The built-in themes in display order, each with its key and its light and dark palettes: the
// one home of their colors, which the admin console draws its swatches from (decision 5). It is
// reference data, a declared list, so it has no failure of its own besides writeJSON's.
func HandleBrandThemesGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, r, http.StatusOK, api.GetBrandThemesResponse{
			BrandThemes: apimapping.ToBrandThemeResponses(brandthemes.All()),
		})
	}
}
