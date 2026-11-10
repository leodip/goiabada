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
	"github.com/leodip/goiabada/authserver/internal/brandthemes"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/inputvalidation"
)

// The admin API's brands (#810), in the settings domain: a brand is a name, an appearance and one
// of the built-in themes, and the one the settings row points at is the default, which every page
// is drawn in (decisions 1 and 5). The last write of a brand wins, as for resources and groups.

// brandsDatabase is what the brand endpoints need: the brands, the default pointer, and the
// transaction the pointer's writes take the settings row's lock in.
type brandsDatabase interface {
	CreateBrand(ctx context.Context, tx *sql.Tx, brand *record.Brand) error
	UpdateBrand(ctx context.Context, tx *sql.Tx, brand *record.Brand) error
	GetBrandById(ctx context.Context, tx *sql.Tx, brandId int64) (*record.Brand, error)
	GetAllBrands(ctx context.Context, tx *sql.Tx) ([]record.Brand, error)
	GetDefaultBrand(ctx context.Context, tx *sql.Tx) (*record.Brand, error)
	MakeBrandDefault(ctx context.Context, tx *sql.Tx, brandId int64) (int64, error)
	DeleteBrand(ctx context.Context, tx *sql.Tx, brandId int64) error
	RunInTransaction(ctx context.Context, fn func(tx *sql.Tx) error) error
}

// validateBrand holds a create's or an update's three fields to decision 5 and answers them as
// stored: the name trimmed, required, at most record.BrandNameMaxLength characters and without
// angle brackets; the appearance one of the three, exactly; the theme one of the built-in keys,
// exactly. A missing appearance or theme is refused as an unknown one.
func validateBrand(name, appearance, theme string) (record.Brand, error) {
	name = strings.TrimSpace(name)
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
	if !record.BrandAppearance(appearance).IsValid() {
		return record.Brand{}, i18n.NewLocalizedError(i18n.ErrCodeBrandAppearanceInvalid, nil)
	}
	if _, ok := brandthemes.StylesheetOf(theme); !ok {
		return record.Brand{}, i18n.NewLocalizedError(i18n.ErrCodeBrandThemeInvalid, nil)
	}
	return record.Brand{Name: name, Appearance: record.BrandAppearance(appearance), Theme: theme}, nil
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

// HandleBrandsGet - GET /api/v1/admin/brands
func HandleBrandsGet(database brandsDatabase) http.HandlerFunc {
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

		slices.SortFunc(brands, func(a, b record.Brand) int { return strings.Compare(a.Name, b.Name) })

		response := api.GetBrandsResponse{Brands: make([]api.BrandResponse, 0, len(brands))}
		for i := range brands {
			response.Brands = append(response.Brands, apimapping.ToBrandResponse(&brands[i], brands[i].Id == defaultId))
		}
		writeJSON(w, r, http.StatusOK, response)
	}
}

// HandleBrandCreatePost - POST /api/v1/admin/brands
func HandleBrandCreatePost(database brandsDatabase, auditLogger AuditLogger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req api.CreateBrandRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}
		brand, err := validateBrand(req.Name, req.Appearance, req.Theme)
		if err != nil {
			writeValidationError(w, r, err)
			return
		}

		if err := database.CreateBrand(r.Context(), nil, &brand); err != nil {
			if !brandNameTaken(w, r, err) {
				writeInternalServerError(w, r, errs.Wrap(err, "database error creating brand"))
			}
			return
		}

		auditLogger.Log(r.Context(), audit.EventCreatedBrand, map[string]interface{}{
			"brand_id":       brand.Id,
			"brand_name":     brand.Name,
			"logged_in_user": callerSubject(r),
		})

		// A brand just created is never the default: the pointer names a brand that existed.
		writeJSON(w, r, http.StatusCreated, api.CreateBrandResponse{Brand: apimapping.ToBrandResponse(&brand, false)})
	}
}

// HandleBrandGet - GET /api/v1/admin/brands/{id}
func HandleBrandGet(database brandsDatabase) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		brand, ok := loadBrand(w, r, database)
		if !ok {
			return
		}
		defaultId, ok := defaultBrandId(w, r, database)
		if !ok {
			return
		}
		writeJSON(w, r, http.StatusOK, api.GetBrandResponse{Brand: apimapping.ToBrandResponse(brand, brand.Id == defaultId)})
	}
}

// HandleBrandUpdatePut - PUT /api/v1/admin/brands/{id}
func HandleBrandUpdatePut(database brandsDatabase, auditLogger AuditLogger) http.HandlerFunc {
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
		fields, err := validateBrand(req.Name, req.Appearance, req.Theme)
		if err != nil {
			writeValidationError(w, r, err)
			return
		}

		brand.Name = fields.Name
		brand.Appearance = fields.Appearance
		brand.Theme = fields.Theme
		if err := database.UpdateBrand(r.Context(), nil, brand); err != nil {
			if !brandNameTaken(w, r, err) {
				writeInternalServerError(w, r, errs.Wrap(err, "database error updating brand"), "brand_id", brand.Id)
			}
			return
		}

		auditLogger.Log(r.Context(), audit.EventUpdatedBrand, map[string]interface{}{
			"brand_id":       brand.Id,
			"brand_name":     brand.Name,
			"appearance":     string(brand.Appearance),
			"theme":          brand.Theme,
			"logged_in_user": callerSubject(r),
		})

		defaultId, ok := defaultBrandId(w, r, database)
		if !ok {
			return
		}
		writeJSON(w, r, http.StatusOK, api.UpdateBrandResponse{Brand: apimapping.ToBrandResponse(brand, brand.Id == defaultId)})
	}
}

// HandleBrandDelete - DELETE /api/v1/admin/brands/{id}
//
// The deletion runs in a transaction because DeleteBrand reads the default pointer under the
// settings row's lock: the default is refused there, before the foreign key is reached, and a
// change of default committed meanwhile is the one it reads (decision 1).
func HandleBrandDelete(database brandsDatabase, auditLogger AuditLogger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		brand, ok := loadBrand(w, r, database)
		if !ok {
			return
		}

		err := database.RunInTransaction(r.Context(), func(tx *sql.Tx) error {
			return database.DeleteBrand(r.Context(), tx, brand.Id)
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
			"logged_in_user": callerSubject(r),
		})

		writeJSON(w, r, http.StatusOK, api.SuccessResponse{Success: true})
	}
}

// HandleBrandMakeDefaultPost - POST /api/v1/admin/brands/{id}/make-default
//
// MakeBrandDefault moves the pointer under the settings row's lock and reads the brand under it,
// so a brand deleted meanwhile is not found rather than made the default (decision 1). The brand
// and the one it replaces are read in the same transaction, after the move, for the answer and
// the audit event. A brand that already is the default is answered as it is, and nothing is
// recorded.
func HandleBrandMakeDefaultPost(database brandsDatabase, auditLogger AuditLogger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := brandId(w, r)
		if !ok {
			return
		}

		var brand, previous *record.Brand
		var previousId int64
		err := database.RunInTransaction(r.Context(), func(tx *sql.Tx) error {
			brand, previous = nil, nil
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

		writeJSON(w, r, http.StatusOK, api.MakeBrandDefaultResponse{Brand: apimapping.ToBrandResponse(brand, true)})
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
