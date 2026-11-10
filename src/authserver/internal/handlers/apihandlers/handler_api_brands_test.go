package apihandlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/data"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The admin API's brands (#810 decision 5), one rule per test, through the handlers with the
// generated database mock: what each refusal answers and writes, what each write stores and
// audits, and how a brand is answered.

const brandCaller = "admin-console-client"

var brandTx = &sql.Tx{}

// brandRequest is an admin API request from brandCaller, with a JSON body when body is not nil and
// the path values the route would set.
func brandRequest(t *testing.T, method string, body any, pathValues ...string) *http.Request {
	t.Helper()
	reader := bytes.NewReader(nil)
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		reader = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, "/api/v1/admin/brands", reader)
	req = req.WithContext(reqctx.WithValidatedToken(req.Context(), oauth.JwtToken{Claims: map[string]any{"sub": brandCaller}}))
	for i := 0; i+1 < len(pathValues); i += 2 {
		req.SetPathValue(pathValues[i], pathValues[i+1])
	}
	return req
}

func serveBrand(handler http.HandlerFunc, req *http.Request) (int, map[string]any) {
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	var body map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	return rr.Code, body
}

var brandTime = time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)

func storedBrand(id int64, name string, appearance record.BrandAppearance, theme string) *record.Brand {
	return &record.Brand{
		Id:         id,
		CreatedAt:  sql.NullTime{Time: brandTime, Valid: true},
		UpdatedAt:  sql.NullTime{Time: brandTime, Valid: true},
		Name:       name,
		Appearance: appearance,
		Theme:      theme,
	}
}

// brandAt reads a JSON answer's value down a path of object keys, nil where the path breaks.
func brandAt(v any, keys ...string) any {
	for _, key := range keys {
		object, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = object[key]
	}
	return v
}

func validBrandBody() map[string]any {
	return map[string]any{"name": "Acme", "appearance": "dark", "theme": "plum"}
}

// brandFieldRefusals are the refusals a create and an update share, each decided on the request
// alone, before anything is read or written.
var brandFieldRefusals = []struct {
	name string
	edit func(body map[string]any)
	code string
}{
	{"no name", func(b map[string]any) { delete(b, "name") }, "handler.brand.name_required"},
	{"a name of spaces", func(b map[string]any) { b["name"] = " \t " }, "handler.brand.name_required"},
	{"61 characters", func(b map[string]any) { b["name"] = strings.Repeat("é", 61) }, "handler.brand.name_too_long"},
	{"an opening angle bracket", func(b map[string]any) { b["name"] = "Acme <b" }, "handler.brand.name_angle_brackets"},
	{"a closing angle bracket", func(b map[string]any) { b["name"] = "Acme>" }, "handler.brand.name_angle_brackets"},
	{"no appearance", func(b map[string]any) { delete(b, "appearance") }, "handler.brand.appearance_invalid"},
	{"an empty appearance", func(b map[string]any) { b["appearance"] = "" }, "handler.brand.appearance_invalid"},
	{"an appearance in capitals", func(b map[string]any) { b["appearance"] = "Dark" }, "handler.brand.appearance_invalid"},
	{"an unknown appearance", func(b map[string]any) { b["appearance"] = "system" }, "handler.brand.appearance_invalid"},
	{"no theme", func(b map[string]any) { delete(b, "theme") }, "handler.brand.theme_invalid"},
	{"a theme by its display name", func(b map[string]any) { b["theme"] = "Plum" }, "handler.brand.theme_invalid"},
	{"the issue's name for Blueberry", func(b map[string]any) { b["theme"] = "default" }, "handler.brand.theme_invalid"},
	{"an unknown theme", func(b map[string]any) { b["theme"] = "lime" }, "handler.brand.theme_invalid"},
}

// --- list ---------------------------------------------------------------------------------------

func TestBrandsGet_SortedByNameWithTheDefaultMarked(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("GetAllBrands", mock.Anything, (*sql.Tx)(nil)).Return([]record.Brand{
		*storedBrand(1, "Default", record.BrandAppearanceAuto, "blueberry"),
		*storedBrand(2, "Zest", record.BrandAppearanceLight, "tangerine"),
		*storedBrand(3, "Acme", record.BrandAppearanceDark, "plum"),
	}, nil).Once()
	database.On("GetDefaultBrand", mock.Anything, (*sql.Tx)(nil)).
		Return(storedBrand(1, "Default", record.BrandAppearanceAuto, "blueberry"), nil).Once()

	status, body := serveBrand(HandleBrandsGet(database), brandRequest(t, http.MethodGet, nil))

	require.Equal(t, http.StatusOK, status)
	brands, _ := body["brands"].([]any)
	require.Len(t, brands, 3)
	var names []any
	var defaults []any
	for _, b := range brands {
		names = append(names, brandAt(b, "name"))
		defaults = append(defaults, brandAt(b, "isDefault"))
	}
	assert.Equal(t, []any{"Acme", "Default", "Zest"}, names)
	assert.Equal(t, []any{false, true, false}, defaults)
	assert.Equal(t, map[string]any{
		"id": float64(3), "name": "Acme", "appearance": "dark", "theme": "plum", "isDefault": false,
		"createdAt": "2026-11-09T12:00:00Z", "updatedAt": "2026-11-09T12:00:00Z",
	}, brands[0])
}

func TestBrandsGet_NoDefaultMarksNone(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("GetAllBrands", mock.Anything, (*sql.Tx)(nil)).Return([]record.Brand{
		*storedBrand(1, "Default", record.BrandAppearanceAuto, "blueberry"),
	}, nil).Once()
	database.On("GetDefaultBrand", mock.Anything, (*sql.Tx)(nil)).Return(nil, nil).Once()

	status, body := serveBrand(HandleBrandsGet(database), brandRequest(t, http.MethodGet, nil))

	require.Equal(t, http.StatusOK, status)
	brands, _ := body["brands"].([]any)
	require.Len(t, brands, 1)
	assert.Equal(t, false, brandAt(brands[0], "isDefault"))
}

// --- create -------------------------------------------------------------------------------------

func TestBrandCreate_Refusals(t *testing.T) {
	for _, c := range brandFieldRefusals {
		t.Run(c.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			body := validBrandBody()
			c.edit(body)

			status, answer := serveBrand(HandleBrandCreatePost(database, handlersmocks.NewAuditLogger(t)),
				brandRequest(t, http.MethodPost, body))

			assert.Equal(t, http.StatusBadRequest, status)
			assert.Equal(t, c.code, errorCode(answer))
			database.AssertNotCalled(t, "CreateBrand", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

func TestBrandCreate_ANameAnotherBrandHoldsIsRefused(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("CreateBrand", mock.Anything, (*sql.Tx)(nil), mock.Anything).
		Return(errs.Wrap(data.ErrUniqueViolation, "unable to insert brand")).Once()

	status, answer := serveBrand(HandleBrandCreatePost(database, handlersmocks.NewAuditLogger(t)),
		brandRequest(t, http.MethodPost, validBrandBody()))

	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "handler.brand.name_in_use", errorCode(answer))
}

func TestBrandWrites_AFailureOtherThanATakenNameIsAServerError(t *testing.T) {
	t.Run("create", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.On("CreateBrand", mock.Anything, (*sql.Tx)(nil), mock.Anything).Return(errs.New("connection reset")).Once()

		status, answer := serveBrand(HandleBrandCreatePost(database, handlersmocks.NewAuditLogger(t)),
			brandRequest(t, http.MethodPost, validBrandBody()))

		assert.Equal(t, http.StatusInternalServerError, status)
		assert.NotEqual(t, "handler.brand.name_in_use", errorCode(answer))
	})
	t.Run("update", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.On("GetBrandById", mock.Anything, (*sql.Tx)(nil), int64(3)).
			Return(storedBrand(3, "Acme", record.BrandAppearanceDark, "plum"), nil).Once()
		database.On("UpdateBrand", mock.Anything, (*sql.Tx)(nil), mock.Anything).Return(errs.New("connection reset")).Once()

		status, answer := serveBrand(HandleBrandUpdatePut(database, handlersmocks.NewAuditLogger(t)),
			brandRequest(t, http.MethodPut, validBrandBody(), "id", "3"))

		assert.Equal(t, http.StatusInternalServerError, status)
		assert.NotEqual(t, "handler.brand.name_in_use", errorCode(answer))
	})
}

func TestBrandCreate_StoresTheTrimmedNameAndAudits(t *testing.T) {
	database := datamocks.NewDatabase(t)
	var stored record.Brand
	database.On("CreateBrand", mock.Anything, (*sql.Tx)(nil), mock.Anything).Run(func(args mock.Arguments) {
		brand := args.Get(2).(*record.Brand)
		stored = *brand
		brand.Id = 7
		brand.CreatedAt = sql.NullTime{Time: brandTime, Valid: true}
		brand.UpdatedAt = sql.NullTime{Time: brandTime, Valid: true}
	}).Return(nil).Once()
	auditLogger := handlersmocks.NewAuditLogger(t)
	auditLogger.On("Log", mock.Anything, audit.EventCreatedBrand, map[string]interface{}{
		"brand_id": int64(7), "brand_name": "Acme Corp", "logged_in_user": brandCaller,
	}).Once()

	status, body := serveBrand(HandleBrandCreatePost(database, auditLogger),
		brandRequest(t, http.MethodPost, map[string]any{"name": "  Acme Corp  ", "appearance": "light", "theme": "high-contrast"}))

	require.Equal(t, http.StatusCreated, status)
	assert.Equal(t, record.Brand{Name: "Acme Corp", Appearance: record.BrandAppearanceLight, Theme: "high-contrast"}, stored)
	assert.Equal(t, map[string]any{
		"id": float64(7), "name": "Acme Corp", "appearance": "light", "theme": "high-contrast", "isDefault": false,
		"createdAt": "2026-11-09T12:00:00Z", "updatedAt": "2026-11-09T12:00:00Z",
	}, body["brand"])
}

func TestBrandCreate_SixtyCharactersAndEveryAppearanceAreTaken(t *testing.T) {
	for _, appearance := range []string{"auto", "light", "dark"} {
		t.Run(appearance, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			database.On("CreateBrand", mock.Anything, (*sql.Tx)(nil), mock.Anything).Return(nil).Once()
			auditLogger := handlersmocks.NewAuditLogger(t)
			auditLogger.On("Log", mock.Anything, audit.EventCreatedBrand, mock.Anything).Once()

			status, _ := serveBrand(HandleBrandCreatePost(database, auditLogger),
				brandRequest(t, http.MethodPost, map[string]any{"name": strings.Repeat("é", 60), "appearance": appearance, "theme": "blueberry"}))

			assert.Equal(t, http.StatusCreated, status)
		})
	}
}

func TestBrandCreate_AnUnreadableBodyIsRefused(t *testing.T) {
	database := datamocks.NewDatabase(t)
	req := brandRequest(t, http.MethodPost, nil)
	req.Body = http.NoBody

	status, answer := serveBrand(HandleBrandCreatePost(database, handlersmocks.NewAuditLogger(t)), req)

	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "INVALID_REQUEST_BODY", errorCode(answer))
}

// --- read ---------------------------------------------------------------------------------------

func TestBrandGet(t *testing.T) {
	t.Run("a brand that is not the default", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.On("GetBrandById", mock.Anything, (*sql.Tx)(nil), int64(3)).
			Return(storedBrand(3, "Acme", record.BrandAppearanceDark, "plum"), nil).Once()
		database.On("GetDefaultBrand", mock.Anything, (*sql.Tx)(nil)).
			Return(storedBrand(1, "Default", record.BrandAppearanceAuto, "blueberry"), nil).Once()

		status, body := serveBrand(HandleBrandGet(database), brandRequest(t, http.MethodGet, nil, "id", "3"))

		require.Equal(t, http.StatusOK, status)
		assert.Equal(t, map[string]any{
			"id": float64(3), "name": "Acme", "appearance": "dark", "theme": "plum", "isDefault": false,
			"createdAt": "2026-11-09T12:00:00Z", "updatedAt": "2026-11-09T12:00:00Z",
		}, body["brand"])
	})
	t.Run("the default brand", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.On("GetBrandById", mock.Anything, (*sql.Tx)(nil), int64(1)).
			Return(storedBrand(1, "Default", record.BrandAppearanceAuto, "blueberry"), nil).Once()
		database.On("GetDefaultBrand", mock.Anything, (*sql.Tx)(nil)).
			Return(storedBrand(1, "Default", record.BrandAppearanceAuto, "blueberry"), nil).Once()

		status, body := serveBrand(HandleBrandGet(database), brandRequest(t, http.MethodGet, nil, "id", "1"))

		require.Equal(t, http.StatusOK, status)
		assert.Equal(t, true, brandAt(body, "brand", "isDefault"))
	})
	t.Run("an unknown brand", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.On("GetBrandById", mock.Anything, (*sql.Tx)(nil), int64(99)).Return(nil, nil).Once()

		status, body := serveBrand(HandleBrandGet(database), brandRequest(t, http.MethodGet, nil, "id", "99"))

		assert.Equal(t, http.StatusNotFound, status)
		assert.Equal(t, "NOT_FOUND", errorCode(body))
	})
	for _, id := range []string{"abc", "0", "-1"} {
		t.Run("the id "+id, func(t *testing.T) {
			database := datamocks.NewDatabase(t)

			status, body := serveBrand(HandleBrandGet(database), brandRequest(t, http.MethodGet, nil, "id", id))

			assert.Equal(t, http.StatusBadRequest, status)
			assert.Equal(t, "VALIDATION_ERROR", errorCode(body))
		})
	}
}

// --- update -------------------------------------------------------------------------------------

func TestBrandUpdate_Refusals(t *testing.T) {
	for _, c := range brandFieldRefusals {
		t.Run(c.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			database.On("GetBrandById", mock.Anything, mock.Anything, int64(3)).
				Return(storedBrand(3, "Acme", record.BrandAppearanceDark, "plum"), nil).Maybe()
			body := validBrandBody()
			c.edit(body)

			status, answer := serveBrand(HandleBrandUpdatePut(database, handlersmocks.NewAuditLogger(t)),
				brandRequest(t, http.MethodPut, body, "id", "3"))

			assert.Equal(t, http.StatusBadRequest, status)
			assert.Equal(t, c.code, errorCode(answer))
			database.AssertNotCalled(t, "UpdateBrand", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

func TestBrandUpdate_AnUnknownBrandIsNotFound(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("GetBrandById", mock.Anything, (*sql.Tx)(nil), int64(99)).Return(nil, nil).Once()

	status, body := serveBrand(HandleBrandUpdatePut(database, handlersmocks.NewAuditLogger(t)),
		brandRequest(t, http.MethodPut, validBrandBody(), "id", "99"))

	assert.Equal(t, http.StatusNotFound, status)
	assert.Equal(t, "NOT_FOUND", errorCode(body))
	database.AssertNotCalled(t, "UpdateBrand", mock.Anything, mock.Anything, mock.Anything)
}

func TestBrandUpdate_ANameAnotherBrandHoldsIsRefused(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("GetBrandById", mock.Anything, (*sql.Tx)(nil), int64(3)).
		Return(storedBrand(3, "Acme", record.BrandAppearanceDark, "plum"), nil).Once()
	database.On("UpdateBrand", mock.Anything, (*sql.Tx)(nil), mock.Anything).
		Return(errs.Wrap(data.ErrUniqueViolation, "unable to update brand")).Once()

	status, answer := serveBrand(HandleBrandUpdatePut(database, handlersmocks.NewAuditLogger(t)),
		brandRequest(t, http.MethodPut, map[string]any{"name": "Default", "appearance": "dark", "theme": "plum"}, "id", "3"))

	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "handler.brand.name_in_use", errorCode(answer))
}

func TestBrandUpdate_ReplacesTheThreeFieldsAndAudits(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("GetBrandById", mock.Anything, (*sql.Tx)(nil), int64(1)).
		Return(storedBrand(1, "Default", record.BrandAppearanceAuto, "blueberry"), nil).Once()
	var written record.Brand
	database.On("UpdateBrand", mock.Anything, (*sql.Tx)(nil), mock.Anything).Run(func(args mock.Arguments) {
		written = *args.Get(2).(*record.Brand)
	}).Return(nil).Once()
	database.On("GetDefaultBrand", mock.Anything, (*sql.Tx)(nil)).
		Return(storedBrand(1, "Default", record.BrandAppearanceAuto, "blueberry"), nil).Once()
	auditLogger := handlersmocks.NewAuditLogger(t)
	auditLogger.On("Log", mock.Anything, audit.EventUpdatedBrand, map[string]interface{}{
		"brand_id": int64(1), "brand_name": "House", "appearance": "light", "theme": "guava",
		"logged_in_user": brandCaller,
	}).Once()

	status, body := serveBrand(HandleBrandUpdatePut(database, auditLogger),
		brandRequest(t, http.MethodPut, map[string]any{"name": " House ", "appearance": "light", "theme": "guava"}, "id", "1"))

	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, int64(1), written.Id)
	assert.Equal(t, "House", written.Name)
	assert.Equal(t, record.BrandAppearanceLight, written.Appearance)
	assert.Equal(t, "guava", written.Theme)
	assert.Equal(t, "House", brandAt(body, "brand", "name"))
	assert.Equal(t, "light", brandAt(body, "brand", "appearance"))
	assert.Equal(t, "guava", brandAt(body, "brand", "theme"))
	assert.Equal(t, true, brandAt(body, "brand", "isDefault"))
}

// --- delete -------------------------------------------------------------------------------------

func TestBrandDelete_TheDefaultIsRefused(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("GetBrandById", mock.Anything, (*sql.Tx)(nil), int64(1)).
		Return(storedBrand(1, "Default", record.BrandAppearanceAuto, "blueberry"), nil).Once()
	datamocks.ExpectRunInTransaction(database, brandTx)
	database.On("DeleteBrand", mock.Anything, brandTx, int64(1)).
		Return(0, errs.WithStack(data.ErrDefaultBrandNotDeletable)).Once()

	status, answer := serveBrand(HandleBrandDelete(database, handlersmocks.NewAuditLogger(t)),
		brandRequest(t, http.MethodDelete, nil, "id", "1"))

	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "handler.brand.default_delete_not_allowed", errorCode(answer))
}

func TestBrandDelete_AnUnknownBrandIsNotFound(t *testing.T) {
	t.Run("gone before the request", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.On("GetBrandById", mock.Anything, (*sql.Tx)(nil), int64(99)).Return(nil, nil).Once()

		status, body := serveBrand(HandleBrandDelete(database, handlersmocks.NewAuditLogger(t)),
			brandRequest(t, http.MethodDelete, nil, "id", "99"))

		assert.Equal(t, http.StatusNotFound, status)
		assert.Equal(t, "NOT_FOUND", errorCode(body))
		database.AssertNotCalled(t, "DeleteBrand", mock.Anything, mock.Anything, mock.Anything)
	})
	t.Run("deleted by another request meanwhile", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.On("GetBrandById", mock.Anything, (*sql.Tx)(nil), int64(3)).
			Return(storedBrand(3, "Acme", record.BrandAppearanceDark, "plum"), nil).Once()
		datamocks.ExpectRunInTransaction(database, brandTx)
		database.On("DeleteBrand", mock.Anything, brandTx, int64(3)).Return(0, errs.WithStack(data.ErrBrandNotFound)).Once()

		status, body := serveBrand(HandleBrandDelete(database, handlersmocks.NewAuditLogger(t)),
			brandRequest(t, http.MethodDelete, nil, "id", "3"))

		assert.Equal(t, http.StatusNotFound, status)
		assert.Equal(t, "NOT_FOUND", errorCode(body))
	})
}

func TestBrandDelete_DeletesUnderTheTransactionAndAudits(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("GetBrandById", mock.Anything, (*sql.Tx)(nil), int64(3)).
		Return(storedBrand(3, "Acme", record.BrandAppearanceDark, "plum"), nil).Once()
	datamocks.ExpectRunInTransaction(database, brandTx)
	database.On("DeleteBrand", mock.Anything, brandTx, int64(3)).Return(0, nil).Once()
	auditLogger := handlersmocks.NewAuditLogger(t)
	auditLogger.On("Log", mock.Anything, audit.EventDeletedBrand, map[string]interface{}{
		"brand_id": int64(3), "brand_name": "Acme", "logged_in_user": brandCaller,
	}).Once()

	status, body := serveBrand(HandleBrandDelete(database, auditLogger), brandRequest(t, http.MethodDelete, nil, "id", "3"))

	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, true, body["success"])
}

// --- make default -------------------------------------------------------------------------------

func TestBrandMakeDefault_MovesTheDefaultAndAuditsBothBrands(t *testing.T) {
	database := datamocks.NewDatabase(t)
	datamocks.ExpectRunInTransaction(database, brandTx)
	database.On("MakeBrandDefault", mock.Anything, brandTx, int64(3)).Return(int64(1), nil).Once()
	database.On("GetBrandById", mock.Anything, brandTx, int64(3)).
		Return(storedBrand(3, "Acme", record.BrandAppearanceDark, "plum"), nil).Once()
	database.On("GetBrandById", mock.Anything, brandTx, int64(1)).
		Return(storedBrand(1, "Default", record.BrandAppearanceAuto, "blueberry"), nil).Once()
	auditLogger := handlersmocks.NewAuditLogger(t)
	auditLogger.On("Log", mock.Anything, audit.EventUpdatedDefaultBrand, map[string]interface{}{
		"brand_id": int64(3), "brand_name": "Acme", "old_brand_id": int64(1), "old_brand_name": "Default",
		"logged_in_user": brandCaller,
	}).Once()

	status, body := serveBrand(HandleBrandMakeDefaultPost(database, auditLogger),
		brandRequest(t, http.MethodPost, nil, "id", "3"))

	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, map[string]any{
		"id": float64(3), "name": "Acme", "appearance": "dark", "theme": "plum", "isDefault": true,
		"createdAt": "2026-11-09T12:00:00Z", "updatedAt": "2026-11-09T12:00:00Z",
	}, body["brand"])
}

func TestBrandMakeDefault_TheDefaultAlreadyRecordsNothing(t *testing.T) {
	database := datamocks.NewDatabase(t)
	datamocks.ExpectRunInTransaction(database, brandTx)
	database.On("MakeBrandDefault", mock.Anything, brandTx, int64(1)).Return(int64(1), nil).Once()
	database.On("GetBrandById", mock.Anything, brandTx, int64(1)).
		Return(storedBrand(1, "Default", record.BrandAppearanceAuto, "blueberry"), nil).Once()

	status, body := serveBrand(HandleBrandMakeDefaultPost(database, handlersmocks.NewAuditLogger(t)),
		brandRequest(t, http.MethodPost, nil, "id", "1"))

	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, true, brandAt(body, "brand", "isDefault"))
}

func TestBrandMakeDefault_AnUnknownBrandIsNotFound(t *testing.T) {
	database := datamocks.NewDatabase(t)
	datamocks.ExpectRunInTransaction(database, brandTx)
	database.On("MakeBrandDefault", mock.Anything, brandTx, int64(99)).Return(int64(0), errs.WithStack(data.ErrBrandNotFound)).Once()

	status, body := serveBrand(HandleBrandMakeDefaultPost(database, handlersmocks.NewAuditLogger(t)),
		brandRequest(t, http.MethodPost, nil, "id", "99"))

	assert.Equal(t, http.StatusNotFound, status)
	assert.Equal(t, "NOT_FOUND", errorCode(body))
}

// --- the built-in themes ------------------------------------------------------------------------

func TestBrandThemesGet_ListsTheEightPresetsInDisplayOrder(t *testing.T) {
	status, body := serveBrand(HandleBrandThemesGet(), brandRequest(t, http.MethodGet, nil))

	require.Equal(t, http.StatusOK, status)
	themes, _ := body["brandThemes"].([]any)
	var keys []any
	for _, theme := range themes {
		keys = append(keys, brandAt(theme, "key"))
		assert.Len(t, brandAt(theme, "light"), 23, brandAt(theme, "key"))
		assert.Len(t, brandAt(theme, "dark"), 23, brandAt(theme, "key"))
	}
	assert.Equal(t, []any{"blueberry", "blackberry", "avocado", "plum", "tangerine", "guava", "coconut", "high-contrast"}, keys)

	// Values from the approved palettes (#810 decision 6).
	byKey := map[any]any{}
	for _, theme := range themes {
		byKey[brandAt(theme, "key")] = theme
	}
	assert.Equal(t, "#a84d08", brandAt(byKey["tangerine"], "light", "brand"))
	assert.Equal(t, "#cda4f0", brandAt(byKey["plum"], "dark", "focus"))
	assert.Equal(t, "#000000", brandAt(byKey["high-contrast"], "dark", "canvas"))
	assert.Equal(t, "#0f2347", brandAt(byKey["high-contrast"], "dark", "note-soft"))
}
