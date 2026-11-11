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

// The admin API's brands (#810 decision 5) and their kit's choices (#813 decision 10), one rule per
// test, through the handlers with the generated database mock: what each refusal answers and
// writes, what each write stores and audits, and how a brand is answered.

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

// storedBrand is a brand as the data layer reads it, its kit the one migration 000091 gives an
// existing brand: rounded, System UI, cover, the app name shown and every slot empty.
func storedBrand(id int64, name string, appearance record.BrandAppearance, theme string) *record.Brand {
	return &record.Brand{
		Id:            id,
		CreatedAt:     sql.NullTime{Time: brandTime, Valid: true},
		UpdatedAt:     sql.NullTime{Time: brandTime, Valid: true},
		Name:          name,
		Appearance:    appearance,
		Theme:         theme,
		Corners:       "rounded",
		Font:          "system-ui",
		BackgroundFit: "cover",
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
	return map[string]any{"name": "Acme", "appearance": "dark", "theme": "plum",
		"corners": "pill", "font": "serif", "backgroundFit": "contain"}
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
	// A brand write names every choice, so a misspelt field is refused rather than becoming a
	// default (#813 decision 10).
	{"no corners", func(b map[string]any) { delete(b, "corners") }, "handler.brand.corners_invalid"},
	{"misspelt corners", func(b map[string]any) { delete(b, "corners"); b["corner"] = "pill" }, "handler.brand.corners_invalid"},
	{"empty corners", func(b map[string]any) { b["corners"] = "" }, "handler.brand.corners_invalid"},
	{"corners in capitals", func(b map[string]any) { b["corners"] = "Pill" }, "handler.brand.corners_invalid"},
	{"unknown corners", func(b map[string]any) { b["corners"] = "round" }, "handler.brand.corners_invalid"},
	{"no font", func(b map[string]any) { delete(b, "font") }, "handler.brand.font_invalid"},
	{"a font by its display name", func(b map[string]any) { b["font"] = "System UI" }, "handler.brand.font_invalid"},
	{"a font named as a CSS family", func(b map[string]any) { b["font"] = "sans-serif" }, "handler.brand.font_invalid"},
	{"a font in capitals", func(b map[string]any) { b["font"] = "Serif" }, "handler.brand.font_invalid"},
	{"neo-grotesque without its hyphen", func(b map[string]any) { b["font"] = "neogrotesque" }, "handler.brand.font_invalid"},
	{"no background fit", func(b map[string]any) { delete(b, "backgroundFit") }, "handler.brand.background_fit_invalid"},
	{"a background fit in snake case", func(b map[string]any) { delete(b, "backgroundFit"); b["background_fit"] = "tile" }, "handler.brand.background_fit_invalid"},
	{"an unknown background fit", func(b map[string]any) { b["backgroundFit"] = "repeat" }, "handler.brand.background_fit_invalid"},
	{"a background fit in capitals", func(b map[string]any) { b["backgroundFit"] = "Cover" }, "handler.brand.background_fit_invalid"},
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
	// Zest draws no client, so the count leaves it out.
	database.On("CountClientsPerBrand", mock.Anything, (*sql.Tx)(nil)).Return(map[int64]int{1: 5, 3: 2}, nil).Once()

	status, body := serveBrand(HandleBrandsGet(database, brandBaseURL), brandRequest(t, http.MethodGet, nil))

	require.Equal(t, http.StatusOK, status)
	brands, _ := body["brands"].([]any)
	require.Len(t, brands, 3)
	var names []any
	var defaults []any
	var counts []any
	for _, b := range brands {
		names = append(names, brandAt(b, "name"))
		defaults = append(defaults, brandAt(b, "isDefault"))
		counts = append(counts, brandAt(b, "clientCount"))
	}
	assert.Equal(t, []any{"Acme", "Default", "Zest"}, names)
	assert.Equal(t, []any{false, true, false}, defaults)
	assert.Equal(t, []any{float64(2), float64(5), float64(0)}, counts)
	assert.Equal(t, map[string]any{
		"id": float64(3), "name": "Acme", "appearance": "dark", "theme": "plum",
		"corners": "rounded", "font": "system-ui", "backgroundFit": "cover", "hideAppName": false,
		"logo": nil, "darkLogo": nil, "favicon": nil, "background": nil, "regularFont": nil, "boldFont": nil,
		"isDefault": false, "clientCount": float64(2),
		"createdAt": "2026-11-09T12:00:00Z", "updatedAt": "2026-11-09T12:00:00Z",
	}, brands[0])
}

func TestBrandsGet_NoDefaultMarksNone(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("GetAllBrands", mock.Anything, (*sql.Tx)(nil)).Return([]record.Brand{
		*storedBrand(1, "Default", record.BrandAppearanceAuto, "blueberry"),
	}, nil).Once()
	database.On("GetDefaultBrand", mock.Anything, (*sql.Tx)(nil)).Return(nil, nil).Once()
	database.On("CountClientsPerBrand", mock.Anything, (*sql.Tx)(nil)).Return(map[int64]int{}, nil).Once()

	status, body := serveBrand(HandleBrandsGet(database, brandBaseURL), brandRequest(t, http.MethodGet, nil))

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

			status, answer := serveBrand(HandleBrandCreatePost(database, handlersmocks.NewAuditLogger(t), brandBaseURL),
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

	status, answer := serveBrand(HandleBrandCreatePost(database, handlersmocks.NewAuditLogger(t), brandBaseURL),
		brandRequest(t, http.MethodPost, validBrandBody()))

	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "handler.brand.name_in_use", errorCode(answer))
}

func TestBrandWrites_AFailureOtherThanATakenNameIsAServerError(t *testing.T) {
	t.Run("create", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.On("CreateBrand", mock.Anything, (*sql.Tx)(nil), mock.Anything).Return(errs.New("connection reset")).Once()

		status, answer := serveBrand(HandleBrandCreatePost(database, handlersmocks.NewAuditLogger(t), brandBaseURL),
			brandRequest(t, http.MethodPost, validBrandBody()))

		assert.Equal(t, http.StatusInternalServerError, status)
		assert.NotEqual(t, "handler.brand.name_in_use", errorCode(answer))
	})
	t.Run("update", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.On("GetBrandById", mock.Anything, (*sql.Tx)(nil), int64(3)).
			Return(storedBrand(3, "Acme", record.BrandAppearanceDark, "plum"), nil).Once()
		database.On("UpdateBrand", mock.Anything, (*sql.Tx)(nil), mock.Anything).Return(errs.New("connection reset")).Once()

		status, answer := serveBrand(HandleBrandUpdatePut(database, handlersmocks.NewAuditLogger(t), brandBaseURL),
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

	status, body := serveBrand(HandleBrandCreatePost(database, auditLogger, brandBaseURL),
		brandRequest(t, http.MethodPost, map[string]any{"name": "  Acme Corp  ", "appearance": "light", "theme": "high-contrast",
			"corners": "square", "font": "neo-grotesque", "backgroundFit": "tile", "hideAppName": true}))

	require.Equal(t, http.StatusCreated, status)
	// The choices as sent, and every slot empty: a create names no asset yet.
	assert.Equal(t, record.Brand{Name: "Acme Corp", Appearance: record.BrandAppearanceLight, Theme: "high-contrast",
		Corners: "square", Font: "neo-grotesque", BackgroundFit: "tile", HideAppName: true}, stored)
	assert.Equal(t, map[string]any{
		"id": float64(7), "name": "Acme Corp", "appearance": "light", "theme": "high-contrast",
		"corners": "square", "font": "neo-grotesque", "backgroundFit": "tile", "hideAppName": true,
		"logo": nil, "darkLogo": nil, "favicon": nil, "background": nil, "regularFont": nil, "boldFont": nil,
		"isDefault": false, "clientCount": float64(0),
		"createdAt": "2026-11-09T12:00:00Z", "updatedAt": "2026-11-09T12:00:00Z",
	}, body["brand"])
}

// The hide-app-name switch is a boolean, false when absent (#813 decision 10), and every value of
// each choice is taken as it is spelt in the API.
func TestBrandCreate_EveryChoiceIsTakenAndTheSwitchIsFalseWhenAbsent(t *testing.T) {
	choices := []struct{ field, value string }{
		{"corners", "square"}, {"corners", "rounded"}, {"corners", "pill"},
		{"font", "system-ui"}, {"font", "humanist"}, {"font", "geometric"}, {"font", "serif"},
		{"font", "neo-grotesque"}, {"font", "rounded"},
		{"backgroundFit", "cover"}, {"backgroundFit", "contain"}, {"backgroundFit", "tile"},
	}
	for _, c := range choices {
		t.Run(c.field+" "+c.value, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			var stored record.Brand
			database.On("CreateBrand", mock.Anything, (*sql.Tx)(nil), mock.Anything).Run(func(args mock.Arguments) {
				stored = *args.Get(2).(*record.Brand)
			}).Return(nil).Once()
			auditLogger := handlersmocks.NewAuditLogger(t)
			auditLogger.On("Log", mock.Anything, audit.EventCreatedBrand, mock.Anything).Once()
			body := validBrandBody()
			body[c.field] = c.value

			status, answer := serveBrand(HandleBrandCreatePost(database, auditLogger, brandBaseURL), brandRequest(t, http.MethodPost, body))

			require.Equal(t, http.StatusCreated, status, "%v", answer)
			assert.Equal(t, c.value, brandAt(answer, "brand", c.field))
			assert.Equal(t, false, brandAt(answer, "brand", "hideAppName"))
			assert.False(t, stored.HideAppName)
			assert.Equal(t, map[string]string{"corners": string(stored.Corners), "font": string(stored.Font),
				"backgroundFit": string(stored.BackgroundFit)}[c.field], c.value)
		})
	}
}

// A new brand holds no font file, so the uploaded font is refused on a create (#813 decision 7).
func TestBrandCreate_TheUploadedFontWithoutARegularFileIsRefused(t *testing.T) {
	database := datamocks.NewDatabase(t)
	body := validBrandBody()
	body["font"] = "uploaded"

	status, answer := serveBrand(HandleBrandCreatePost(database, handlersmocks.NewAuditLogger(t), brandBaseURL),
		brandRequest(t, http.MethodPost, body))

	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "handler.brand.uploaded_font_regular_required", errorCode(answer))
	database.AssertNotCalled(t, "CreateBrand", mock.Anything, mock.Anything, mock.Anything)
}

func TestBrandCreate_SixtyCharactersAndEveryAppearanceAreTaken(t *testing.T) {
	for _, appearance := range []string{"auto", "light", "dark"} {
		t.Run(appearance, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			database.On("CreateBrand", mock.Anything, (*sql.Tx)(nil), mock.Anything).Return(nil).Once()
			auditLogger := handlersmocks.NewAuditLogger(t)
			auditLogger.On("Log", mock.Anything, audit.EventCreatedBrand, mock.Anything).Once()

			status, _ := serveBrand(HandleBrandCreatePost(database, auditLogger, brandBaseURL),
				brandRequest(t, http.MethodPost, map[string]any{"name": strings.Repeat("é", 60), "appearance": appearance, "theme": "blueberry",
					"corners": "rounded", "font": "system-ui", "backgroundFit": "cover"}))

			assert.Equal(t, http.StatusCreated, status)
		})
	}
}

func TestBrandCreate_AnUnreadableBodyIsRefused(t *testing.T) {
	database := datamocks.NewDatabase(t)
	req := brandRequest(t, http.MethodPost, nil)
	req.Body = http.NoBody

	status, answer := serveBrand(HandleBrandCreatePost(database, handlersmocks.NewAuditLogger(t), brandBaseURL), req)

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
		database.On("CountClientsPerBrand", mock.Anything, (*sql.Tx)(nil)).Return(map[int64]int{1: 9, 3: 4}, nil).Once()

		status, body := serveBrand(HandleBrandGet(database, brandBaseURL), brandRequest(t, http.MethodGet, nil, "id", "3"))

		require.Equal(t, http.StatusOK, status)
		assert.Equal(t, map[string]any{
			"id": float64(3), "name": "Acme", "appearance": "dark", "theme": "plum",
			"corners": "rounded", "font": "system-ui", "backgroundFit": "cover", "hideAppName": false,
			"logo": nil, "darkLogo": nil, "favicon": nil, "background": nil, "regularFont": nil, "boldFont": nil,
			"isDefault": false, "clientCount": float64(4),
			"createdAt": "2026-11-09T12:00:00Z", "updatedAt": "2026-11-09T12:00:00Z",
		}, body["brand"])
	})
	t.Run("the default brand", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.On("GetBrandById", mock.Anything, (*sql.Tx)(nil), int64(1)).
			Return(storedBrand(1, "Default", record.BrandAppearanceAuto, "blueberry"), nil).Once()
		database.On("GetDefaultBrand", mock.Anything, (*sql.Tx)(nil)).
			Return(storedBrand(1, "Default", record.BrandAppearanceAuto, "blueberry"), nil).Once()
		database.On("CountClientsPerBrand", mock.Anything, (*sql.Tx)(nil)).Return(map[int64]int{1: 9, 3: 4}, nil).Once()

		status, body := serveBrand(HandleBrandGet(database, brandBaseURL), brandRequest(t, http.MethodGet, nil, "id", "1"))

		require.Equal(t, http.StatusOK, status)
		assert.Equal(t, true, brandAt(body, "brand", "isDefault"))
		assert.InDelta(t, 9, brandAt(body, "brand", "clientCount"), 0)
	})
	t.Run("a brand no client is drawn in", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.On("GetBrandById", mock.Anything, (*sql.Tx)(nil), int64(3)).
			Return(storedBrand(3, "Acme", record.BrandAppearanceDark, "plum"), nil).Once()
		database.On("GetDefaultBrand", mock.Anything, (*sql.Tx)(nil)).
			Return(storedBrand(1, "Default", record.BrandAppearanceAuto, "blueberry"), nil).Once()
		database.On("CountClientsPerBrand", mock.Anything, (*sql.Tx)(nil)).Return(map[int64]int{1: 9}, nil).Once()

		status, body := serveBrand(HandleBrandGet(database, brandBaseURL), brandRequest(t, http.MethodGet, nil, "id", "3"))

		require.Equal(t, http.StatusOK, status)
		assert.InDelta(t, 0, brandAt(body, "brand", "clientCount"), 0)
	})
	t.Run("a count that cannot be read fails the answer", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.On("GetBrandById", mock.Anything, (*sql.Tx)(nil), int64(3)).
			Return(storedBrand(3, "Acme", record.BrandAppearanceDark, "plum"), nil).Once()
		database.On("GetDefaultBrand", mock.Anything, (*sql.Tx)(nil)).
			Return(storedBrand(1, "Default", record.BrandAppearanceAuto, "blueberry"), nil).Once()
		database.On("CountClientsPerBrand", mock.Anything, (*sql.Tx)(nil)).Return(nil, errs.New("connection reset")).Once()

		status, body := serveBrand(HandleBrandGet(database, brandBaseURL), brandRequest(t, http.MethodGet, nil, "id", "3"))

		assert.Equal(t, http.StatusInternalServerError, status)
		assert.Nil(t, body["brand"])
	})
	t.Run("an unknown brand", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.On("GetBrandById", mock.Anything, (*sql.Tx)(nil), int64(99)).Return(nil, nil).Once()

		status, body := serveBrand(HandleBrandGet(database, brandBaseURL), brandRequest(t, http.MethodGet, nil, "id", "99"))

		assert.Equal(t, http.StatusNotFound, status)
		assert.Equal(t, "NOT_FOUND", errorCode(body))
	})
	for _, id := range []string{"abc", "0", "-1"} {
		t.Run("the id "+id, func(t *testing.T) {
			database := datamocks.NewDatabase(t)

			status, body := serveBrand(HandleBrandGet(database, brandBaseURL), brandRequest(t, http.MethodGet, nil, "id", id))

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

			status, answer := serveBrand(HandleBrandUpdatePut(database, handlersmocks.NewAuditLogger(t), brandBaseURL),
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

	status, body := serveBrand(HandleBrandUpdatePut(database, handlersmocks.NewAuditLogger(t), brandBaseURL),
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

	status, answer := serveBrand(HandleBrandUpdatePut(database, handlersmocks.NewAuditLogger(t), brandBaseURL),
		brandRequest(t, http.MethodPut, map[string]any{"name": "Default", "appearance": "dark", "theme": "plum",
			"corners": "rounded", "font": "system-ui", "backgroundFit": "cover"}, "id", "3"))

	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "handler.brand.name_in_use", errorCode(answer))
}

func TestBrandUpdate_ReplacesEveryFieldAndAudits(t *testing.T) {
	database := datamocks.NewDatabase(t)
	stored := storedBrand(1, "Default", record.BrandAppearanceAuto, "blueberry")
	stored.HideAppName = true
	database.On("GetBrandById", mock.Anything, (*sql.Tx)(nil), int64(1)).Return(stored, nil).Once()
	var written record.Brand
	database.On("UpdateBrand", mock.Anything, (*sql.Tx)(nil), mock.Anything).Run(func(args mock.Arguments) {
		written = *args.Get(2).(*record.Brand)
	}).Return(nil).Once()
	database.On("GetDefaultBrand", mock.Anything, (*sql.Tx)(nil)).
		Return(storedBrand(1, "Default", record.BrandAppearanceAuto, "blueberry"), nil).Once()
	database.On("CountClientsPerBrand", mock.Anything, (*sql.Tx)(nil)).Return(map[int64]int{1: 6}, nil).Once()
	auditLogger := handlersmocks.NewAuditLogger(t)
	auditLogger.On("Log", mock.Anything, audit.EventUpdatedBrand, map[string]interface{}{
		"brand_id": int64(1), "brand_name": "House", "appearance": "light", "theme": "guava",
		"corners": "pill", "font": "humanist", "background_fit": "contain", "hide_app_name": false,
		"logged_in_user": brandCaller,
	}).Once()

	// hideAppName is left out, so the stored true becomes false: an update is a full replace.
	status, body := serveBrand(HandleBrandUpdatePut(database, auditLogger, brandBaseURL),
		brandRequest(t, http.MethodPut, map[string]any{"name": " House ", "appearance": "light", "theme": "guava",
			"corners": "pill", "font": "humanist", "backgroundFit": "contain"}, "id", "1"))

	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, record.Brand{
		Id: 1, CreatedAt: stored.CreatedAt, UpdatedAt: stored.UpdatedAt,
		Name: "House", Appearance: record.BrandAppearanceLight, Theme: "guava",
		Corners: "pill", Font: "humanist", BackgroundFit: "contain", HideAppName: false,
	}, written)
	assert.Equal(t, "House", brandAt(body, "brand", "name"))
	assert.Equal(t, "light", brandAt(body, "brand", "appearance"))
	assert.Equal(t, "guava", brandAt(body, "brand", "theme"))
	assert.Equal(t, "pill", brandAt(body, "brand", "corners"))
	assert.Equal(t, "humanist", brandAt(body, "brand", "font"))
	assert.Equal(t, "contain", brandAt(body, "brand", "backgroundFit"))
	assert.Equal(t, false, brandAt(body, "brand", "hideAppName"))
	assert.Equal(t, true, brandAt(body, "brand", "isDefault"))
	assert.InDelta(t, 6, brandAt(body, "brand", "clientCount"), 0)
}

// storedKitBrand is a brand whose six slots are all filled: assets 11 to 16, kitAssets.
func storedKitBrand() *record.Brand {
	stored := storedBrand(4, "Acme", record.BrandAppearanceDark, "plum")
	stored.Corners, stored.Font, stored.BackgroundFit, stored.HideAppName = "pill", "uploaded", "tile", true
	stored.LogoAssetId = sql.NullInt64{Int64: 11, Valid: true}
	stored.DarkLogoAssetId = sql.NullInt64{Int64: 12, Valid: true}
	stored.FaviconAssetId = sql.NullInt64{Int64: 13, Valid: true}
	stored.BackgroundAssetId = sql.NullInt64{Int64: 14, Valid: true}
	stored.RegularFontAssetId = sql.NullInt64{Int64: 15, Valid: true}
	stored.BoldFontAssetId = sql.NullInt64{Int64: 16, Valid: true}
	return stored
}

// An update is a full replace, the slots included: a slot the request leaves out is emptied, and one
// it names takes the asset it names (#813 decision 10). The audit event lists the slots the brand
// holds after the save, by asset id, and leaves an empty one out.
func TestBrandUpdate_ReplacesTheSlots(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("GetBrandById", mock.Anything, (*sql.Tx)(nil), int64(4)).Return(storedKitBrand(), nil).Once()
	expectBrandAssets(database)
	var written record.Brand
	database.On("UpdateBrand", mock.Anything, (*sql.Tx)(nil), mock.Anything).Run(func(args mock.Arguments) {
		written = *args.Get(2).(*record.Brand)
	}).Return(nil).Once()
	database.On("GetDefaultBrand", mock.Anything, (*sql.Tx)(nil)).
		Return(storedBrand(1, "Default", record.BrandAppearanceAuto, "blueberry"), nil).Once()
	database.On("CountClientsPerBrand", mock.Anything, (*sql.Tx)(nil)).Return(map[int64]int{}, nil).Once()
	auditLogger := handlersmocks.NewAuditLogger(t)
	auditLogger.On("Log", mock.Anything, audit.EventUpdatedBrand, map[string]interface{}{
		"brand_id": int64(4), "brand_name": "Acme", "appearance": "light", "theme": "guava",
		"corners": "square", "font": "serif", "background_fit": "cover", "hide_app_name": true,
		"logo_asset_id": int64(21), "background_asset_id": int64(23),
		"logged_in_user": brandCaller,
	}).Once()

	status, body := serveBrand(HandleBrandUpdatePut(database, auditLogger, brandBaseURL),
		brandRequest(t, http.MethodPut, map[string]any{"name": "Acme", "appearance": "light", "theme": "guava",
			"corners": "square", "font": "serif", "backgroundFit": "cover", "hideAppName": true,
			"logo": map[string]any{"id": 21}, "darkLogo": nil, "background": map[string]any{"id": 23}}, "id", "4"))

	require.Equal(t, http.StatusOK, status, "%v", body)
	assert.Equal(t, []sql.NullInt64{{Int64: 21, Valid: true}, {}, {}, {Int64: 23, Valid: true}, {}, {}},
		[]sql.NullInt64{written.LogoAssetId, written.DarkLogoAssetId, written.FaviconAssetId,
			written.BackgroundAssetId, written.RegularFontAssetId, written.BoldFontAssetId})
	assert.InDelta(t, 21, brandAt(body, "brand", "logo", "id"), 0)
	assert.Nil(t, brandAt(body, "brand", "darkLogo"))
	assert.Nil(t, brandAt(body, "brand", "favicon"))
	assert.InDelta(t, 23, brandAt(body, "brand", "background", "id"), 0)
	assert.Nil(t, brandAt(body, "brand", "regularFont"))
	assert.Nil(t, brandAt(body, "brand", "boldFont"))
}

// A brand answered, then sent back as its own update, is written exactly as it was stored, its six
// slots included: each slot answers the id a write names it by (#813 decision 10).
func TestBrandUpdate_ABrandReadAndWrittenBackIsUnchanged(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("GetBrandById", mock.Anything, (*sql.Tx)(nil), int64(4)).Return(storedKitBrand(), nil).Twice()
	expectBrandAssets(database)
	database.On("GetDefaultBrand", mock.Anything, (*sql.Tx)(nil)).
		Return(storedBrand(1, "Default", record.BrandAppearanceAuto, "blueberry"), nil).Twice()
	database.On("CountClientsPerBrand", mock.Anything, (*sql.Tx)(nil)).Return(map[int64]int{}, nil).Twice()
	var written record.Brand
	database.On("UpdateBrand", mock.Anything, (*sql.Tx)(nil), mock.Anything).Run(func(args mock.Arguments) {
		written = *args.Get(2).(*record.Brand)
	}).Return(nil).Once()
	auditLogger := handlersmocks.NewAuditLogger(t)
	auditLogger.On("Log", mock.Anything, audit.EventUpdatedBrand, mock.Anything).Once()

	status, read := serveBrand(HandleBrandGet(database, brandBaseURL), brandRequest(t, http.MethodGet, nil, "id", "4"))
	require.Equal(t, http.StatusOK, status)
	status, again := serveBrand(HandleBrandUpdatePut(database, auditLogger, brandBaseURL),
		brandRequest(t, http.MethodPut, read["brand"], "id", "4"))

	require.Equal(t, http.StatusOK, status, "%v", again)
	assert.Equal(t, *storedKitBrand(), written)
	assert.Equal(t, read["brand"], again["brand"])
}

// The uploaded font is refused while the brand names no regular font file, and a bold file alone is
// not one (#813 decision 7).
func TestBrandUpdate_TheUploadedFontWithoutARegularFileIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		bold any
	}{
		{"no font file", nil},
		{"a bold file alone", map[string]any{"id": 24}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			database.On("GetBrandById", mock.Anything, (*sql.Tx)(nil), int64(4)).Return(storedKitBrand(), nil).Once()
			expectBrandAssets(database).Maybe()
			body := validBrandBody()
			body["font"] = "uploaded"
			body["boldFont"] = tc.bold

			status, answer := serveBrand(HandleBrandUpdatePut(database, handlersmocks.NewAuditLogger(t), brandBaseURL),
				brandRequest(t, http.MethodPut, body, "id", "4"))

			assert.Equal(t, http.StatusBadRequest, status)
			assert.Equal(t, "handler.brand.uploaded_font_regular_required", errorCode(answer))
			database.AssertNotCalled(t, "UpdateBrand", mock.Anything, mock.Anything, mock.Anything)
		})
	}
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
	// The deletion moved three clients to the default brand.
	database.On("DeleteBrand", mock.Anything, brandTx, int64(3)).Return(3, nil).Once()
	auditLogger := handlersmocks.NewAuditLogger(t)
	auditLogger.On("Log", mock.Anything, audit.EventDeletedBrand, map[string]interface{}{
		"brand_id": int64(3), "brand_name": "Acme", "client_count": 3, "logged_in_user": brandCaller,
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
	database.On("CountClientsPerBrand", mock.Anything, brandTx).Return(map[int64]int{1: 1, 3: 8}, nil).Once()
	auditLogger := handlersmocks.NewAuditLogger(t)
	auditLogger.On("Log", mock.Anything, audit.EventUpdatedDefaultBrand, map[string]interface{}{
		"brand_id": int64(3), "brand_name": "Acme", "old_brand_id": int64(1), "old_brand_name": "Default",
		"logged_in_user": brandCaller,
	}).Once()

	status, body := serveBrand(HandleBrandMakeDefaultPost(database, auditLogger, brandBaseURL),
		brandRequest(t, http.MethodPost, nil, "id", "3"))

	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, map[string]any{
		"id": float64(3), "name": "Acme", "appearance": "dark", "theme": "plum",
		"corners": "rounded", "font": "system-ui", "backgroundFit": "cover", "hideAppName": false,
		"logo": nil, "darkLogo": nil, "favicon": nil, "background": nil, "regularFont": nil, "boldFont": nil,
		"isDefault": true, "clientCount": float64(8),
		"createdAt": "2026-11-09T12:00:00Z", "updatedAt": "2026-11-09T12:00:00Z",
	}, body["brand"])
}

func TestBrandMakeDefault_TheDefaultAlreadyRecordsNothing(t *testing.T) {
	database := datamocks.NewDatabase(t)
	datamocks.ExpectRunInTransaction(database, brandTx)
	database.On("MakeBrandDefault", mock.Anything, brandTx, int64(1)).Return(int64(1), nil).Once()
	database.On("GetBrandById", mock.Anything, brandTx, int64(1)).
		Return(storedBrand(1, "Default", record.BrandAppearanceAuto, "blueberry"), nil).Once()
	database.On("CountClientsPerBrand", mock.Anything, brandTx).Return(map[int64]int{1: 4}, nil).Once()

	status, body := serveBrand(HandleBrandMakeDefaultPost(database, handlersmocks.NewAuditLogger(t), brandBaseURL),
		brandRequest(t, http.MethodPost, nil, "id", "1"))

	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, true, brandAt(body, "brand", "isDefault"))
}

func TestBrandMakeDefault_AnUnknownBrandIsNotFound(t *testing.T) {
	database := datamocks.NewDatabase(t)
	datamocks.ExpectRunInTransaction(database, brandTx)
	database.On("MakeBrandDefault", mock.Anything, brandTx, int64(99)).Return(int64(0), errs.WithStack(data.ErrBrandNotFound)).Once()

	status, body := serveBrand(HandleBrandMakeDefaultPost(database, handlersmocks.NewAuditLogger(t), brandBaseURL),
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
