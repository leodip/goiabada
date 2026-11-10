package integration

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The admin API's brands end to end (#810 decision 5): the seven operations, their refusals, what
// they store, read back through the data layer, and the audit events they record.

const (
	brandsPath      = "/api/v1/admin/brands"
	brandThemesPath = "/api/v1/admin/brand-themes"
)

func brandPath(id int64, suffix string) string {
	return brandsPath + "/" + strconv.FormatInt(id, 10) + suffix
}

// brandCall sends one admin API request and answers its status, its JSON body and its request id.
func brandCall(t *testing.T, accessToken, method, path string, body any) (int, map[string]any, string) {
	t.Helper()
	resp, requestId := sendAdmin(t, accessToken, method, path, body)
	defer func() { _ = resp.Body.Close() }()
	var answer map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&answer)
	return resp.StatusCode, answer, requestId
}

func brandName(prefix string) string {
	return prefix + " " + fake.LetterN(10)
}

// keepDefaultBrand puts back, when the test ends, the default brand the test started with, then
// deletes every brand the test created over the API. UpdateSettings never writes the pointer, so
// restoreSettings cannot put it back.
func keepDefaultBrand(t *testing.T) (defaultId int64, created *[]int64) {
	t.Helper()
	ctx := context.Background()
	current, err := database.GetDefaultBrand(ctx, nil)
	require.NoError(t, err)
	require.NotNil(t, current, "the installation has a default brand")
	ids := &[]int64{}
	t.Cleanup(func() {
		assert.NoError(t, database.RunInTransaction(ctx, func(tx *sql.Tx) error {
			if _, err := database.MakeBrandDefault(ctx, tx, current.Id); err != nil {
				return err
			}
			for _, id := range *ids {
				if err := database.DeleteBrand(ctx, tx, id); err != nil && !errors.Is(err, data.ErrBrandNotFound) {
					return err
				}
			}
			return nil
		}), "unable to put the default brand back")
	})
	return current.Id, ids
}

// createBrandOverAPI creates a brand and answers its id, which keepDefaultBrand's cleanup deletes.
func createBrandOverAPI(t *testing.T, accessToken string, created *[]int64, name, appearance, theme string) int64 {
	t.Helper()
	status, body, _ := brandCall(t, accessToken, http.MethodPost, brandsPath,
		map[string]any{"name": name, "appearance": appearance, "theme": theme})
	require.Equal(t, http.StatusCreated, status, "create: %v", body)
	id := int64(body["brand"].(map[string]any)["id"].(float64))
	*created = append(*created, id)
	return id
}

func TestAPIBrands_CreateReadUpdateAndDelete(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	_, created := keepDefaultBrand(t)
	ctx := context.Background()
	name := brandName("Acme")

	status, body, _ := brandCall(t, accessToken, http.MethodPost, brandsPath,
		map[string]any{"name": "  " + name + "  ", "appearance": "dark", "theme": "plum"})
	require.Equal(t, http.StatusCreated, status, "create: %v", body)
	brand := body["brand"].(map[string]any)
	id := int64(brand["id"].(float64))
	*created = append(*created, id)
	assert.Equal(t, name, brand["name"])
	assert.Equal(t, "dark", brand["appearance"])
	assert.Equal(t, "plum", brand["theme"])
	assert.Equal(t, false, brand["isDefault"])
	assert.NotNil(t, brand["createdAt"])
	assert.NotNil(t, brand["updatedAt"])

	stored, err := database.GetBrandById(ctx, nil, id)
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.Equal(t, name, stored.Name)
	assert.Equal(t, "dark", string(stored.Appearance))
	assert.Equal(t, "plum", stored.Theme)

	status, body, _ = brandCall(t, accessToken, http.MethodGet, brandPath(id, ""), nil)
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, brand, body["brand"], "a read answers what the create did")

	renamed := brandName("Zest")
	status, body, _ = brandCall(t, accessToken, http.MethodPut, brandPath(id, ""),
		map[string]any{"name": renamed, "appearance": "light", "theme": "high-contrast"})
	require.Equal(t, http.StatusOK, status, "update: %v", body)
	assert.Equal(t, renamed, body["brand"].(map[string]any)["name"])
	stored, err = database.GetBrandById(ctx, nil, id)
	require.NoError(t, err)
	assert.Equal(t, renamed, stored.Name)
	assert.Equal(t, "light", string(stored.Appearance))
	assert.Equal(t, "high-contrast", stored.Theme)

	status, body, _ = brandCall(t, accessToken, http.MethodDelete, brandPath(id, ""), nil)
	require.Equal(t, http.StatusOK, status, "delete: %v", body)
	assert.Equal(t, true, body["success"])
	stored, err = database.GetBrandById(ctx, nil, id)
	require.NoError(t, err)
	assert.Nil(t, stored)

	status, body, _ = brandCall(t, accessToken, http.MethodGet, brandPath(id, ""), nil)
	assert.Equal(t, http.StatusNotFound, status)
	assert.Equal(t, "NOT_FOUND", body["error_code"])
	status, _, _ = brandCall(t, accessToken, http.MethodPut, brandPath(id, ""),
		map[string]any{"name": renamed, "appearance": "light", "theme": "plum"})
	assert.Equal(t, http.StatusNotFound, status)
	status, _, _ = brandCall(t, accessToken, http.MethodDelete, brandPath(id, ""), nil)
	assert.Equal(t, http.StatusNotFound, status)
	status, _, _ = brandCall(t, accessToken, http.MethodPost, brandPath(id, "/make-default"), nil)
	assert.Equal(t, http.StatusNotFound, status)
}

func TestAPIBrands_TheListIsSortedByNameWithTheDefaultMarked(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	defaultId, created := keepDefaultBrand(t)
	suffix := fake.LetterN(10)
	zest := createBrandOverAPI(t, accessToken, created, "zz list "+suffix, "auto", "guava")
	acme := createBrandOverAPI(t, accessToken, created, "AA list "+suffix, "light", "coconut")

	status, body, _ := brandCall(t, accessToken, http.MethodGet, brandsPath, nil)
	require.Equal(t, http.StatusOK, status)

	var names []string
	position := map[int64]int{}
	var defaults []int64
	for i, b := range body["brands"].([]any) {
		brand := b.(map[string]any)
		id := int64(brand["id"].(float64))
		names = append(names, brand["name"].(string))
		position[id] = i
		if brand["isDefault"] == true {
			defaults = append(defaults, id)
		}
	}
	for i := 1; i < len(names); i++ {
		assert.LessOrEqual(t, names[i-1], names[i], "the list is sorted by name")
	}
	assert.Less(t, position[acme], position[zest], "AA comes before zz, though it was created after")
	assert.Equal(t, []int64{defaultId}, defaults, "exactly the default is marked")
}

func TestAPIBrands_Refusals(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	defaultId, created := keepDefaultBrand(t)
	taken := createBrandOverAPI(t, accessToken, created, brandName("Taken"), "auto", "blueberry")
	other := createBrandOverAPI(t, accessToken, created, brandName("Other"), "auto", "blueberry")
	takenName := func() string {
		brand, err := database.GetBrandById(context.Background(), nil, taken)
		require.NoError(t, err)
		return brand.Name
	}()

	valid := func(edit func(map[string]any)) map[string]any {
		body := map[string]any{"name": brandName("New"), "appearance": "auto", "theme": "avocado"}
		edit(body)
		return body
	}
	refusals := []struct {
		name string
		body map[string]any
		code string
	}{
		{"no name", valid(func(b map[string]any) { b["name"] = "   " }), "handler.brand.name_required"},
		{"61 characters", valid(func(b map[string]any) { b["name"] = strings.Repeat("b", 61) }), "handler.brand.name_too_long"},
		{"an angle bracket", valid(func(b map[string]any) { b["name"] = "<script>" }), "handler.brand.name_angle_brackets"},
		{"a name another brand holds", valid(func(b map[string]any) { b["name"] = takenName }), "handler.brand.name_in_use"},
		{"a name another brand holds, with spaces around it", valid(func(b map[string]any) { b["name"] = " " + takenName + " " }), "handler.brand.name_in_use"},
		{"no appearance", valid(func(b map[string]any) { delete(b, "appearance") }), "handler.brand.appearance_invalid"},
		{"an unknown appearance", valid(func(b map[string]any) { b["appearance"] = "sepia" }), "handler.brand.appearance_invalid"},
		{"no theme", valid(func(b map[string]any) { delete(b, "theme") }), "handler.brand.theme_invalid"},
		{"an unknown theme", valid(func(b map[string]any) { b["theme"] = "graphite" }), "handler.brand.theme_invalid"},
	}
	for _, c := range refusals {
		t.Run("create: "+c.name, func(t *testing.T) {
			status, body, _ := brandCall(t, accessToken, http.MethodPost, brandsPath, c.body)
			assert.Equal(t, http.StatusBadRequest, status)
			assert.Equal(t, c.code, body["error_code"])
		})
		t.Run("update: "+c.name, func(t *testing.T) {
			status, body, _ := brandCall(t, accessToken, http.MethodPut, brandPath(other, ""), c.body)
			assert.Equal(t, http.StatusBadRequest, status)
			assert.Equal(t, c.code, body["error_code"])
		})
	}

	// The English sentences, as the catalog says them.
	_, body, _ := brandCall(t, accessToken, http.MethodPost, brandsPath, refusals[1].body)
	assert.Equal(t, "The name cannot exceed a maximum length of 60 characters.", body["error_description"])
	_, body, _ = brandCall(t, accessToken, http.MethodPost, brandsPath, refusals[3].body)
	assert.Equal(t, "Another brand already uses this name.", body["error_description"])

	// Sixty characters are taken.
	status, body, _ := brandCall(t, accessToken, http.MethodPut, brandPath(other, ""),
		map[string]any{"name": strings.Repeat("ü", 50) + fake.LetterN(10), "appearance": "dark", "theme": "tangerine"})
	assert.Equal(t, http.StatusOK, status, "60 characters: %v", body)

	// The default brand cannot be deleted, and stays.
	status, body, _ = brandCall(t, accessToken, http.MethodDelete, brandPath(defaultId, ""), nil)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "handler.brand.default_delete_not_allowed", body["error_code"])
	assert.Equal(t, "The default brand cannot be deleted. Make another brand the default first.", body["error_description"])
	still, err := database.GetDefaultBrand(context.Background(), nil)
	require.NoError(t, err)
	require.NotNil(t, still)
	assert.Equal(t, defaultId, still.Id)

	// A malformed id and a body that is not JSON.
	status, body, _ = brandCall(t, accessToken, http.MethodGet, brandsPath+"/abc", nil)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "VALIDATION_ERROR", body["error_code"])
	status, body, _ = brandCall(t, accessToken, http.MethodPost, brandsPath, "not an object")
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "INVALID_REQUEST_BODY", body["error_code"])
}

func TestAPIBrands_MakeDefault(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	previousId, created := keepDefaultBrand(t)
	id := createBrandOverAPI(t, accessToken, created, brandName("Next"), "dark", "avocado")

	status, body, _ := brandCall(t, accessToken, http.MethodPost, brandPath(id, "/make-default"), nil)
	require.Equal(t, http.StatusOK, status, "make default: %v", body)
	assert.Equal(t, id, int64(body["brand"].(map[string]any)["id"].(float64)))
	assert.Equal(t, true, body["brand"].(map[string]any)["isDefault"])

	current, err := database.GetDefaultBrand(context.Background(), nil)
	require.NoError(t, err)
	require.NotNil(t, current)
	assert.Equal(t, id, current.Id, "the settings row points at the brand")

	status, body, _ = brandCall(t, accessToken, http.MethodGet, brandPath(previousId, ""), nil)
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, false, body["brand"].(map[string]any)["isDefault"], "the brand it replaced is no longer the default")

	// Already the default: answered unchanged.
	status, body, _ = brandCall(t, accessToken, http.MethodPost, brandPath(id, "/make-default"), nil)
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, true, body["brand"].(map[string]any)["isDefault"])

	// Now it is the default, it cannot be deleted; the one it replaced can be read and is kept.
	status, body, _ = brandCall(t, accessToken, http.MethodDelete, brandPath(id, ""), nil)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "handler.brand.default_delete_not_allowed", body["error_code"])

	status, body, _ = brandCall(t, accessToken, http.MethodPost, brandPath(999999999, "/make-default"), nil)
	assert.Equal(t, http.StatusNotFound, status)
	assert.Equal(t, "NOT_FOUND", body["error_code"])
	current, err = database.GetDefaultBrand(context.Background(), nil)
	require.NoError(t, err)
	assert.Equal(t, id, current.Id, "an unknown brand moves nothing")
}

func TestAPIBrands_ChangesAreAudited(t *testing.T) {
	requireDatabaseAuditLogs(t)
	accessToken, caller := createAdminClientWithToken(t)
	who := caller.ClientIdentifier
	previousId, created := keepDefaultBrand(t)
	previous, err := database.GetBrandById(context.Background(), nil, previousId)
	require.NoError(t, err)

	name := brandName("Audit")
	resp, requestId := sendAdmin(t, accessToken, http.MethodPost, brandsPath,
		map[string]any{"name": name, "appearance": "auto", "theme": "guava"})
	var answer map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&answer))
	_ = resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	id := int64(answer["brand"].(map[string]any)["id"].(float64))
	*created = append(*created, id)
	assert.Equal(t, []map[string]any{{"brand_id": float64(id), "brand_name": name, "logged_in_user": who}},
		auditRows(t, accessToken, "created_brand", requestId))

	renamed := brandName("Audited")
	_, _, requestId = brandCall(t, accessToken, http.MethodPut, brandPath(id, ""),
		map[string]any{"name": renamed, "appearance": "dark", "theme": "coconut"})
	assert.Equal(t, []map[string]any{{"brand_id": float64(id), "brand_name": renamed, "appearance": "dark",
		"theme": "coconut", "logged_in_user": who}},
		auditRows(t, accessToken, "updated_brand", requestId))

	_, _, requestId = brandCall(t, accessToken, http.MethodPost, brandPath(id, "/make-default"), nil)
	assert.Equal(t, []map[string]any{{"brand_id": float64(id), "brand_name": renamed,
		"old_brand_id": float64(previousId), "old_brand_name": previous.Name, "logged_in_user": who}},
		auditRows(t, accessToken, "updated_default_brand", requestId))

	// A make-default that changes nothing, and a refused deletion, record nothing.
	_, _, requestId = brandCall(t, accessToken, http.MethodPost, brandPath(id, "/make-default"), nil)
	assert.Empty(t, auditRows(t, accessToken, "updated_default_brand", requestId))
	status, _, requestId := brandCall(t, accessToken, http.MethodDelete, brandPath(id, ""), nil)
	require.Equal(t, http.StatusBadRequest, status)
	assert.Empty(t, auditRows(t, accessToken, "deleted_brand", requestId))

	// Put the default back, then delete the brand.
	status, _, _ = brandCall(t, accessToken, http.MethodPost, brandPath(previousId, "/make-default"), nil)
	require.Equal(t, http.StatusOK, status)
	_, _, requestId = brandCall(t, accessToken, http.MethodDelete, brandPath(id, ""), nil)
	assert.Equal(t, []map[string]any{{"brand_id": float64(id), "brand_name": renamed, "logged_in_user": who}},
		auditRows(t, accessToken, "deleted_brand", requestId))
}

func TestAPIBrandThemes_ListsTheEightPresetsInDisplayOrder(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	status, body, _ := brandCall(t, accessToken, http.MethodGet, brandThemesPath, nil)
	require.Equal(t, http.StatusOK, status)

	var keys []string
	themes := map[string]map[string]any{}
	for _, raw := range body["brandThemes"].([]any) {
		theme := raw.(map[string]any)
		key := theme["key"].(string)
		keys = append(keys, key)
		themes[key] = theme
		assert.Len(t, theme["light"], 23, key)
		assert.Len(t, theme["dark"], 23, key)
	}
	assert.Equal(t, []string{"blueberry", "blackberry", "avocado", "plum", "tangerine", "guava", "coconut", "high-contrast"}, keys)
	assert.Equal(t, "#a84d08", themes["tangerine"]["light"].(map[string]any)["focus"])
	assert.Equal(t, "#7fd3a0", themes["avocado"]["dark"].(map[string]any)["brand"])
	assert.Equal(t, "#0037a6", themes["high-contrast"]["light"].(map[string]any)["brand"])
}

func TestAPIBrands_TheSettingsDomainsScopes(t *testing.T) {
	manageToken, _ := createAdminClientWithToken(t)
	_, created := keepDefaultBrand(t)
	id := createBrandOverAPI(t, manageToken, created, brandName("Scopes"), "auto", "plum")

	reads := []string{brandsPath, brandPath(id, ""), brandThemesPath}
	writes := []struct {
		method, path string
		body         any
	}{
		{http.MethodPost, brandsPath, map[string]any{"name": "", "appearance": "auto", "theme": "plum"}},
		{http.MethodPut, brandPath(id, ""), map[string]any{"name": "", "appearance": "auto", "theme": "plum"}},
		{http.MethodPost, brandPath(999999999, "/make-default"), nil},
		{http.MethodDelete, brandPath(999999999, ""), nil},
	}

	for _, c := range []struct {
		permission string
		read       int
		write      bool
	}{
		{builtin.AdminReadPermissionIdentifier, http.StatusOK, false},
		{builtin.ManageUsersPermissionIdentifier, http.StatusForbidden, false},
		{builtin.ManageClientsPermissionIdentifier, http.StatusForbidden, false},
		{builtin.ManageSettingsPermissionIdentifier, http.StatusOK, true},
	} {
		t.Run(c.permission, func(t *testing.T) {
			token, client := createClientWithGranularScope(t, c.permission)
			t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.Id) })

			for _, path := range reads {
				status, _, _ := brandCall(t, token, http.MethodGet, path, nil)
				assert.Equalf(t, c.read, status, "GET %s", path)
			}
			for _, w := range writes {
				status, body, _ := brandCall(t, token, w.method, w.path, w.body)
				if c.write {
					assert.NotEqualf(t, http.StatusForbidden, status, "%s %s reaches its handler: %v", w.method, w.path, body)
				} else {
					assert.Equalf(t, http.StatusForbidden, status, "%s %s", w.method, w.path)
					assert.Equalf(t, "INSUFFICIENT_SCOPE", body["error_code"], "%s %s", w.method, w.path)
				}
			}
		})
	}

	t.Run("no token", func(t *testing.T) {
		for _, path := range reads {
			req, err := http.NewRequest(http.MethodGet, appConfig.AuthServer.BaseURL+path, nil)
			require.NoError(t, err)
			resp, err := createHttpClient(t).Do(req)
			require.NoError(t, err)
			_ = resp.Body.Close()
			assert.Equalf(t, http.StatusUnauthorized, resp.StatusCode, "GET %s", path)
		}
	})
}
