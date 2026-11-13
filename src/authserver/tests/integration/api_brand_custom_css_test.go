package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A brand's custom CSS through the admin API and its stylesheet on a real engine (#816 decision 4):
// CSS saved with its line endings made uniform, read, listed and written back unchanged, the
// refusals with error_field /customCss and the line, the audit events recording its size and never
// its text, and the CSS at the end of the brand's full stylesheet and never in its colors-only one.

// writtenCustomCSS is CSS as a browser's form sends it, with CRLF line endings, and storedCustomCSS
// the same CSS as it is stored.
const (
	writtenCustomCSS = "body[data-page=\"sign-in\"] .auth-card {\r\n  border: 2px solid var(--color-brand);\r\n}\r\n" +
		".auth-logo { background: url(\"data:image/png;base64,iVBORw0KGgo=\"); }"
	storedCustomCSS = "body[data-page=\"sign-in\"] .auth-card {\n  border: 2px solid var(--color-brand);\n}\n" +
		".auth-logo { background: url(\"data:image/png;base64,iVBORw0KGgo=\"); }"
)

func TestAPIBrandCustomCSS_StoredReadListedAndWrittenBack(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	_, created := keepDefaultBrand(t)

	name := brandName("Styled")
	status, answer, _ := brandCall(t, accessToken, http.MethodPost, brandsPath,
		brandBody(map[string]any{"name": name, "appearance": "auto", "theme": "plum", "customCss": writtenCustomCSS}))
	require.Equal(t, http.StatusCreated, status, "create: %v", answer)
	id := int64(answer["brand"].(map[string]any)["id"].(float64))
	*created = append(*created, id)
	assert.Equal(t, storedCustomCSS, answer["brand"].(map[string]any)["customCss"])

	stored, err := database.GetBrandById(context.Background(), nil, id)
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.Equal(t, storedCustomCSS, stored.CustomCSS, "stored with its line endings made uniform")

	status, read, _ := brandCall(t, accessToken, http.MethodGet, brandPath(id, ""), nil)
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, storedCustomCSS, read["brand"].(map[string]any)["customCss"])

	status, list, _ := brandCall(t, accessToken, http.MethodGet, brandsPath, nil)
	require.Equal(t, http.StatusOK, status)
	var listed any
	for _, raw := range list["brands"].([]any) {
		if raw.(map[string]any)["name"] == name {
			listed = raw.(map[string]any)["customCss"]
		}
	}
	assert.Equal(t, storedCustomCSS, listed)

	// Read and sent back as it came, the brand is unchanged.
	status, written, _ := brandCall(t, accessToken, http.MethodPut, brandPath(id, ""), read["brand"])
	require.Equal(t, http.StatusOK, status, "update: %v", written)
	assert.Equal(t, read["brand"].(map[string]any)["customCss"], written["brand"].(map[string]any)["customCss"])

	// Blank CSS is none, and an update leaving customCss out stores none.
	for _, body := range []map[string]any{
		brandBody(map[string]any{"name": name, "appearance": "auto", "theme": "plum", "customCss": " \r\n\t "}),
		brandBody(map[string]any{"name": name, "appearance": "auto", "theme": "plum", "customCss": storedCustomCSS}),
		brandBody(map[string]any{"name": name, "appearance": "auto", "theme": "plum"}),
	} {
		status, answer, _ = brandCall(t, accessToken, http.MethodPut, brandPath(id, ""), body)
		require.Equal(t, http.StatusOK, status, "update: %v", answer)
		want := ""
		if body["customCss"] == storedCustomCSS {
			want = storedCustomCSS
		}
		assert.Equal(t, want, answer["brand"].(map[string]any)["customCss"])
		stored, err = database.GetBrandById(context.Background(), nil, id)
		require.NoError(t, err)
		assert.Equal(t, want, stored.CustomCSS)
	}
}

func TestAPIBrandCustomCSS_Refusals(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	_, created := keepDefaultBrand(t)
	other := createBrandOverAPI(t, accessToken, created, brandName("Other"), "auto", "blueberry")

	refusals := []struct {
		name, css, code, description string
	}{
		{"an @import", ".auth-card { color: red; }\r\n@import \"https://evil.example/x.css\";",
			"handler.brand.custom_css_import",
			"Line 2 of the custom CSS has an @import. Custom CSS cannot load another stylesheet."},
		{"a path in url()", ".a {}\n.b {}\n.auth-page { background: url(/favicon.ico); }",
			"handler.brand.custom_css_url",
			"Line 3 of the custom CSS has a URL that is not a data: image. Custom CSS can hold no other URL."},
		{"image-set()", ".auth-page { background-image: image-set(\"data:image/png;base64,AA==\" 1x); }",
			"handler.brand.custom_css_function",
			"Line 1 of the custom CSS uses src(), image() or image-set(). Write a data: image in url() instead."},
		{"an unterminated string", ".a {}\n.auth-title::after { content: \"never closed\n}",
			"handler.brand.custom_css_malformed",
			"Line 2 of the custom CSS cannot be read as CSS: a comment, a string or a url() is not closed or is written wrongly."},
		{"one byte past 64 KB", "/*" + strings.Repeat("a", 65533) + "*/", "handler.brand.custom_css_too_large",
			"The custom CSS cannot exceed 65536 bytes."},
	}
	for _, c := range refusals {
		for _, write := range []struct{ method, path string }{{http.MethodPost, brandsPath}, {http.MethodPut, brandPath(other, "")}} {
			t.Run(write.method+" "+c.name, func(t *testing.T) {
				status, body, _ := brandCall(t, accessToken, write.method, write.path,
					brandBody(map[string]any{"name": brandName("New"), "appearance": "auto", "theme": "plum", "customCss": c.css}))
				assert.Equal(t, http.StatusBadRequest, status)
				assert.Equal(t, c.code, body["error_code"])
				assert.Equal(t, c.description, body["error_description"])
				assert.Equal(t, "/customCss", body["error_field"])
			})
		}
	}

	stored, err := database.GetBrandById(context.Background(), nil, other)
	require.NoError(t, err)
	assert.Equal(t, "blueberry", stored.Theme, "no refused update wrote the brand")
	assert.Empty(t, stored.CustomCSS)
}

// The audit events record the CSS's size in bytes as stored, and never its text.
func TestAPIBrandCustomCSS_ChangesAreAudited(t *testing.T) {
	requireDatabaseAuditLogs(t)
	accessToken, caller := createAdminClientWithToken(t)
	who := caller.ClientIdentifier
	_, created := keepDefaultBrand(t)

	name := brandName("AuditCSS")
	resp, requestId := sendAdmin(t, accessToken, http.MethodPost, brandsPath, brandBody(map[string]any{
		"name": name, "appearance": "light", "theme": "plum", "customCss": writtenCustomCSS}))
	var answer map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&answer))
	_ = resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode, "%v", answer)
	id := int64(answer["brand"].(map[string]any)["id"].(float64))
	*created = append(*created, id)
	createdRows := auditRows(t, accessToken, "created_brand", requestId)
	assert.Equal(t, []map[string]any{{"brand_id": float64(id), "brand_name": name,
		"custom_css_bytes": float64(len(storedCustomCSS)), "logged_in_user": who}}, createdRows)

	_, _, requestId = brandCall(t, accessToken, http.MethodPut, brandPath(id, ""),
		brandBody(map[string]any{"name": name, "appearance": "dark", "theme": "plum", "customCss": ".x{}"}))
	updatedRows := auditRows(t, accessToken, "updated_brand", requestId)
	assert.Equal(t, []map[string]any{{"brand_id": float64(id), "brand_name": name, "appearance": "dark",
		"theme": "plum", "corners": "rounded", "font": "system-ui", "background_fit": "cover",
		"hide_app_name": false, "custom_css_bytes": float64(4), "logged_in_user": who}}, updatedRows)

	encoded, err := json.Marshal(createdRows)
	require.NoError(t, err)
	assert.NotContains(t, string(encoded), "auth-card", "the CSS is not recorded")
}

// The CSS saved through the admin API ends the brand's full stylesheet, which the pages link, and
// is never in its colors-only one; a saved change moves the full stylesheet's address alone.
func TestAPIBrandCustomCSS_TheFullStylesheetEndsWithIt(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	_, created := keepDefaultBrand(t)
	base := appConfig.AuthServer.BaseURL
	browser := createHttpClient(t)

	name := brandName("Served")
	status, answer, _ := brandCall(t, accessToken, http.MethodPost, brandsPath,
		brandBody(map[string]any{"name": name, "appearance": "auto", "theme": "plum", "corners": "pill",
			"customCss": writtenCustomCSS}))
	require.Equal(t, http.StatusCreated, status, "create: %v", answer)
	id := int64(answer["brand"].(map[string]any)["id"].(float64))
	*created = append(*created, id)
	makeBrandDefault(t, id)

	full, colors := publishedStylesheets(t, browser)
	require.NotEmpty(t, full)
	page := loadPage(t, browser, base+"/no-such-page-xyz")
	defer func() { _ = page.Body.Close() }()
	head := readBrandedPageHead(t, page)
	require.Len(t, head.stylesheets, 2, "main.css, then the brand's stylesheet")
	assert.Equal(t, full, base+head.stylesheets[1])

	status, fullCSS, _ := getStylesheet(t, browser, full)
	require.Equal(t, http.StatusOK, status)
	assert.True(t, strings.HasSuffix(fullCSS, "  --radius-panel: 1.5rem;\n}\n\n"+storedCustomCSS),
		"the kit, then the CSS as stored, last: %q", fullCSS[max(0, len(fullCSS)-300):])
	status, colorsCSS, _ := getStylesheet(t, browser, colors)
	require.Equal(t, http.StatusOK, status)
	assert.NotContains(t, colorsCSS, "auth-card")
	assert.NotContains(t, colorsCSS, "radius")

	status, answer, _ = brandCall(t, accessToken, http.MethodPut, brandPath(id, ""),
		brandBody(map[string]any{"name": name, "appearance": "auto", "theme": "plum", "corners": "pill",
			"customCss": ".auth-title { letter-spacing: 0.05em; }"}))
	require.Equal(t, http.StatusOK, status, "update: %v", answer)
	changedFull, changedColors := publishedStylesheets(t, browser)
	assert.NotEqual(t, full, changedFull)
	assert.Equal(t, colors, changedColors)
	status, fullCSS, _ = getStylesheet(t, browser, changedFull)
	require.Equal(t, http.StatusOK, status)
	assert.True(t, strings.HasSuffix(fullCSS, "}\n\n.auth-title { letter-spacing: 0.05em; }"), "%q", fullCSS)
	assert.NotContains(t, fullCSS, "auth-card")
}
