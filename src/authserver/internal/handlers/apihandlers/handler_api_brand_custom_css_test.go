package apihandlers

import (
	"database/sql"
	"net/http"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// A brand's custom CSS in the admin API (#816 decision 4), through the create, update and read
// handlers with the generated database mock: customCss stored as written with its line endings
// made uniform, blank CSS as none, each refusal with error_field /customCss and a sentence naming
// the line, the 64 KB cap measured on what is stored, the CSS on every answer, a brand read and
// sent back unchanged, and the audit events recording its size and never its text.
//
// The check itself, rule by rule, is customcss's table of cases; here each rule is reached once
// through the API, to hold the code, the field and the sentence it answers.

// withCustomCSS is a valid brand write's body with css as its customCss.
func withCustomCSS(css any) map[string]any {
	body := validBrandBody()
	body["customCss"] = css
	return body
}

// cssOfBytes is a comment exactly n bytes long, which every rule passes.
func cssOfBytes(n int) string {
	return "/*" + strings.Repeat("a", n-4) + "*/"
}

// brandCustomCSSRefusals are the refusals of decision 4, each decided on the request alone, with
// the sentence each answers in English.
var brandCustomCSSRefusals = []struct {
	name, css, code, description string
}{
	{"an @import", "@import \"theme.css\";\n.auth-card { color: red; }",
		"handler.brand.custom_css_import",
		"Line 1 of the custom CSS has an @import. Custom CSS cannot load another stylesheet."},
	{"an @import written with an escape", ".auth-card { color: red; }\n\n@\\69mport url(data:image/png;base64,AA==);",
		"handler.brand.custom_css_import",
		"Line 3 of the custom CSS has an @import. Custom CSS cannot load another stylesheet."},
	{"a path in url()", ".auth-card {\n  color: red;\n}\n.auth-page { background: url(/static/bg.png); }",
		"handler.brand.custom_css_url",
		"Line 4 of the custom CSS has a URL that is not a data: image. Custom CSS can hold no other URL."},
	{"another origin in a quoted url()", ".auth-logo { background: url(\"https://evil.example/x.png\"); }",
		"handler.brand.custom_css_url",
		"Line 1 of the custom CSS has a URL that is not a data: image. Custom CSS can hold no other URL."},
	{"a data: value that is not an image", ":root {\n  --x: url(data:text/css,body{});\n}",
		"handler.brand.custom_css_url",
		"Line 2 of the custom CSS has a URL that is not a data: image. Custom CSS can hold no other URL."},
	{"image-set() through a variable, the probe's example", ":root { --picture: \"/some/path\"; }\n" +
		".auth-page { background-image: image-set(var(--picture) 1x); }",
		"handler.brand.custom_css_function",
		"Line 2 of the custom CSS uses src(), image() or image-set(). Write a data: image in url() instead."},
	{"-webkit-image-set()", ".auth-page {\n  background-image: -webkit-image-set(url(data:image/png;base64,AA==) 1x);\n}",
		"handler.brand.custom_css_function",
		"Line 2 of the custom CSS uses src(), image() or image-set(). Write a data: image in url() instead."},
	{"an unterminated comment", ".auth-card { color: red; }\n/* never closed",
		"handler.brand.custom_css_malformed",
		"Line 2 of the custom CSS cannot be read as CSS: a comment, a string or a url() is not closed or is written wrongly."},
	{"url(var(--x))", ".auth-page { background: url(var(--x)); }",
		"handler.brand.custom_css_malformed",
		"Line 1 of the custom CSS cannot be read as CSS: a comment, a string or a url() is not closed or is written wrongly."},
	// The lines are counted on the CSS as it is stored, its line endings made uniform.
	{"a line ending in CRLF", ".a { color: red; }\r\n.b { color: blue; }\r\n@import x;",
		"handler.brand.custom_css_import",
		"Line 3 of the custom CSS has an @import. Custom CSS cannot load another stylesheet."},
	{"a line ending in CR alone", ".a { color: red; }\r.b { color: blue; }\r@import x;",
		"handler.brand.custom_css_import",
		"Line 3 of the custom CSS has an @import. Custom CSS cannot load another stylesheet."},
	{"one byte past 64 KB", cssOfBytes(65537), "handler.brand.custom_css_too_large",
		"The custom CSS cannot exceed 65536 bytes."},
}

func TestBrandCustomCSS_CreateRefusals(t *testing.T) {
	for _, c := range brandCustomCSSRefusals {
		t.Run(c.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)

			status, answer := serveBrand(HandleBrandCreatePost(database, handlersmocks.NewAuditLogger(t), brandBaseURL),
				brandRequest(t, http.MethodPost, withCustomCSS(c.css)))

			assert.Equal(t, http.StatusBadRequest, status)
			assert.Equal(t, c.code, errorCode(answer))
			assert.Equal(t, c.description, answer["error_description"])
			assertErrorField(t, "/customCss", answer)
			database.AssertNotCalled(t, "CreateBrand", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

func TestBrandCustomCSS_UpdateRefusals(t *testing.T) {
	for _, c := range brandCustomCSSRefusals {
		t.Run(c.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			database.On("GetBrandById", mock.Anything, (*sql.Tx)(nil), int64(3)).
				Return(storedBrand(3, "Acme", record.BrandAppearanceDark, "plum"), nil).Once()

			status, answer := serveBrand(HandleBrandUpdatePut(database, handlersmocks.NewAuditLogger(t), brandBaseURL),
				brandRequest(t, http.MethodPut, withCustomCSS(c.css), "id", "3"))

			assert.Equal(t, http.StatusBadRequest, status)
			assert.Equal(t, c.code, errorCode(answer))
			assert.Equal(t, c.description, answer["error_description"])
			assertErrorField(t, "/customCss", answer)
			database.AssertNotCalled(t, "UpdateBrand", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// What is stored is what was written, with its line endings made uniform, and blank CSS is none;
// customCss left out and null are none too. The answer carries the CSS as stored.
func TestBrandCustomCSS_StoredAsWrittenWithUniformLineEndings(t *testing.T) {
	cases := []struct {
		name   string
		body   map[string]any
		stored string
	}{
		{"CSS as written", withCustomCSS("body[data-page=\"sign-in\"] .auth-card {\n  border: 2px solid var(--color-brand);\n}\n"),
			"body[data-page=\"sign-in\"] .auth-card {\n  border: 2px solid var(--color-brand);\n}\n"},
		{"leading and trailing space kept", withCustomCSS("\n\n  .auth-card { color: red; }  \n\n"),
			"\n\n  .auth-card { color: red; }  \n\n"},
		{"CRLF line endings", withCustomCSS(".a {\r\n  color: red;\r\n}\r\n"), ".a {\n  color: red;\n}\n"},
		{"CR line endings", withCustomCSS(".a {\r  color: red;\r}\r"), ".a {\n  color: red;\n}\n"},
		{"mixed line endings", withCustomCSS(".a {\r\n\r  color: red;\n}"), ".a {\n\n  color: red;\n}"},
		{"a data: image in url()", withCustomCSS(".auth-logo { background: url(\"data:image/png;base64,iVBORw0KGgo=\"); }"),
			".auth-logo { background: url(\"data:image/png;base64,iVBORw0KGgo=\"); }"},
		{"blank CSS", withCustomCSS(" \r\n\t\n  "), ""},
		{"empty CSS", withCustomCSS(""), ""},
		{"null", withCustomCSS(nil), ""},
		{"left out", validBrandBody(), ""},
		{"exactly 64 KB", withCustomCSS(cssOfBytes(65536)), cssOfBytes(65536)},
		// The cap is measured on what is stored: 65,537 bytes written with one CRLF are 65,536 stored.
		{"64 KB once its CRLF is made uniform", withCustomCSS(cssOfBytes(65535) + "\r\n"), cssOfBytes(65535) + "\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			var stored record.Brand
			expectCreate(database, &stored)
			auditLogger := handlersmocks.NewAuditLogger(t)
			auditLogger.On("Log", mock.Anything, audit.EventCreatedBrand, mock.Anything).Once()

			status, answer := serveBrand(HandleBrandCreatePost(database, auditLogger, brandBaseURL),
				brandRequest(t, http.MethodPost, c.body))

			require.Equal(t, http.StatusCreated, status, "%v", answer)
			assert.Equal(t, c.stored, stored.CustomCSS, "stored")
			assert.Equal(t, c.stored, brandAt(answer, "brand", "customCss"), "answered")
		})
	}
}

// An update is a full replace: CSS sent replaces the stored CSS, and a write leaving customCss out
// stores none.
func TestBrandCustomCSS_AnUpdateReplacesTheCSS(t *testing.T) {
	for _, c := range []struct {
		name   string
		body   map[string]any
		stored string
	}{
		{"new CSS", withCustomCSS(".auth-title { letter-spacing: 0.1em; }"), ".auth-title { letter-spacing: 0.1em; }"},
		{"left out", validBrandBody(), ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			before := storedBrand(3, "Acme", record.BrandAppearanceDark, "plum")
			before.CustomCSS = ".auth-card { border-width: 3px; }"
			database.On("GetBrandById", mock.Anything, (*sql.Tx)(nil), int64(3)).Return(before, nil).Once()
			var written record.Brand
			database.On("UpdateBrand", mock.Anything, (*sql.Tx)(nil), mock.Anything).Run(func(args mock.Arguments) {
				written = *args.Get(2).(*record.Brand)
			}).Return(nil).Once()
			database.On("GetDefaultBrand", mock.Anything, (*sql.Tx)(nil)).
				Return(storedBrand(1, "Default", record.BrandAppearanceAuto, "blueberry"), nil).Once()
			database.On("CountClientsPerBrand", mock.Anything, (*sql.Tx)(nil)).Return(map[int64]int{}, nil).Once()
			auditLogger := handlersmocks.NewAuditLogger(t)
			auditLogger.On("Log", mock.Anything, audit.EventUpdatedBrand, mock.Anything).Once()

			status, answer := serveBrand(HandleBrandUpdatePut(database, auditLogger, brandBaseURL),
				brandRequest(t, http.MethodPut, c.body, "id", "3"))

			require.Equal(t, http.StatusOK, status, "%v", answer)
			assert.Equal(t, c.stored, written.CustomCSS)
			assert.Equal(t, c.stored, brandAt(answer, "brand", "customCss"))
		})
	}
}

// A read answers the stored CSS, and the brand read and sent back as it came is written unchanged.
func TestBrandCustomCSS_ABrandReadAndWrittenBackIsUnchanged(t *testing.T) {
	const css = ".auth-card {\n  border: 2px solid var(--color-brand);\n}\n"
	read := datamocks.NewDatabase(t)
	stored := storedBrand(3, "Acme", record.BrandAppearanceDark, "plum")
	stored.CustomCSS = css
	expectBrandRead(read, stored)

	status, answer := serveBrand(HandleBrandGet(read, brandBaseURL), brandRequest(t, http.MethodGet, nil, "id", "3"))
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, css, brandAt(answer, "brand", "customCss"))

	write := datamocks.NewDatabase(t)
	write.On("GetBrandById", mock.Anything, (*sql.Tx)(nil), int64(3)).Return(stored, nil).Once()
	var written record.Brand
	write.On("UpdateBrand", mock.Anything, (*sql.Tx)(nil), mock.Anything).Run(func(args mock.Arguments) {
		written = *args.Get(2).(*record.Brand)
	}).Return(nil).Once()
	write.On("GetDefaultBrand", mock.Anything, (*sql.Tx)(nil)).
		Return(storedBrand(1, "Default", record.BrandAppearanceAuto, "blueberry"), nil).Once()
	write.On("CountClientsPerBrand", mock.Anything, (*sql.Tx)(nil)).Return(map[int64]int{}, nil).Once()
	auditLogger := handlersmocks.NewAuditLogger(t)
	auditLogger.On("Log", mock.Anything, audit.EventUpdatedBrand, mock.Anything).Once()

	status, _ = serveBrand(HandleBrandUpdatePut(write, auditLogger, brandBaseURL),
		brandRequest(t, http.MethodPut, answer["brand"], "id", "3"))
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, css, written.CustomCSS)
}

// The audit events record the CSS's size in bytes after the save, and never its text; a brand
// with none records nothing about it.
func TestBrandCustomCSS_TheAuditEventsRecordTheSizeAndNotTheText(t *testing.T) {
	// 26 bytes as stored: each CRLF is one byte once made uniform, and é is two.
	const written = ".x {\r\n  content: \"café\";\r\n}"
	t.Run("create", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		var stored record.Brand
		expectCreate(database, &stored)
		auditLogger := handlersmocks.NewAuditLogger(t)
		auditLogger.On("Log", mock.Anything, audit.EventCreatedBrand, map[string]interface{}{
			"brand_id": int64(7), "brand_name": "Acme", "custom_css_bytes": 26, "logged_in_user": brandCaller,
		}).Once()

		status, answer := serveBrand(HandleBrandCreatePost(database, auditLogger, brandBaseURL),
			brandRequest(t, http.MethodPost, withCustomCSS(written)))

		require.Equal(t, http.StatusCreated, status, "%v", answer)
	})
	t.Run("update", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.On("GetBrandById", mock.Anything, (*sql.Tx)(nil), int64(3)).
			Return(storedBrand(3, "Acme", record.BrandAppearanceDark, "plum"), nil).Once()
		database.On("UpdateBrand", mock.Anything, (*sql.Tx)(nil), mock.Anything).Return(nil).Once()
		database.On("GetDefaultBrand", mock.Anything, (*sql.Tx)(nil)).
			Return(storedBrand(1, "Default", record.BrandAppearanceAuto, "blueberry"), nil).Once()
		database.On("CountClientsPerBrand", mock.Anything, (*sql.Tx)(nil)).Return(map[int64]int{}, nil).Once()
		auditLogger := handlersmocks.NewAuditLogger(t)
		auditLogger.On("Log", mock.Anything, audit.EventUpdatedBrand, map[string]interface{}{
			"brand_id": int64(3), "brand_name": "Acme", "appearance": "dark", "theme": "plum",
			"corners": "pill", "font": "serif", "background_fit": "contain", "hide_app_name": false,
			"custom_css_bytes": 26, "logged_in_user": brandCaller,
		}).Once()

		status, answer := serveBrand(HandleBrandUpdatePut(database, auditLogger, brandBaseURL),
			brandRequest(t, http.MethodPut, withCustomCSS(written), "id", "3"))

		require.Equal(t, http.StatusOK, status, "%v", answer)
	})
}
