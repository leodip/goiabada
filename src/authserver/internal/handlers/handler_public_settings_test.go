package handlers

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/stretchr/testify/mock"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/brandasset"
	"github.com/leodip/goiabada/authserver/internal/brandthemes"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// /api/public/settings
//
// This endpoint requires no authentication: it is what the login and account
// pages read before anyone has a token. record.Settings holds every setting,
// among them the legacy AES encryption key and the encrypted SMTP password, so the
// narrow PublicSettingsResponse DTO is the entire boundary between an anonymous
// caller and all of it. The two guards further down exist to fail if that
// boundary ever widens, whether by growing the DTO or by serializing the model
// directly.
// =============================================================================

// publicSettingsBaseURL is the auth server's base URL in these tests, the one a brand's stylesheet
// URL is built from.
const publicSettingsBaseURL = "https://auth.example.test"

// expectNoDefaultBrand has database answer no brand for the admin console's client and an empty
// default brand pointer, for a case about something other than the brand.
func expectNoDefaultBrand(database *datamocks.Database) {
	expectConsoleClientBrand(database, nil, nil)
	database.On("GetDefaultBrand", mock.Anything, (*sql.Tx)(nil)).Return(nil, nil).Once()
}

// expectConsoleClientBrand has database answer brand, or err, as the brand the admin console's own
// client is drawn in: its own, or the default when it has none.
func expectConsoleClientBrand(database *datamocks.Database, brand *record.Brand, err error) {
	database.On("GetClientPageBrand", mock.Anything, (*sql.Tx)(nil), "admin-console-client").Return(brand, err).Once()
}

func TestPublicSettings_Success(t *testing.T) {
	database := datamocks.NewDatabase(t)
	handler := HandlePublicSettingsGet(database, publicSettingsBaseURL)

	database.On("GetSettingsById", mock.Anything, (*sql.Tx)(nil), int64(1)).Return(&record.Settings{
		Id:          1,
		AppName:     "Goiabada Test",
		SMTPEnabled: true,
		Issuer:      "https://issuer.example",
	}, nil).Once()
	expectNoDefaultBrand(database)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest("GET", "/api/public/settings", nil))

	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, "application/json", recorder.Header().Get("Content-Type"))

	var body api.PublicSettingsResponse
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
	assert.Equal(t, "Goiabada Test", body.AppName)
	assert.True(t, body.SMTPEnabled)
	assert.Equal(t, "https://issuer.example", body.Issuer)
}

// The brand of the admin console's own client rides with the public settings as brand: its own, or
// the default brand when it has none, which the data layer answers alike (#812 decision 7). It is the
// brand's appearance, and the absolute URLs of its two stylesheets, built from the auth server's base
// URL as a client logo's URL is (#810 decision 3): stylesheetUrl is the full one, which the auth
// server's own pages link, and colorsStylesheetUrl the one with the colors alone, which the console's
// admin pages link (#813 decision 9). uiTheme is no longer answered.
func TestPublicSettings_CarriesTheConsoleClientsBrand(t *testing.T) {
	pill := func(brand record.Brand) *record.Brand {
		brand.Corners = record.BrandCornersPill
		return &brand
	}
	for _, tc := range []struct {
		name           string
		brand          *record.Brand
		wantAppearance string
		wantPath       string
	}{
		{"a dark brand", pill(record.Brand{Id: 7, Name: "Night", Appearance: record.BrandAppearanceDark, Theme: "plum"}),
			"dark", "/brand/7/"},
		{"a light brand", pill(record.Brand{Id: 12, Name: "Day", Appearance: record.BrandAppearanceLight, Theme: "avocado"}),
			"light", "/brand/12/"},
		{"an automatic brand on Blueberry", pill(record.Brand{Id: 1, Name: "Default", Appearance: record.BrandAppearanceAuto, Theme: "blueberry"}),
			"auto", "/brand/1/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			database.On("GetSettingsById", mock.Anything, (*sql.Tx)(nil), int64(1)).Return(&record.Settings{
				Id: 1, AppName: "Goiabada",
			}, nil).Once()
			expectConsoleClientBrand(database, tc.brand, nil)

			recorder := httptest.NewRecorder()
			HandlePublicSettingsGet(database, publicSettingsBaseURL).ServeHTTP(recorder, httptest.NewRequest("GET", "/api/public/settings", nil))

			require.Equal(t, http.StatusOK, recorder.Code)
			var body map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
			colors, ok := brandthemes.StylesheetOf(tc.brand.Theme)
			require.True(t, ok)
			require.Regexp(t, `^[0-9a-f]{12}$`, colors.Fingerprint)
			full, err := brandthemes.FullStylesheet(tc.brand, brandasset.Slots{})
			require.NoError(t, err)
			require.NotEqual(t, colors.Fingerprint, full.Fingerprint, "pill corners are not the colors alone")
			assert.JSONEq(t, `{"appearance":"`+tc.wantAppearance+`",`+
				`"stylesheetUrl":"`+publicSettingsBaseURL+tc.wantPath+`stylesheet.css?v=`+full.Fingerprint+`",`+
				`"colorsStylesheetUrl":"`+publicSettingsBaseURL+tc.wantPath+`colors.css?v=`+colors.Fingerprint+`",`+
				`"hideAppName":false,"hasBackground":false,"footerLinks":[],"supportEmail":"","supportUrl":"","supportPhone":""}`,
				string(body["brand"]))
			assert.NotContains(t, body, "uiTheme")
		})
	}
}

// The brand also carries the absolute URLs of its logo, dark logo and favicon, each with its asset's
// fingerprint, and whether the app name's text gives way to the logo, which it does only beside one
// (#813 decisions 5 and 9). An empty slot is left out. hasBackground says whether the brand has a
// background image, so the console draws its card pages' footer on a panel (#814 D1). The full stylesheet's URL names the
// stylesheet the brand's files draw.
func TestPublicSettings_CarriesTheBrandsLogosFaviconAndSwitch(t *testing.T) {
	brand := record.NewBrand("Night", record.BrandAppearanceDark, "plum")
	brand.Id = 7
	brand.HideAppName = true
	brand.LogoAssetId = sql.NullInt64{Int64: 11, Valid: true}
	brand.DarkLogoAssetId = sql.NullInt64{Int64: 12, Valid: true}
	brand.FaviconAssetId = sql.NullInt64{Int64: 13, Valid: true}
	brand.BackgroundAssetId = sql.NullInt64{Int64: 14, Valid: true}
	assets := []record.BrandAsset{
		{Id: 14, Kind: record.BrandAssetKindBackground, Fingerprint: "444444444444"},
		{Id: 13, Kind: record.BrandAssetKindFavicon, Fingerprint: "333333333333"},
		{Id: 12, Kind: record.BrandAssetKindLogo, Fingerprint: "222222222222"},
		{Id: 11, Kind: record.BrandAssetKindLogo, Fingerprint: "111111111111"},
	}
	database := datamocks.NewDatabase(t)
	database.On("GetSettingsById", mock.Anything, (*sql.Tx)(nil), int64(1)).Return(&record.Settings{Id: 1, AppName: "Goiabada"}, nil).Once()
	expectConsoleClientBrand(database, &brand, nil)
	database.On("GetBrandAssetsByIds", mock.Anything, (*sql.Tx)(nil), []int64{11, 12, 13, 14}).Return(assets, nil).Once()

	recorder := httptest.NewRecorder()
	HandlePublicSettingsGet(database, publicSettingsBaseURL).ServeHTTP(recorder, httptest.NewRequest("GET", "/api/public/settings", nil))

	require.Equal(t, http.StatusOK, recorder.Code)
	var body struct {
		Brand map[string]any `json:"brand"`
	}
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
	assert.Equal(t, publicSettingsBaseURL+"/brand-assets/11?v=111111111111", body.Brand["logoUrl"])
	assert.Equal(t, publicSettingsBaseURL+"/brand-assets/12?v=222222222222", body.Brand["darkLogoUrl"])
	assert.Equal(t, publicSettingsBaseURL+"/brand-assets/13?v=333333333333", body.Brand["faviconUrl"])
	assert.Equal(t, true, body.Brand["hideAppName"])
	assert.Equal(t, true, body.Brand["hasBackground"], "the brand has a background image")
	full, err := brandthemes.FullStylesheet(&brand, brandasset.Slots{Background: &assets[0]})
	require.NoError(t, err)
	assert.Equal(t, publicSettingsBaseURL+"/brand/7/stylesheet.css?v="+full.Fingerprint, body.Brand["stylesheetUrl"])

	// Without a logo the switch has no effect, and the empty slots are left out.
	brand.LogoAssetId, brand.DarkLogoAssetId, brand.BackgroundAssetId = sql.NullInt64{}, sql.NullInt64{}, sql.NullInt64{}
	database = datamocks.NewDatabase(t)
	database.On("GetSettingsById", mock.Anything, (*sql.Tx)(nil), int64(1)).Return(&record.Settings{Id: 1, AppName: "Goiabada"}, nil).Once()
	expectConsoleClientBrand(database, &brand, nil)
	database.On("GetBrandAssetsByIds", mock.Anything, (*sql.Tx)(nil), []int64{13}).Return(assets[1:2], nil).Once()

	recorder = httptest.NewRecorder()
	HandlePublicSettingsGet(database, publicSettingsBaseURL).ServeHTTP(recorder, httptest.NewRequest("GET", "/api/public/settings", nil))

	require.Equal(t, http.StatusOK, recorder.Code)
	body.Brand = nil
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
	assert.NotContains(t, body.Brand, "logoUrl")
	assert.NotContains(t, body.Brand, "darkLogoUrl")
	assert.Equal(t, publicSettingsBaseURL+"/brand-assets/13?v=333333333333", body.Brand["faviconUrl"])
	assert.Equal(t, false, body.Brand["hideAppName"])
	assert.Equal(t, false, body.Brand["hasBackground"], "the background slot is empty")
}

// The brand carries its footer links in order, each with every label it has, so the admin console
// picks one by the language of each page it draws, and its support contact; an answer always carries
// all four, [] for no links, {} for a link with no labels and "" for an unset value (#814 decision 9).
func TestPublicSettings_CarriesTheBrandsFooterLinksAndContact(t *testing.T) {
	brand := record.NewBrand("Night", record.BrandAppearanceDark, "plum")
	brand.Id = 7
	brand.FooterLinks = record.BrandFooterLinks{
		{URL: "https://acme.example/privacy", Label: "Privacy", Labels: map[string]string{"de": "Datenschutz", "pt-BR": "Privacidade"}},
		{URL: "https://status.acme.example/", Label: "Status"},
	}
	brand.SupportEmail = "help@acme.example"
	brand.SupportPhone = "+442079460958"
	database := datamocks.NewDatabase(t)
	database.On("GetSettingsById", mock.Anything, (*sql.Tx)(nil), int64(1)).Return(&record.Settings{Id: 1, AppName: "Goiabada"}, nil).Once()
	expectConsoleClientBrand(database, &brand, nil)

	recorder := httptest.NewRecorder()
	HandlePublicSettingsGet(database, publicSettingsBaseURL).ServeHTTP(recorder, httptest.NewRequest("GET", "/api/public/settings", nil))

	require.Equal(t, http.StatusOK, recorder.Code)
	var body struct {
		Brand map[string]json.RawMessage `json:"brand"`
	}
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
	assert.JSONEq(t, `[`+
		`{"url":"https://acme.example/privacy","label":"Privacy","labels":{"de":"Datenschutz","pt-BR":"Privacidade"}},`+
		`{"url":"https://status.acme.example/","label":"Status","labels":{}}]`, string(body.Brand["footerLinks"]))
	assert.JSONEq(t, `"help@acme.example"`, string(body.Brand["supportEmail"]))
	assert.JSONEq(t, `""`, string(body.Brand["supportUrl"]))
	assert.JSONEq(t, `"+442079460958"`, string(body.Brand["supportPhone"]))
}

// With no brand for the admin console's client, the client not being there, the answer is the
// default brand.
func TestPublicSettings_CarriesTheDefaultBrandWithoutTheConsoleClient(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("GetSettingsById", mock.Anything, (*sql.Tx)(nil), int64(1)).Return(&record.Settings{
		Id: 1, AppName: "Goiabada",
	}, nil).Once()
	expectConsoleClientBrand(database, nil, nil)
	database.On("GetDefaultBrand", mock.Anything, (*sql.Tx)(nil)).Return(&record.Brand{
		Id: 9, Name: "Default", Appearance: record.BrandAppearanceDark, Theme: "plum",
	}, nil).Once()

	recorder := httptest.NewRecorder()
	HandlePublicSettingsGet(database, publicSettingsBaseURL).ServeHTTP(recorder, httptest.NewRequest("GET", "/api/public/settings", nil))

	require.Equal(t, http.StatusOK, recorder.Code)
	var body api.PublicSettingsResponse
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
	require.NotNil(t, body.Brand)
	assert.Equal(t, "dark", body.Brand.Appearance)
	assert.Regexp(t, `^https://auth\.example\.test/brand/9/stylesheet\.css\?v=[0-9a-f]{12}$`, body.Brand.StylesheetURL)
}

// A brand that cannot be read leaves brand out of the answer, which is otherwise whole: the console
// draws its pages automatic in the built-in colors, as the auth server draws its own then, rather
// than every console page failing over the look. That is no brand for the console's client and an
// empty default pointer, a failed read of either, and a stored theme that is none of the built-in
// ones; the last three are faults, and logged.
func TestPublicSettings_AnswersNoBrandWhenTheBrandCannotBeRead(t *testing.T) {
	for _, tc := range []struct {
		name         string
		consoleBrand *record.Brand
		consoleErr   error
		readsDefault bool
		defaultBrand *record.Brand
		defaultErr   error
		wantLog      string
	}{
		{name: "no default brand", readsDefault: true},
		{name: "a failed read of the console client's brand", consoleErr: errors.New("the database went away"),
			wantLog: "unable to read the brand of the client a page is drawn for"},
		{name: "a failed read of the default brand", readsDefault: true, defaultErr: errors.New("the database went away"),
			wantLog: "unable to read the default brand"},
		{name: "a theme none of the built-in ones",
			consoleBrand: &record.Brand{Id: 3, Name: "Odd", Appearance: record.BrandAppearanceDark, Theme: "mango"},
			wantLog:      "unable to link the brand's stylesheet"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := logtest.CaptureSlog(t)
			database := datamocks.NewDatabase(t)
			database.On("GetSettingsById", mock.Anything, (*sql.Tx)(nil), int64(1)).Return(&record.Settings{
				Id: 1, AppName: "Goiabada", Issuer: "https://issuer.example",
			}, nil).Once()
			expectConsoleClientBrand(database, tc.consoleBrand, tc.consoleErr)
			if tc.readsDefault {
				database.On("GetDefaultBrand", mock.Anything, (*sql.Tx)(nil)).Return(tc.defaultBrand, tc.defaultErr).Once()
			}

			recorder := httptest.NewRecorder()
			HandlePublicSettingsGet(database, publicSettingsBaseURL).ServeHTTP(recorder, httptest.NewRequest("GET", "/api/public/settings", nil))

			require.Equal(t, http.StatusOK, recorder.Code)
			var body map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
			assert.NotContains(t, body, "brand")
			assert.JSONEq(t, `"Goiabada"`, string(body["appName"]))
			assert.JSONEq(t, `"https://issuer.example"`, string(body["issuer"]))

			var messages []string
			for _, record := range logs.Records() {
				messages = append(messages, record.Message)
			}
			if tc.wantLog == "" {
				assert.Empty(t, messages)
			} else {
				assert.Equal(t, []string{tc.wantLog}, messages)
			}
		})
	}
}

// The stored policy's rules ride with the public settings, as data, so the admin console states
// them under its password fields without keeping its own copy of each policy's numbers (#550
// decision 11).
func TestPublicSettings_CarriesTheStoredPolicysRules(t *testing.T) {
	for _, tc := range []struct {
		policy record.PasswordPolicy
		want   string
	}{
		{record.PasswordPolicyNist, `{"minLength":15,"requiresLowercase":false,"requiresUppercase":false,` +
			`"requiresNumber":false,"requiresSymbol":false,"refusesCommon":true,"refusesAccountWords":true}`},
		{record.PasswordPolicyHigh, `{"minLength":10,"requiresLowercase":true,"requiresUppercase":true,` +
			`"requiresNumber":true,"requiresSymbol":true,"refusesCommon":false,"refusesAccountWords":false}`},
		{record.PasswordPolicyNone, `{"minLength":1,"requiresLowercase":false,"requiresUppercase":false,` +
			`"requiresNumber":false,"requiresSymbol":false,"refusesCommon":false,"refusesAccountWords":false}`},
	} {
		t.Run(tc.policy.String(), func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			database.On("GetSettingsById", mock.Anything, (*sql.Tx)(nil), int64(1)).Return(&record.Settings{
				Id: 1, AppName: "Goiabada", PasswordPolicy: tc.policy,
			}, nil).Once()
			expectNoDefaultBrand(database)

			recorder := httptest.NewRecorder()
			HandlePublicSettingsGet(database, publicSettingsBaseURL).ServeHTTP(recorder, httptest.NewRequest("GET", "/api/public/settings", nil))

			require.Equal(t, http.StatusOK, recorder.Code)
			var body map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
			assert.JSONEq(t, tc.want, string(body["passwordRules"]))
		})
	}
}

// Whether users may delete their own account rides with the public settings, as stored, so the
// admin console draws its account menu from the settings it already caches (#783 decision 6).
func TestPublicSettings_CarriesAccountDeletionEnabled(t *testing.T) {
	for _, stored := range []bool{true, false} {
		database := datamocks.NewDatabase(t)
		database.On("GetSettingsById", mock.Anything, (*sql.Tx)(nil), int64(1)).Return(&record.Settings{
			Id: 1, AppName: "Goiabada", AccountDeletionEnabled: stored,
		}, nil).Once()
		expectNoDefaultBrand(database)

		recorder := httptest.NewRecorder()
		HandlePublicSettingsGet(database, publicSettingsBaseURL).ServeHTTP(recorder, httptest.NewRequest("GET", "/api/public/settings", nil))

		require.Equal(t, http.StatusOK, recorder.Code)
		var body map[string]any
		require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
		assert.Equal(t, stored, body["accountDeletionEnabled"], "stored %v", stored)
	}
}

func TestPublicSettings_DatabaseError(t *testing.T) {
	database := datamocks.NewDatabase(t)
	handler := HandlePublicSettingsGet(database, publicSettingsBaseURL)

	database.On("GetSettingsById", mock.Anything, (*sql.Tx)(nil), int64(1)).
		Return(nil, errors.New("database is down")).Once()

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest("GET", "/api/public/settings", nil))

	// JSON, not text/plain: this endpoint answers JSON, so its refusals do too, and the body is
	// the API envelope every other 500 answers with (#279 decision 17).
	assert.Equal(t, http.StatusInternalServerError, recorder.Code)
	assert.Equal(t, "application/json", recorder.Header().Get("Content-Type"))
	assert.Contains(t, recorder.Body.String(), "INTERNAL_SERVER_ERROR")
}

// GetSettingsById returns (nil, nil) when the row is absent. Without a nil guard
// the handler dereferenced it, which panicked an endpoint reachable without any
// authentication.
func TestPublicSettings_MissingSettingsRowDoesNotPanic(t *testing.T) {
	database := datamocks.NewDatabase(t)
	handler := HandlePublicSettingsGet(database, publicSettingsBaseURL)

	database.On("GetSettingsById", mock.Anything, (*sql.Tx)(nil), int64(1)).Return(nil, nil).Once()

	recorder := httptest.NewRecorder()
	assert.NotPanics(t, func() {
		handler.ServeHTTP(recorder, httptest.NewRequest("GET", "/api/public/settings", nil))
	})

	assert.Equal(t, http.StatusInternalServerError, recorder.Code)
	assert.Equal(t, "application/json", recorder.Header().Get("Content-Type"))
	assert.Contains(t, recorder.Body.String(), "INTERNAL_SERVER_ERROR")
}

// failingResponseWriter fails every write, so the encode error path is reachable.
type failingResponseWriter struct {
	header http.Header
}

func (f *failingResponseWriter) Header() http.Header {
	if f.header == nil {
		f.header = http.Header{}
	}
	return f.header
}

func (f *failingResponseWriter) Write([]byte) (int, error) {
	return 0, errors.New("connection reset")
}

// WriteHeader discards the status: the case this writer serves asserts that the encode failure
// does not panic, and nothing reads the status back off it.
func (f *failingResponseWriter) WriteHeader(int) {}

func TestPublicSettings_EncodeFailure(t *testing.T) {
	database := datamocks.NewDatabase(t)
	handler := HandlePublicSettingsGet(database, publicSettingsBaseURL)

	database.On("GetSettingsById", mock.Anything, (*sql.Tx)(nil), int64(1)).Return(&record.Settings{
		Id: 1, AppName: "Goiabada",
	}, nil).Once()
	expectNoDefaultBrand(database)

	writer := &failingResponseWriter{}
	assert.NotPanics(t, func() {
		handler.ServeHTTP(writer, httptest.NewRequest("GET", "/api/public/settings", nil))
	})
}

// =============================================================================
// Leak guards
// =============================================================================

// publicSettingsAllowedFields is the complete set of fields this unauthenticated
// endpoint may expose. Adding anything here is a deliberate decision to make that
// value world-readable, so the list is spelled out rather than derived.
var publicSettingsAllowedFields = map[string]string{
	"AppName":     "appName",
	"SMTPEnabled": "smtpEnabled",
	// The appearance and stylesheet URL of the admin console's own client's brand, which the console
	// draws its pages in (#810 decision 3, #812 decision 7). That client's sign-in pages already
	// carry both to anyone, as data-theme and as a stylesheet link.
	"Brand": "brand",
	// Already world-readable: /.well-known/openid-configuration serves the same
	// value to anonymous callers, as OIDC Discovery 1.0 section 3 requires.
	"Issuer": "issuer",
	// The stored password policy's rules, which the admin console states under its password
	// fields (#550 decision 11). Already readable by anyone who opens the registration form
	// while registration is on, and NIST SP 800-63B assumes an attacker knows them.
	"PasswordRules": "passwordRules",
	// Whether users may delete their own account, which the admin console's account menu and page
	// read (#783 decision 6). A policy, not data about anyone: an anonymous caller learning it is
	// harmless.
	"AccountDeletionEnabled": "accountDeletionEnabled",
}

// publicPasswordRulesAllowedFields is the complete set of fields the password rules carry: the
// minimum, the kinds of character required, and whether common passwords and the account's words
// are refused, and nothing else about the settings row.
var publicPasswordRulesAllowedFields = map[string]string{
	"MinLength":           "minLength",
	"RequiresLowercase":   "requiresLowercase",
	"RequiresUppercase":   "requiresUppercase",
	"RequiresNumber":      "requiresNumber",
	"RequiresSymbol":      "requiresSymbol",
	"RefusesCommon":       "refusesCommon",
	"RefusesAccountWords": "refusesAccountWords",
}

// publicBrandAllowedFields is the complete set of fields the brand carries: its appearance and the
// URLs of its two stylesheets, which a sign-in page drawn in the brand already serves anyone (#813
// decision 9), and nothing else about the brand, its name among it.
var publicBrandAllowedFields = map[string]string{
	"Appearance":          "appearance",
	"StylesheetURL":       "stylesheetUrl",
	"ColorsStylesheetURL": "colorsStylesheetUrl",
	// The brand's images and whether its name gives way to the logo, which its sign-in pages show
	// anyone (#813 decision 9).
	"LogoURL":     "logoUrl",
	"DarkLogoURL": "darkLogoUrl",
	"FaviconURL":  "faviconUrl",
	"HideAppName": "hideAppName",
	// Whether the brand has a background image, which its sign-in pages show anyone, so the console
	// draws its card pages' footer on a panel over it (#814 decision 6, D1).
	"HasBackground": "hasBackground",
	// The brand's footer links, every label included, and its support contact, which its sign-in
	// pages draw under the card for anyone (#814 decision 9).
	"FooterLinks":  "footerLinks",
	"SupportEmail": "supportEmail",
	"SupportURL":   "supportUrl",
	"SupportPhone": "supportPhone",
}

// publicBrandFooterLinkAllowedFields is the complete set of fields a footer link carries: its URL,
// its fallback label and its label per language, all of which its sign-in pages draw.
var publicBrandFooterLinkAllowedFields = map[string]string{
	"Url":    "url",
	"Label":  "label",
	"Labels": "labels",
}

// This fails if a field is added to PublicSettingsResponse without being added to
// the allowlist above, which forces the question "should this really be public?"
// into review.
func TestPublicSettingsResponse_ExposesOnlyAllowlistedFields(t *testing.T) {
	assertOnlyAllowlistedFields(t, reflect.TypeOf(api.PublicSettingsResponse{}), publicSettingsAllowedFields)
	assertOnlyAllowlistedFields(t, reflect.TypeOf(api.PasswordRulesResponse{}), publicPasswordRulesAllowedFields)
	assertOnlyAllowlistedFields(t, reflect.TypeOf(api.PublicBrandResponse{}), publicBrandAllowedFields)
	assertOnlyAllowlistedFields(t, reflect.TypeOf(api.BrandFooterLinkResponse{}), publicBrandFooterLinkAllowedFields)
}

// assertOnlyAllowlistedFields holds responseType to the fields allowed, each under its JSON name.
func assertOnlyAllowlistedFields(t *testing.T, responseType reflect.Type, allowed map[string]string) {
	t.Helper()
	assert.Equal(t, len(allowed), responseType.NumField(),
		"PublicSettingsResponse gained or lost a field; this endpoint needs no "+
			"authentication, so update publicSettingsAllowedFields only if the new "+
			"field is genuinely safe to expose to anonymous callers")

	for i := 0; i < responseType.NumField(); i++ {
		field := responseType.Field(i)
		wantJSON, isAllowed := allowed[field.Name]
		assert.True(t, isAllowed, "field %q of %s is not in the allowlist", field.Name, responseType.Name())
		if isAllowed {
			gotJSON := strings.Split(field.Tag.Get("json"), ",")[0]
			assert.Equal(t, wantJSON, gotJSON, "field %q changed its JSON name", field.Name)
		}
	}
}

// The stronger guard: fill the MODEL with recognizable secrets and assert none of
// them reach the response body. This catches the case the struct check cannot,
// namely someone replacing the DTO mapping with a direct encode of settings.
func TestPublicSettings_DoesNotLeakSensitiveSettings(t *testing.T) {
	database := datamocks.NewDatabase(t)
	handler := HandlePublicSettingsGet(database, publicSettingsBaseURL)

	aesKey := []byte("SENTINEL-legacy-aes-encryption-key")
	smtpPassword := []byte("SENTINEL-smtp-password-encrypted")
	turnstileSecretKey := []byte("SENTINEL-turnstile-secret-key-encrypted")

	settings := &record.Settings{
		Id:                          1,
		AppName:                     "Goiabada Test",
		SMTPEnabled:                 true,
		AESEncryptionKeyLegacy:      aesKey,
		SMTPPasswordEncrypted:       smtpPassword,
		SMTPHost:                    "SENTINEL-smtp-host",
		SMTPUsername:                "SENTINEL-smtp-username",
		SMTPFromEmail:               "SENTINEL-smtp-from@example.com",
		SMTPFromName:                "SENTINEL-smtp-from-name",
		SMTPEncryption:              "SENTINEL-smtp-encryption",
		SMTPPort:                    2525,
		TurnstileEnabled:            true,
		TurnstileSiteKey:            "SENTINEL-turnstile-site-key",
		TurnstileSecretKeyEncrypted: turnstileSecretKey,
	}

	database.On("GetSettingsById", mock.Anything, (*sql.Tx)(nil), int64(1)).Return(settings, nil).Once()
	// The brand's name is not one of its public fields.
	expectConsoleClientBrand(database, &record.Brand{
		Id: 4, Name: "SENTINEL-brand-name", Appearance: record.BrandAppearanceLight, Theme: "guava",
	}, nil)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest("GET", "/api/public/settings", nil))

	assert.Equal(t, http.StatusOK, recorder.Code)
	payload := recorder.Body.String()

	// Plaintext secrets.
	for _, secret := range []string{
		"SENTINEL-smtp-host",
		"SENTINEL-smtp-username",
		"SENTINEL-smtp-from@example.com",
		"SENTINEL-smtp-from-name",
		"SENTINEL-smtp-encryption",
		"SENTINEL-turnstile-site-key",
		"SENTINEL-brand-name",
	} {
		assert.NotContains(t, payload, secret, "the response must not expose %q", secret)
	}

	// Byte slices would serialize as base64, so check that encoding too.
	for _, secret := range [][]byte{aesKey, smtpPassword, turnstileSecretKey} {
		assert.NotContains(t, payload, string(secret))
		assert.NotContains(t, payload, base64.StdEncoding.EncodeToString(secret))
	}

	// And no key named after a sensitive setting.
	var asMap map[string]any
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &asMap))
	for key := range asMap {
		_, allowed := publicSettingsAllowedFields[key]
		if !allowed {
			// The map is keyed by JSON name, so compare against those.
			found := false
			for _, jsonName := range publicSettingsAllowedFields {
				if jsonName == key {
					found = true
					break
				}
			}
			assert.True(t, found, "unexpected key %q in a public, unauthenticated response", key)
		}
	}

	// Not passing by returning nothing.
	assert.Contains(t, payload, "Goiabada Test")
}

// A guard on the guard: if record.Settings itself stops carrying the sensitive
// fields the test above pins, the sentinels would silently stop proving anything.
func TestPublicSettings_SensitiveSettingsFieldsStillExist(t *testing.T) {
	settingsType := reflect.TypeOf(record.Settings{})

	for _, name := range []string{
		"AESEncryptionKeyLegacy",
		"SMTPPasswordEncrypted",
		"SMTPHost",
		"SMTPUsername",
		"TurnstileSiteKey",
		"TurnstileSecretKeyEncrypted",
	} {
		_, present := settingsType.FieldByName(name)
		assert.True(t, present,
			"record.Settings no longer has %q; update TestPublicSettings_DoesNotLeakSensitiveSettings", name)
	}
}
