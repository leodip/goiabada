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
// pages read before anyone has a token. record.Settings holds 37 fields, among
// them the legacy AES encryption key and the encrypted SMTP password, so the
// narrow PublicSettingsResponse DTO is the entire boundary between an anonymous
// caller and all of it. The two guards further down exist to fail if that
// boundary ever widens, whether by growing the DTO or by serializing the model
// directly.
// =============================================================================

// publicSettingsBaseURL is the auth server's base URL in these tests, the one a brand's stylesheet
// URL is built from.
const publicSettingsBaseURL = "https://auth.example.test"

// expectNoDefaultBrand has database answer an empty default brand pointer, for a case about
// something other than the brand.
func expectNoDefaultBrand(database *datamocks.Database) {
	database.On("GetDefaultBrand", mock.Anything, (*sql.Tx)(nil)).Return(nil, nil).Once()
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

// The default brand rides with the public settings as brand: its appearance, and the absolute URL
// of its stylesheet, built from the auth server's base URL as a client logo's URL is, so the admin
// console links it after main.css and draws every page as the auth server draws its own (#810
// decision 3). uiTheme is no longer answered.
func TestPublicSettings_CarriesTheDefaultBrand(t *testing.T) {
	for _, tc := range []struct {
		name           string
		brand          *record.Brand
		wantAppearance string
		wantStylesheet string
	}{
		{"a dark brand", &record.Brand{Id: 7, Name: "Night", Appearance: record.BrandAppearanceDark, Theme: "plum"},
			"dark", "/brand/7/stylesheet.css?v="},
		{"a light brand", &record.Brand{Id: 12, Name: "Day", Appearance: record.BrandAppearanceLight, Theme: "avocado"},
			"light", "/brand/12/stylesheet.css?v="},
		{"an automatic brand on Blueberry", &record.Brand{Id: 1, Name: "Default", Appearance: record.BrandAppearanceAuto, Theme: "blueberry"},
			"auto", "/brand/1/stylesheet.css?v="},
	} {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			database.On("GetSettingsById", mock.Anything, (*sql.Tx)(nil), int64(1)).Return(&record.Settings{
				Id: 1, AppName: "Goiabada",
			}, nil).Once()
			database.On("GetDefaultBrand", mock.Anything, (*sql.Tx)(nil)).Return(tc.brand, nil).Once()

			recorder := httptest.NewRecorder()
			HandlePublicSettingsGet(database, publicSettingsBaseURL).ServeHTTP(recorder, httptest.NewRequest("GET", "/api/public/settings", nil))

			require.Equal(t, http.StatusOK, recorder.Code)
			var body map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
			stylesheet, ok := brandthemes.StylesheetOf(tc.brand.Theme)
			require.True(t, ok)
			require.Regexp(t, `^[0-9a-f]{12}$`, stylesheet.Fingerprint)
			assert.JSONEq(t, `{"appearance":"`+tc.wantAppearance+`","stylesheetUrl":"`+
				publicSettingsBaseURL+tc.wantStylesheet+stylesheet.Fingerprint+`"}`, string(body["brand"]))
			assert.NotContains(t, body, "uiTheme")
		})
	}
}

// A default brand that cannot be read leaves brand out of the answer, which is otherwise whole: the
// console draws its pages automatic in the built-in colors, as the auth server draws its own then,
// rather than every console page failing over the look. That is an empty pointer, a failed read,
// and a stored theme that is none of the built-in ones; the last two are faults, and logged.
func TestPublicSettings_AnswersNoBrandWhenTheDefaultCannotBeRead(t *testing.T) {
	for _, tc := range []struct {
		name    string
		brand   *record.Brand
		err     error
		wantLog string
	}{
		{name: "no default brand"},
		{name: "a failed read", err: errors.New("the database went away"), wantLog: "unable to read the default brand"},
		{name: "a theme none of the built-in ones",
			brand:   &record.Brand{Id: 3, Name: "Odd", Appearance: record.BrandAppearanceDark, Theme: "mango"},
			wantLog: "unable to link the brand's stylesheet"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := logtest.CaptureSlog(t)
			database := datamocks.NewDatabase(t)
			database.On("GetSettingsById", mock.Anything, (*sql.Tx)(nil), int64(1)).Return(&record.Settings{
				Id: 1, AppName: "Goiabada", Issuer: "https://issuer.example",
			}, nil).Once()
			database.On("GetDefaultBrand", mock.Anything, (*sql.Tx)(nil)).Return(tc.brand, tc.err).Once()

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
	// The default brand's appearance and stylesheet URL, which the admin console draws its pages in
	// (#810 decision 3). Every page the auth server serves to anyone already carries both, as
	// data-theme and as a stylesheet link.
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

// publicBrandAllowedFields is the complete set of fields the brand carries: its appearance and its
// stylesheet's URL, and nothing else about the brand, its name among it.
var publicBrandAllowedFields = map[string]string{
	"Appearance":    "appearance",
	"StylesheetURL": "stylesheetUrl",
}

// This fails if a field is added to PublicSettingsResponse without being added to
// the allowlist above, which forces the question "should this really be public?"
// into review.
func TestPublicSettingsResponse_ExposesOnlyAllowlistedFields(t *testing.T) {
	assertOnlyAllowlistedFields(t, reflect.TypeOf(api.PublicSettingsResponse{}), publicSettingsAllowedFields)
	assertOnlyAllowlistedFields(t, reflect.TypeOf(api.PasswordRulesResponse{}), publicPasswordRulesAllowedFields)
	assertOnlyAllowlistedFields(t, reflect.TypeOf(api.PublicBrandResponse{}), publicBrandAllowedFields)
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
	database.On("GetDefaultBrand", mock.Anything, (*sql.Tx)(nil)).Return(&record.Brand{
		Id: 4, Name: "SENTINEL-brand-name", Appearance: record.BrandAppearanceLight, Theme: "guava",
	}, nil).Once()

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
