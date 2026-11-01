package handlers

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/legaldocuments"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// fixedLegalDocuments answers the documents in effect for all apps that a test sets, or err.
type fixedLegalDocuments struct {
	allApps []legaldocuments.InEffect
	err     error
}

func (f fixedLegalDocuments) ForAllApps(context.Context) ([]legaldocuments.InEffect, error) {
	return f.allApps, f.err
}

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

func TestPublicSettings_Success(t *testing.T) {
	database := datamocks.NewDatabase(t)
	handler := NewPublicSettings(database, fixedLegalDocuments{}, "https://auth.example")

	database.On("GetSettingsById", mock.Anything, (*sql.Tx)(nil), int64(1)).Return(&record.Settings{
		Id:          1,
		AppName:     "Goiabada Test",
		UITheme:     "dark",
		SMTPEnabled: true,
		Issuer:      "https://issuer.example",
	}, nil).Once()

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest("GET", "/api/public/settings", nil))

	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, "application/json", recorder.Header().Get("Content-Type"))

	var body api.PublicSettingsResponse
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
	assert.Equal(t, "Goiabada Test", body.AppName)
	assert.Equal(t, "dark", body.UITheme)
	assert.True(t, body.SMTPEnabled)
	assert.Equal(t, "https://issuer.example", body.Issuer)
}

// The legal documents in effect for all apps ride with the public settings, each with its current
// version's title and its public page's address, for My Account's footer (#622).
func TestPublicSettings_CarriesTheAllAppsLegalDocuments(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("GetSettingsById", mock.Anything, (*sql.Tx)(nil), int64(1)).Return(&record.Settings{Id: 1}, nil).Once()
	documents := fixedLegalDocuments{allApps: []legaldocuments.InEffect{
		{Document: record.LegalDocument{Id: 3, ShortName: "privacy"}, Current: record.LegalDocumentVersion{VersionNumber: 2, Title: "Privacy notice"}},
		{Document: record.LegalDocument{Id: 5, ShortName: "terms"}, Current: record.LegalDocumentVersion{VersionNumber: 1, Title: "Terms of use"}},
	}}

	recorder := httptest.NewRecorder()
	NewPublicSettings(database, documents, "https://auth.example").ServeHTTP(recorder, httptest.NewRequest("GET", "/api/public/settings", nil))

	require.Equal(t, http.StatusOK, recorder.Code)
	var body map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
	assert.JSONEq(t, `[
		{"title":"Privacy notice","shortName":"privacy","url":"https://auth.example/legal/privacy"},
		{"title":"Terms of use","shortName":"terms","url":"https://auth.example/legal/terms"}
	]`, string(body["legalDocuments"]))
}

// No document in effect is an empty list, never null, so the console reads it as none.
func TestPublicSettings_NoLegalDocumentIsAnEmptyList(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("GetSettingsById", mock.Anything, (*sql.Tx)(nil), int64(1)).Return(&record.Settings{Id: 1}, nil).Once()

	recorder := httptest.NewRecorder()
	NewPublicSettings(database, fixedLegalDocuments{}, "https://auth.example").ServeHTTP(recorder, httptest.NewRequest("GET", "/api/public/settings", nil))

	require.Equal(t, http.StatusOK, recorder.Code)
	var body map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
	assert.JSONEq(t, `[]`, string(body["legalDocuments"]))
}

func TestPublicSettings_AFailedLegalDocumentsReadIsTheAPIs500(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("GetSettingsById", mock.Anything, (*sql.Tx)(nil), int64(1)).Return(&record.Settings{Id: 1}, nil).Once()

	recorder := httptest.NewRecorder()
	NewPublicSettings(database, fixedLegalDocuments{err: errors.New("database is down")}, "https://auth.example").
		ServeHTTP(recorder, httptest.NewRequest("GET", "/api/public/settings", nil))

	assert.Equal(t, http.StatusInternalServerError, recorder.Code)
	assert.Contains(t, recorder.Body.String(), "INTERNAL_SERVER_ERROR")
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

			recorder := httptest.NewRecorder()
			NewPublicSettings(database, fixedLegalDocuments{}, "https://auth.example").ServeHTTP(recorder, httptest.NewRequest("GET", "/api/public/settings", nil))

			require.Equal(t, http.StatusOK, recorder.Code)
			var body map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
			assert.JSONEq(t, tc.want, string(body["passwordRules"]))
		})
	}
}

func TestPublicSettings_DatabaseError(t *testing.T) {
	database := datamocks.NewDatabase(t)
	handler := NewPublicSettings(database, fixedLegalDocuments{}, "https://auth.example")

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
	handler := NewPublicSettings(database, fixedLegalDocuments{}, "https://auth.example")

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
	handler := NewPublicSettings(database, fixedLegalDocuments{}, "https://auth.example")

	database.On("GetSettingsById", mock.Anything, (*sql.Tx)(nil), int64(1)).Return(&record.Settings{
		Id: 1, AppName: "Goiabada",
	}, nil).Once()

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
	"UITheme":     "uiTheme",
	"SMTPEnabled": "smtpEnabled",
	// Already world-readable: /.well-known/openid-configuration serves the same
	// value to anonymous callers, as OIDC Discovery 1.0 section 3 requires.
	"Issuer": "issuer",
	// The stored password policy's rules, which the admin console states under its password
	// fields (#550 decision 11). Already readable by anyone who opens the registration form
	// while registration is on, and NIST SP 800-63B assumes an attacker knows them.
	"PasswordRules": "passwordRules",
	// The legal documents in effect for all apps, which My Account's footer links (#622). Each
	// one's page is public, and every sign-in page's footer links them to anyone.
	"LegalDocuments": "legalDocuments",
}

// publicLegalDocumentAllowedFields is the complete set of fields a legal document carries here:
// its current version's title, its short name and its public page's address.
var publicLegalDocumentAllowedFields = map[string]string{
	"Title":     "title",
	"ShortName": "shortName",
	"URL":       "url",
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

// This fails if a field is added to PublicSettingsResponse without being added to
// the allowlist above, which forces the question "should this really be public?"
// into review.
func TestPublicSettingsResponse_ExposesOnlyAllowlistedFields(t *testing.T) {
	assertOnlyAllowlistedFields(t, reflect.TypeOf(api.PublicSettingsResponse{}), publicSettingsAllowedFields)
	assertOnlyAllowlistedFields(t, reflect.TypeOf(api.PasswordRulesResponse{}), publicPasswordRulesAllowedFields)
	assertOnlyAllowlistedFields(t, reflect.TypeOf(api.PublicLegalDocumentResponse{}), publicLegalDocumentAllowedFields)
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
	handler := NewPublicSettings(database, fixedLegalDocuments{}, "https://auth.example")

	aesKey := []byte("SENTINEL-legacy-aes-encryption-key")
	smtpPassword := []byte("SENTINEL-smtp-password-encrypted")
	turnstileSecretKey := []byte("SENTINEL-turnstile-secret-key-encrypted")

	settings := &record.Settings{
		Id:                          1,
		AppName:                     "Goiabada Test",
		UITheme:                     "light",
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
