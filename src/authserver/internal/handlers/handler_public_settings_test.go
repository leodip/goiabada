package handlers

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/dtos"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
)

// =============================================================================
// /api/public/settings
//
// This endpoint requires no authentication: it is what the login and account
// pages read before anyone has a token. models.Settings holds 32 fields, among
// them the legacy AES encryption key and the encrypted SMTP password, so the
// narrow PublicSettingsResponse DTO is the entire boundary between an anonymous
// caller and all of it. The two guards further down exist to fail if that
// boundary ever widens, whether by growing the DTO or by serializing the model
// directly.
// =============================================================================

func TestPublicSettings_Success(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	handler := NewHandlerPublicSettings(database)

	database.On("GetSettingsById", (*sql.Tx)(nil), int64(1)).Return(&models.Settings{
		Id:          1,
		AppName:     "Goiabada Test",
		UITheme:     "dark",
		SMTPEnabled: true,
	}, nil).Once()

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest("GET", "/api/public/settings", nil))

	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, "application/json", recorder.Header().Get("Content-Type"))

	var body dtos.PublicSettingsResponse
	assert.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
	assert.Equal(t, "Goiabada Test", body.AppName)
	assert.Equal(t, "dark", body.UITheme)
	assert.True(t, body.SMTPEnabled)
}

func TestPublicSettings_OnlyGetIsAllowed(t *testing.T) {
	for _, method := range []string{"POST", "PUT", "DELETE", "PATCH", "HEAD"} {
		t.Run(method, func(t *testing.T) {
			// NewDatabase(t) fails on any unexpected call, so the absence of a
			// GetSettingsById expectation proves the method check short circuits.
			database := mocks_data.NewDatabase(t)
			handler := NewHandlerPublicSettings(database)

			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest(method, "/api/public/settings", nil))

			assert.Equal(t, http.StatusMethodNotAllowed, recorder.Code)
		})
	}
}

func TestPublicSettings_DatabaseError(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	handler := NewHandlerPublicSettings(database)

	database.On("GetSettingsById", (*sql.Tx)(nil), int64(1)).
		Return(nil, errors.New("database is down")).Once()

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest("GET", "/api/public/settings", nil))

	assert.Equal(t, http.StatusInternalServerError, recorder.Code)
	assert.Contains(t, recorder.Body.String(), "Unable to retrieve settings")
}

// GetSettingsById returns (nil, nil) when the row is absent. Without a nil guard
// the handler dereferenced it, which panicked an endpoint reachable without any
// authentication.
func TestPublicSettings_MissingSettingsRowDoesNotPanic(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	handler := NewHandlerPublicSettings(database)

	database.On("GetSettingsById", (*sql.Tx)(nil), int64(1)).Return(nil, nil).Once()

	recorder := httptest.NewRecorder()
	assert.NotPanics(t, func() {
		handler.ServeHTTP(recorder, httptest.NewRequest("GET", "/api/public/settings", nil))
	})

	assert.Equal(t, http.StatusInternalServerError, recorder.Code)
	assert.Contains(t, recorder.Body.String(), "Unable to retrieve settings")
}

// failingResponseWriter fails every write, so the encode error path is reachable.
type failingResponseWriter struct {
	header http.Header
	code   int
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

func (f *failingResponseWriter) WriteHeader(statusCode int) {
	f.code = statusCode
}

func TestPublicSettings_EncodeFailure(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	handler := NewHandlerPublicSettings(database)

	database.On("GetSettingsById", (*sql.Tx)(nil), int64(1)).Return(&models.Settings{
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
}

// This fails if a field is added to PublicSettingsResponse without being added to
// the allowlist above, which forces the question "should this really be public?"
// into review.
func TestPublicSettingsResponse_ExposesOnlyAllowlistedFields(t *testing.T) {
	responseType := reflect.TypeOf(dtos.PublicSettingsResponse{})

	assert.Equal(t, len(publicSettingsAllowedFields), responseType.NumField(),
		"PublicSettingsResponse gained or lost a field; this endpoint needs no "+
			"authentication, so update publicSettingsAllowedFields only if the new "+
			"field is genuinely safe to expose to anonymous callers")

	for i := 0; i < responseType.NumField(); i++ {
		field := responseType.Field(i)
		wantJSON, allowed := publicSettingsAllowedFields[field.Name]
		assert.True(t, allowed, "field %q is not in the allowlist", field.Name)
		if allowed {
			gotJSON := strings.Split(field.Tag.Get("json"), ",")[0]
			assert.Equal(t, wantJSON, gotJSON, "field %q changed its JSON name", field.Name)
		}
	}
}

// The stronger guard: fill the MODEL with recognizable secrets and assert none of
// them reach the response body. This catches the case the struct check cannot,
// namely someone replacing the DTO mapping with a direct encode of settings.
func TestPublicSettings_DoesNotLeakSensitiveSettings(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	handler := NewHandlerPublicSettings(database)

	aesKey := []byte("SENTINEL-legacy-aes-encryption-key")
	smtpPassword := []byte("SENTINEL-smtp-password-encrypted")

	settings := &models.Settings{
		Id:                     1,
		AppName:                "Goiabada Test",
		UITheme:                "light",
		SMTPEnabled:            true,
		AESEncryptionKeyLegacy: aesKey,
		SMTPPasswordEncrypted:  smtpPassword,
		SMTPHost:               "SENTINEL-smtp-host",
		SMTPUsername:           "SENTINEL-smtp-username",
		SMTPFromEmail:          "SENTINEL-smtp-from@example.com",
		SMTPFromName:           "SENTINEL-smtp-from-name",
		SMTPEncryption:         "SENTINEL-smtp-encryption",
		SMTPPort:               2525,
	}

	database.On("GetSettingsById", (*sql.Tx)(nil), int64(1)).Return(settings, nil).Once()

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
	} {
		assert.NotContains(t, payload, secret, "the response must not expose %q", secret)
	}

	// Byte slices would serialize as base64, so check that encoding too.
	for _, secret := range [][]byte{aesKey, smtpPassword} {
		assert.NotContains(t, payload, string(secret))
		assert.NotContains(t, payload, base64.StdEncoding.EncodeToString(secret))
	}

	// And no key named after a sensitive setting.
	var asMap map[string]any
	assert.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &asMap))
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

// A guard on the guard: if models.Settings itself stops carrying the sensitive
// fields the test above pins, the sentinels would silently stop proving anything.
func TestPublicSettings_SensitiveSettingsFieldsStillExist(t *testing.T) {
	settingsType := reflect.TypeOf(models.Settings{})

	for _, name := range []string{
		"AESEncryptionKeyLegacy",
		"SMTPPasswordEncrypted",
		"SMTPHost",
		"SMTPUsername",
	} {
		_, present := settingsType.FieldByName(name)
		assert.True(t, present,
			"models.Settings no longer has %q; update TestPublicSettings_DoesNotLeakSensitiveSettings", name)
	}
}
