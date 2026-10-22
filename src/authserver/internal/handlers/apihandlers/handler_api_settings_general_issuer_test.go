package apihandlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/inputvalidation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// issuerRuleBaseURL is the configured base URL these tests run under: an http one, as a new install
// on localhost seeds, so the one http issuer the rule accepts is told apart from every other.
const issuerRuleBaseURL = "http://localhost:9090"

// issuerRuleRefusal is the URL refusal's English sentence, which states the rule (#576 decision 3).
const issuerRuleRefusal = "Invalid issuer. Enter an https URL with no query, fragment or user info, or the auth server's base URL."

// putGeneralIssuer saves the general settings with issuer over a stored row holding storedIssuer,
// and answers the response and the row written, nil when nothing was.
func putGeneralIssuer(t *testing.T, storedIssuer, issuer string) (*httptest.ResponseRecorder, *record.Settings) {
	t.Helper()
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	var saved *record.Settings
	allowSettingsSave(database)
	database.On("UpdateSettings", mock.Anything, settingsSaveTx, mock.Anything).
		Run(func(args mock.Arguments) { saved = args.Get(2).(*record.Settings) }).Return(nil).Maybe()
	auditLogger.On("Log", mock.Anything, audit.EventUpdatedGeneralSettings, mock.Anything).Return().Maybe()

	body, err := json.Marshal(api.UpdateSettingsGeneralRequest{
		AppName:                 "Goiabada",
		Issuer:                  issuer,
		SelfRegistrationEnabled: true,
		PasswordPolicy:          "low",
	})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/settings/general", bytes.NewReader(body))
	req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{Id: 1, Issuer: storedIssuer}))
	rr := httptest.NewRecorder()

	HandleSettingsGeneralPut(database, auditLogger, issuerRuleBaseURL).ServeHTTP(rr, req)
	return rr, saved
}

// The issuer is an https URL with no query, fragment or user info, as RFC 8414 section 2, RFC 9207
// section 2 and OpenID Connect Discovery 1.0 section 3 require, or exactly the configured base URL
// whatever its scheme, which is the URL discovery is fetched under and what a new install seeds
// (#576 decision 3). An empty query or fragment, a trailing "?" or "#", counts as one.
func TestHandleSettingsGeneralPut_TheIssuerRule(t *testing.T) {
	const stored = "https://stored.example.com"

	accepted := []struct{ name, issuer, want string }{
		{"an https URL", "https://auth.example.com", "https://auth.example.com"},
		{"an https URL with a path", "https://auth.example.com/tenant-a", "https://auth.example.com/tenant-a"},
		{"an https URL with a port", "https://auth.example.com:8443", "https://auth.example.com:8443"},
		{"the base URL in http", "http://localhost:9090", "http://localhost:9090"},
		{"an https URL with surrounding spaces, trimmed", "  https://auth.example.com  ", "https://auth.example.com"},
	}
	for _, c := range accepted {
		t.Run("accepts "+c.name, func(t *testing.T) {
			rr, saved := putGeneralIssuer(t, stored, c.issuer)

			require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
			require.NotNil(t, saved)
			assert.Equal(t, c.want, saved.Issuer)
		})
	}

	refused := []struct{ name, issuer string }{
		{"a plain name", "goiabada"},
		{"a plain name with a space", "my issuer"},
		{"an http URL other than the base URL", "http://auth.example.com"},
		{"the base URL with a trailing slash", "http://localhost:9090/"},
		{"the base URL with another host spelling", "http://127.0.0.1:9090"},
		{"another scheme", "ftp://auth.example.com"},
		{"user info", "https://admin@auth.example.com"},
		{"user info with a password", "https://admin:secret@auth.example.com"},
		{"a query", "https://auth.example.com?tenant=a"},
		{"an empty query", "https://auth.example.com?"},
		{"a fragment", "https://auth.example.com#top"},
		{"an empty fragment", "https://auth.example.com#"},
		{"no host", "https://"},
		{"no host before a path", "https:///tenant-a"},
		{"a port and no host", "https://:443"},
		{"an empty port and no host before a path", "https://:/tenant-a"},
		{"an opaque URL", "https:auth.example.com"},
		{"a malformed percent escape", "https://auth.example.com/%zz"},
		{"a malformed port", "https://auth.example.com:invalid"},
		{"a space in the host", "https://auth example.com"},
		{"a space in the path", "https://auth.example.com/my tenant"},
	}
	for _, c := range refused {
		t.Run("refuses "+c.name, func(t *testing.T) {
			rr, saved := putGeneralIssuer(t, stored, c.issuer)

			require.Equal(t, http.StatusBadRequest, rr.Code)
			code, description := decodeErrorEnvelope(t, rr)
			assert.Equal(t, "handler.settings_general.issuer_uri_invalid", code)
			assert.Equal(t, issuerRuleRefusal, description)
			assert.Nil(t, saved, "a refused save writes nothing")
		})
	}
}

// A stored issuer the rule refuses stands until the operator changes it: the save applies the rule
// only to an issuer that differs from the stored one, so the other general settings still save
// around it (#576 decision 4). Changing it is held to the rule like any other value.
func TestHandleSettingsGeneralPut_AStoredIssuerTheRuleRefusesStandsUntilChanged(t *testing.T) {
	for _, stored := range []string{"goiabada", "http://auth.example.com"} {
		t.Run(stored, func(t *testing.T) {
			rr, saved := putGeneralIssuer(t, stored, stored)

			require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
			require.NotNil(t, saved)
			assert.Equal(t, stored, saved.Issuer, "the stored issuer is kept")
			assert.True(t, saved.SelfRegistrationEnabled, "the other settings are saved around it")

			rr, saved = putGeneralIssuer(t, stored, stored+"-changed")

			require.Equal(t, http.StatusBadRequest, rr.Code)
			_, description := decodeErrorEnvelope(t, rr)
			assert.Equal(t, issuerRuleRefusal, description)
			assert.Nil(t, saved)
		})
	}
}

// The 60-character limit and the angle-bracket refusal hold every save, an unchanged issuer
// included: only the issuer rule stands aside for a stored issuer (#576 decisions 3 and 4).
func TestHandleSettingsGeneralPut_AnUnchangedIssuerIsStillHeldToItsBounds(t *testing.T) {
	cases := []struct{ name, stored, code, description string }{
		{"longer than 60 characters", "https://auth.example.com/" + strings.Repeat("a", 36),
			"handler.settings_general.issuer_too_long", "Issuer is too long. The maximum length is 60 characters."},
		// 61 UTF-16 code units in 60 code points, as the start refuses it (#615).
		{"one code unit past 60 in 60 code points", "https://auth.example.com/" + strings.Repeat("a", 34) + "\U0001F600",
			"handler.settings_general.issuer_too_long", "Issuer is too long. The maximum length is 60 characters."},
		{"holding an angle bracket", "https://example.org/<b>",
			"validator.settings.issuer_angle_brackets", "The issuer cannot contain the characters < or >."},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rr, saved := putGeneralIssuer(t, c.stored, c.stored)

			require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
			code, description := decodeErrorEnvelope(t, rr)
			assert.Equal(t, c.code, code)
			assert.Equal(t, c.description, description)
			assert.Nil(t, saved, "a refused save writes nothing")
		})
	}
}

// An issuer at the limit saves, as the start accepts a base URL at it, so whatever the start lets
// through the first start seeds and every later save keeps (#615). The limit is counted in UTF-16
// code units, as the start counts it: two astral characters, two units and four bytes each, make an
// issuer of 60 units and 64 bytes that saves. The strings are the start's own cases in
// config/base_url_test.go, and the counts are checked here so they cannot drift from what each case
// is for.
func TestHandleSettingsGeneralPut_AnIssuerAtTheLimitSaves(t *testing.T) {
	ascii := "https://auth." + strings.Repeat("a", 60-len("https://auth.")-len(".example.com")) + ".example.com"
	astral := "https://auth." + strings.Repeat("a", 60-len("https://auth.")-len(".example.com")-4) +
		"\U0001F600\U0001F600.example.com"
	require.Equal(t, 60, inputvalidation.TextLength(ascii))
	require.Len(t, ascii, 60)
	require.Equal(t, 60, inputvalidation.TextLength(astral))
	require.Len(t, astral, 64)

	for name, issuer := range map[string]string{"60 ASCII characters": ascii, "60 code units in 64 bytes": astral} {
		t.Run(name, func(t *testing.T) {
			rr, saved := putGeneralIssuer(t, issuer, issuer)

			require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
			require.NotNil(t, saved)
			assert.Equal(t, issuer, saved.Issuer, "the issuer is kept")
		})
	}
}
