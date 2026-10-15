package apihandlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
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
	database.On("UpdateSettings", mock.Anything, mock.Anything, mock.Anything).
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
		{"an opaque URL", "https:auth.example.com"},
		{"a space in the host", "https://auth example.com"},
		{"a space in the path", "https://auth.example.com/my tenant"},
	}
	for _, c := range refused {
		t.Run("refuses "+c.name, func(t *testing.T) {
			rr, saved := putGeneralIssuer(t, stored, c.issuer)

			require.Equal(t, http.StatusBadRequest, rr.Code)
			code, description := decodeErrorEnvelope(t, rr)
			assert.Equal(t, "VALIDATION_ERROR", code)
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
