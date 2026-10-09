package apihandlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every admin and account API route runs under middleware.Settings, so a handler reached without
// settings is a wiring defect. It answers the one JSON 500 envelope this surface uses, with
// reqctx.ErrNoSettings in the record, and this row stands for every settings read in the package:
// they share this writer (#433 decision 6).
func TestHandleSettingsGeneralGet_WithoutSettingsAnswersTheJSON500Envelope(t *testing.T) {
	capture := logtest.CaptureSlog(t)
	rr := httptest.NewRecorder()

	HandleSettingsGeneralGet().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/admin/settings/general", nil))

	require.Equal(t, http.StatusInternalServerError, rr.Code)
	code, description := decodeErrorEnvelope(t, rr)
	assert.Equal(t, "INTERNAL_SERVER_ERROR", code)
	assert.Contains(t, description, "Request Id:")

	attrs := oneErrorRecord(t, capture)
	logged, isError := attrs["error"].(error)
	require.True(t, isError, "the error attribute must carry the error value itself")
	assert.ErrorIs(t, logged, reqctx.ErrNoSettings)
}
