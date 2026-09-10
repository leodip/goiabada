package handlers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	chimiddleware "github.com/go-chi/chi/v5/middleware"
	mocks_audit "github.com/leodip/goiabada/authserver/internal/audit/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"

	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Dynamic client registration is the one 500 surface #279 decision 7 does not take over. Its body
// is fixed by RFC 7591 section 3.2.2, which section 2 of the agreement leaves alone, so it takes the
// primitive's logging half and keeps its own envelope. This case holds both halves at once: the
// record exists, structured and with the request id, and nothing on the wire moved.
func TestDCR_AStorageFailureLogsOnceAndKeepsTheRFC7591Envelope(t *testing.T) {
	const requestId = "req-dcr-1"

	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)

	database.On("CreateClient", (*sql.Tx)(nil), mock.Anything).
		Return(errors.New("the disk is full")).Once()

	body, err := json.Marshal(api.DynamicClientRegistrationRequest{
		ClientName:   "A Test Client",
		RedirectURIs: []string{"https://client.example.com/callback"},
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/connect/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(req.Context(), constants.ContextKeySettings,
		&models.Settings{Id: 1, DynamicClientRegistrationEnabled: true})
	ctx = context.WithValue(ctx, chimiddleware.RequestIDKey, requestId)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	var buf strings.Builder
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	HandleDynamicClientRegistrationPost(httpHelper, database, auditLogger).ServeHTTP(rr, req)
	slog.SetDefault(previous)

	// The envelope is DCR's own, not the API's: "error" and "error_description", as RFC 7591
	// section 3.2.2 spells them, and no error_code.
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	var envelope map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &envelope))
	assert.Equal(t, "server_error", envelope["error"])
	assert.Equal(t, "Failed to register client", envelope["error_description"])
	assert.NotContains(t, envelope, "error_code")

	logged := buf.String()
	assert.Equal(t, 1, strings.Count(logged, "internal server error"))
	assert.Contains(t, logged, "the disk is full")
	assert.Contains(t, logged, "request_id="+requestId)
	database.AssertExpectations(t)
}
