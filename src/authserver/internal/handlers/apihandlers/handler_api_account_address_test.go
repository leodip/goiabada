package apihandlers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5/middleware"
	mocks_audit "github.com/leodip/goiabada/authserver/internal/audit/mocks"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/testutil"
	"github.com/leodip/goiabada/core/validators"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// This handler is the agreement's representative site for the two defects stage 6 closes, so it is
// the one that gets a case for each. Before #279 decision 7, a database failure here answered
// "Internal server error" and discarded err: no log line in the four lines above it and no request
// id anywhere, which left an operator nothing to join a caller's report to. And the 200 was
// committed with WriteHeader before the encoder ran, so a failing encode could only add a
// superfluous header to a body already half on the wire (decision 8).

const addressRequestId = "req-address-1"

func addressPutRequest(t *testing.T, subject string, body api.UpdateUserAddressRequest) *http.Request {
	t.Helper()
	encoded, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/account/address", bytes.NewReader(encoded))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.RequestIDKey, addressRequestId))
	return setTokenContextWithClaims(req, map[string]interface{}{"sub": subject})
}

// The `api/unlogged-500` anchor: this exact line answered 500 and threw the error away.
func TestHandleAPIAccountAddressPut_ADatabaseFailureIsOneLoggedFiveHundred(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	database.On("GetUserBySubject", (*sql.Tx)(nil), "the-subject").
		Return(nil, errors.New("the database is down")).Once()

	rr := httptest.NewRecorder()
	handler := HandleAPIAccountAddressPut(database, validators.NewAddressValidator(database), auditLogger)

	capture := testutil.CaptureSlog(t)

	handler.ServeHTTP(rr, addressPutRequest(t, "the-subject", api.UpdateUserAddressRequest{}))

	logged := capture.Text()

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))

	var body map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.Equal(t, "INTERNAL_SERVER_ERROR", body["error_code"])
	assert.Contains(t, body["error_description"], addressRequestId)

	// One record, carrying the error that was discarded and the request id the body names, so
	// the two can be joined.
	assert.Equal(t, 1, strings.Count(logged, "internal server error"))
	assert.Contains(t, logged, "the database is down")
	assert.Contains(t, logged, "request_id="+addressRequestId)
	database.AssertExpectations(t)
}

// The `api/encode-after-header` anchor: the success body is buffered and written whole, under the
// status and Content-Type, and nothing is logged.
func TestHandleAPIAccountAddressPut_ASuccessWritesTheWholeBody(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	user := &models.User{Id: 42, Subject: "the-subject"}
	database.On("GetUserBySubject", (*sql.Tx)(nil), "the-subject").Return(user, nil).Once()
	database.On("UpdateUser", (*sql.Tx)(nil), mock.Anything).Return(nil).Once()
	auditLogger.On("Log", constants.AuditUpdatedOwnAddress, mock.Anything).Return().Once()

	rr := httptest.NewRecorder()
	handler := HandleAPIAccountAddressPut(database, validators.NewAddressValidator(database), auditLogger)

	capture := testutil.CaptureSlog(t)

	handler.ServeHTTP(rr, addressPutRequest(t, "the-subject", api.UpdateUserAddressRequest{
		AddressLine1:    "1 Example Street",
		AddressLocality: "Example City",
	}))

	logged := capture.Text()

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))

	var body api.UpdateUserResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body), "the body decodes whole")
	assert.Equal(t, "1 Example Street", body.User.AddressLine1)
	assert.Empty(t, logged, "a success logs nothing")
	database.AssertExpectations(t)
	auditLogger.AssertExpectations(t)
}
