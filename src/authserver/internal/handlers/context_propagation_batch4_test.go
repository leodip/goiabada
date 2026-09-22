package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/authserver/internal/handlerhelpers/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Seam 4 of #386 for the last batch of Database methods, in this package: the JWKS endpoint's key
// read and the public settings endpoint's settings read.
//
// Same argument and same thinness as context_propagation_test.go, whose requestCarryingId and
// theRequestsContext this file reuses. Both endpoints below are unauthenticated and both are
// polled -- /certs by every relying party that caches keys, /api/v1/public/settings by the admin
// console on its own schedule -- so both are reads a peer that has gone away leaves running.

// The accept arm for the key read: /certs serves whatever key pairs the install holds, on behalf
// of the request that asked for them.
func TestHandleCertsGet_ReadsKeysUnderTheRequestsContext(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	database := mocks_data.NewDatabase(t)

	database.On("GetAllSigningKeys", theRequestsContext(), mock.Anything).
		Return([]models.KeyPair{}, nil).Once()
	httpHelper.On("EncodeJson", mock.Anything, mock.Anything, mock.Anything).Return().Once()

	rr := httptest.NewRecorder()
	HandleCertsGet(httpHelper, database).ServeHTTP(rr, requestCarryingId(t, http.MethodGet, "/certs"))

	database.AssertExpectations(t)
	httpHelper.AssertExpectations(t)
}

// The accept arm for the settings read.
func TestHandlerPublicSettings_ReadsSettingsUnderTheRequestsContext(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	database.On("GetSettingsById", theRequestsContext(), mock.Anything, int64(1)).
		Return(&models.Settings{Id: 1, AppName: "TestApp"}, nil).Once()

	rr := httptest.NewRecorder()
	NewHandlerPublicSettings(database).ServeHTTP(rr, requestCarryingId(t, http.MethodGet, "/api/v1/public/settings"))

	require.Equal(t, http.StatusOK, rr.Code)
	database.AssertExpectations(t)
}

// The reject arm: a method other than GET is refused before the settings read, so the port is
// never reached and there is no context to get wrong. It is the arm that stops the accept arm
// passing on a handler that read the settings before deciding whether to answer at all.
func TestHandlerPublicSettings_AWrongMethodReachesNoSettingsPort(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	rr := httptest.NewRecorder()
	NewHandlerPublicSettings(database).ServeHTTP(rr, requestCarryingId(t, http.MethodPost, "/api/v1/public/settings"))

	require.Equal(t, http.StatusMethodNotAllowed, rr.Code)
	database.AssertNotCalled(t, "GetSettingsById", mock.Anything, mock.Anything, mock.Anything)
}
