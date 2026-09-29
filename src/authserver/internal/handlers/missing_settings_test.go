package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	mocks_handlers "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Every application route runs under MiddlewareSettings, so a handler reached without settings is
// a wiring defect rather than a request a client can make. Each answers it through the 500 writer
// its other failures already use, passing reqctx.ErrNoSettings, and nothing is read or written
// first. One row per writer in this package, not one per read site: the rest share these writers
// (#433 decision 6).

func isErrNoSettings(err error) bool {
	return errors.Is(err, reqctx.ErrNoSettings)
}

// A browser page answers the 500 page through HttpHelper.
func TestMissingSettings_ABrowserPageAnswersTheErrorPage(t *testing.T) {
	httpHelper := mocks_handlers.NewHttpHelper(t)
	authHelper := mocks_handlers.NewAuthHelper(t)
	database := mocks_data.NewDatabase(t)

	req := httptest.NewRequest(http.MethodGet, "/auth/pwd", nil)
	rr := httptest.NewRecorder()

	authHelper.On("GetAuthContext", req).Return(&ceremony.AuthContext{
		AuthState: ceremony.AuthStateLevel1Password,
		ClientId:  "test-client",
	}, nil)
	httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(isErrNoSettings)).Return().Once()

	HandleAuthPwdGet(httpHelper, authHelper, database, testAdminConsoleBaseURL).ServeHTTP(rr, req)

	httpHelper.AssertExpectations(t)
	database.AssertNotCalled(t, "GetClientByClientIdentifier", mock.Anything, mock.Anything, mock.Anything)
}

// The token endpoint answers its 500 through the JSON writer, RFC 6749 section 5.2's shape, as
// every other failure there is answered, and it is refused before the validator sees the request
// (#435).
func TestMissingSettings_TheTokenEndpointAnswersItsOwn500(t *testing.T) {
	httpHelper := mocks_handlers.NewHttpHelper(t)
	tokenValidator := mocks_handlers.NewTokenValidator(t)

	req := httptest.NewRequest(http.MethodPost, "/auth/token",
		strings.NewReader("grant_type=client_credentials&client_id=test-client&client_secret=secret"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	httpHelper.On("JsonError", rr, req, mock.MatchedBy(isErrNoSettings)).Return().Once()

	HandleTokenPost(httpHelper, mocks_handlers.NewUserSessionManager(t), mocks_data.NewDatabase(t),
		mocks_handlers.NewTokenIssuer(t), tokenValidator, mocks_handlers.NewAuditLogger(t),
		noCredentialFailures{}).ServeHTTP(rr, req)

	httpHelper.AssertExpectations(t)
	tokenValidator.AssertNotCalled(t, "ValidateTokenRequest", mock.Anything, mock.Anything, mock.Anything)
}

// Dynamic client registration keeps RFC 7591 section 3.2.2's envelope for this 500 as for its
// others, and logs the sentinel once.
func TestMissingSettings_DynamicClientRegistrationAnswersTheRFC7591Envelope(t *testing.T) {
	database := mocks_data.NewDatabase(t)

	body, err := json.Marshal(oidc.DynamicClientRegistrationRequest{
		ClientName:   "A Test Client",
		RedirectURIs: []string{"https://client.example.com/callback"},
	})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/connect/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	capture := logtest.CaptureSlog(t)
	HandleDynamicClientRegistrationPost(database,
		mocks_handlers.NewAuditLogger(t), testDataCipher).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	var envelope map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &envelope))
	assert.Equal(t, map[string]any{"error": "server_error", "error_description": "Internal server error"}, envelope)

	records := capture.Records()
	require.Len(t, records, 1)
	assert.Equal(t, "internal server error", records[0].Message)
	logged, isError := records[0].Attrs["error"].(error)
	require.True(t, isError, "the error attribute must carry the error value itself")
	assert.True(t, isErrNoSettings(logged))
	database.AssertNotCalled(t, "RunInTransaction", mock.Anything, mock.Anything)
}
