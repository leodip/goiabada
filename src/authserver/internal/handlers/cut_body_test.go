package handlers

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	mocks_handlers "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// A request body the request-body limit cut short reaches a handler as a failed read, and each
// surface answers it the way it already answers a body it cannot read (#426 decision 6). The
// limit's own boundary through the real root chain is server/body_limit_test.go's; what is claimed
// here is each handler's answer, with the same body read whole under a limit equal to its length
// and refused one byte short of it. The token endpoint's cases are in handler_token_test.go.

// cutBody is body behind a limit of limit bytes, as the root's MiddlewareBodyLimit leaves it.
func cutBody(w http.ResponseWriter, body string, limit int) io.ReadCloser {
	return http.MaxBytesReader(w, io.NopCloser(strings.NewReader(body)), int64(limit))
}

// Dynamic client registration answers RFC 7591 section 3.2.2's 400 invalid_client_metadata.
func TestCutBody_DynamicClientRegistration(t *testing.T) {
	body, err := json.Marshal(oidc.DynamicClientRegistrationRequest{
		ClientName:   "A Test Client",
		RedirectURIs: []string{"https://client.example.com/callback"},
	})
	require.NoError(t, err)

	serve := func(t *testing.T, limit int, database *mocks_data.Database, auditLogger *mocks_handlers.AuditLogger) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/connect/register", nil)
		req.Body = cutBody(rr, string(body), limit)
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(reqctx.WithSettings(req.Context(), &models.Settings{Id: 1, DynamicClientRegistrationEnabled: true}))

		HandleDynamicClientRegistrationPost(database, auditLogger, testDataCipher).ServeHTTP(rr, req)
		return rr
	}

	t.Run("at exactly the limit the client is registered", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)
		mocks_data.ExpectRunInTransaction(database, dcrTx)
		database.On("CreateClient", mock.Anything, dcrTx, mock.Anything).Return(nil).Once()
		database.On("CreateRedirectURI", mock.Anything, dcrTx, mock.Anything).Return(nil).Once()
		auditLogger := mocks_handlers.NewAuditLogger(t)
		auditLogger.On("Log", mock.Anything, audit.AuditDynamicClientRegistration, mock.Anything).Return().Once()

		rr := serve(t, len(body), database, auditLogger)

		assert.Equal(t, http.StatusCreated, rr.Code)
		var response oidc.DynamicClientRegistrationResponse
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &response))
		assert.Equal(t, "A Test Client", response.ClientName)
	})

	t.Run("one byte short it is refused and nothing is written", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)

		rr := serve(t, len(body)-1, database, mocks_handlers.NewAuditLogger(t))

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		var envelope oidc.DynamicClientRegistrationError
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &envelope))
		assert.Equal(t, oidc.DCRErrorInvalidClientMetadata, envelope.Error)
		database.AssertNotCalled(t, "RunInTransaction", mock.Anything, mock.Anything)
		database.AssertNotCalled(t, "CreateClient", mock.Anything, mock.Anything, mock.Anything)
	})
}

// The password form reads its fields with PostFormValue, which swallows the parse error, so a cut
// body reads as a form with every field blank. The blank ceremony id is what answers: the sign-in
// is refused with the ceremony-mismatch page at 400, before any user is looked up or password
// checked, which is how the form already treats a body that names no ceremony.
func TestCutBody_ThePasswordForm(t *testing.T) {
	form := url.Values{}
	form.Add(ceremonyIdField, testCeremonyId)
	form.Add("email", "test@example.com")
	form.Add("password", "the password")
	body := form.Encode()

	serve := func(t *testing.T, limit int, prepare func(pageRenderer *mocks_handlers.PageRenderer,
		auditLogger *mocks_handlers.AuditLogger, database *mocks_data.Database, rr *httptest.ResponseRecorder, req *http.Request)) {
		pageRenderer := mocks_handlers.NewPageRenderer(t)
		authHelper := mocks_handlers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_handlers.NewAuditLogger(t)

		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/auth/pwd", nil)
		req.Body = cutBody(rr, body, limit)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req = req.WithContext(reqctx.WithSettings(req.Context(), &models.Settings{Id: 1}))

		authHelper.On("GetAuthContext", mock.Anything).Return(&ceremony.AuthContext{
			AuthState:  ceremony.AuthStateLevel1Password,
			CeremonyId: testCeremonyId,
			ClientId:   "test-client",
		}, nil).Once()
		prepare(pageRenderer, auditLogger, database, rr, req)

		HandleAuthPwdPost(pageRenderer, authHelper, database, auditLogger, noCredentialFailures{}, testBaseURL, testAdminConsoleBaseURL).ServeHTTP(rr, req)

		pageRenderer.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
		database.AssertExpectations(t)
	}

	t.Run("at exactly the limit the ceremony matches and the sign-in proceeds", func(t *testing.T) {
		serve(t, len(body), func(pageRenderer *mocks_handlers.PageRenderer, _ *mocks_handlers.AuditLogger,
			database *mocks_data.Database, rr *httptest.ResponseRecorder, req *http.Request) {
			// The first read past the ceremony gate. Failing it ends the case there, which is all
			// this side needs to show: the body was read and the gate passed.
			database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").
				Return(nil, assert.AnError).Once()
			pageRenderer.On("InternalServerError", rr, req, mock.Anything).Return().Once()
		})
	})

	t.Run("one byte short the sign-in is refused before any credential is read", func(t *testing.T) {
		serve(t, len(body)-1, func(pageRenderer *mocks_handlers.PageRenderer, auditLogger *mocks_handlers.AuditLogger,
			_ *mocks_data.Database, rr *httptest.ResponseRecorder, req *http.Request) {
			expectCeremonyMismatch(t, pageRenderer, auditLogger, rr, req)
		})
	})
}
