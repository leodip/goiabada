package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_audit "github.com/leodip/goiabada/core/audit/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	mocks_test "github.com/leodip/goiabada/core/mocks"
	mocks_oauth "github.com/leodip/goiabada/core/oauth/mocks"
)

func TestHandleIssueGet(t *testing.T) {
	t.Run("Error when getting GetAuthContext", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		templateFS := &mocks_test.TestFS{}
		codeIssuer := mocks_oauth.NewCodeIssuer(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleIssueGet(httpHelper, authHelper, templateFS, codeIssuer, auditLogger)

		req, err := http.NewRequest("GET", "/auth/issue", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		expectedError := &customerrors.ErrorDetail{} // Create an appropriate error
		authHelper.On("GetAuthContext", mock.Anything).Return(nil, expectedError)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err == expectedError
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("Unexpected AuthState", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		templateFS := &mocks_test.TestFS{}
		codeIssuer := mocks_oauth.NewCodeIssuer(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleIssueGet(httpHelper, authHelper, templateFS, codeIssuer, auditLogger)

		req, err := http.NewRequest("GET", "/auth/issue", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateInitial, // Unexpected state
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "authContext.AuthState is not ready_to_issue_code"
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("Successfully issues a code", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		templateFS := &mocks_test.TestFS{}
		codeIssuer := mocks_oauth.NewCodeIssuer(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleIssueGet(httpHelper, authHelper, templateFS, codeIssuer, auditLogger)

		req, err := http.NewRequest("GET", "/auth/issue", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		// Mock auth context
		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateReadyToIssueCode,
			ClientId:     "test-client",
			UserId:       123,
			ResponseMode: "query",
			RedirectURI:  "https://example.com/callback",
		}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		// Mock code creation
		mockCode := &models.Code{
			Id:          1,
			Code:        "test-code",
			ClientId:    1,
			RedirectURI: "https://example.com/callback",
			State:       "test-state",
		}
		codeIssuer.On("CreateAuthCode", mock.MatchedBy(func(input *oauth.CreateCodeInput) bool {
			return input.AuthContext == *authContext
		})).Return(mockCode, nil)

		// Mock audit logging
		auditLogger.On("Log", constants.AuditCreatedAuthCode, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["userId"] == int64(123) && details["clientId"] == int64(1) && details["codeId"] == int64(1)
		})).Return()

		// Mock clearing auth context
		authHelper.On("ClearAuthContext", rr, req).Return(nil)

		// Execute the handler
		handler.ServeHTTP(rr, req)

		// Assertions
		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, "https://example.com/callback?code=test-code&state=test-state", rr.Header().Get("Location"))

		// Verify that all expected actions were performed
		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		codeIssuer.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})
}

func TestIssueAuthCode(t *testing.T) {
	t.Run("Query response mode", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/auth/issue", nil)
		code := &models.Code{
			Code:        "test_code",
			RedirectURI: "https://example.com/callback",
			State:       "test_state",
		}

		err := issueAuthCode(w, r, nil, code, "query")

		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, w.Code)
		assert.Equal(t, "https://example.com/callback?code=test_code&state=test_state", w.Header().Get("Location"))
	})

	t.Run("Fragment response mode", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/auth/issue", nil)
		code := &models.Code{
			Code:        "test_code",
			RedirectURI: "https://example.com/callback",
			State:       "test_state",
		}

		err := issueAuthCode(w, r, nil, code, "fragment")

		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, w.Code)
		assert.Equal(t, "https://example.com/callback#code=test_code&state=test_state", w.Header().Get("Location"))
	})

	t.Run("Form post response mode", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/auth/issue", nil)
		code := &models.Code{
			Code:        "test_code",
			RedirectURI: "https://example.com/callback",
			State:       "test_state",
		}

		templateFS := &mocks_test.TestFS{
			FileContents: map[string]string{
				"form_post.html": `<form method="post" action="{{.redirectURI}}">
					<input type="hidden" name="code" value="{{.code}}">
					<input type="hidden" name="state" value="{{.state}}">
				</form>`,
			},
		}

		err := issueAuthCode(w, r, templateFS, code, "form_post")

		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), `<form method="post" action="https://example.com/callback">`)
		assert.Contains(t, w.Body.String(), `<input type="hidden" name="code" value="test_code">`)
		assert.Contains(t, w.Body.String(), `<input type="hidden" name="state" value="test_state">`)
	})

	t.Run("Default to query response mode", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/auth/issue", nil)
		code := &models.Code{
			Code:        "test_code",
			RedirectURI: "https://example.com/callback",
			State:       "test_state",
		}

		err := issueAuthCode(w, r, nil, code, "")

		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, w.Code)
		assert.Equal(t, "https://example.com/callback?code=test_code&state=test_state", w.Header().Get("Location"))
	})

	t.Run("Error parsing template", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/auth/issue", nil)
		code := &models.Code{
			Code:        "test_code",
			RedirectURI: "https://example.com/callback",
			State:       "test_state",
		}

		templateFS := &mocks_test.TestFS{
			FileContents: map[string]string{
				"form_post.html": `{{.InvalidTemplate`,
			},
		}

		err := issueAuthCode(w, r, templateFS, code, "form_post")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unable to parse template")
	})
}
