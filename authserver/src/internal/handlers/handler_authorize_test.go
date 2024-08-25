package handlers

import (
	"context"
	"embed"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	mocks_audit "github.com/leodip/goiabada/authserver/internal/audit/mocks"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/authserver/internal/handlers/handlerhelpers/mocks"
	mocks_users "github.com/leodip/goiabada/authserver/internal/users/mocks"
	mocks_validators "github.com/leodip/goiabada/authserver/internal/validators/mocks"

	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/constants"
	"github.com/leodip/goiabada/authserver/internal/customerrors"
	"github.com/leodip/goiabada/authserver/internal/enums"
	"github.com/leodip/goiabada/authserver/internal/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/oauth"
	"github.com/leodip/goiabada/authserver/internal/validators"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestHandleAuthorizeGet(t *testing.T) {
	t.Run("SaveAuthContext gives an error", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_users.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		r := httptest.NewRequest("GET", "/authorize?client_id=test_client&redirect_uri=http://example.com&response_type=code", nil)
		w := httptest.NewRecorder()

		authHelper.On("SaveAuthContext", mock.Anything, mock.Anything, mock.Anything).Return(assert.AnError)
		httpHelper.On("InternalServerError", w, r, assert.AnError).Once()

		HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger)(w, r)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("ValidateClientAndRedirectURI fails with a customerrors.ErrorDetail", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_users.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		r := httptest.NewRequest("GET", "/authorize?client_id=test_client&redirect_uri=http://example.com&response_type=code", nil)
		w := httptest.NewRecorder()

		authHelper.On("SaveAuthContext", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		errorDetail := customerrors.NewErrorDetail("invalid_something", "Invalid something")
		authorizeValidator.On("ValidateClientAndRedirectURI", mock.Anything, mock.Anything).Return(errorDetail)

		httpHelper.On("RenderTemplate", w, r, "/layouts/no_menu_layout.html", "/auth_error.html", mock.Anything).Return(nil)

		HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger)(w, r)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		authorizeValidator.AssertExpectations(t)
	})

	t.Run("ValidateClientAndRedirectURI fails with error", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_users.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		r := httptest.NewRequest("GET", "/authorize?client_id=test_client&redirect_uri=http://example.com&response_type=code", nil)
		w := httptest.NewRecorder()

		authHelper.On("SaveAuthContext", mock.Anything, mock.Anything, mock.Anything).Return(nil)
		authorizeValidator.On("ValidateClientAndRedirectURI", mock.Anything, mock.Anything).Return(assert.AnError)
		httpHelper.On("InternalServerError", w, r, assert.AnError).Once()

		HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger)(w, r)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		authorizeValidator.AssertExpectations(t)
	})

	t.Run("ValidateClientAndRedirectURI fails with a customerrors.ErrorDetail", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_users.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		r := httptest.NewRequest("GET", "/authorize?client_id=test_client&redirect_uri=http://example.com&response_type=code", nil)
		w := httptest.NewRecorder()

		authHelper.On("SaveAuthContext", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		errorDetail := customerrors.NewErrorDetail("invalid_client", "Invalid client")
		authorizeValidator.On("ValidateClientAndRedirectURI", mock.Anything, mock.Anything).Return(errorDetail)

		httpHelper.On("RenderTemplate", w, r, "/layouts/no_menu_layout.html", "/auth_error.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["title"] == "Unable to authorize" && data["error"] == "Invalid client"
		})).Return(nil)

		HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger)(w, r)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		authorizeValidator.AssertExpectations(t)
	})

	t.Run("ValidateClientAndRedirectURI fails with error", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_users.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		r := httptest.NewRequest("GET", "/authorize?client_id=test_client&redirect_uri=http://example.com&response_type=code", nil)
		w := httptest.NewRecorder()

		authHelper.On("SaveAuthContext", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		err := assert.AnError
		authorizeValidator.On("ValidateClientAndRedirectURI", mock.Anything, mock.Anything).Return(err)

		httpHelper.On("InternalServerError", w, r, err).Once()

		HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger)(w, r)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		authorizeValidator.AssertExpectations(t)
	})

	t.Run("ValidateRequest fails with a customerrors.ErrorDetail", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_users.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		r := httptest.NewRequest("GET", "/authorize?client_id=test_client&redirect_uri=http://example.com&response_type=code&code_challenge_method=S256&code_challenge=challenge&state=somestate", nil)
		w := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			ClientId:            "test_client",
			RedirectURI:         "http://example.com",
			ResponseType:        "code",
			CodeChallengeMethod: "S256",
			CodeChallenge:       "challenge",
			State:               "somestate",
		}

		authHelper.On("SaveAuthContext", w, r, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.ClientId == authContext.ClientId &&
				ac.RedirectURI == authContext.RedirectURI &&
				ac.ResponseType == authContext.ResponseType &&
				ac.CodeChallengeMethod == authContext.CodeChallengeMethod &&
				ac.CodeChallenge == authContext.CodeChallenge &&
				ac.State == authContext.State
		})).Return(nil)

		authorizeValidator.On("ValidateClientAndRedirectURI", mock.Anything, &validators.ValidateClientAndRedirectURIInput{
			ClientId:    authContext.ClientId,
			RedirectURI: authContext.RedirectURI,
		}).Return(nil)

		errorDetail := customerrors.NewErrorDetail("invalid_request", "Invalid request")
		authorizeValidator.On("ValidateRequest", mock.Anything, &validators.ValidateRequestInput{
			ResponseType:        authContext.ResponseType,
			CodeChallengeMethod: authContext.CodeChallengeMethod,
			CodeChallenge:       authContext.CodeChallenge,
		}).Return(errorDetail)

		HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger)(w, r)

		assert.Equal(t, http.StatusFound, w.Code)

		location, err := w.Result().Location()
		assert.NoError(t, err)
		assert.NotNil(t, location)

		query := location.Query()
		assert.Equal(t, "invalid_request", query.Get("error"))
		assert.Equal(t, "Invalid request", query.Get("error_description"))
		assert.Equal(t, "somestate", query.Get("state"))

		assert.True(t, strings.HasPrefix(location.String(), "http://example.com"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		authorizeValidator.AssertExpectations(t)
	})

	t.Run("ValidateRequest fails with an error", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_users.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		r := httptest.NewRequest("GET", "/authorize?client_id=test_client&redirect_uri=http://example.com&response_type=code&code_challenge_method=S256&code_challenge=challenge", nil)
		w := httptest.NewRecorder()

		authHelper.On("SaveAuthContext", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		authorizeValidator.On("ValidateClientAndRedirectURI", mock.Anything, mock.MatchedBy(func(input *validators.ValidateClientAndRedirectURIInput) bool {
			return input.ClientId == "test_client" && input.RedirectURI == "http://example.com"
		})).Return(nil)

		err := assert.AnError
		authorizeValidator.On("ValidateRequest", mock.Anything, mock.MatchedBy(func(input *validators.ValidateRequestInput) bool {
			return input.ResponseType == "code" &&
				input.CodeChallengeMethod == "S256" &&
				input.CodeChallenge == "challenge"
		})).Return(err)

		httpHelper.On("InternalServerError", w, r, err).Once()

		HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger)(w, r)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		authorizeValidator.AssertExpectations(t)
	})

	t.Run("ValidateScopes fails with a customerrors.ErrorDetail", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_users.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		authHelper.On("SaveAuthContext", mock.Anything, mock.Anything, mock.Anything).Return(nil)
		authorizeValidator.On("ValidateClientAndRedirectURI", mock.Anything, mock.Anything).Return(nil)
		authorizeValidator.On("ValidateRequest", mock.Anything, mock.Anything).Return(nil)

		expectedError := customerrors.NewErrorDetail("invalid_scope", "The requested scope is invalid")
		authorizeValidator.On("ValidateScopes", mock.Anything, mock.Anything).Return(expectedError)

		req, _ := http.NewRequest("GET", "/auth/authorize?client_id=test&redirect_uri=http://example.com&response_type=code&scope=openid", nil)
		rr := httptest.NewRecorder()

		HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger)(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		location, err := rr.Result().Location()
		assert.NoError(t, err)
		assert.Contains(t, location.String(), "http://example.com?")

		query, err := url.ParseQuery(location.RawQuery)
		assert.NoError(t, err)
		assert.Equal(t, "invalid_scope", query.Get("error"))
		assert.Equal(t, "The requested scope is invalid", query.Get("error_description"))
	})

	t.Run("ValidateScopes fails with error", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_users.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		authHelper.On("SaveAuthContext", mock.Anything, mock.Anything, mock.Anything).Return(nil)
		authorizeValidator.On("ValidateClientAndRedirectURI", mock.Anything, mock.Anything).Return(nil)
		authorizeValidator.On("ValidateRequest", mock.Anything, mock.Anything).Return(nil)
		authorizeValidator.On("ValidateScopes", mock.Anything, mock.Anything).Return(assert.AnError)

		httpHelper.On("InternalServerError", mock.Anything, mock.Anything, assert.AnError).Return()

		req, _ := http.NewRequest("GET", "/auth/authorize?client_id=test&redirect_uri=http://example.com&response_type=code&scope=openid", nil)
		rr := httptest.NewRecorder()

		HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger)(rr, req)

		httpHelper.AssertCalled(t, "InternalServerError", mock.Anything, mock.Anything, assert.AnError)
	})

	t.Run("GetClientByClientIdentifier returns nil", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockUserSessionManager := mocks_users.NewUserSessionManager(t)
		mockDatabase := mocks_data.NewDatabase(t)
		mockAuthorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		mockAuthHelper.On("SaveAuthContext", mock.Anything, mock.Anything, mock.Anything).Return(nil)
		mockAuthorizeValidator.On("ValidateClientAndRedirectURI", mock.Anything, mock.Anything).Return(nil)
		mockAuthorizeValidator.On("ValidateRequest", mock.Anything, mock.Anything).Return(nil)
		mockAuthorizeValidator.On("ValidateScopes", mock.Anything, mock.Anything).Return(nil)
		mockDatabase.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything).Return(&models.UserSession{}, nil)
		mockDatabase.On("UserSessionLoadUser", mock.Anything, mock.Anything).Return(nil)
		mockDatabase.On("GetClientByClientIdentifier", mock.Anything, mock.Anything).Return(nil, nil)

		mockHttpHelper.On("InternalServerError",
			mock.Anything,
			mock.Anything,
			mock.MatchedBy(func(err error) bool { return err.Error() == "client test_client not found" }),
		).Return().Once()

		handler := HandleAuthorizeGet(
			mockHttpHelper,
			mockAuthHelper,
			mockUserSessionManager,
			mockDatabase,
			nil,
			mockAuthorizeValidator,
			mockAuditLogger,
		)

		req, _ := http.NewRequest("GET", "/authorize?client_id=test_client", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("hasValidUserSession and user is disabled", func(t *testing.T) {
		// Setup
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockUserSessionManager := mocks_users.NewUserSessionManager(t)
		mockDatabase := mocks_data.NewDatabase(t)
		mockAuthorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		mockAuthHelper.On("SaveAuthContext", mock.Anything, mock.Anything, mock.Anything).Return(nil)
		mockAuthorizeValidator.On("ValidateClientAndRedirectURI", mock.Anything, mock.Anything).Return(nil)
		mockAuthorizeValidator.On("ValidateRequest", mock.Anything, mock.Anything).Return(nil)
		mockAuthorizeValidator.On("ValidateScopes", mock.Anything, mock.Anything).Return(nil)

		userSession := &models.UserSession{
			User: models.User{
				Id:      1,
				Enabled: false,
			},
		}
		mockDatabase.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything).Return(userSession, nil)
		mockDatabase.On("UserSessionLoadUser", mock.Anything, mock.Anything).Return(nil)
		mockDatabase.On("GetClientByClientIdentifier", mock.Anything, mock.Anything).Return(&models.Client{
			Id:               1,
			ClientIdentifier: "test_client",
			DefaultAcrLevel:  enums.AcrLevel1,
		}, nil)

		mockUserSessionManager.On("HasValidUserSession", mock.Anything, mock.Anything, mock.Anything).Return(true)

		mockAuditLogger.On("Log", constants.AuditUserDisabled, mock.Anything).Return()

		templateFS := embed.FS{}

		handler := HandleAuthorizeGet(
			mockHttpHelper,
			mockAuthHelper,
			mockUserSessionManager,
			mockDatabase,
			templateFS,
			mockAuthorizeValidator,
			mockAuditLogger,
		)

		req, _ := http.NewRequest("GET", "/authorize?client_id=test_client&redirect_uri=http://example.com&response_type=code", nil)
		req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeySessionIdentifier, "test_session"))
		rr := httptest.NewRecorder()

		// Act
		handler.ServeHTTP(rr, req)

		// Assert
		assert.Equal(t, http.StatusFound, rr.Code)
		location := rr.Header().Get("Location")
		assert.Contains(t, location, "error=access_denied")
		assert.Contains(t, location, "error_description=The+user+account+is+disabled.")
		mockAuditLogger.AssertCalled(t, "Log", constants.AuditUserDisabled, mock.Anything)
	})

	t.Run("hasValidUserSession and requires OTP auth, SaveAuthContext errors", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockUserSessionManager := mocks_users.NewUserSessionManager(t)
		mockDatabase := mocks_data.NewDatabase(t)
		mockAuthorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		req, _ := http.NewRequest("GET", "/authorize?client_id=test_client&redirect_uri=http://example.com&response_type=code", nil)
		rr := httptest.NewRecorder()

		userSession := &models.UserSession{
			User: models.User{Id: 123, Enabled: true},
		}
		client := &models.Client{Id: 456, DefaultAcrLevel: enums.AcrLevel1}

		mockAuthHelper.On("SaveAuthContext", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
		mockAuthorizeValidator.On("ValidateClientAndRedirectURI", mock.Anything, mock.Anything).Return(nil)
		mockAuthorizeValidator.On("ValidateRequest", mock.Anything, mock.Anything).Return(nil)
		mockAuthorizeValidator.On("ValidateScopes", mock.Anything, mock.Anything).Return(nil)
		mockDatabase.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything).Return(userSession, nil)
		mockDatabase.On("UserSessionLoadUser", mock.Anything, mock.Anything).Return(nil)
		mockDatabase.On("GetClientByClientIdentifier", mock.Anything, mock.Anything).Return(client, nil)
		mockUserSessionManager.On("HasValidUserSession", mock.Anything, mock.Anything, mock.Anything).Return(true)
		mockUserSessionManager.On("RequiresOTPAuth", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true)
		mockAuthHelper.On("SaveAuthContext", mock.Anything, mock.Anything, mock.Anything).Return(customerrors.NewErrorDetailWithHttpStatusCode("internal_server_error", "Failed to save auth context", http.StatusInternalServerError))
		mockHttpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything)

		HandleAuthorizeGet(mockHttpHelper, mockAuthHelper, mockUserSessionManager, mockDatabase, nil, mockAuthorizeValidator, mockAuditLogger)(rr, req)

		mockHttpHelper.AssertExpectations(t)
		mockAuthHelper.AssertExpectations(t)
		mockUserSessionManager.AssertExpectations(t)
		mockDatabase.AssertExpectations(t)
		mockAuthorizeValidator.AssertExpectations(t)
	})

	t.Run("hasValidUserSession and requires OTP auth, redirect to OTP", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockUserSessionManager := mocks_users.NewUserSessionManager(t)
		mockDatabase := mocks_data.NewDatabase(t)
		mockAuthorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		req, _ := http.NewRequest("GET", "/authorize?client_id=test_client&redirect_uri=http://example.com&response_type=code", nil)
		rr := httptest.NewRecorder()

		userSession := &models.UserSession{
			User: models.User{Id: 123, Enabled: true},
		}
		client := &models.Client{Id: 456, DefaultAcrLevel: enums.AcrLevel1}

		mockAuthHelper.On("SaveAuthContext", mock.Anything, mock.Anything, mock.Anything).Return(nil).Twice()
		mockAuthorizeValidator.On("ValidateClientAndRedirectURI", mock.Anything, mock.Anything).Return(nil)
		mockAuthorizeValidator.On("ValidateRequest", mock.Anything, mock.Anything).Return(nil)
		mockAuthorizeValidator.On("ValidateScopes", mock.Anything, mock.Anything).Return(nil)
		mockDatabase.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything).Return(userSession, nil)
		mockDatabase.On("UserSessionLoadUser", mock.Anything, mock.Anything).Return(nil)
		mockDatabase.On("GetClientByClientIdentifier", mock.Anything, mock.Anything).Return(client, nil)
		mockUserSessionManager.On("HasValidUserSession", mock.Anything, mock.Anything, mock.Anything).Return(true)
		mockUserSessionManager.On("RequiresOTPAuth", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true)

		HandleAuthorizeGet(mockHttpHelper, mockAuthHelper, mockUserSessionManager, mockDatabase, nil, mockAuthorizeValidator, mockAuditLogger)(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.True(t, strings.HasSuffix(rr.Header().Get("Location"), "/auth/otp"))
		mockHttpHelper.AssertExpectations(t)
		mockAuthHelper.AssertExpectations(t)
		mockUserSessionManager.AssertExpectations(t)
		mockDatabase.AssertExpectations(t)
		mockAuthorizeValidator.AssertExpectations(t)
	})

	t.Run("no valid session and SaveAuthContext errors", func(t *testing.T) {
		// Setup
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_users.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		authHelper.On("SaveAuthContext", mock.Anything, mock.Anything, mock.Anything).Return(customerrors.NewErrorDetailWithHttpStatusCode("internal_server_error", "Failed to save auth context", http.StatusInternalServerError))

		httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.AnythingOfType("*customerrors.ErrorDetail")).Return()

		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger)

		req := httptest.NewRequest("GET", "/authorize?client_id=test_client&redirect_uri=http://example.com&response_type=code", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		httpHelper.AssertCalled(t, "InternalServerError", w, req, mock.AnythingOfType("*customerrors.ErrorDetail"))
		authHelper.AssertCalled(t, "SaveAuthContext", w, req, mock.AnythingOfType("*oauth.AuthContext"))
	})

	t.Run("no valid session and redirects to pwd auth", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_users.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		authHelper.On("SaveAuthContext", mock.Anything, mock.Anything, mock.Anything).Return(nil)
		authorizeValidator.On("ValidateClientAndRedirectURI", mock.Anything, mock.Anything).Return(nil)
		authorizeValidator.On("ValidateRequest", mock.Anything, mock.Anything).Return(nil)
		authorizeValidator.On("ValidateScopes", mock.Anything, mock.Anything).Return(nil)

		database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything).Return(nil, nil)
		database.On("UserSessionLoadUser", mock.Anything, mock.Anything).Return(nil)
		database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything).Return(&models.Client{
			Id:              1,
			DefaultAcrLevel: "urn:goiabada:pwd",
		}, nil)

		userSessionManager.On("HasValidUserSession", mock.Anything, mock.Anything, mock.Anything).Return(false)

		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger)

		req := httptest.NewRequest("GET", "/authorize?client_id=test_client&redirect_uri=http://example.com&response_type=code", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusFound, w.Code)
		assert.True(t, strings.HasSuffix(w.Header().Get("Location"), "/auth/pwd"))

		authHelper.AssertExpectations(t)
		authorizeValidator.AssertExpectations(t)
		database.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
	})

	t.Run("no further authentication is needed, BumpUserSession errors", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_users.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		validUserSession := &models.UserSession{
			Id:                1,
			UserId:            1,
			SessionIdentifier: "valid-session-id",
			AuthTime:          time.Now(),
			AcrLevel:          "urn:goiabada:pwd",
			User:              models.User{Id: 1, Enabled: true},
		}

		authHelper.On("SaveAuthContext", mock.Anything, mock.Anything, mock.Anything).Return(nil)
		authorizeValidator.On("ValidateClientAndRedirectURI", mock.Anything, mock.Anything).Return(nil)
		authorizeValidator.On("ValidateRequest", mock.Anything, mock.Anything).Return(nil)
		authorizeValidator.On("ValidateScopes", mock.Anything, mock.Anything).Return(nil)

		database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything).Return(validUserSession, nil)
		database.On("UserSessionLoadUser", mock.Anything, validUserSession).Return(nil)
		database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything).Return(&models.Client{
			Id:              1,
			DefaultAcrLevel: "urn:goiabada:pwd",
		}, nil)

		userSessionManager.On("HasValidUserSession", mock.Anything, validUserSession, mock.Anything).Return(true)
		userSessionManager.On("RequiresOTPAuth", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(false)
		userSessionManager.On("BumpUserSession", mock.Anything, "valid-session-id", mock.Anything).Return(nil, customerrors.NewErrorDetailWithHttpStatusCode("internal_server_error", "Failed to bump user session", http.StatusInternalServerError))

		httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.AnythingOfType("*customerrors.ErrorDetail")).Return()

		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger)

		req := httptest.NewRequest("GET", "/authorize?client_id=test_client&redirect_uri=http://example.com&response_type=code", nil)
		w := httptest.NewRecorder()

		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySessionIdentifier, "valid-session-id")
		req = req.WithContext(ctx)

		handler.ServeHTTP(w, req)

		httpHelper.AssertCalled(t, "InternalServerError", w, req, mock.AnythingOfType("*customerrors.ErrorDetail"))

		authHelper.AssertExpectations(t)
		authorizeValidator.AssertExpectations(t)
		database.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
		httpHelper.AssertExpectations(t)
	})

	t.Run("Redirect to consent", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		userSessionManager := mocks_users.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		authorizeValidator := mocks_validators.NewAuthorizeValidator(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		validUserSession := &models.UserSession{
			Id:                1,
			UserId:            1,
			SessionIdentifier: "valid-session-id",
			AuthTime:          time.Now(),
			AcrLevel:          "urn:goiabada:pwd",
			AuthMethods:       "pwd",
			User:              models.User{Id: 1, Enabled: true},
		}

		client := &models.Client{
			Id:              1,
			DefaultAcrLevel: "urn:goiabada:pwd",
		}

		authHelper.On("SaveAuthContext", mock.Anything, mock.Anything, mock.Anything).Return(nil)
		authorizeValidator.On("ValidateClientAndRedirectURI", mock.Anything, mock.Anything).Return(nil)
		authorizeValidator.On("ValidateRequest", mock.Anything, mock.Anything).Return(nil)
		authorizeValidator.On("ValidateScopes", mock.Anything, mock.Anything).Return(nil)

		database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything).Return(validUserSession, nil)
		database.On("UserSessionLoadUser", mock.Anything, validUserSession).Return(nil)
		database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything).Return(client, nil)

		userSessionManager.On("HasValidUserSession", mock.Anything, validUserSession, mock.Anything).Return(true)
		userSessionManager.On("RequiresOTPAuth", mock.Anything, client, validUserSession, mock.Anything).Return(false)
		userSessionManager.On("BumpUserSession", mock.Anything, "valid-session-id", mock.Anything).Return(validUserSession, nil)

		auditLogger.On("Log", mock.Anything, mock.Anything).Return()

		config.AuthServerBaseUrl = "http://localhost:8080"

		handler := HandleAuthorizeGet(httpHelper, authHelper, userSessionManager, database, nil, authorizeValidator, auditLogger)

		req := httptest.NewRequest("GET", "/authorize?client_id=test_client&redirect_uri=http://example.com&response_type=code", nil)
		w := httptest.NewRecorder()

		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySessionIdentifier, "valid-session-id")
		req = req.WithContext(ctx)

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusFound, w.Code)
		assert.Equal(t, "http://localhost:8080/auth/consent", w.Header().Get("Location"))

		authHelper.AssertExpectations(t)
		authorizeValidator.AssertExpectations(t)
		database.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})
}

func TestRedirToClientWithError(t *testing.T) {
	testFS := &mocks.TestFS{
		FileContents: map[string]string{
			"form_post.html": `<form method="post" action="{{.redirectURI}}">
				<input type="hidden" name="error" value="{{.error}}">
				<input type="hidden" name="error_description" value="{{.error_description}}">
				{{if .state}}<input type="hidden" name="state" value="{{.state}}">{{end}}
				<noscript><button type="submit">Submit</button></noscript>
			</form>`,
		},
	}

	t.Run("fragment response mode", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/authorize", nil)
		err := redirToClientWithError(w, r, testFS, "error_code", "Error description", "fragment", "http://example.com/callback", "state123")

		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, w.Code)
		assert.Equal(t, "http://example.com/callback#error=error_code&error_description=Error+description&state=state123", w.Header().Get("Location"))
	})

	t.Run("fragment response mode without state", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/authorize", nil)
		err := redirToClientWithError(w, r, testFS, "error_code", "Error description", "fragment", "http://example.com/callback", "")

		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, w.Code)
		assert.Equal(t, "http://example.com/callback#error=error_code&error_description=Error+description", w.Header().Get("Location"))
	})

	t.Run("form_post response mode", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/authorize", nil)
		err := redirToClientWithError(w, r, testFS, "error_code", "Error description", "form_post", "http://example.com/callback", "state123")

		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "<form method=\"post\" action=\"http://example.com/callback\">")
		assert.Contains(t, w.Body.String(), "<input type=\"hidden\" name=\"error\" value=\"error_code\">")
		assert.Contains(t, w.Body.String(), "<input type=\"hidden\" name=\"error_description\" value=\"Error description\">")
		assert.Contains(t, w.Body.String(), "<input type=\"hidden\" name=\"state\" value=\"state123\">")
	})

	t.Run("form_post response mode without state", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/authorize", nil)
		err := redirToClientWithError(w, r, testFS, "error_code", "Error description", "form_post", "http://example.com/callback", "")

		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "<form method=\"post\" action=\"http://example.com/callback\">")
		assert.Contains(t, w.Body.String(), "<input type=\"hidden\" name=\"error\" value=\"error_code\">")
		assert.Contains(t, w.Body.String(), "<input type=\"hidden\" name=\"error_description\" value=\"Error description\">")
		assert.NotContains(t, w.Body.String(), "<input type=\"hidden\" name=\"state\" value=\"\">")
	})

	t.Run("form_post response mode with template parsing error", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/authorize", nil)
		emptyFS := &mocks.TestFS{FileContents: map[string]string{}}
		err := redirToClientWithError(w, r, emptyFS, "error_code", "Error description", "form_post", "http://example.com/callback", "state123")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unable to parse template")
	})

	t.Run("query response mode (default)", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/authorize", nil)
		err := redirToClientWithError(w, r, testFS, "error_code", "Error description", "query", "http://example.com/callback", "state123")

		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, w.Code)
		assert.Equal(t, "http://example.com/callback?error=error_code&error_description=Error+description&state=state123", w.Header().Get("Location"))
	})

	t.Run("query response mode without state", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/authorize", nil)
		err := redirToClientWithError(w, r, testFS, "error_code", "Error description", "query", "http://example.com/callback", "")

		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, w.Code)
		assert.Equal(t, "http://example.com/callback?error=error_code&error_description=Error+description", w.Header().Get("Location"))
	})

	t.Run("query response mode with existing query parameters", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/authorize", nil)
		err := redirToClientWithError(w, r, testFS, "error_code", "Error description", "query", "http://example.com/callback?existing=param", "state123")
		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, w.Code)

		locationHeader := w.Header().Get("Location")
		locationURL, err := url.Parse(locationHeader)
		require.NoError(t, err)

		query := locationURL.Query()
		assert.Equal(t, "param", query.Get("existing"))
		assert.Equal(t, "error_code", query.Get("error"))
		assert.Equal(t, "Error description", query.Get("error_description"))
		assert.Equal(t, "state123", query.Get("state"))
		assert.Equal(t, "http://example.com/callback", locationURL.Scheme+"://"+locationURL.Host+locationURL.Path)
	})
}
