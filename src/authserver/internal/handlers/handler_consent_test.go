package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	mocks_audit "github.com/leodip/goiabada/authserver/internal/audit/mocks"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	"github.com/leodip/goiabada/core/i18n"
	mocks_test "github.com/leodip/goiabada/core/mocks"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestBuildScopeInfoArray(t *testing.T) {
	t.Run("Empty scope", func(t *testing.T) {
		result := buildScopeInfoArray(context.Background(), "", nil)
		assert.Empty(t, result)
	})

	t.Run("Single ID token scope", func(t *testing.T) {
		result := buildScopeInfoArray(context.Background(), "openid", nil)
		assert.Len(t, result, 1)
		assert.Equal(t, ScopeInfo{
			Scope:            "openid",
			Description:      "Authenticate your user and identify you via a unique ID",
			AlreadyConsented: false,
		}, result[0])
	})

	t.Run("Multiple ID token scopes", func(t *testing.T) {
		result := buildScopeInfoArray(context.Background(), "openid profile email", nil)
		assert.Len(t, result, 3)
		assert.Equal(t, ScopeInfo{
			Scope:            "openid",
			Description:      "Authenticate your user and identify you via a unique ID",
			AlreadyConsented: false,
		}, result[0])
		assert.Equal(t, ScopeInfo{
			Scope:            "profile",
			Description:      "Access to claims: name, family_name, given_name, middle_name, nickname, preferred_username, profile, website, gender, birthdate, zoneinfo, locale, and updated_at",
			AlreadyConsented: false,
		}, result[1])
		assert.Equal(t, ScopeInfo{
			Scope:            "email",
			Description:      "Access to claims: email, email_verified",
			AlreadyConsented: false,
		}, result[2])
	})

	t.Run("Offline access scope", func(t *testing.T) {
		result := buildScopeInfoArray(context.Background(), "openid offline_access", nil)
		assert.Len(t, result, 2)
		assert.Equal(t, ScopeInfo{
			Scope:            "offline_access",
			Description:      "Access to an offline refresh token, allowing the client to obtain a new access token without requiring your immediate interaction",
			AlreadyConsented: false,
		}, result[1])
	})

	t.Run("Custom scope", func(t *testing.T) {
		result := buildScopeInfoArray(context.Background(), "openid custom:read", nil)
		assert.Len(t, result, 2)
		assert.Equal(t, ScopeInfo{
			Scope:            "custom:read",
			Description:      "Permission read on resource custom",
			AlreadyConsented: false,
		}, result[1])
	})

	t.Run("With existing consent", func(t *testing.T) {
		consent := &models.UserConsent{
			Scope: "openid profile",
		}
		result := buildScopeInfoArray(context.Background(), "openid profile email", consent)
		assert.Len(t, result, 3)
		assert.True(t, result[0].AlreadyConsented)
		assert.True(t, result[1].AlreadyConsented)
		assert.False(t, result[2].AlreadyConsented)
	})

	t.Run("Mixed scopes with consent", func(t *testing.T) {
		consent := &models.UserConsent{
			Scope: "openid custom:read",
		}
		result := buildScopeInfoArray(context.Background(), "openid profile custom:read custom:write", consent)
		assert.Len(t, result, 4)
		assert.True(t, result[0].AlreadyConsented)
		assert.False(t, result[1].AlreadyConsented)
		assert.True(t, result[2].AlreadyConsented)
		assert.False(t, result[3].AlreadyConsented)
	})

	// Guards §6.9: consent scope descriptions (OIDC scopes and the
	// resource-permission template) must localize to the active locale, not
	// render hardcoded English.
	t.Run("Localizes descriptions in pt-BR", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/consent", nil)
		req = i18n.RefineLocalizerWithUILocales(req, []string{"pt-BR"})

		result := buildScopeInfoArray(req.Context(), "openid offline_access custom:read", nil)
		assert.Len(t, result, 3)
		assert.Equal(t, "Autenticar seu usuário e identificá-lo por um ID único", result[0].Description)
		assert.Contains(t, result[1].Description, "token de atualização offline")
		assert.Equal(t, "Permissão read no recurso custom", result[2].Description)
	})
}

func TestHandleConsentGet(t *testing.T) {
	t.Run("Error when getting AuthContext", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleConsentGet(httpHelper, authHelper, database)

		req, _ := http.NewRequest("GET", "/auth/consent", nil)
		rr := httptest.NewRecorder()

		expectedError := &customerrors.ErrorDetail{}
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
		database := mocks_data.NewDatabase(t)

		handler := HandleConsentGet(httpHelper, authHelper, database)

		req, _ := http.NewRequest("GET", "/auth/consent", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateInitial,
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "authContext.AuthState is not requires_consent"
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("User not found", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleConsentGet(httpHelper, authHelper, database)

		req, _ := http.NewRequest("GET", "/auth/consent", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateRequiresConsent,
			UserId:    1,
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		database.On("GetUserById", mock.Anything, int64(1)).Return(nil, nil)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "user not found"
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("Client not found", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleConsentGet(httpHelper, authHelper, database)

		req, _ := http.NewRequest("GET", "/auth/consent", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateRequiresConsent,
			UserId:    1,
			ClientId:  "test-client",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		user := &models.User{Id: 1}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(nil, nil)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "client not found"
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("Successful consent page rendering", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleConsentGet(httpHelper, authHelper, database)

		req, _ := http.NewRequest("GET", "/auth/consent", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateRequiresConsent,
			UserId:    1,
			ClientId:  "test-client",
			Scope:     "openid profile email",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		user := &models.User{Id: 1}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			Description:      "Test Client",
			WebsiteURL:       "https://example.com",
			ShowLogo:         true,
			ShowDescription:  true,
			ShowWebsiteURL:   true,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		database.On("GetConsentByUserIdAndClientId", mock.Anything, int64(1), int64(1)).Return(nil, nil)

		database.On("ClientHasLogo", mock.Anything, int64(1)).Return(true, nil)

		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/consent.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			scopes, ok := data["scopes"].([]ScopeInfo)
			return ok && len(scopes) == 3 &&
				data["showClientSection"] == true &&
				data["clientName"] == "test-client" &&
				data["clientDescription"] == "Test Client" &&
				data["clientLogoUrl"] == "/client/logo/test-client" &&
				data["clientWebsiteUrl"] == "https://example.com" &&
				data["hasLogo"] == true
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("Fully consented scopes, redirect to issue", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleConsentGet(httpHelper, authHelper, database)

		req, _ := http.NewRequest("GET", "/auth/consent", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateRequiresConsent,
			UserId:    1,
			ClientId:  "test-client",
			Scope:     "openid profile",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		user := &models.User{Id: 1}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			Description:      "Test Client",
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		consent := &models.UserConsent{
			UserId:   1,
			ClientId: 1,
			Scope:    "openid profile",
		}
		database.On("GetConsentByUserIdAndClientId", mock.Anything, int64(1), int64(1)).Return(consent, nil)

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateReadyToIssueCode
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/issue", rr.Header().Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("Partial consent, render consent page", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleConsentGet(httpHelper, authHelper, database)

		req, _ := http.NewRequest("GET", "/auth/consent", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateRequiresConsent,
			UserId:    1,
			ClientId:  "test-client",
			Scope:     "openid profile email",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		user := &models.User{Id: 1}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			Description:      "Test Client",
			ShowDescription:  true,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		consent := &models.UserConsent{
			UserId:   1,
			ClientId: 1,
			Scope:    "openid profile",
		}
		database.On("GetConsentByUserIdAndClientId", mock.Anything, int64(1), int64(1)).Return(consent, nil)

		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/consent.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			scopes, ok := data["scopes"].([]ScopeInfo)
			return ok && len(scopes) == 3 &&
				data["showClientSection"] == true &&
				data["clientName"] == "test-client" &&
				data["clientDescription"] == "Test Client" &&
				data["hasLogo"] == false &&
				scopes[0].AlreadyConsented && scopes[1].AlreadyConsented && !scopes[2].AlreadyConsented
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})
}

func TestHandleConsentPost(t *testing.T) {
	t.Run("Error when getting AuthContext", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleConsentPost(httpHelper, authHelper, database, nil, auditLogger)

		req, _ := http.NewRequest("POST", "/auth/consent", nil)
		rr := httptest.NewRecorder()

		expectedError := &customerrors.ErrorDetail{}
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
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleConsentPost(httpHelper, authHelper, database, nil, auditLogger)

		req, _ := http.NewRequest("POST", "/auth/consent", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateInitial,
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "authContext.AuthState is not requires_consent"
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("User cancels consent", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleConsentPost(httpHelper, authHelper, database, nil, auditLogger)

		form := url.Values{}
		form.Add("btnCancel", "cancel")
		req, _ := http.NewRequest("POST", "/auth/consent", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateRequiresConsent,
			ResponseMode: "query",
			RedirectURI:  "https://example.com/callback",
			State:        "test-state",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		// The clear has to reach the browser, so it must happen before the response is
		// committed. rr.Header() is the live map the handler and this stub share, so it shows
		// the sentinel under either ordering; rr.Result() reads the snapshot taken when the
		// status line was written, which is the only unit-tier view that tells them apart.
		const clearedContextCookie = "cleared-auth-context"
		authHelper.On("ClearAuthContext", rr, req).Run(func(args mock.Arguments) {
			args.Get(0).(http.ResponseWriter).Header().Set("Set-Cookie", clearedContextCookie)
		}).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Contains(t, rr.Header().Get("Location"), "https://example.com/callback?error=access_denied")

		assert.Equal(t, clearedContextCookie, rr.Result().Header.Get("Set-Cookie"),
			"the auth context must be cleared before the client response is committed")

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("User cancels consent, failing clear - server_error to the client", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleConsentPost(httpHelper, authHelper, database, nil, auditLogger)

		form := url.Values{}
		form.Add("btnCancel", "cancel")
		req, _ := http.NewRequest("POST", "/auth/consent", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateRequiresConsent,
			ResponseMode: "query",
			RedirectURI:  "https://example.com/callback",
			State:        "test-state",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		// A failed clear writes no cookie, so the browser keeps the auth context whatever the
		// handler does next. The client is still owed its error response, and server_error is
		// the code RFC 6749 4.1.2.1 mints for a fault that cannot travel as a 500.
		authHelper.On("ClearAuthContext", rr, req).Return(errors.New("the session store is unreachable"))

		handler.ServeHTTP(rr, req)

		// httpHelper has no InternalServerError expectation, so the mock fails the test if the
		// handler answers with a bare 500 instead of redirecting the client.
		assert.Equal(t, http.StatusFound, rr.Code)
		location := rr.Result().Header.Get("Location")
		assert.Contains(t, location, "error=server_error")
		assert.Contains(t, location, "error_description=Internal+server+error")
		assert.NotContains(t, location, "access_denied")

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("User cancels consent, failing clear and an unusable form_post template - last-resort 500", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		// Deliberately malformed, an unclosed action, so template.ParseFS fails and
		// redirToClientWithError returns "unable to parse template" instead of committing.
		// form_post is the only response mode whose arm can fail after the redirect URI has
		// been validated, so it is how this branch is reached at all.
		templateFS := &mocks_test.TestFS{
			FileContents: map[string]string{
				"form_post.html": `<form action="{{ .redirectURI`,
			},
		}

		handler := HandleConsentPost(httpHelper, authHelper, database, templateFS, auditLogger)

		form := url.Values{}
		form.Add("btnCancel", "cancel")
		req, _ := http.NewRequest("POST", "/auth/consent", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateRequiresConsent,
			ResponseMode: "form_post",
			RedirectURI:  "https://example.com/callback",
			State:        "test-state",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		authHelper.On("ClearAuthContext", rr, req).Return(errors.New("the session store is unreachable"))

		// The clear failed and the server_error response the client is owed cannot be built
		// either, so there is nowhere left to send it and the 500 is the last resort. Without
		// this expectation the handler would answer nothing at all.
		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return strings.Contains(err.Error(), "unable to parse template")
		})).Once()

		handler.ServeHTTP(rr, req)

		// Nothing reached the client: the form_post arm fails before it writes, and the 500 is
		// the mock's, so no redirect is committed.
		assert.Empty(t, rr.Result().Header.Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("User cancels consent, unusable form_post template - 500 when the refusal itself cannot be sent", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		templateFS := &mocks_test.TestFS{
			FileContents: map[string]string{
				"form_post.html": `<form action="{{ .redirectURI`,
			},
		}

		handler := HandleConsentPost(httpHelper, authHelper, database, templateFS, auditLogger)

		form := url.Values{}
		form.Add("btnCancel", "cancel")
		req, _ := http.NewRequest("POST", "/auth/consent", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateRequiresConsent,
			ResponseMode: "form_post",
			RedirectURI:  "https://example.com/callback",
			State:        "test-state",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		// The other half of the same family: here the clear succeeds and it is the ordinary
		// refusal that cannot be committed. This is the site's second and pre-existing 500,
		// pinned separately so a future edit cannot delete either copy unnoticed.
		authHelper.On("ClearAuthContext", rr, req).Return(nil)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return strings.Contains(err.Error(), "unable to parse template")
		})).Once()

		handler.ServeHTTP(rr, req)

		assert.Empty(t, rr.Result().Header.Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("User provides consent", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleConsentPost(httpHelper, authHelper, database, nil, auditLogger)

		form := url.Values{}
		form.Add("btnSubmit", "submit")
		form.Add("consent0", "openid")
		form.Add("consent1", "profile")
		req, _ := http.NewRequest("POST", "/auth/consent", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateRequiresConsent,
			UserId:    1,
			ClientId:  "test-client",
			Scope:     "openid profile email",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		user := &models.User{Id: 1}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		database.On("GetConsentByUserIdAndClientId", mock.Anything, int64(1), int64(1)).Return(nil, nil)

		database.On("CreateUserConsent", mock.Anything, mock.MatchedBy(func(consent *models.UserConsent) bool {
			return consent.UserId == 1 && consent.ClientId == 1 && consent.Scope == "openid profile"
		})).Return(nil)

		auditLogger.On("Log", constants.AuditSavedConsent, mock.Anything).Return()

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateReadyToIssueCode && ac.ConsentedScope == "openid profile"
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/issue", rr.Header().Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("Partial consent given", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleConsentPost(httpHelper, authHelper, database, nil, auditLogger)

		form := url.Values{}
		form.Add("btnSubmit", "submit")
		form.Add("consent0", "openid")
		form.Add("consent1", "profile")
		req, _ := http.NewRequest("POST", "/auth/consent", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateRequiresConsent,
			UserId:    1,
			ClientId:  "test-client",
			Scope:     "openid profile email",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		client := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		user := &models.User{Id: 1}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		existingConsent := &models.UserConsent{
			Id:       1,
			UserId:   1,
			ClientId: 1,
			Scope:    "openid",
		}
		database.On("GetConsentByUserIdAndClientId", mock.Anything, int64(1), int64(1)).Return(existingConsent, nil)

		database.On("UpdateUserConsent", mock.Anything, mock.MatchedBy(func(consent *models.UserConsent) bool {
			return consent.UserId == 1 && consent.ClientId == 1 && consent.Scope == "openid profile"
		})).Return(nil)

		auditLogger.On("Log", constants.AuditSavedConsent, mock.Anything).Return()

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateReadyToIssueCode && ac.ConsentedScope == "openid profile"
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/issue", rr.Header().Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("No consent given", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleConsentPost(httpHelper, authHelper, database, nil, auditLogger)

		form := url.Values{}
		form.Add("btnSubmit", "submit")
		req, _ := http.NewRequest("POST", "/auth/consent", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateRequiresConsent,
			ResponseMode: "query",
			RedirectURI:  "https://example.com/callback",
			State:        "test-state",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		// Same sentinel as the cancel case, for the second refusal in this handler. This one is
		// reached with btnSubmit and no consent boxes ticked rather than with btnCancel.
		const clearedContextCookie = "cleared-auth-context"
		authHelper.On("ClearAuthContext", rr, req).Run(func(args mock.Arguments) {
			args.Get(0).(http.ResponseWriter).Header().Set("Set-Cookie", clearedContextCookie)
		}).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Contains(t, rr.Header().Get("Location"), "https://example.com/callback?error=access_denied")

		assert.Equal(t, clearedContextCookie, rr.Result().Header.Get("Set-Cookie"),
			"the auth context must be cleared before the client response is committed")

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("No consent given, failing clear - server_error to the client", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleConsentPost(httpHelper, authHelper, database, nil, auditLogger)

		form := url.Values{}
		form.Add("btnSubmit", "submit")
		req, _ := http.NewRequest("POST", "/auth/consent", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateRequiresConsent,
			ResponseMode: "query",
			RedirectURI:  "https://example.com/callback",
			State:        "test-state",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		authHelper.On("ClearAuthContext", rr, req).Return(errors.New("the session store is unreachable"))

		handler.ServeHTTP(rr, req)

		// No InternalServerError expectation, so a bare 500 fails the mock instead of passing
		// silently the way it would if the client were simply left unanswered.
		assert.Equal(t, http.StatusFound, rr.Code)
		location := rr.Result().Header.Get("Location")
		assert.Contains(t, location, "error=server_error")
		assert.Contains(t, location, "error_description=Internal+server+error")
		assert.NotContains(t, location, "access_denied")

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("No consent given, failing clear and an unusable form_post template - last-resort 500", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		templateFS := &mocks_test.TestFS{
			FileContents: map[string]string{
				"form_post.html": `<form action="{{ .redirectURI`,
			},
		}

		handler := HandleConsentPost(httpHelper, authHelper, database, templateFS, auditLogger)

		form := url.Values{}
		form.Add("btnSubmit", "submit")
		req, _ := http.NewRequest("POST", "/auth/consent", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateRequiresConsent,
			ResponseMode: "form_post",
			RedirectURI:  "https://example.com/callback",
			State:        "test-state",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		authHelper.On("ClearAuthContext", rr, req).Return(errors.New("the session store is unreachable"))

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return strings.Contains(err.Error(), "unable to parse template")
		})).Once()

		handler.ServeHTTP(rr, req)

		assert.Empty(t, rr.Result().Header.Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("No consent given, unusable form_post template - 500 when the refusal itself cannot be sent", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		templateFS := &mocks_test.TestFS{
			FileContents: map[string]string{
				"form_post.html": `<form action="{{ .redirectURI`,
			},
		}

		handler := HandleConsentPost(httpHelper, authHelper, database, templateFS, auditLogger)

		form := url.Values{}
		form.Add("btnSubmit", "submit")
		req, _ := http.NewRequest("POST", "/auth/consent", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateRequiresConsent,
			ResponseMode: "form_post",
			RedirectURI:  "https://example.com/callback",
			State:        "test-state",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		// The clear succeeds here and the ordinary refusal is what cannot be committed, which
		// is this site's pre-existing 500. It is pinned separately from the last-resort one so
		// a future edit cannot delete either copy unnoticed.
		authHelper.On("ClearAuthContext", rr, req).Return(nil)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return strings.Contains(err.Error(), "unable to parse template")
		})).Once()

		handler.ServeHTTP(rr, req)

		assert.Empty(t, rr.Result().Header.Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})
}
