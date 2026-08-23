package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_audit "github.com/leodip/goiabada/authserver/internal/audit/mocks"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
)

func TestHandleAuthPwdGet(t *testing.T) {
	t.Run("Error when getting GetAuthContext", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleAuthPwdGet(httpHelper, authHelper, database)

		req, err := http.NewRequest("GET", "/auth/pwd", nil)
		assert.NoError(t, err)

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

		handler := HandleAuthPwdGet(httpHelper, authHelper, database)

		req, err := http.NewRequest("GET", "/auth/pwd", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateInitial,
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "authContext.AuthState is not level1_password"
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("Successful rendering with email from user session", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleAuthPwdGet(httpHelper, authHelper, database)

		req, err := http.NewRequest("GET", "/auth/pwd", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:  oauth.AuthStateLevel1Password,
			CeremonyId: testCeremonyId,
			ClientId:   "my-app",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		sessionIdentifier := "test-session"
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySessionIdentifier, sessionIdentifier)
		req = req.WithContext(ctx)

		userSession := &models.UserSession{
			Id: 1,
			User: models.User{
				Email: "test@example.com",
			},
		}
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(userSession, nil)

		client := &models.Client{
			ClientIdentifier: "my-app",
			DisplayName:      "",
			ShowLogo:         false,
			ShowDisplayName:  false,
			ShowDescription:  false,
			ShowWebsiteURL:   false,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "my-app").Return(client, nil)

		settings := &models.Settings{
			SMTPEnabled: true,
		}
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_pwd.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["email"] == "test@example.com" && data["smtpEnabled"] == true &&
				data["layoutShowClientSection"] == true &&
				data["layoutClientName"] == "my-app" && data["layoutHasClientLogo"] == false &&
				data["layoutClientLogoUrl"] == "" && data["layoutClientDescription"] == "" &&
				data["layoutClientWebsiteUrl"] == ""
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("Successful rendering without email", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleAuthPwdGet(httpHelper, authHelper, database)

		req, err := http.NewRequest("GET", "/auth/pwd", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateLevel1Password,
			ClientId:  "another-app",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		client := &models.Client{
			ClientIdentifier: "another-app",
			DisplayName:      "",
			ShowLogo:         false,
			ShowDisplayName:  false,
			ShowDescription:  false,
			ShowWebsiteURL:   false,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "another-app").Return(client, nil)

		settings := &models.Settings{
			SMTPEnabled: false,
		}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_pwd.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			_, hasEmail := data["email"]
			return !hasEmail && data["smtpEnabled"] == false &&
				data["layoutShowClientSection"] == true &&
				data["layoutClientName"] == "another-app" && data["layoutHasClientLogo"] == false &&
				data["layoutClientLogoUrl"] == "" && data["layoutClientDescription"] == "" &&
				data["layoutClientWebsiteUrl"] == ""
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	// The rendered form has to name the ceremony it was rendered for, or every submission of it is
	// refused by HandleAuthPwdPost. Asserted as an equality rather than as "not empty", because the
	// value has to be THIS ceremony's (#79 seam 4).
	t.Run("The render names the ceremony", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleAuthPwdGet(httpHelper, authHelper, database)

		req, err := http.NewRequest("GET", "/auth/pwd", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:  oauth.AuthStateLevel1Password,
			CeremonyId: testCeremonyId,
			ClientId:   "my-app",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		database.On("GetClientByClientIdentifier", mock.Anything, "my-app").
			Return(&models.Client{ClientIdentifier: "my-app"}, nil)

		ctx := context.WithValue(req.Context(), constants.ContextKeySettings, &models.Settings{})
		req = req.WithContext(ctx)

		var rendered map[string]interface{}
		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_pwd.html",
			mock.MatchedBy(func(data map[string]interface{}) bool {
				rendered = data
				return true
			})).Return(nil)

		handler.ServeHTTP(rr, req)

		if assert.NotNil(t, rendered) {
			assert.Equal(t, testCeremonyId, rendered["ceremonyId"])
		}

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})
}

func TestHandleAuthPwdPost(t *testing.T) {
	t.Run("Error when getting AuthContext", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthPwdPost(httpHelper, authHelper, database, auditLogger, noCredentialFailures{})

		req, _ := http.NewRequest("POST", "/auth/pwd", nil)
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

		handler := HandleAuthPwdPost(httpHelper, authHelper, database, auditLogger, noCredentialFailures{})

		// The ceremony matches, so the state check is what answers. Without an id in the body the
		// submission would be refused one gate earlier and this case would stop proving anything.
		form := url.Values{}
		form.Add(ceremonyIdField, testCeremonyId)
		req, _ := http.NewRequest("POST", "/auth/pwd", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:  oauth.AuthStateInitial,
			CeremonyId: testCeremonyId,
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "authContext.AuthState is not level1_password"
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	// A login form left open in another tab, submitted after a second /auth/authorize replaced the
	// ceremony it was rendered for. Every one of these is the mismatch page at 400.
	//
	// Every case carries a real email and the correct password, and the database mock is given NO
	// expectations at all. That is the assertion that matters here and it is why the credentials are
	// correct: if the check ever moved below GetUserByEmail or VerifyPasswordHash, the mock would be
	// called and the test would fail. A stale form must not authenticate anybody for anything, and
	// with a client requiring no consent the authorization it would finish is one the user never saw
	// a screen for (#79 decisions 5 and 6).
	t.Run("Stale ceremony", func(t *testing.T) {
		const password = "testpassword"

		staleCases := []struct {
			name string
			// stored is the id the browser's current auth context holds.
			stored string
			// submitted is what the stale page posts; the empty string means the field is absent.
			submitted string
			// inQuery puts submitted in the URL query instead of the body.
			inQuery   bool
			authState string
		}{
			{
				// The defect's own shape: the password screen of the request that was replaced.
				name: "a different ceremony's id", stored: testCeremonyId,
				submitted: "another-ceremony-0123456789abcde",
				authState: oauth.AuthStateLevel1Password,
			},
			{
				// A hand-built body, or a template that lost the hidden input.
				name: "no ceremony field at all", stored: testCeremonyId,
				submitted: "", authState: oauth.AuthStateLevel1Password,
			},
			{
				// The upgrade case: an auth context written before this change carries no id, so
				// the ceremony is refused once and the user starts again. Refused rather than
				// matched against an empty submission, which is the fail-closed direction.
				name: "an auth context from before the ceremony id existed", stored: "",
				submitted: "", authState: oauth.AuthStateLevel1Password,
			},
			{
				// The check runs before the AuthState check, so the replaced ceremony's state
				// produces the 400 mismatch page rather than a 500 naming an internal invariant.
				name: "a replaced ceremony that has moved on", stored: testCeremonyId,
				submitted: "another-ceremony-0123456789abcde",
				authState: oauth.AuthStateRequiresConsent,
			},
			{
				// The id has to come from the body. This form posts to action="", so reading it
				// with r.FormValue would let /auth/pwd?ceremonyId=... supply an id the submission
				// never carried, and a page rendered for no ceremony at all would pass the gate
				// (#79).
				name: "the current id in the query alone", stored: testCeremonyId,
				submitted: testCeremonyId, inQuery: true,
				authState: oauth.AuthStateLevel1Password,
			},
		}

		for _, tc := range staleCases {
			t.Run(tc.name, func(t *testing.T) {
				httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
				authHelper := mocks_handlerhelpers.NewAuthHelper(t)
				database := mocks_data.NewDatabase(t)
				auditLogger := mocks_audit.NewAuditLogger(t)

				handler := HandleAuthPwdPost(httpHelper, authHelper, database, auditLogger, noCredentialFailures{})

				form := url.Values{}
				form.Add("email", "test@example.com")
				form.Add("password", password)
				target := "/auth/pwd"
				if tc.submitted != "" {
					if tc.inQuery {
						target += "?" + url.Values{ceremonyIdField: {tc.submitted}}.Encode()
					} else {
						form.Add(ceremonyIdField, tc.submitted)
					}
				}
				req, _ := http.NewRequest("POST", target, strings.NewReader(form.Encode()))
				req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
				rr := httptest.NewRecorder()

				authContext := &oauth.AuthContext{
					AuthState:  tc.authState,
					CeremonyId: tc.stored,
					ClientId:   "test-client",
				}
				authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

				expectCeremonyMismatch(t, httpHelper, auditLogger, rr, req)

				handler.ServeHTTP(rr, req)

				// Nothing was saved and nowhere was redirected to: the auth context is untouched,
				// so the ceremony the user is actually on is still theirs to finish.
				assert.Empty(t, rr.Header().Get("Location"))

				httpHelper.AssertExpectations(t)
				authHelper.AssertExpectations(t)
				database.AssertExpectations(t)
				auditLogger.AssertExpectations(t)
			})
		}
	})

	t.Run("Missing email", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthPwdPost(httpHelper, authHelper, database, auditLogger, noCredentialFailures{})

		form := url.Values{}
		form.Add(ceremonyIdField, testCeremonyId)
		form.Add("password", "testpassword")
		req, _ := http.NewRequest("POST", "/auth/pwd", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:  oauth.AuthStateLevel1Password,
			CeremonyId: testCeremonyId,
			ClientId:   "my-app",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		client := &models.Client{
			ClientIdentifier: "my-app",
			DisplayName:      "",
			ShowLogo:         false,
			ShowDisplayName:  false,
			ShowDescription:  false,
			ShowWebsiteURL:   false,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "my-app").Return(client, nil)

		settings := &models.Settings{
			SMTPEnabled: true,
		}
		ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_pwd.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == "Email is required." &&
				data["layoutShowClientSection"] == true &&
				data["layoutClientName"] == "my-app" && data["layoutHasClientLogo"] == false
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("Missing password", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthPwdPost(httpHelper, authHelper, database, auditLogger, noCredentialFailures{})

		form := url.Values{}
		form.Add(ceremonyIdField, testCeremonyId)
		form.Add("email", "test@example.com")
		req, _ := http.NewRequest("POST", "/auth/pwd", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:  oauth.AuthStateLevel1Password,
			CeremonyId: testCeremonyId,
			ClientId:   "test-client",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		client := &models.Client{
			ClientIdentifier: "test-client",
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		settings := &models.Settings{
			SMTPEnabled: true,
		}
		ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		// The validation-error re-render is a path no happy-path case sees, and it has to carry the
		// ceremony id: without it a single mistyped password would end the ceremony, because the
		// retry would name no ceremony and be refused (#79 seam 4).
		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_pwd.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == "Password is required." &&
				data["ceremonyId"] == testCeremonyId
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	// Identical to "Missing password" except the password rides in the target's query rather
	// than the body, and it must behave the same way. r.FormValue would merge the query behind
	// the body and authenticate on it, putting the password in the browser's history, in the
	// Referer of anything the page loads, and in every proxy log in front of the deployment
	// (#202).
	//
	// mocks_data.NewDatabase(t) is given GetClientByClientIdentifier and nothing else, so a
	// GetUserByEmail or VerifyPasswordHash call fails the test on an unexpected call. That
	// absence is the assertion that no credential check ran.
	t.Run("Password in the query alone", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthPwdPost(httpHelper, authHelper, database, auditLogger, noCredentialFailures{})

		form := url.Values{}
		form.Add(ceremonyIdField, testCeremonyId)
		form.Add("email", "test@example.com")
		target := "/auth/pwd?" + url.Values{"password": {"testpassword"}}.Encode()
		req, _ := http.NewRequest("POST", target, strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:  oauth.AuthStateLevel1Password,
			CeremonyId: testCeremonyId,
			ClientId:   "test-client",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		client := &models.Client{
			ClientIdentifier: "test-client",
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		settings := &models.Settings{
			SMTPEnabled: true,
		}
		ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_pwd.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == "Password is required." &&
				data["ceremonyId"] == testCeremonyId
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("User not found", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthPwdPost(httpHelper, authHelper, database, auditLogger, noCredentialFailures{})

		form := url.Values{}
		form.Add(ceremonyIdField, testCeremonyId)
		form.Add("email", "test@example.com")
		form.Add("password", "testpassword")
		req, _ := http.NewRequest("POST", "/auth/pwd", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:  oauth.AuthStateLevel1Password,
			CeremonyId: testCeremonyId,
			ClientId:   "test-client",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		client := &models.Client{
			ClientIdentifier: "test-client",
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		settings := &models.Settings{
			SMTPEnabled: true,
		}
		ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		database.On("GetUserByEmail", mock.Anything, "test@example.com").Return(nil, nil)

		auditLogger.On("Log", constants.AuditAuthFailedPwd, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["email"] == "test@example.com"
		})).Return()

		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_pwd.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == "Authentication failed."
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	// The rate limiter keys its per-account tier on strings.ToLower(strings.TrimSpace(email)),
	// so the lookup has to agree or the middleware and the handler disagree about which
	// account a request is and a case variant buys a fresh bucket. It is also a live
	// user-facing fix: mysql and mssql compare email case-insensitively and postgres and
	// sqlite do not, so a stored bob@x.com typed as Bob@x.com used to sign in on two engines
	// and be refused on the other two (#219).
	//
	// The mock's expectation is exact-argument, which is what makes this observable: with
	// the normalization removed the lookup is called with "  Bob@Example.com  " and no
	// expectation matches. The audit entry and the re-rendered form are asserted on the same
	// spelling, which is decision 4's two visible consequences.
	t.Run("The address reaches the lookup, the audit entry and the form normalized", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthPwdPost(httpHelper, authHelper, database, auditLogger, noCredentialFailures{})

		form := url.Values{}
		form.Add(ceremonyIdField, testCeremonyId)
		form.Add("email", "  Bob@Example.com  ")
		form.Add("password", "testpassword")
		req, _ := http.NewRequest("POST", "/auth/pwd", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:  oauth.AuthStateLevel1Password,
			CeremonyId: testCeremonyId,
			ClientId:   "test-client",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		client := &models.Client{
			ClientIdentifier: "test-client",
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		settings := &models.Settings{
			SMTPEnabled: true,
		}
		ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		database.On("GetUserByEmail", mock.Anything, "bob@example.com").Return(nil, nil)

		auditLogger.On("Log", constants.AuditAuthFailedPwd, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["email"] == "bob@example.com"
		})).Return()

		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_pwd.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == "Authentication failed." && data["email"] == "bob@example.com"
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	// A whitespace-only address is still the missing-email error, not a lookup on the
	// empty string: the trim now happens before the check rather than inside it.
	t.Run("A whitespace-only address is refused as missing", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthPwdPost(httpHelper, authHelper, database, auditLogger, noCredentialFailures{})

		form := url.Values{}
		form.Add(ceremonyIdField, testCeremonyId)
		form.Add("email", "   ")
		form.Add("password", "testpassword")
		req, _ := http.NewRequest("POST", "/auth/pwd", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:  oauth.AuthStateLevel1Password,
			CeremonyId: testCeremonyId,
			ClientId:   "test-client",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		client := &models.Client{
			ClientIdentifier: "test-client",
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		settings := &models.Settings{SMTPEnabled: true}
		req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeySettings, settings))

		// No GetUserByEmail expectation: the mock fails the test if the lookup is reached.
		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_pwd.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == "Email is required."
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("Successful authentication", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthPwdPost(httpHelper, authHelper, database, auditLogger, noCredentialFailures{})

		password := "testpassword"
		passwordHash, err := hashutil.HashPassword(password)
		assert.NoError(t, err)

		form := url.Values{}
		form.Add(ceremonyIdField, testCeremonyId)
		form.Add("email", "test@example.com")
		form.Add("password", password)
		req, _ := http.NewRequest("POST", "/auth/pwd", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:  oauth.AuthStateLevel1Password,
			CeremonyId: testCeremonyId,
			ClientId:   "test-client",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		client := &models.Client{
			ClientIdentifier: "test-client",
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		settings := &models.Settings{
			SMTPEnabled: true,
		}
		ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		user := &models.User{
			Id:           1,
			Email:        "test@example.com",
			PasswordHash: passwordHash,
			Enabled:      true,
			// Nonzero so the assertion below cannot pass on the zero value if the
			// capture were dropped (#106 decision 11 rule 1).
			AuthStateGeneration: 7,
			// The same trick for the OTP configuration generation, and a different number so
			// the two cannot be crossed (#242).
			OtpConfigGeneration: 4,
		}
		database.On("GetUserByEmail", mock.Anything, "test@example.com").Return(user, nil)

		auditLogger.On("Log", constants.AuditAuthSuccessPwd, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["userId"] == int64(1)
		})).Return()

		// mock.Anything for the request: handler_auth_pwd.go calls
		// i18n.RefineLocalizerWithUser after password verifies, which returns
		// a fresh *http.Request, so the pointer no longer matches `req`.
		authHelper.On("SaveAuthContext", rr, mock.Anything, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.UserId == 1 &&
				ac.AuthState == oauth.AuthStateLevel1PasswordCompleted &&
				ac.AuthMethods == enums.AuthMethodPassword.String() &&
				ac.AuthenticatedAt != nil && !ac.AuthenticatedAt.IsZero() &&
				// This handler is the only writer of Level1AuthCompleted, so this is the
				// only unit case that fails if the write is dropped. Without it the gate in
				// handler_auth_completed sends every fresh login back to /auth/pwd and only
				// the integration tier notices (#129 decision 15).
				ac.Level1AuthCompleted &&
				// Captured from the user whose credentials were just verified. Thin on
				// purpose: token_issuer_auth_state_generation_test.go owns the tables.
				ac.AuthStateGeneration == 7 &&
				// The OTP configuration generation is captured here too, so a ceremony that
				// creates a session without passing through /auth/level2 stamps the user's
				// current counter on it rather than 0. It is defence in depth rather than a
				// reachable bypass, since every ceremony whose target is above level 1 goes
				// through /auth/level2 and overwrites this, and it is asserted here for that
				// reason: this is the only place the write is observable at all (#242).
				ac.OtpConfigGeneration != nil && *ac.OtpConfigGeneration == 4
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/level1completed", rr.Header().Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("Disabled user account", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthPwdPost(httpHelper, authHelper, database, auditLogger, noCredentialFailures{})

		password := "testpassword"
		passwordHash, err := hashutil.HashPassword(password)
		assert.NoError(t, err)

		form := url.Values{}
		form.Add(ceremonyIdField, testCeremonyId)
		form.Add("email", "disabled@example.com")
		form.Add("password", password)
		req, _ := http.NewRequest("POST", "/auth/pwd", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:  oauth.AuthStateLevel1Password,
			CeremonyId: testCeremonyId,
			ClientId:   "test-client",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		client := &models.Client{
			ClientIdentifier: "test-client",
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		settings := &models.Settings{
			SMTPEnabled: true,
		}
		ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		disabledUser := &models.User{
			Id:           2,
			Email:        "disabled@example.com",
			PasswordHash: passwordHash,
			Enabled:      false,
		}
		database.On("GetUserByEmail", mock.Anything, "disabled@example.com").Return(disabledUser, nil)

		auditLogger.On("Log", constants.AuditUserDisabled, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["userId"] == int64(2)
		})).Return()

		// mock.Anything for the request: i18n.RefineLocalizerWithUser fires
		// after password verifies and returns a fresh request, so renderError
		// renders against the refined request, not the original `req` pointer.
		httpHelper.On("RenderTemplate", rr, mock.Anything, "/layouts/auth_layout.html", "/auth_pwd.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			return data["error"] == "Your user account is disabled."
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})
}

// TestHandleAuthPwdPost_SpendsTheLimiterBudgetOnFailuresOnly is seam 2 for the password
// form: the handler driven through a real RateLimiterMiddleware, so what is asserted is the
// limiter's own observable behaviour rather than a spy reporting that a method was called.
//
// Through the middleware rather than directly, and this is the point of the case. Since
// stage 3 the reservation the handler converts is placed by the limiter and lives in the
// request context, so a handler invoked on a bare request has nothing to convert and
// RecordCredentialFailure is a no-op. A case written that way passes while proving nothing.
//
// The budgets themselves are pinned at seam 1 in core/middleware. What is new here is the
// wiring: that a wrong password reaches the counter at all, and that a right one does not.
func TestHandleAuthPwdPost_SpendsTheLimiterBudgetOnFailuresOnly(t *testing.T) {
	const tightBudget = 10 // failures per 15 minutes per (account, client block)
	const email = "victim@example.com"

	password := "correct horse battery staple"
	passwordHash, err := hashutil.HashPassword(password)
	assert.NoError(t, err)

	knownAccount := func() *models.User {
		return &models.User{Id: 1, Enabled: true, Email: email, PasswordHash: passwordHash}
	}

	// newHandler wires one handler and its limiter together, the way routes.go does. The
	// auth context comes back so a case driving repeated sign-ins can reset the state the
	// handler advances, which in production is a fresh ceremony each time.
	//
	// account is what GetUserByEmail answers with. A nil one is the address that names no
	// account, which is its own rejection branch with its own recording call.
	newHandler := func(t *testing.T, account *models.User) (http.Handler, *mocks_data.Database, *oauth.AuthContext) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		authContext := &oauth.AuthContext{
			AuthState:  oauth.AuthStateLevel1Password,
			CeremonyId: testCeremonyId,
			ClientId:   "test-client",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)
		authHelper.On("SaveAuthContext", mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").
			Return(&models.Client{ClientIdentifier: "test-client"}, nil)
		database.On("GetUserByEmail", mock.Anything, email).Return(account, nil)
		auditLogger.On("Log", mock.Anything, mock.Anything).Return().Maybe()
		httpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/auth_layout.html",
			"/auth_pwd.html", mock.Anything).Return(nil).Maybe()

		rateLimiter := newTestRateLimiter(authHelper)
		handler := HandleAuthPwdPost(httpHelper, authHelper, database, auditLogger, rateLimiter)
		return rateLimiter.LimitPwd(handler), database, authContext
	}

	// post submits one attempt from a fixed host and reports the status.
	post := func(handler http.Handler, submitted string) int {
		form := url.Values{}
		form.Add(ceremonyIdField, testCeremonyId)
		form.Add("email", email)
		form.Add("password", submitted)
		req, _ := http.NewRequest("POST", "/auth/pwd", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "203.0.113.7:5000"
		req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeySettings,
			&models.Settings{SMTPEnabled: true}))
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr.Code
	}

	t.Run("wrong passwords fill the budget and the next attempt is refused", func(t *testing.T) {
		handler, database, _ := newHandler(t, knownAccount())
		for i := 0; i < tightBudget; i++ {
			assert.Equal(t, http.StatusOK, post(handler, "wrong"), "attempt %d should reach the handler", i+1)
		}
		assert.Equal(t, http.StatusTooManyRequests, post(handler, "wrong"),
			"attempt %d should be refused by the limiter", tightBudget+1)
		// The refused request never reached the handler, so it never looked an account
		// up: 10 lookups for 11 attempts.
		database.AssertNumberOfCalls(t, "GetUserByEmail", tightBudget)
	})

	// The unknown-account branch is a separate call site from the wrong-password one above,
	// and it is the branch an attacker enumerating addresses lands on. If it stopped
	// charging, guessing at an address that names no account would cost nothing, which is
	// both an unbounded oracle and a cheaper probe than guessing at one that does (#219).
	t.Run("an address naming no account spends the budget too", func(t *testing.T) {
		handler, database, _ := newHandler(t, nil)
		for i := 0; i < tightBudget; i++ {
			assert.Equal(t, http.StatusOK, post(handler, "wrong"), "attempt %d should reach the handler", i+1)
		}
		assert.Equal(t, http.StatusTooManyRequests, post(handler, "wrong"),
			"attempt %d should be refused by the limiter", tightBudget+1)
		database.AssertNumberOfCalls(t, "GetUserByEmail", tightBudget)
	})

	t.Run("a correct password spends nothing", func(t *testing.T) {
		handler, _, authContext := newHandler(t, knownAccount())
		// Well past the budget. A tier that counted every request would refuse the 11th,
		// which is an account locked out of its own login by using it.
		for i := 0; i < tightBudget*2; i++ {
			authContext.AuthState = oauth.AuthStateLevel1Password
			assert.Equal(t, http.StatusFound, post(handler, password),
				"sign-in %d should succeed", i+1)
		}
	})
}
