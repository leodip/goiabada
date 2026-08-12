package handlers

import (
	"context"
	"fmt"
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
				// An administrator created this client, so nothing on the page is
				// self-asserted and the unverified notice must stay off (#108).
				data["clientNameUnverified"] == false &&
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
				// An administrator created this client, so nothing on the page is
				// self-asserted and the unverified notice must stay off (#108).
				data["clientNameUnverified"] == false &&
				data["clientDescription"] == "Test Client" &&
				data["hasLogo"] == false &&
				scopes[0].AlreadyConsented && scopes[1].AlreadyConsented && !scopes[2].AlreadyConsented
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	// The rendered form has to name the ceremony it was rendered for, or every submission of it
	// is refused by HandleConsentPost. Asserted as an equality rather than as "not empty",
	// because the value has to be THIS ceremony's (#79 seam 4).
	t.Run("The render names the ceremony", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleConsentGet(httpHelper, authHelper, database)

		req, _ := http.NewRequest("GET", "/auth/consent", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:  oauth.AuthStateRequiresConsent,
			CeremonyId: testCeremonyId,
			UserId:     1,
			ClientId:   "test-client",
			Scope:      "openid profile email",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		database.On("GetUserById", mock.Anything, int64(1)).Return(&models.User{Id: 1}, nil)
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").
			Return(&models.Client{Id: 1, ClientIdentifier: "test-client"}, nil)
		database.On("GetConsentByUserIdAndClientId", mock.Anything, int64(1), int64(1)).Return(nil, nil)

		var rendered map[string]interface{}
		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/consent.html",
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

		// The ceremony matches, so the state check is what answers. Without an id in the body the
		// submission would be refused one gate earlier and this case would stop proving anything.
		form := url.Values{}
		form.Add(ceremonyIdField, testCeremonyId)
		req, _ := http.NewRequest("POST", "/auth/consent", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:  oauth.AuthStateInitial,
			CeremonyId: testCeremonyId,
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "authContext.AuthState is not requires_consent"
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	// A form left open in another tab, submitted after a second /auth/authorize replaced the
	// ceremony it was rendered for. Every one of these is the mismatch page at 400, and in none of
	// them is the auth context touched: the ceremony that is actually current is still the user's
	// to finish in its own tab (#79 decision 5).
	t.Run("Stale ceremony", func(t *testing.T) {
		staleCases := []struct {
			name string
			// stored is the id the browser's current auth context holds.
			stored string
			// submitted is what the stale page posts; the empty string means the field is absent.
			submitted string
			// inQuery puts submitted in the URL query instead of the body.
			inQuery   bool
			authState string
			btn       string
		}{
			{
				// The defect's own shape: the consent screen of the request that was replaced.
				name: "a different ceremony's id", stored: testCeremonyId,
				submitted: "another-ceremony-0123456789abcde",
				authState: oauth.AuthStateRequiresConsent, btn: "btnSubmit",
			},
			{
				// A hand-built body, or a template that lost the hidden input.
				name: "no ceremony field at all", stored: testCeremonyId,
				submitted: "", authState: oauth.AuthStateRequiresConsent, btn: "btnSubmit",
			},
			{
				// The upgrade case: an auth context written before this change carries no id, so
				// the ceremony is refused once and the user starts again. Refused rather than
				// matched against an empty submission, which is the fail-closed direction.
				name: "an auth context from before the ceremony id existed", stored: "",
				submitted: "", authState: oauth.AuthStateRequiresConsent, btn: "btnSubmit",
			},
			{
				// The id has to come from the body. This form posts to action="", so reading it
				// with r.FormValue would let /auth/consent?ceremonyId=... supply an id the
				// submission never carried, and a page rendered for no ceremony at all would
				// pass the gate (#79).
				name: "the current id in the query alone", stored: testCeremonyId,
				submitted: testCeremonyId, inQuery: true,
				authState: oauth.AuthStateRequiresConsent, btn: "btnSubmit",
			},
			{
				// The check runs before the btnSubmit/btnCancel dispatch, so a stale CANCEL
				// cannot clear the live ceremony's auth context. ClearAuthContext has no
				// expectation here, so the mock fails the test if it is called at all.
				name: "a stale cancel", stored: testCeremonyId,
				submitted: "another-ceremony-0123456789abcde",
				authState: oauth.AuthStateRequiresConsent, btn: "btnCancel",
			},
			{
				// The check runs before the AuthState check too, so the replaced ceremony's
				// state produces the 400 mismatch page rather than a 500 naming an internal
				// invariant, which is what the user would have met without this ordering.
				name: "a replaced ceremony that has moved on", stored: testCeremonyId,
				submitted: "another-ceremony-0123456789abcde",
				authState: oauth.AuthStateLevel1Password, btn: "btnSubmit",
			},
		}

		for _, tc := range staleCases {
			t.Run(tc.name, func(t *testing.T) {
				httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
				authHelper := mocks_handlerhelpers.NewAuthHelper(t)
				database := mocks_data.NewDatabase(t)
				auditLogger := mocks_audit.NewAuditLogger(t)

				handler := HandleConsentPost(httpHelper, authHelper, database, nil, auditLogger)

				form := url.Values{}
				if tc.btn == "btnSubmit" {
					form.Add("btnSubmit", "submit")
					form.Add("consent0", "[on]")
				} else {
					form.Add("btnCancel", "cancel")
				}
				target := "/auth/consent"
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
					AuthState:    tc.authState,
					CeremonyId:   tc.stored,
					UserId:       1,
					ClientId:     "test-client",
					Scope:        "openid profile email",
					ResponseMode: "query",
					RedirectURI:  "https://example.com/callback",
					State:        "test-state",
				}
				authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

				expectCeremonyMismatch(t, httpHelper, auditLogger, rr, req)

				handler.ServeHTTP(rr, req)

				// Nothing was cleared, nothing was saved and no consent was written: the mocks
				// have no expectation for any of it, and database is empty besides.
				assert.Empty(t, rr.Header().Get("Location"))

				httpHelper.AssertExpectations(t)
				authHelper.AssertExpectations(t)
				database.AssertExpectations(t)
				auditLogger.AssertExpectations(t)
			})
		}
	})

	t.Run("User cancels consent", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleConsentPost(httpHelper, authHelper, database, nil, auditLogger)

		form := url.Values{}
		form.Add("btnCancel", "cancel")
		form.Add(ceremonyIdField, testCeremonyId)
		req, _ := http.NewRequest("POST", "/auth/consent", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateRequiresConsent,
			CeremonyId:   testCeremonyId,
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
		form.Add(ceremonyIdField, testCeremonyId)
		req, _ := http.NewRequest("POST", "/auth/consent", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateRequiresConsent,
			CeremonyId:   testCeremonyId,
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
		form.Add(ceremonyIdField, testCeremonyId)
		req, _ := http.NewRequest("POST", "/auth/consent", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateRequiresConsent,
			CeremonyId:   testCeremonyId,
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
		form.Add(ceremonyIdField, testCeremonyId)
		req, _ := http.NewRequest("POST", "/auth/consent", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateRequiresConsent,
			CeremonyId:   testCeremonyId,
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
		form.Add(ceremonyIdField, testCeremonyId)
		form.Add("consent0", "openid")
		form.Add("consent1", "profile")
		req, _ := http.NewRequest("POST", "/auth/consent", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:  oauth.AuthStateRequiresConsent,
			CeremonyId: testCeremonyId,
			UserId:     1,
			ClientId:   "test-client",
			Scope:      "openid profile email",
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
		form.Add(ceremonyIdField, testCeremonyId)
		form.Add("consent0", "openid")
		form.Add("consent1", "profile")
		req, _ := http.NewRequest("POST", "/auth/consent", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:  oauth.AuthStateRequiresConsent,
			CeremonyId: testCeremonyId,
			UserId:     1,
			ClientId:   "test-client",
			Scope:      "openid profile email",
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
		form.Add(ceremonyIdField, testCeremonyId)
		req, _ := http.NewRequest("POST", "/auth/consent", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateRequiresConsent,
			CeremonyId:   testCeremonyId,
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
		form.Add(ceremonyIdField, testCeremonyId)
		req, _ := http.NewRequest("POST", "/auth/consent", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateRequiresConsent,
			CeremonyId:   testCeremonyId,
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
		form.Add(ceremonyIdField, testCeremonyId)
		req, _ := http.NewRequest("POST", "/auth/consent", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateRequiresConsent,
			CeremonyId:   testCeremonyId,
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
		form.Add(ceremonyIdField, testCeremonyId)
		req, _ := http.NewRequest("POST", "/auth/consent", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateRequiresConsent,
			CeremonyId:   testCeremonyId,
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

	// The consent checkboxes are named positionally, consent0 .. consentN, and the handler used
	// to match them with strings.Contains against one joined string of every submitted key.
	// "consent1" is a substring of "consent10", so a scope the user had unchecked was granted
	// from 11 scopes upwards. These cases pin the exact-key lookup, the body-only source and the
	// refusal gate that decides on matched scopes rather than on submitted keys (#79).
	t.Run("Exact-key consent selection", func(t *testing.T) {

		// Indices 0 to 2 are real OIDC scopes and the rest are resource:permission pairs, which
		// is the shape of a request large enough to collide: eight permissions on top of the
		// three built-in scopes is 11.
		scopeList := func(n int) []string {
			scopes := make([]string, 0, n)
			for i := 0; i < n; i++ {
				switch i {
				case 0:
					scopes = append(scopes, "openid")
				case 1:
					scopes = append(scopes, "profile")
				case 2:
					scopes = append(scopes, "email")
				default:
					scopes = append(scopes, fmt.Sprintf("resource%d:permission%d", i, i))
				}
			}
			return scopes
		}

		allBut := func(n int, denied int) []int {
			indices := make([]int, 0, n-1)
			for i := 0; i < n; i++ {
				if i != denied {
					indices = append(indices, i)
				}
			}
			return indices
		}

		// A submitted body carrying btnSubmit and one key per checked index, which is what the
		// browser sends for consent.html.
		checked := func(indices ...int) url.Values {
			form := url.Values{}
			form.Add("btnSubmit", "submit")
			form.Add(ceremonyIdField, testCeremonyId)
			for _, idx := range indices {
				form.Add(fmt.Sprintf("consent%d", idx), "[on]")
			}
			return form
		}

		type consentCase struct {
			name        string
			scopeCount  int
			query       url.Values // keys in the URL query, never in the body
			body        url.Values // keys in the POST body
			rawBody     string     // wins over body, for orderings url.Values.Encode cannot express
			contentType string     // empty means application/x-www-form-urlencoded
			granted     []int      // indices expected to be granted; nil means the request is refused
			// ceremonyMismatch means the refusal happens at the ceremony gate rather than at the
			// consent gate, so the answer is the 400 page and not access_denied.
			ceremonyMismatch bool
		}

		cases := []consentCase{
			{
				// The regression guard. Under the substring match index 1 was granted anyway,
				// because "consent1" appears inside consent10.
				name: "11 scopes, index 1 denied", scopeCount: 11,
				body: checked(allBut(11, 1)...), granted: allBut(11, 1),
			},
			{
				// Two collisions at once: consent1 sits inside consent10..19 and the count
				// crosses 20 as well.
				name: "21 scopes, index 1 denied", scopeCount: 21,
				body: checked(allBut(21, 1)...), granted: allBut(21, 1),
			},
			{
				// The second over-granting pair the probe found: consent2 inside consent20.
				name: "21 scopes, index 2 denied", scopeCount: 21,
				body: checked(allBut(21, 2)...), granted: allBut(21, 2),
			},
			{
				// The control, one below the boundary. It passes under the old match too, and
				// it is here to say where the boundary is rather than to catch anything.
				name: "10 scopes, index 1 denied, below the collision boundary", scopeCount: 10,
				body: checked(allBut(10, 1)...), granted: allBut(10, 1),
			},
			{
				name: "one box checked", scopeCount: 3,
				body: checked(0), granted: []int{0},
			},
			{
				name: "every box checked", scopeCount: 3,
				body: checked(0, 1, 2), granted: []int{0, 1, 2},
			},
			{
				// The granted order comes from the scope list, never from the body.
				name: "indices submitted out of order", scopeCount: 3,
				rawBody: "consent2=%5Bon%5D&consent0=%5Bon%5D&btnSubmit=submit&ceremonyId=" + testCeremonyId,
				granted: []int{0, 2},
			},
			{
				// Fails closed: nothing beginning consent arrived at all.
				name: "no box checked", scopeCount: 11,
				body: url.Values{"btnSubmit": {"submit"}, ceremonyIdField: {testCeremonyId}}, granted: nil,
			},
			{
				// A key naming no index used to pass the refusal gate, persist an empty consent
				// and leave the issuers to fall back to the full requested scope.
				name: "a key naming no index", scopeCount: 3,
				body: checked(99), granted: nil,
			},
			{
				name: "a non-numeric consent key", scopeCount: 3,
				body:    url.Values{"btnSubmit": {"submit"}, "consentX": {"[on]"}, ceremonyIdField: {testCeremonyId}},
				granted: nil,
			},
			{
				// The query cannot grant on its own: this form posts to action="", so r.Form
				// would have merged /auth/consent?consent1=on into the submission.
				name: "a consent key in the query alone", scopeCount: 3,
				query: url.Values{"consent1": {"[on]"}},
				body:  url.Values{"btnSubmit": {"submit"}, ceremonyIdField: {testCeremonyId}}, granted: nil,
			},
			{
				// The other direction: a real submission does not launder the query key
				// travelling alongside it.
				name: "a consent key in the query beside a real submission", scopeCount: 3,
				query: url.Values{"consent1": {"[on]"}},
				body:  checked(0), granted: []int{0},
			},
			{
				// The action controls come from the body too. This is a click on Cancel with every
				// box still checked, which is what the browser posts, on a consent screen reached
				// at /auth/consent?btnSubmit=submit. r.FormValue found the query's btnSubmit where
				// the body carried only btnCancel, so the user's refusal granted all three scopes.
				// The database mock has no expectations, so persisting anything fails this case
				// rather than merely changing the redirect (#79).
				name: "a cancel submission with btnSubmit in the query", scopeCount: 3,
				query: url.Values{"btnSubmit": {"submit"}},
				body: url.Values{
					"btnCancel": {"cancel"}, ceremonyIdField: {testCeremonyId},
					"consent0": {"[on]"}, "consent1": {"[on]"}, "consent2": {"[on]"},
				},
				granted: nil,
			},
			{
				// No browser sends both controls, so a body that does is hand-built. Approval
				// needs the submit control alone and this is refused rather than resolved in
				// favour of granting (#79).
				name: "both action buttons in the body", scopeCount: 3,
				body: url.Values{
					"btnSubmit": {"submit"}, "btnCancel": {"cancel"},
					ceremonyIdField: {testCeremonyId}, "consent0": {"[on]"},
				},
				granted: nil,
			},
			{
				// The value is checked, not merely the key's presence. consent.html sends
				// btnSubmit=submit and nothing else does, so anything carrying the key with
				// another value is hand-built and is refused. Without this case the predicate
				// weakens to PostForm.Has("btnSubmit") and the suite stays green (#79).
				name: "btnSubmit carrying a value no button sends", scopeCount: 3,
				body: url.Values{
					"btnSubmit": {"yes"}, ceremonyIdField: {testCeremonyId}, "consent0": {"[on]"},
				},
				granted: nil,
			},
			{
				// Fails closed on the action too, not only on the selection: a body naming
				// neither control is not a click on anything, so it grants nothing however many
				// boxes it carries. Without this case a predicate that approves when both keys
				// are absent stays green (#79).
				name: "neither action button in the body", scopeCount: 3,
				body: url.Values{
					ceremonyIdField: {testCeremonyId}, "consent0": {"[on]"},
				},
				granted: nil,
			},
			{
				// The mirror of the cancel case above, and the direction that costs a grant
				// rather than leaking one: a crafted /auth/consent?btnCancel=cancel must not
				// turn the user's real click on Submit into a refusal. Reading the cancel
				// control from merged r.Form rather than the body would do exactly that, and
				// nothing else in the table notices (#79).
				name: "a cancel control in the query beside a real submission", scopeCount: 3,
				query:   url.Values{"btnCancel": {"cancel"}},
				body:    checked(0),
				granted: []int{0},
			},
			{
				// An unparsed body leaves r.PostForm empty, so nothing is granted. Since the
				// ceremony binding landed the refusal happens one gate earlier and shows the
				// mismatch page instead of access_denied: the ceremony id is read from the body
				// too, so a body Go will not parse names no ceremony. Both are refusals and the
				// selection's own fail-closed behaviour is still pinned by "no box checked" and
				// "a key naming no index", which do parse (#79).
				name: "a body Go will not parse", scopeCount: 3,
				query: url.Values{"btnSubmit": {"submit"}},
				//nolint:goconst // the body is deliberately spelled out here
				rawBody: "consent0=%5Bon%5D", contentType: "text/plain",
				granted: nil, ceremonyMismatch: true,
			},
		}

		// Case 2 of the plan's table: every index of an 11-scope request denied in turn, so the
		// whole collision boundary is covered rather than only its first member.
		for denied := 0; denied < 11; denied++ {
			cases = append(cases, consentCase{
				name:       fmt.Sprintf("11 scopes, only index %d denied", denied),
				scopeCount: 11,
				body:       checked(allBut(11, denied)...),
				granted:    allBut(11, denied),
			})
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
				authHelper := mocks_handlerhelpers.NewAuthHelper(t)
				database := mocks_data.NewDatabase(t)
				auditLogger := mocks_audit.NewAuditLogger(t)

				handler := HandleConsentPost(httpHelper, authHelper, database, nil, auditLogger)

				scopes := scopeList(tc.scopeCount)

				target := "/auth/consent"
				if len(tc.query) > 0 {
					target += "?" + tc.query.Encode()
				}
				body := tc.rawBody
				if body == "" {
					body = tc.body.Encode()
				}
				contentType := tc.contentType
				if contentType == "" {
					contentType = "application/x-www-form-urlencoded"
				}
				req, _ := http.NewRequest("POST", target, strings.NewReader(body))
				req.Header.Add("Content-Type", contentType)
				rr := httptest.NewRecorder()

				authContext := &oauth.AuthContext{
					AuthState:    oauth.AuthStateRequiresConsent,
					CeremonyId:   testCeremonyId,
					UserId:       1,
					ClientId:     "test-client",
					Scope:        strings.Join(scopes, " "),
					ResponseMode: "query",
					RedirectURI:  "https://example.com/callback",
					State:        "test-state",
				}
				authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

				if tc.ceremonyMismatch {
					expectCeremonyMismatch(t, httpHelper, auditLogger, rr, req)

					handler.ServeHTTP(rr, req)

					// Nothing was cleared and nothing was saved, which the mocks enforce by
					// having no expectation for either call.
					assert.Empty(t, rr.Header().Get("Location"))
				} else if tc.granted == nil {
					authHelper.On("ClearAuthContext", rr, req).Return(nil)

					handler.ServeHTTP(rr, req)

					assert.Equal(t, http.StatusFound, rr.Code)
					assert.Contains(t, rr.Header().Get("Location"),
						"https://example.com/callback?error=access_denied")
				} else {
					grantedScopes := make([]string, 0, len(tc.granted))
					for _, idx := range tc.granted {
						grantedScopes = append(grantedScopes, scopes[idx])
					}
					expectedScope := strings.Join(grantedScopes, " ")

					client := &models.Client{Id: 1, ClientIdentifier: "test-client"}
					database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)
					database.On("GetUserById", mock.Anything, int64(1)).Return(&models.User{Id: 1}, nil)
					database.On("GetConsentByUserIdAndClientId", mock.Anything, int64(1), int64(1)).Return(nil, nil)

					var persisted *models.UserConsent
					database.On("CreateUserConsent", mock.Anything, mock.MatchedBy(func(consent *models.UserConsent) bool {
						persisted = consent
						return true
					})).Return(nil)

					auditLogger.On("Log", constants.AuditSavedConsent, mock.Anything).Return()

					var saved *oauth.AuthContext
					authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
						saved = ac
						return true
					})).Return(nil)

					handler.ServeHTTP(rr, req)

					assert.Equal(t, http.StatusFound, rr.Code)
					assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/issue", rr.Header().Get("Location"))

					if assert.NotNil(t, persisted) {
						assert.Equal(t, expectedScope, persisted.Scope)
						assert.Equal(t, int64(1), persisted.UserId)
						assert.Equal(t, int64(1), persisted.ClientId)
					}
					if assert.NotNil(t, saved) {
						assert.Equal(t, oauth.AuthStateReadyToIssueCode, saved.AuthState)
						assert.Equal(t, expectedScope, saved.ConsentedScope)
					}
				}

				httpHelper.AssertExpectations(t)
				authHelper.AssertExpectations(t)
				database.AssertExpectations(t)
				auditLogger.AssertExpectations(t)
			})
		}
	})

	// An existing consent row is replaced by the new selection rather than appended to, which is
	// what the now-deleted consent.Scope = "" blanking used to ensure (#79).
	t.Run("Existing consent is replaced, not appended to", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleConsentPost(httpHelper, authHelper, database, nil, auditLogger)

		form := url.Values{}
		form.Add("btnSubmit", "submit")
		form.Add(ceremonyIdField, testCeremonyId)
		form.Add("consent2", "[on]")
		req, _ := http.NewRequest("POST", "/auth/consent", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:  oauth.AuthStateRequiresConsent,
			CeremonyId: testCeremonyId,
			UserId:     1,
			ClientId:   "test-client",
			Scope:      "openid profile email",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").
			Return(&models.Client{Id: 1, ClientIdentifier: "test-client"}, nil)
		database.On("GetUserById", mock.Anything, int64(1)).Return(&models.User{Id: 1}, nil)
		database.On("GetConsentByUserIdAndClientId", mock.Anything, int64(1), int64(1)).
			Return(&models.UserConsent{Id: 1, UserId: 1, ClientId: 1, Scope: "openid profile"}, nil)

		database.On("UpdateUserConsent", mock.Anything, mock.MatchedBy(func(consent *models.UserConsent) bool {
			return consent.Scope == "email"
		})).Return(nil)

		auditLogger.On("Log", constants.AuditSavedConsent, mock.Anything).Return()

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.ConsentedScope == "email"
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/issue", rr.Header().Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})
}
