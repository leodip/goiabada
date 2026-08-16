package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/sessions"
	mocks_audit "github.com/leodip/goiabada/authserver/internal/audit/mocks"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/otp"
	"github.com/pkg/errors"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	mocks_otp "github.com/leodip/goiabada/core/otp/mocks"
	mocks_sessionstore "github.com/leodip/goiabada/core/sessionstore/mocks"
)

// otpTestAESKey is a fixed 32-byte AES key used to exercise the encrypted OTP
// secret paths (issue #82). It matches the process data cipher key initialized
// in TestMain, so values encrypted with it decrypt via encryption.DecryptData.
var otpTestAESKey = []byte("0123456789abcdef0123456789abcdef")

func encryptOTPForTest(t *testing.T, secret string) []byte {
	t.Helper()
	enc, err := encryption.EncryptText(secret, otpTestAESKey)
	if err != nil {
		t.Fatalf("encryptOTPForTest: %v", err)
	}
	return enc
}

func TestHandleAuthOtpGet(t *testing.T) {
	t.Run("Error when getting GetAuthContext", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		otpSecretGenerator := mocks_otp.NewOtpSecretGenerator(t)

		handler := HandleAuthOtpGet(httpHelper, httpSession, authHelper, database, otpSecretGenerator)

		req, _ := http.NewRequest("GET", "/auth/otp", nil)
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
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		otpSecretGenerator := mocks_otp.NewOtpSecretGenerator(t)

		handler := HandleAuthOtpGet(httpHelper, httpSession, authHelper, database, otpSecretGenerator)

		req, _ := http.NewRequest("GET", "/auth/otp", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateInitial,
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "authContext.AuthState is not level2_otp"
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("OTP enabled user", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		otpSecretGenerator := mocks_otp.NewOtpSecretGenerator(t)

		handler := HandleAuthOtpGet(httpHelper, httpSession, authHelper, database, otpSecretGenerator)

		req, _ := http.NewRequest("GET", "/auth/otp", nil)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:  oauth.AuthStateLevel2OTP,
			CeremonyId: testCeremonyId,
			UserId:     1,
			ClientId:   "test-client",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		session := sessions.NewSession(httpSession, constants.AuthServerSessionName)
		httpSession.On("Get", req, constants.AuthServerSessionName).Return(session, nil)
		httpSession.On("Save", req, rr, session).Return(nil)

		user := &models.User{
			Id:         1,
			OTPEnabled: true,
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		client := &models.Client{
			ClientIdentifier: "test-client",
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		httpHelper.On("RenderTemplate",
			mock.Anything,
			mock.Anything,
			"/layouts/auth_layout.html",
			"/auth_otp.html",
			mock.MatchedBy(func(bind map[string]interface{}) bool {
				if len(bind) != 8 {
					return false
				}
				if err, ok := bind["error"]; !ok || err != nil {
					return false
				}
				// The rendered form has to name THIS ceremony, or every submission of it is
				// refused by HandleAuthOtpPost (#79 seam 4).
				if bind["ceremonyId"] != testCeremonyId {
					return false
				}
				if _, ok := bind["layoutShowClientSection"]; !ok {
					return false
				}
				if _, ok := bind["layoutClientName"]; !ok {
					return false
				}
				if _, ok := bind["layoutHasClientLogo"]; !ok {
					return false
				}
				if _, ok := bind["layoutClientLogoUrl"]; !ok {
					return false
				}
				if _, ok := bind["layoutClientDescription"]; !ok {
					return false
				}
				if _, ok := bind["layoutClientWebsiteUrl"]; !ok {
					return false
				}
				return true
			}),
		).Return(nil)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		httpSession.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("OTP not enabled user", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		otpSecretGenerator := mocks_otp.NewOtpSecretGenerator(t)

		handler := HandleAuthOtpGet(httpHelper, httpSession, authHelper, database, otpSecretGenerator)

		req, _ := http.NewRequest("GET", "/auth/otp", nil)
		rr := httptest.NewRecorder()

		settings := &models.Settings{
			AppName: "TestApp",
		}
		ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		authContext := &oauth.AuthContext{
			AuthState:  oauth.AuthStateLevel2OTP,
			CeremonyId: testCeremonyId,
			UserId:     1,
			ClientId:   "test-client",
		}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		session := sessions.NewSession(httpSession, constants.AuthServerSessionName)
		httpSession.On("Get", mock.MatchedBy(func(r *http.Request) bool {
			return r.Context().Value(constants.ContextKeySettings) == settings
		}), constants.AuthServerSessionName).Return(session, nil)
		httpSession.On("Save", req, rr, session).Return(nil)

		user := &models.User{
			Id:         1,
			OTPEnabled: false,
			Email:      "test@example.com",
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		client := &models.Client{
			ClientIdentifier: "test-client",
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		otpSecretGenerator.On("GenerateOTPSecret", "test@example.com", "TestApp").Return("base64Image", "secretKey", nil)

		httpHelper.On("RenderTemplate",
			mock.Anything,
			mock.Anything,
			"/layouts/auth_layout.html",
			"/auth_otp_enrollment.html",
			mock.MatchedBy(func(bind map[string]interface{}) bool {
				if len(bind) != 10 {
					return false
				}
				if err, ok := bind["error"]; !ok || err != nil {
					return false
				}
				// The enrollment form is bound too: it is a form in the ceremony like any other,
				// and a user enrolling is the one case where nothing else guards the submission.
				if bind["ceremonyId"] != testCeremonyId {
					return false
				}
				if base64Image, ok := bind["base64Image"]; !ok || base64Image != "base64Image" {
					return false
				}
				if secretKey, ok := bind["secretKey"]; !ok || secretKey != "secretKey" {
					return false
				}
				if _, ok := bind["layoutShowClientSection"]; !ok {
					return false
				}
				if _, ok := bind["layoutClientName"]; !ok {
					return false
				}
				if _, ok := bind["layoutHasClientLogo"]; !ok {
					return false
				}
				if _, ok := bind["layoutClientLogoUrl"]; !ok {
					return false
				}
				if _, ok := bind["layoutClientDescription"]; !ok {
					return false
				}
				if _, ok := bind["layoutClientWebsiteUrl"]; !ok {
					return false
				}
				return true
			}),
		).Return(nil)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		httpSession.AssertExpectations(t)
		database.AssertExpectations(t)
		otpSecretGenerator.AssertExpectations(t)

		assert.Equal(t, "secretKey", session.Values[constants.SessionKeyOTPSecret])
		assert.Equal(t, "base64Image", session.Values[constants.SessionKeyOTPImage])
	})
}

func TestHandleAuthOtpPost(t *testing.T) {
	t.Run("Error when getting AuthContext", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthOtpPost(httpHelper, httpSession, authHelper, database, auditLogger, noCredentialFailures{})

		// The ceremony matches, so the gate below is what answers. Without an id in the body the
		// submission would be refused one gate earlier and this case would stop proving anything.
		form := url.Values{}
		form.Add(ceremonyIdField, testCeremonyId)
		req, _ := http.NewRequest("POST", "/auth/otp", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		expectedError := errors.New("auth context error")
		authHelper.On("GetAuthContext", mock.Anything).Return(nil, expectedError)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == expectedError.Error()
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	// A missing auth context is what someone with an absent or expired session
	// cookie hits, and it is the branch the OTP rate limiter now hands through to
	// rather than answering itself (#114). It must redirect, not error.
	t.Run("No auth context redirects to the profile URL", func(t *testing.T) {
		previousBaseURL := config.GetAdminConsole().BaseURL
		t.Cleanup(func() { config.GetAdminConsole().BaseURL = previousBaseURL })
		config.GetAdminConsole().BaseURL = "https://admin.example.com"

		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthOtpPost(httpHelper, httpSession, authHelper, database, auditLogger, noCredentialFailures{})

		// The ceremony matches, so the gate below is what answers. Without an id in the body the
		// submission would be refused one gate earlier and this case would stop proving anything.
		form := url.Values{}
		form.Add(ceremonyIdField, testCeremonyId)
		req, _ := http.NewRequest("POST", "/auth/otp", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authHelper.On("GetAuthContext", mock.Anything).Return(nil, customerrors.ErrNoAuthContext)

		// No InternalServerError expectation is set, so the mock fails this subtest
		// if the handler takes the other branch. Location is asserted against the
		// literal rather than GetProfileURL(), which would move with the function it
		// is meant to check; GetProfileURL is pinned by TestGetProfileURL.
		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, "https://admin.example.com/account/profile", rr.Header().Get("Location"))
		authHelper.AssertExpectations(t)
	})

	t.Run("Unexpected AuthState", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthOtpPost(httpHelper, httpSession, authHelper, database, auditLogger, noCredentialFailures{})

		// The ceremony matches, so the gate below is what answers. Without an id in the body the
		// submission would be refused one gate earlier and this case would stop proving anything.
		form := url.Values{}
		form.Add(ceremonyIdField, testCeremonyId)
		req, _ := http.NewRequest("POST", "/auth/otp", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:  oauth.AuthStateInitial,
			CeremonyId: testCeremonyId,
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "authContext.AuthState is not level2_otp"
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	// An OTP prompt left open in another tab, submitted after a second /auth/authorize replaced the
	// ceremony it was rendered for. Every one of these is the mismatch page at 400.
	//
	// The httpSession and database mocks are given NO expectations, which is the assertion that
	// carries this case: the check sits above httpSession.Get, above GetUserById and therefore above
	// otp.MatchStep and TryConsumeUserOTPStep. A stale submission that reached the claim would burn
	// a step of a passcode the ceremony the user is actually on still needs, so a forgotten tab
	// could make a correct code stop working (#79 decision 5, #111 decision 3).
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
		}{
			{
				// The defect's own shape: the OTP prompt of the request that was replaced.
				name: "a different ceremony's id", stored: testCeremonyId,
				submitted: "another-ceremony-0123456789abcde",
				authState: oauth.AuthStateLevel2OTP,
			},
			{
				// A hand-built body, or a template that lost the hidden input.
				name: "no ceremony field at all", stored: testCeremonyId,
				submitted: "", authState: oauth.AuthStateLevel2OTP,
			},
			{
				// The upgrade case: an auth context written before this change carries no id, so
				// the ceremony is refused once and the user starts again.
				name: "an auth context from before the ceremony id existed", stored: "",
				submitted: "", authState: oauth.AuthStateLevel2OTP,
			},
			{
				// The check runs before the AuthState check, so the replaced ceremony's state
				// produces the 400 mismatch page rather than a 500 naming an internal invariant.
				name: "a replaced ceremony that has moved on", stored: testCeremonyId,
				submitted: "another-ceremony-0123456789abcde",
				authState: oauth.AuthStateRequiresConsent,
			},
			{
				// The id has to come from the body. Both templates this handler serves post to
				// action="", so reading it with r.FormValue would let /auth/otp?ceremonyId=...
				// supply an id the submission never carried, and a page rendered for no ceremony
				// at all would pass the gate (#79).
				name: "the current id in the query alone", stored: testCeremonyId,
				submitted: testCeremonyId, inQuery: true,
				authState: oauth.AuthStateLevel2OTP,
			},
		}

		for _, tc := range staleCases {
			t.Run(tc.name, func(t *testing.T) {
				httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
				httpSession := mocks_sessionstore.NewStore(t)
				authHelper := mocks_handlerhelpers.NewAuthHelper(t)
				database := mocks_data.NewDatabase(t)
				auditLogger := mocks_audit.NewAuditLogger(t)

				handler := HandleAuthOtpPost(httpHelper, httpSession, authHelper, database, auditLogger, noCredentialFailures{})

				form := url.Values{}
				form.Add("otp", "123456")
				target := "/auth/otp"
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
					UserId:     1,
					ClientId:   "test-client",
				}
				authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

				expectCeremonyMismatch(t, httpHelper, auditLogger, rr, req)

				handler.ServeHTTP(rr, req)

				// Nothing was saved and nowhere was redirected to: the auth context is untouched,
				// so the ceremony the user is actually on is still theirs to finish.
				assert.Empty(t, rr.Header().Get("Location"))

				httpHelper.AssertExpectations(t)
				httpSession.AssertExpectations(t)
				authHelper.AssertExpectations(t)
				database.AssertExpectations(t)
				auditLogger.AssertExpectations(t)
			})
		}
	})

	t.Run("User not found", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthOtpPost(httpHelper, httpSession, authHelper, database, auditLogger, noCredentialFailures{})

		// The ceremony matches, so the gate below is what answers. Without an id in the body the
		// submission would be refused one gate earlier and this case would stop proving anything.
		form := url.Values{}
		form.Add(ceremonyIdField, testCeremonyId)
		req, _ := http.NewRequest("POST", "/auth/otp", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:  oauth.AuthStateLevel2OTP,
			CeremonyId: testCeremonyId,
			UserId:     1,
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		session := sessions.NewSession(httpSession, constants.AuthServerSessionName)
		httpSession.On("Get", req, constants.AuthServerSessionName).Return(session, nil)

		database.On("GetUserById", mock.Anything, int64(1)).Return(nil, nil)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "user not found"
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("User disabled", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthOtpPost(httpHelper, httpSession, authHelper, database, auditLogger, noCredentialFailures{})

		// The ceremony matches, so the gate below is what answers. Without an id in the body the
		// submission would be refused one gate earlier and this case would stop proving anything.
		form := url.Values{}
		form.Add(ceremonyIdField, testCeremonyId)
		req, _ := http.NewRequest("POST", "/auth/otp", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:  oauth.AuthStateLevel2OTP,
			CeremonyId: testCeremonyId,
			UserId:     1,
			ClientId:   "test-client",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		session := sessions.NewSession(httpSession, constants.AuthServerSessionName)
		httpSession.On("Get", req, constants.AuthServerSessionName).Return(session, nil)

		user := &models.User{
			Id:      1,
			Enabled: false,
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		client := &models.Client{
			ClientIdentifier: "test-client",
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		auditLogger.On("Log", constants.AuditUserDisabled, mock.Anything).Return()

		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_otp.html", mock.Anything).Return(nil)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("Empty OTP code", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthOtpPost(httpHelper, httpSession, authHelper, database, auditLogger, noCredentialFailures{})

		// The ceremony matches, so the gate below is what answers. Without an id in the body the
		// submission would be refused one gate earlier and this case would stop proving anything.
		form := url.Values{}
		form.Add(ceremonyIdField, testCeremonyId)
		req, _ := http.NewRequest("POST", "/auth/otp", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:  oauth.AuthStateLevel2OTP,
			CeremonyId: testCeremonyId,
			UserId:     1,
			ClientId:   "test-client",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		session := sessions.NewSession(httpSession, constants.AuthServerSessionName)
		httpSession.On("Get", req, constants.AuthServerSessionName).Return(session, nil)

		user := &models.User{
			Id:      1,
			Enabled: true,
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		client := &models.Client{
			ClientIdentifier: "test-client",
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_otp.html", mock.Anything).Return(nil)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("Invalid OTP code for enabled OTP", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthOtpPost(httpHelper, httpSession, authHelper, database, auditLogger, noCredentialFailures{})

		form := url.Values{}
		form.Add(ceremonyIdField, testCeremonyId)
		form.Add("otp", "123456")
		req, _ := http.NewRequest("POST", "/auth/otp", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:  oauth.AuthStateLevel2OTP,
			CeremonyId: testCeremonyId,
			UserId:     1,
			ClientId:   "test-client",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		session := sessions.NewSession(httpSession, constants.AuthServerSessionName)
		httpSession.On("Get", req, constants.AuthServerSessionName).Return(session, nil)

		user := &models.User{
			Id:                 1,
			Enabled:            true,
			OTPEnabled:         true,
			OTPSecretEncrypted: encryptOTPForTest(t, "test-secret"),
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		client := &models.Client{
			ClientIdentifier: "test-client",
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		auditLogger.On("Log", constants.AuditAuthFailedOtp, mock.Anything).Return()

		// The error re-render is a path no happy-path case sees, and it has to carry the ceremony
		// id: without it a single mistyped code would end the ceremony, because the retry would
		// name no ceremony and be refused (#79 seam 4).
		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_otp.html",
			mock.MatchedBy(func(bind map[string]interface{}) bool {
				return bind["ceremonyId"] == testCeremonyId && bind["error"] != nil
			})).Return(nil)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	// The other template the error path can pick. renderError chooses the enrollment form when the
	// session holds both the image and the secret, which the enrolled case above never does, so this
	// is the only case that observes the ceremony id on that branch (#79 seam 4).
	t.Run("Invalid OTP code while enrolling rerenders the enrollment form", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthOtpPost(httpHelper, httpSession, authHelper, database, auditLogger, noCredentialFailures{})

		form := url.Values{}
		form.Add(ceremonyIdField, testCeremonyId)
		form.Add("otp", "123456")
		req, _ := http.NewRequest("POST", "/auth/otp", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:  oauth.AuthStateLevel2OTP,
			CeremonyId: testCeremonyId,
			UserId:     1,
			ClientId:   "test-client",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		session := sessions.NewSession(httpSession, constants.AuthServerSessionName)
		session.Values[constants.SessionKeyOTPSecret] = "test-secret"
		session.Values[constants.SessionKeyOTPImage] = "test-image"
		httpSession.On("Get", req, constants.AuthServerSessionName).Return(session, nil)

		database.On("GetUserById", mock.Anything, int64(1)).
			Return(&models.User{Id: 1, Enabled: true, OTPEnabled: false}, nil)
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").
			Return(&models.Client{ClientIdentifier: "test-client"}, nil)

		auditLogger.On("Log", constants.AuditAuthFailedOtp, mock.Anything).Return()

		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html",
			"/auth_otp_enrollment.html", mock.MatchedBy(func(bind map[string]interface{}) bool {
				return bind["ceremonyId"] == testCeremonyId &&
					bind["secretKey"] == "test-secret" && bind["base64Image"] == "test-image"
			})).Return(nil)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("Invalid OTP code for disabled OTP", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthOtpPost(httpHelper, httpSession, authHelper, database, auditLogger, noCredentialFailures{})

		form := url.Values{}
		form.Add(ceremonyIdField, testCeremonyId)
		form.Add("otp", "123456")
		req, _ := http.NewRequest("POST", "/auth/otp", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:  oauth.AuthStateLevel2OTP,
			CeremonyId: testCeremonyId,
			UserId:     1,
			ClientId:   "test-client",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		session := sessions.NewSession(httpSession, constants.AuthServerSessionName)
		session.Values[constants.SessionKeyOTPSecret] = "test-secret"
		httpSession.On("Get", req, constants.AuthServerSessionName).Return(session, nil)

		user := &models.User{
			Id:         1,
			Enabled:    true,
			OTPEnabled: false,
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		client := &models.Client{
			ClientIdentifier: "test-client",
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		auditLogger.On("Log", constants.AuditAuthFailedOtp, mock.Anything).Return()

		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_otp.html", mock.Anything).Return(nil)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("Successful OTP validation for enabled OTP", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthOtpPost(httpHelper, httpSession, authHelper, database, auditLogger, noCredentialFailures{})

		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      "TestApp",
			AccountName: "test@test.com",
		})
		assert.Nil(t, err)

		otpCode, err := totp.GenerateCode(key.Secret(), time.Now())
		assert.Nil(t, err)

		form := url.Values{}
		form.Add(ceremonyIdField, testCeremonyId)
		form.Add("otp", otpCode)
		req, _ := http.NewRequest("POST", "/auth/otp", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:  oauth.AuthStateLevel2OTP,
			CeremonyId: testCeremonyId,
			UserId:     1,
			ClientId:   "test-client",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		session := sessions.NewSession(httpSession, constants.AuthServerSessionName)
		httpSession.On("Get", req, constants.AuthServerSessionName).Return(session, nil)

		otpSecret := key.Secret()
		user := &models.User{
			Id:                 1,
			Enabled:            true,
			OTPEnabled:         true,
			OTPSecretEncrypted: encryptOTPForTest(t, otpSecret),
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		client := &models.Client{
			ClientIdentifier: "test-client",
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		// requireOTPEnabled is matched exactly rather than with mock.Anything: true is what
		// makes a verification claim assert an enrolled authenticator (#111 decision 10),
		// and passing false here would go unnoticed otherwise.
		database.On("TryConsumeUserOTPStep", mock.Anything, int64(1), mock.Anything, true).
			Return(true, nil)

		auditLogger.On("Log", constants.AuditAuthSuccessOtp, mock.Anything).Return()

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateAuthenticationCompleted &&
				ac.AuthMethods == enums.AuthMethodOTP.String() &&
				ac.AuthenticatedAt != nil && !ac.AuthenticatedAt.IsZero() &&
				// OTP is level 2 and must not claim level 1: a ceremony can reach here by
				// reusing a session rather than by entering a password, so setting this
				// would let it recreate a session that was just ended (#129 decision 15).
				!ac.Level1AuthCompleted
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/completed", rr.Header().Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("Successful OTP validation for disabled OTP (enrollment)", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthOtpPost(httpHelper, httpSession, authHelper, database, auditLogger, noCredentialFailures{})

		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      "TestApp",
			AccountName: "test@test.com",
		})
		assert.Nil(t, err)

		otpCode, err := totp.GenerateCode(key.Secret(), time.Now())
		assert.Nil(t, err)

		form := url.Values{}
		form.Add(ceremonyIdField, testCeremonyId)
		form.Add("otp", otpCode)
		req, _ := http.NewRequest("POST", "/auth/otp", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:  oauth.AuthStateLevel2OTP,
			CeremonyId: testCeremonyId,
			UserId:     1,
			ClientId:   "test-client",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		session := sessions.NewSession(httpSession, constants.AuthServerSessionName)
		otpSecret := key.Secret()
		session.Values[constants.SessionKeyOTPSecret] = otpSecret
		httpSession.On("Get", req, constants.AuthServerSessionName).Return(session, nil)

		user := &models.User{
			Id:         1,
			Enabled:    true,
			OTPEnabled: false,
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		client := &models.Client{
			ClientIdentifier: "test-client",
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		// false, because enrollment claims before the enable write and otp_enabled is
		// still off at that point (#111 decision 10). Matched exactly for the reason the
		// verification subtest above matches true.
		database.On("TryConsumeUserOTPStep", mock.Anything, int64(1), mock.Anything, false).
			Return(true, nil)

		database.On("UpdateUser", mock.Anything, mock.MatchedBy(func(u *models.User) bool {
			// The secret must be stored encrypted, with the plaintext column cleared.
			if u.Id != 1 || !u.OTPEnabled || u.OTPSecret != "" || len(u.OTPSecretEncrypted) == 0 {
				return false
			}
			decrypted, err := u.GetOTPSecret()
			return err == nil && decrypted == otpSecret
		})).Return(nil)

		auditLogger.On("Log", constants.AuditEnabledOTP, mock.Anything).Return()
		auditLogger.On("Log", constants.AuditAuthSuccessOtp, mock.Anything).Return()

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateAuthenticationCompleted &&
				ac.AuthMethods == enums.AuthMethodOTP.String() &&
				ac.AuthenticatedAt != nil && !ac.AuthenticatedAt.IsZero() &&
				// OTP is level 2 and must not claim level 1: a ceremony can reach here by
				// reusing a session rather than by entering a password, so setting this
				// would let it recreate a session that was just ended (#129 decision 15).
				!ac.Level1AuthCompleted
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/completed", rr.Header().Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("Error updating user during OTP enrollment", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthOtpPost(httpHelper, httpSession, authHelper, database, auditLogger, noCredentialFailures{})

		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      "TestApp",
			AccountName: "test@test.com",
		})
		assert.Nil(t, err)

		otpCode, err := totp.GenerateCode(key.Secret(), time.Now())
		assert.Nil(t, err)

		form := url.Values{}
		form.Add(ceremonyIdField, testCeremonyId)
		form.Add("otp", otpCode)
		req, _ := http.NewRequest("POST", "/auth/otp", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:  oauth.AuthStateLevel2OTP,
			CeremonyId: testCeremonyId,
			UserId:     1,
			ClientId:   "test-client",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		session := sessions.NewSession(httpSession, constants.AuthServerSessionName)
		otpSecret := key.Secret()
		session.Values[constants.SessionKeyOTPSecret] = otpSecret
		httpSession.On("Get", req, constants.AuthServerSessionName).Return(session, nil)

		user := &models.User{
			Id:         1,
			Enabled:    true,
			OTPEnabled: false,
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		client := &models.Client{
			ClientIdentifier: "test-client",
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		// The claim succeeds and the enable write then fails, which is the ordering §4
		// asks for: a burned code and a retry beats OTP left enabled on a refused request.
		database.On("TryConsumeUserOTPStep", mock.Anything, int64(1), mock.Anything, false).
			Return(true, nil)

		updateError := errors.New("failed to update user")
		database.On("UpdateUser", mock.Anything, mock.Anything).Return(updateError)

		httpHelper.On("InternalServerError", rr, req, updateError).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	// The two subtests below are deliberately thin: seam 1 owns the matcher table and seam 2
	// owns the claim table, so all this layer has to show is that the handler consults the
	// claim and translates its two answers correctly (#111 seam 5).
	t.Run("Replayed OTP code is refused for enabled OTP", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthOtpPost(httpHelper, httpSession, authHelper, database, auditLogger, noCredentialFailures{})

		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      "TestApp",
			AccountName: "test@test.com",
		})
		assert.Nil(t, err)

		otpCode, err := totp.GenerateCode(key.Secret(), time.Now())
		assert.Nil(t, err)

		form := url.Values{}
		form.Add(ceremonyIdField, testCeremonyId)
		form.Add("otp", otpCode)
		req, _ := http.NewRequest("POST", "/auth/otp", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:  oauth.AuthStateLevel2OTP,
			CeremonyId: testCeremonyId,
			UserId:     1,
			ClientId:   "test-client",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		session := sessions.NewSession(httpSession, constants.AuthServerSessionName)
		httpSession.On("Get", req, constants.AuthServerSessionName).Return(session, nil)

		user := &models.User{
			Id:                 1,
			Enabled:            true,
			OTPEnabled:         true,
			OTPSecretEncrypted: encryptOTPForTest(t, key.Secret()),
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		client := &models.Client{
			ClientIdentifier: "test-client",
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		// The code validates against the secret, so the matcher accepts it; the claim is
		// what refuses it. That is the whole point of the case: without the claim this is
		// an ordinary successful authentication.
		expectedStep := time.Now().UTC().Unix() / otp.StepSeconds
		database.On("TryConsumeUserOTPStep", mock.Anything, int64(1), mock.Anything, true).
			Return(false, nil)

		auditLogger.On("Log", constants.AuditOTPCodeReplayDetected,
			mock.MatchedBy(func(payload map[string]interface{}) bool {
				step, ok := payload["step"].(int64)
				if !ok {
					return false
				}
				// The submitted code is generated at the same instant, so its step is the
				// current one; allow the neighbours in case the clock crosses a period
				// boundary mid-test. Never the code itself.
				if step < expectedStep-1 || step > expectedStep+1 {
					return false
				}
				_, hasCode := payload["otp"]
				return payload["userId"] == int64(1) && !hasCode
			})).Return()
		// Emitted alongside, not instead: the replay is additional signal on top of the
		// ordinary failure the caller sees (#111 decision 5).
		auditLogger.On("Log", constants.AuditAuthFailedOtp, mock.Anything).Return()

		// A replay must be indistinguishable from a wrong code, so it renders the same
		// message the wrong-code branch renders, computed here the way the handler does.
		expectedError := i18n.NewLocalizedError(i18n.ErrCodeOtpIncorrectCode, nil).Localize(req.Context())
		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_otp.html",
			mock.MatchedBy(func(bind map[string]interface{}) bool {
				return bind["error"] == expectedError
			})).Return(nil)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("Error consuming the OTP step", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthOtpPost(httpHelper, httpSession, authHelper, database, auditLogger, noCredentialFailures{})

		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      "TestApp",
			AccountName: "test@test.com",
		})
		assert.Nil(t, err)

		otpCode, err := totp.GenerateCode(key.Secret(), time.Now())
		assert.Nil(t, err)

		form := url.Values{}
		form.Add(ceremonyIdField, testCeremonyId)
		form.Add("otp", otpCode)
		req, _ := http.NewRequest("POST", "/auth/otp", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:  oauth.AuthStateLevel2OTP,
			CeremonyId: testCeremonyId,
			UserId:     1,
			ClientId:   "test-client",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		session := sessions.NewSession(httpSession, constants.AuthServerSessionName)
		httpSession.On("Get", req, constants.AuthServerSessionName).Return(session, nil)

		user := &models.User{
			Id:                 1,
			Enabled:            true,
			OTPEnabled:         true,
			OTPSecretEncrypted: encryptOTPForTest(t, key.Secret()),
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		client := &models.Client{
			ClientIdentifier: "test-client",
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		// A database fault must surface as a 500 rather than being collapsed into either
		// answer: "not consumed" would refuse valid codes for the duration of the fault,
		// and "consumed" would accept replays through it.
		consumeError := errors.New("failed to consume the OTP step")
		database.On("TryConsumeUserOTPStep", mock.Anything, int64(1), mock.Anything, true).
			Return(false, consumeError)

		httpHelper.On("InternalServerError", rr, req, consumeError).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("User account is disabled", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthOtpPost(httpHelper, httpSession, authHelper, database, auditLogger, noCredentialFailures{})

		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      "TestApp",
			AccountName: "test@test.com",
		})
		assert.Nil(t, err)

		otpCode, err := totp.GenerateCode(key.Secret(), time.Now())
		assert.Nil(t, err)

		form := url.Values{}
		form.Add(ceremonyIdField, testCeremonyId)
		form.Add("otp", otpCode)
		req, _ := http.NewRequest("POST", "/auth/otp", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:  oauth.AuthStateLevel2OTP,
			CeremonyId: testCeremonyId,
			UserId:     1,
			ClientId:   "test-client",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		session := sessions.NewSession(httpSession, constants.AuthServerSessionName)
		httpSession.On("Get", req, constants.AuthServerSessionName).Return(session, nil)

		user := &models.User{
			Id:         1,
			Enabled:    false,
			OTPEnabled: true,
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		client := &models.Client{
			ClientIdentifier: "test-client",
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		auditLogger.On("Log", constants.AuditUserDisabled, mock.Anything).Return()

		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_otp.html", mock.Anything).Return(nil)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})
}

// TestHandleAuthOtpPost_SpendsTheLimiterBudgetOnFailuresOnly is seam 2 for the OTP form,
// with the same shape and the same reason as the password one: the handler is driven
// through a real RateLimiterMiddleware, because the reservation it converts is placed by
// the limiter and lives in the request context. Called directly, the handler has nothing to
// convert and RecordCredentialFailure is a no-op, so the case would pass while proving
// nothing (#219).
func TestHandleAuthOtpPost_SpendsTheLimiterBudgetOnFailuresOnly(t *testing.T) {
	const budget = 5 // failures per 15 minutes, keyed on the user id

	key, err := totp.Generate(totp.GenerateOpts{Issuer: "TestApp", AccountName: "test@test.com"})
	assert.Nil(t, err)

	// newHandler wires one handler and its limiter together, the way routes.go does.
	//
	// enrolled picks which half of the handler runs: the enrolled half verifies the code
	// against the user's stored secret, the enrollment half against the one the session is
	// carrying. consumed is TryConsumeUserOTPStep's answer, and false is a step that has
	// already been spent. The two flags together select one of the four credential-rejection
	// branches, each of which is its own recording call site.
	newHandler := func(t *testing.T, enrolled bool, consumed bool) (http.Handler, *oauth.AuthContext) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		authContext := &oauth.AuthContext{
			AuthState:  oauth.AuthStateLevel2OTP,
			CeremonyId: testCeremonyId,
			UserId:     1,
			ClientId:   "test-client",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)
		authHelper.On("SaveAuthContext", mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()

		session := sessions.NewSession(httpSession, constants.AuthServerSessionName)
		user := &models.User{Id: 1, Enabled: true, OTPEnabled: enrolled}
		template := "/auth_otp.html"
		if enrolled {
			user.OTPSecretEncrypted = encryptOTPForTest(t, key.Secret())
		} else {
			// What HandleAuthOtpGet leaves behind for an enrolling user, and what puts the
			// handler on its enrollment branch: the secret it verifies against comes from
			// the session rather than from the user row.
			session.Values[constants.SessionKeyOTPSecret] = key.Secret()
			session.Values[constants.SessionKeyOTPImage] = "test-image"
			template = "/auth_otp_enrollment.html"
		}
		httpSession.On("Get", mock.Anything, constants.AuthServerSessionName).Return(session, nil)

		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").
			Return(&models.Client{ClientIdentifier: "test-client"}, nil)
		// requireOTPEnabled mirrors enrolled: the enrolled half asserts an authenticator and
		// the enrollment half establishes one (#111 decision 10).
		database.On("TryConsumeUserOTPStep", mock.Anything, int64(1), mock.Anything, enrolled).
			Return(consumed, nil).Maybe()
		auditLogger.On("Log", mock.Anything, mock.Anything).Return().Maybe()
		httpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/auth_layout.html",
			template, mock.Anything).Return(nil).Maybe()

		rateLimiter := newTestRateLimiter(authHelper)
		handler := HandleAuthOtpPost(httpHelper, httpSession, authHelper, database, auditLogger, rateLimiter)
		return rateLimiter.LimitOtp(handler), authContext
	}

	post := func(handler http.Handler, code string) int {
		form := url.Values{}
		form.Add(ceremonyIdField, testCeremonyId)
		form.Add("otp", code)
		req, _ := http.NewRequest("POST", "/auth/otp", strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "203.0.113.7:5000"
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr.Code
	}

	// currentCode is the code an authenticator would be showing right now. The replay cases
	// need a code that matches, since a replay is refused after the match rather than
	// instead of it.
	currentCode := func(t *testing.T) string {
		t.Helper()
		code, err := totp.GenerateCode(key.Secret(), time.Now())
		assert.Nil(t, err)
		return code
	}

	// wrongCode is six digits this secret refuses at this instant. A literal cannot be
	// assumed wrong: TOTP emits every six-digit value, and MatchStep accepts the current
	// step plus one either side, so a fixed "000000" is the right answer about three runs
	// in a million and the case then takes the success or replay path instead of the
	// rejection it claims to drive. Confirmed against the matcher the handler itself
	// uses, which is the only thing that can establish it (#219).
	wrongCode := func(t *testing.T) string {
		t.Helper()
		for _, candidate := range []string{"000000", "111111", "222222"} {
			if _, matched := otp.MatchStep(candidate, key.Secret(), time.Now().UTC()); !matched {
				return candidate
			}
		}
		t.Fatal("could not find a six-digit code that the secret refuses")
		return ""
	}

	// Each of the four cases below drives one credential-rejection branch. They are separate
	// call sites, so a mutation deleting any one recording call has to fail exactly one of
	// them; a single case covering "the OTP form charges failures" would leave the other
	// three branches free to stop charging without a test noticing (#219).
	t.Run("wrong codes fill the budget and the next attempt is refused", func(t *testing.T) {
		handler, _ := newHandler(t, true, true)
		for i := 0; i < budget; i++ {
			assert.Equal(t, http.StatusOK, post(handler, wrongCode(t)), "attempt %d should reach the handler", i+1)
		}
		assert.Equal(t, http.StatusTooManyRequests, post(handler, wrongCode(t)),
			"attempt %d should be refused by the limiter", budget+1)
	})

	t.Run("a replayed code fills the budget", func(t *testing.T) {
		// The code matches and the step is refused as already spent. A replay proves
		// nothing about who is submitting it, so it costs what a wrong code costs.
		handler, _ := newHandler(t, true, false)
		for i := 0; i < budget; i++ {
			assert.Equal(t, http.StatusOK, post(handler, currentCode(t)), "attempt %d should reach the handler", i+1)
		}
		assert.Equal(t, http.StatusTooManyRequests, post(handler, currentCode(t)),
			"attempt %d should be refused by the limiter", budget+1)
	})

	t.Run("a wrong enrollment code fills the budget", func(t *testing.T) {
		handler, _ := newHandler(t, false, true)
		for i := 0; i < budget; i++ {
			assert.Equal(t, http.StatusOK, post(handler, wrongCode(t)), "attempt %d should reach the handler", i+1)
		}
		assert.Equal(t, http.StatusTooManyRequests, post(handler, wrongCode(t)),
			"attempt %d should be refused by the limiter", budget+1)
	})

	t.Run("a replayed enrollment code fills the budget", func(t *testing.T) {
		handler, _ := newHandler(t, false, false)
		for i := 0; i < budget; i++ {
			assert.Equal(t, http.StatusOK, post(handler, currentCode(t)), "attempt %d should reach the handler", i+1)
		}
		assert.Equal(t, http.StatusTooManyRequests, post(handler, currentCode(t)),
			"attempt %d should be refused by the limiter", budget+1)
	})

	t.Run("a correct code spends nothing", func(t *testing.T) {
		handler, authContext := newHandler(t, true, true)
		// Well past the budget. The same limiter covers enrollment, where a user pointing
		// an authenticator at the form legitimately submits several codes in a row.
		for i := 0; i < budget*3; i++ {
			otpCode, err := totp.GenerateCode(key.Secret(), time.Now())
			assert.Nil(t, err)
			authContext.AuthState = oauth.AuthStateLevel2OTP
			assert.Equal(t, http.StatusFound, post(handler, otpCode), "verification %d should succeed", i+1)
		}
	})
}
