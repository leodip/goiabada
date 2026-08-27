package handlers

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

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

// otpEnrolTx is an opaque non-nil transaction, the counterpart of apihandlers' otpDisableTx. The
// enrollment cases register every write against this exact handle, so a write that slipped back to
// the pool would arrive carrying a nil tx and fail as an unexpected call. That is the assertion;
// nothing about *sql.Tx itself is exercised (#242 decision 2).
var otpEnrolTx = &sql.Tx{}

// otpTestKeyURL is the otpauth:// URL for a secret, the form the ceremony carries since the
// seed and its QR code collapsed into one field. The handler parses what it holds and derives
// both from it, so a case cannot stand a placeholder here the way it could when the two were
// stored verbatim (#247).
func otpTestKeyURL(secret string) string {
	return "otpauth://totp/TestApp:test@example.com" +
		"?algorithm=SHA1&digits=6&issuer=TestApp&period=30&secret=" + secret
}

// otpTestRenderedQR is the QR code the handler will draw for a key URL. Computed with the same
// function the handler calls rather than pinned to a literal: what the cases below are about is
// that the image on the page comes from the key the ceremony holds, not what a PNG encoder emits.
func otpTestRenderedQR(t *testing.T, keyURL string) string {
	t.Helper()
	image, err := otp.RenderQRCodeImage(keyURL)
	if err != nil {
		t.Fatalf("otpTestRenderedQR: %v", err)
	}
	return image
}

func TestHandleAuthOtpGet(t *testing.T) {
	t.Run("Error when getting GetAuthContext", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		otpSecretGenerator := mocks_otp.NewOtpSecretGenerator(t)

		handler := HandleAuthOtpGet(httpHelper, authHelper, database, otpSecretGenerator)

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
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		otpSecretGenerator := mocks_otp.NewOtpSecretGenerator(t)

		handler := HandleAuthOtpGet(httpHelper, authHelper, database, otpSecretGenerator)

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
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		otpSecretGenerator := mocks_otp.NewOtpSecretGenerator(t)

		handler := HandleAuthOtpGet(httpHelper, authHelper, database, otpSecretGenerator)

		req, _ := http.NewRequest("GET", "/auth/otp", nil)
		rr := httptest.NewRecorder()

		// The stale pair is what this case is about as much as the render is: a ceremony that
		// reached /auth/otp before the user enrolled somewhere else carries a seed that is now
		// dead, and HandleAuthOtpPost picks its error template by whether one is present.
		authContext := &oauth.AuthContext{
			AuthState:  oauth.AuthStateLevel2OTP,
			CeremonyId: testCeremonyId,
			UserId:     1,
			ClientId:   "test-client",
			OTPKeyURL:  otpTestKeyURL("STALESECRETSTALE"),
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)
		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.OTPKeyURL == ""
		})).Return(nil)

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
		database.AssertExpectations(t)

		assert.Empty(t, authContext.OTPKeyURL)
	})

	t.Run("OTP not enabled user", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		otpSecretGenerator := mocks_otp.NewOtpSecretGenerator(t)

		handler := HandleAuthOtpGet(httpHelper, authHelper, database, otpSecretGenerator)

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
		// A real key URL, because the handler parses what the generator returns: the page's
		// secret and QR code are both derived from it (#247).
		generatedKeyURL := otpTestKeyURL("JBSWY3DPEHPK3PXP")
		wantImage := otpTestRenderedQR(t, generatedKeyURL)

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.OTPKeyURL == generatedKeyURL
		})).Return(nil)

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

		otpSecretGenerator.On("GenerateOTPSecret", "test@example.com", "TestApp").Return(generatedKeyURL, nil)

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
				if base64Image, ok := bind["base64Image"]; !ok || base64Image != wantImage {
					return false
				}
				if secretKey, ok := bind["secretKey"]; !ok || secretKey != "JBSWY3DPEHPK3PXP" {
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
		database.AssertExpectations(t)
		otpSecretGenerator.AssertExpectations(t)

		// The generated key is left on the ceremony, which is what the next GET reads to
		// render the same QR code rather than a fresh one (#242 part 3).
		assert.Equal(t, generatedKeyURL, authContext.OTPKeyURL)
	})

	// The reload. Nothing else in this file pins it, and it is the whole of part 3: with a seed
	// already on the ceremony the generator must not run, because the user has scanned the QR
	// code drawn from the one that is there. otpSecretGenerator carries NO expectation, so a
	// handler that regenerates fails on an unexpected call rather than on an assertion this
	// case could have forgotten to make.
	t.Run("OTP not enabled user, reload renders the secret already on the ceremony", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		otpSecretGenerator := mocks_otp.NewOtpSecretGenerator(t)

		handler := HandleAuthOtpGet(httpHelper, authHelper, database, otpSecretGenerator)

		req, _ := http.NewRequest("GET", "/auth/otp", nil)
		rr := httptest.NewRecorder()

		settings := &models.Settings{
			AppName: "TestApp",
		}
		ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		firstRenderKeyURL := otpTestKeyURL("FIRSTRENDERSECRET")
		authContext := &oauth.AuthContext{
			AuthState:  oauth.AuthStateLevel2OTP,
			CeremonyId: testCeremonyId,
			UserId:     1,
			ClientId:   "test-client",
			OTPKeyURL:  firstRenderKeyURL,
		}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)
		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.OTPKeyURL == firstRenderKeyURL
		})).Return(nil)

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

		httpHelper.On("RenderTemplate",
			mock.Anything,
			mock.Anything,
			"/layouts/auth_layout.html",
			"/auth_otp_enrollment.html",
			mock.MatchedBy(func(bind map[string]interface{}) bool {
				return bind["secretKey"] == "FIRSTRENDERSECRET" &&
					bind["base64Image"] == otpTestRenderedQR(t, firstRenderKeyURL)
			}),
		).Return(nil)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		otpSecretGenerator.AssertExpectations(t)

		assert.Equal(t, firstRenderKeyURL, authContext.OTPKeyURL)
	})
}

func TestHandleAuthOtpPost(t *testing.T) {
	t.Run("Error when getting AuthContext", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthOtpPost(httpHelper, authHelper, database, auditLogger, noCredentialFailures{})

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
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthOtpPost(httpHelper, authHelper, database, auditLogger, noCredentialFailures{})

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
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthOtpPost(httpHelper, authHelper, database, auditLogger, noCredentialFailures{})

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
	// The database mock is given NO expectations, which is the assertion that carries this
	// case: the check sits above GetUserById and therefore above otp.MatchStep and
	// TryConsumeUserOTPStep. A stale submission that reached the claim would burn
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
				authHelper := mocks_handlerhelpers.NewAuthHelper(t)
				database := mocks_data.NewDatabase(t)
				auditLogger := mocks_audit.NewAuditLogger(t)

				handler := HandleAuthOtpPost(httpHelper, authHelper, database, auditLogger, noCredentialFailures{})

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
				authHelper.AssertExpectations(t)
				database.AssertExpectations(t)
				auditLogger.AssertExpectations(t)
			})
		}
	})

	t.Run("User not found", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthOtpPost(httpHelper, authHelper, database, auditLogger, noCredentialFailures{})

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
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthOtpPost(httpHelper, authHelper, database, auditLogger, noCredentialFailures{})

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
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthOtpPost(httpHelper, authHelper, database, auditLogger, noCredentialFailures{})

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

	// A live passcode, correct for the user's own secret, put in the target's query alone. It
	// must be answered as though no code were submitted at all. r.FormValue would merge the
	// query behind the body and verify it, which is worse than a leak: TryConsumeUserOTPStep
	// would burn the step, so the passcode the user is about to type into the real form would
	// then be refused as a replay. The mock is given no TryConsumeUserOTPStep expectation, so
	// reaching it fails the test on an unexpected call (#202).
	t.Run("OTP code in the query alone", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthOtpPost(httpHelper, authHelper, database, auditLogger, noCredentialFailures{})

		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      "TestApp",
			AccountName: "test@test.com",
		})
		assert.Nil(t, err)

		otpCode, err := totp.GenerateCode(key.Secret(), time.Now())
		assert.Nil(t, err)

		// The ceremony id is in the body, so the gate above passes and the credential read is
		// what answers. The passcode is in the query and nowhere else.
		form := url.Values{}
		form.Add(ceremonyIdField, testCeremonyId)
		target := "/auth/otp?" + url.Values{"otp": {otpCode}}.Encode()
		req, _ := http.NewRequest("POST", target, strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:  oauth.AuthStateLevel2OTP,
			CeremonyId: testCeremonyId,
			UserId:     1,
			ClientId:   "test-client",
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

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

		// The code-required re-render, carrying the ceremony id so the user can retry: the
		// same answer an empty submission gets. No audit entry either, because no credential
		// was checked, which is why auditLogger is given no expectation.
		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_otp.html",
			mock.MatchedBy(func(bind map[string]interface{}) bool {
				return bind["ceremonyId"] == testCeremonyId &&
					bind["error"] == "OTP code is required."
			})).Return(nil)

		handler.ServeHTTP(rr, req)

		// Nothing was authenticated and nothing was redirected to.
		assert.Empty(t, rr.Header().Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("Invalid OTP code for enabled OTP", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthOtpPost(httpHelper, authHelper, database, auditLogger, noCredentialFailures{})

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
	// ceremony carries both the image and the secret, which the enrolled case above never does, so
	// this is the only case that observes the ceremony id on that branch (#79 seam 4).
	t.Run("Invalid OTP code while enrolling rerenders the enrollment form", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthOtpPost(httpHelper, authHelper, database, auditLogger, noCredentialFailures{})

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

		authContext.OTPKeyURL = otpTestKeyURL("test-secret")

		database.On("GetUserById", mock.Anything, int64(1)).
			Return(&models.User{Id: 1, Enabled: true, OTPEnabled: false}, nil)
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").
			Return(&models.Client{ClientIdentifier: "test-client"}, nil)

		auditLogger.On("Log", constants.AuditAuthFailedOtp, mock.Anything).Return()

		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html",
			"/auth_otp_enrollment.html", mock.MatchedBy(func(bind map[string]interface{}) bool {
				return bind["ceremonyId"] == testCeremonyId &&
					bind["secretKey"] == "test-secret" &&
					bind["base64Image"] == otpTestRenderedQR(t, otpTestKeyURL("test-secret"))
			})).Return(nil)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	// The other arm of the error rerender's template selection, and the only one left now that
	// the seed and its image are one field: a ceremony carrying no key falls back to the
	// verification page, because there is nothing to draw an enrolment page from. Reachable
	// when HandleAuthOtpGet's enrolled arm cleared the key and the authenticator was then
	// removed elsewhere before this submission arrived.
	//
	// It used to be reached by setting a secret and no image, which the two-field condition
	// read as "not enrolling". No GET ever wrote that state, so what the case pinned was an
	// inconsistency rather than a branch (#247).
	t.Run("Invalid OTP code for disabled OTP with no key on the ceremony", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthOtpPost(httpHelper, authHelper, database, auditLogger, noCredentialFailures{})

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

		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/auth_otp.html",
			mock.MatchedBy(func(bind map[string]interface{}) bool {
				// Neither is bound, because neither can be derived from nothing.
				_, hasImage := bind["base64Image"]
				_, hasSecret := bind["secretKey"]
				return !hasImage && !hasSecret
			})).Return(nil)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("Successful OTP validation for enabled OTP", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthOtpPost(httpHelper, authHelper, database, auditLogger, noCredentialFailures{})

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

		// An accepted authenticator code replaces the browser session's identifier at once,
		// rather than leaving it to /auth/completed one redirect later. Ordering is asserted
		// as well as occurrence: rotation persists the session's contents as they are, so
		// running it after the save would leave a failure window in which the identifier the
		// browser arrived with names a row already marked authentication_completed, which is
		// what a planted identifier needs (#266 decision 20).
		authContextSaved := false
		authHelper.On("RegenerateSession", rr, req).Return(nil).Once().
			Run(func(mock.Arguments) {
				assert.False(t, authContextSaved,
					"rotation must run before the auth context recording the OTP is saved")
			})

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateAuthenticationCompleted &&
				ac.AuthMethods == enums.AuthMethodOTP.String() &&
				ac.AuthenticatedAt != nil && !ac.AuthenticatedAt.IsZero() &&
				// OTP is level 2 and must not claim level 1: a ceremony can reach here by
				// reusing a session rather than by entering a password, so setting this
				// would let it recreate a session that was just ended (#129 decision 15).
				!ac.Level1AuthCompleted
		})).Return(nil).Run(func(mock.Arguments) { authContextSaved = true })

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/completed", rr.Header().Get("Location"))
		assert.True(t, authContextSaved, "the ceremony must still record that the code was accepted")

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("Successful OTP validation for disabled OTP (enrollment)", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthOtpPost(httpHelper, authHelper, database, auditLogger, noCredentialFailures{})

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

		otpSecret := key.Secret()
		authContext.OTPKeyURL = otpTestKeyURL(otpSecret)

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

		// The enable write and the counter advance commit together, so there is no state in
		// which the authenticator is on and no session knows (#242 decision 2). Registered
		// against this exact handle, so a write that slipped back to the pool would arrive
		// carrying a nil tx and fail as an unexpected call.
		var calls []string
		database.On("BeginTransaction").Return(otpEnrolTx, nil).
			Run(func(mock.Arguments) { calls = append(calls, "begin") }).Once()
		database.On("UpdateUser", otpEnrolTx, mock.MatchedBy(func(u *models.User) bool {
			// The secret must be stored encrypted, with the plaintext column cleared.
			if u.Id != 1 || !u.OTPEnabled || u.OTPSecret != "" || len(u.OTPSecretEncrypted) == 0 {
				return false
			}
			decrypted, err := u.GetOTPSecret()
			return err == nil && decrypted == otpSecret
		})).Return(nil).
			Run(func(mock.Arguments) { calls = append(calls, "update") }).Once()
		database.On("IncrementUserOtpConfigGeneration", otpEnrolTx, int64(1)).Return(int64(6), nil).
			Run(func(mock.Arguments) { calls = append(calls, "increment") }).Once()
		database.On("ClearPendingOTPEnrollment", otpEnrolTx, int64(1)).Return(nil).
			Run(func(mock.Arguments) { calls = append(calls, "clear") }).Once()
		database.On("CommitTransaction", otpEnrolTx).Return(nil).
			Run(func(mock.Arguments) { calls = append(calls, "commit") }).Once()
		database.On("RollbackTransaction", otpEnrolTx).Return(nil).Once()

		auditLogger.On("Log", constants.AuditEnabledOTP, mock.Anything).Return()
		auditLogger.On("Log", constants.AuditAuthSuccessOtp, mock.Anything).Return()

		// Rotation joins the ordering this case already tracks, which is what makes the
		// sequence readable in one assertion: the enrolment commits, THEN the identifier is
		// replaced, THEN the acceptance is recorded (#266 decision 20).
		authHelper.On("RegenerateSession", rr, req).Return(nil).Once().
			Run(func(mock.Arguments) { calls = append(calls, "rotate") })

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateAuthenticationCompleted &&
				ac.AuthMethods == enums.AuthMethodOTP.String() &&
				ac.AuthenticatedAt != nil && !ac.AuthenticatedAt.IsZero() &&
				// The value the increment returned, not the pre-enrollment value /auth/level2
				// captured. This ceremony answered the level 2 question by MOVING the counter,
				// so promoting the older value at /auth/completed would leave the session it is
				// about to create owing another prompt at once (#242).
				ac.OtpConfigGeneration != nil && *ac.OtpConfigGeneration == 6 &&
				// The enrolment key is spent: it has just proved the user holds the
				// authenticator and nothing downstream reads it, so carrying it through
				// /auth/completed, /auth/consent and /auth/issue, and leaving it in the
				// cookie of a ceremony abandoned here, is a credential outliving its
				// purpose. Asserted on the value SAVED rather than on the field afterwards,
				// because what the cookie receives is the whole claim (#247).
				ac.OTPKeyURL == "" &&
				// OTP is level 2 and must not claim level 1: a ceremony can reach here by
				// reusing a session rather than by entering a password, so setting this
				// would let it recreate a session that was just ended (#129 decision 15).
				!ac.Level1AuthCompleted
		})).Return(nil).Run(func(mock.Arguments) { calls = append(calls, "save") })

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, config.GetAuthServer().BaseURL+"/auth/completed", rr.Header().Get("Location"))

		assert.Equal(t, []string{"begin", "update", "increment", "clear", "commit", "rotate", "save"}, calls,
			"the enable write, the counter advance and the pending-enrolment clear belong inside "+
				"one transaction, commit last. The clear is handed otpEnrolTx rather than nil: on "+
				"a nil transaction it would commit on its own, and a rolled back enrolment would "+
				"discard a pending seed the account API still owes the user (#247). The identifier "+
				"is then replaced BEFORE the acceptance is saved, so a failure between the two "+
				"cannot leave a planted identifier naming an authentication_completed row "+
				"(#266 decision 20)")

		assert.Empty(t, authContext.OTPKeyURL,
			"a successful enrolment must leave no copy of the key on the ceremony")

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("Error updating user during OTP enrollment", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthOtpPost(httpHelper, authHelper, database, auditLogger, noCredentialFailures{})

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

		otpSecret := key.Secret()
		authContext.OTPKeyURL = otpTestKeyURL(otpSecret)

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
		database.On("BeginTransaction").Return(otpEnrolTx, nil).Once()
		database.On("UpdateUser", otpEnrolTx, mock.Anything).Return(updateError).Once()
		database.On("RollbackTransaction", otpEnrolTx).Return(nil).Once()

		httpHelper.On("InternalServerError", rr, req, updateError).Return()

		handler.ServeHTTP(rr, req)

		// Neither is registered, so reaching either would already fail. Saying so explicitly is
		// the point: a failed enable rolls back whole, and the counter must not move for an
		// authenticator that was never established.
		database.AssertNotCalled(t, "IncrementUserOtpConfigGeneration", mock.Anything, mock.Anything)
		database.AssertNotCalled(t, "CommitTransaction", mock.Anything)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	// The other half of the transaction: the enable write lands and the counter advance fails.
	// Committing here would leave the authenticator on with every session's snapshot still
	// matching, so they would all keep asserting acr level2_optional with amr ["pwd"] for a user
	// who now has an authenticator. That is precisely the state the re-prompt exists to prevent,
	// and the caller cannot recover from it: a retry is refused with OTP_ALREADY_ENABLED
	// (#242 decision 2).
	t.Run("Counter advance failure rolls the enrollment back", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthOtpPost(httpHelper, authHelper, database, auditLogger, noCredentialFailures{})

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

		authContext.OTPKeyURL = otpTestKeyURL(key.Secret())

		user := &models.User{Id: 1, Enabled: true, OTPEnabled: false}
		database.On("GetUserById", mock.Anything, int64(1)).Return(user, nil)

		client := &models.Client{ClientIdentifier: "test-client"}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(client, nil)

		database.On("TryConsumeUserOTPStep", mock.Anything, int64(1), mock.Anything, false).
			Return(true, nil)

		incrementError := errors.New("the database is unwell")
		database.On("BeginTransaction").Return(otpEnrolTx, nil).Once()
		database.On("UpdateUser", otpEnrolTx, mock.Anything).Return(nil).Once()
		database.On("IncrementUserOtpConfigGeneration", otpEnrolTx, int64(1)).
			Return(int64(0), incrementError).Once()
		database.On("RollbackTransaction", otpEnrolTx).Return(nil).Once()

		// The clear sits after the increment inside the transaction, so a failed increment must
		// stop before it. Asserted below rather than stubbed here.

		httpHelper.On("InternalServerError", rr, req, incrementError).Return()

		handler.ServeHTTP(rr, req)

		database.AssertNotCalled(t, "CommitTransaction", mock.Anything)
		database.AssertNotCalled(t, "ClearPendingOTPEnrollment", mock.Anything, mock.Anything)
		// Nothing is audited as an enrollment that did not happen, and the ceremony does not
		// advance: no auth method is added and no context is saved.
		auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything)
		authHelper.AssertNotCalled(t, "SaveAuthContext", mock.Anything, mock.Anything, mock.Anything)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	// The two subtests below are deliberately thin: seam 1 owns the matcher table and seam 2
	// owns the claim table, so all this layer has to show is that the handler consults the
	// claim and translates its two answers correctly (#111 seam 5).
	t.Run("Replayed OTP code is refused for enabled OTP", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthOtpPost(httpHelper, authHelper, database, auditLogger, noCredentialFailures{})

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
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthOtpPost(httpHelper, authHelper, database, auditLogger, noCredentialFailures{})

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
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAuthOtpPost(httpHelper, authHelper, database, auditLogger, noCredentialFailures{})

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
	// against the user's stored secret, the enrollment half against the one the ceremony is
	// carrying. consumed is TryConsumeUserOTPStep's answer, and false is a step that has
	// already been spent. The two flags together select one of the four credential-rejection
	// branches, each of which is its own recording call site.
	newHandler := func(t *testing.T, enrolled bool, consumed bool) (http.Handler, *oauth.AuthContext) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
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
		// Only the accepted-code case reaches it, and this table covers both outcomes.
		authHelper.On("RegenerateSession", mock.Anything, mock.Anything).Return(nil).Maybe()

		user := &models.User{Id: 1, Enabled: true, OTPEnabled: enrolled}
		template := "/auth_otp.html"
		if enrolled {
			user.OTPSecretEncrypted = encryptOTPForTest(t, key.Secret())
		} else {
			// What HandleAuthOtpGet leaves on the ceremony for an enrolling user, and what
			// puts the handler on its enrollment branch: the secret it verifies against comes
			// from the auth context rather than from the user row.
			authContext.OTPKeyURL = otpTestKeyURL(key.Secret())
			template = "/auth_otp_enrollment.html"
		}

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
		handler := HandleAuthOtpPost(httpHelper, authHelper, database, auditLogger, rateLimiter)
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
