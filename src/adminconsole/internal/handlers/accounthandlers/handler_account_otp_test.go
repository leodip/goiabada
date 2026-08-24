package accounthandlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	mocks_handler_helpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
)

// This file did not exist before #247. The package carried only its TestMain, and the console's OTP
// page was covered end to end or not at all.
//
// It exists because the change that took the TOTP seed out of the browser's hands took away the
// only source the enrolment form's rerender had. The seed and its QR code used to travel in two
// hidden inputs and come back on every submission, so a wrong password redrew the form from what
// the browser had posted. Those inputs are gone, and every rerender now has to fetch the enrolment
// again. The failure that would replace them is silent and complete: the template draws the <img>
// and the <pre> unconditionally, so the page still renders, with an empty QR code and an empty
// seed, and the user simply cannot finish enrolling.
//
// What these cases own is that binding. Whether the rendered form carries a hidden input is HTML,
// which a mocked RenderTemplate cannot see; that lives in adminconsole/internal/rendertest.

const (
	testAccessToken = "an-access-token"
	testBase64Image = "aW1hZ2UtYnl0ZXM="
	testSecretKey   = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	accountOTPPath  = "/account/otp"
)

// stubApiClient embeds apiclient.ApiClient so its other methods come for free, and any of them a
// test does not stub panics on the nil interface, which is the right outcome for a call the test
// did not expect.
type stubApiClient struct {
	apiclient.ApiClient

	profile *models.User

	enrollment    *api.AccountOTPEnrollmentResponse
	enrollmentErr error
	enrollmentGET int

	updateErr error
	updateReq *api.UpdateAccountOTPRequest
}

func (s *stubApiClient) GetAccountProfile(accessToken string) (*models.User, error) {
	return s.profile, nil
}

func (s *stubApiClient) GetAccountOTPEnrollment(accessToken string) (*api.AccountOTPEnrollmentResponse, error) {
	s.enrollmentGET++
	if s.enrollmentErr != nil {
		return nil, s.enrollmentErr
	}
	return s.enrollment, nil
}

func (s *stubApiClient) UpdateAccountOTP(accessToken string,
	request *api.UpdateAccountOTPRequest) (*models.User, error) {

	s.updateReq = request
	if s.updateErr != nil {
		return nil, s.updateErr
	}
	return s.profile, nil
}

func newStubApiClient(otpEnabled bool) *stubApiClient {
	return &stubApiClient{
		profile: &models.User{Id: 7, OTPEnabled: otpEnabled},
		enrollment: &api.AccountOTPEnrollmentResponse{
			Base64Image: testBase64Image,
			SecretKey:   testSecretKey,
		},
	}
}

// otpPostRequest builds a submission carrying the access token the handler reads out of the request
// context, without which it answers 500 before reaching anything these cases are about.
func otpPostRequest(form url.Values) *http.Request {
	req := httptest.NewRequest(http.MethodPost, accountOTPPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req.WithContext(context.WithValue(req.Context(), constants.ContextKeyJwtInfo,
		oauth.JwtInfo{TokenResponse: oauth.TokenResponse{AccessToken: testAccessToken}}))
}

// mustJSON is how the cases assert on the wire form rather than on the struct. The struct no longer
// has a SecretKey field, so asserting it is empty would assert nothing; asserting the marshalled
// body never mentions secretKey is the claim that survives someone adding the field back.
func mustJSON(t *testing.T, v interface{}) string {
	t.Helper()
	encoded, err := json.Marshal(v)
	require.NoError(t, err)
	return string(encoded)
}

// bindOf captures the map the handler renders with, which is what these cases assert on.
func bindOf(t *testing.T, httpHelper *mocks_handler_helpers.HttpHelper) map[string]interface{} {
	t.Helper()
	for _, call := range httpHelper.Calls {
		if call.Method == "RenderTemplate" {
			return call.Arguments.Get(4).(map[string]interface{})
		}
	}
	t.Fatal("the handler rendered nothing")
	return nil
}

func apiError(code string) error {
	return &apiclient.APIError{Code: code, Message: "the API said so", StatusCode: http.StatusBadRequest}
}

// Every way the enrolment form can be redrawn must carry a QR code and a seed, fetched from the API
// rather than read back off the submission. An empty one is a page the user cannot enrol from.
func TestHandleAccountOtpPost_EveryEnrollmentRerenderCarriesTheQRAndTheSeed(t *testing.T) {
	testCases := []struct {
		name      string
		form      url.Values
		updateErr error
	}{
		{
			name: "a blank code, refused by the console itself",
			form: url.Values{"password": {"P4ss!word"}, "otp": {""}},
		},
		{
			name:      "a wrong password, refused by the API",
			form:      url.Values{"password": {"wrong"}, "otp": {"123456"}},
			updateErr: apiError("AUTHENTICATION_FAILED"),
		},
		{
			name:      "a wrong OTP code",
			form:      url.Values{"password": {"P4ss!word"}, "otp": {"123456"}},
			updateErr: apiError("INVALID_OTP_CODE"),
		},
		{
			name:      "no pending enrolment, or one that expired",
			form:      url.Values{"password": {"P4ss!word"}, "otp": {"123456"}},
			updateErr: apiError("OTP_ENROLLMENT_NOT_PENDING"),
		},
		{
			name:      "a secretKey refusal, which this client cannot provoke but must still explain",
			form:      url.Values{"password": {"P4ss!word"}, "otp": {"123456"}},
			updateErr: apiError("SECRET_KEY_NOT_ACCEPTED"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := mocks_handler_helpers.NewHttpHelper(t)
			httpHelper.On("RenderTemplate", mock.Anything, mock.Anything,
				"/layouts/menu_layout.html", "/account_otp.html", mock.Anything).Return(nil).Once()

			client := newStubApiClient(false)
			client.updateErr = tc.updateErr

			rr := httptest.NewRecorder()
			HandleAccountOtpPost(httpHelper, client).ServeHTTP(rr, otpPostRequest(tc.form))

			bind := bindOf(t, httpHelper)
			assert.Equal(t, testBase64Image, bind["base64Image"],
				"an enrolment form with no QR code cannot be enrolled from")
			assert.Equal(t, testSecretKey, bind["secretKey"])
			assert.Equal(t, false, bind["otpEnabled"])
			assert.NotEmpty(t, bind["error"])

			assert.Equal(t, 1, client.enrollmentGET,
				"the seed comes from the API on every rerender, since the form no longer carries it")

			if tc.updateErr != nil {
				require.NotNil(t, client.updateReq)
				assert.False(t, strings.Contains(mustJSON(t, client.updateReq), "secretKey"),
					"the console must send no secret at all")
			}
		})
	}
}

// An enrolment that succeeded elsewhere while this form was open reloads the page instead of
// redrawing the form. Redrawing it would call the enrolment endpoint, which refuses for the same
// reason, turning a race that resolved correctly into an error page.
func TestHandleAccountOtpPost_AlreadyEnabledReloadsRatherThanRedrawing(t *testing.T) {
	httpHelper := mocks_handler_helpers.NewHttpHelper(t)

	client := newStubApiClient(false)
	client.updateErr = apiError("OTP_ALREADY_ENABLED")

	rr := httptest.NewRecorder()
	HandleAccountOtpPost(httpHelper, client).ServeHTTP(rr,
		otpPostRequest(url.Values{"password": {"P4ss!word"}, "otp": {"123456"}}))

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Contains(t, rr.Header().Get("Location"), "/account/otp")
	assert.Zero(t, client.enrollmentGET,
		"a user who is already enrolled must not be handed a fresh enrolment")
	httpHelper.AssertNotCalled(t, "RenderTemplate",
		mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// The disable form has no QR code and no seed, and must not acquire one: fetching an enrolment for
// a user who has OTP enabled is refused by the API.
func TestHandleAccountOtpPost_DisableErrorFetchesNoEnrollment(t *testing.T) {
	httpHelper := mocks_handler_helpers.NewHttpHelper(t)
	httpHelper.On("RenderTemplate", mock.Anything, mock.Anything,
		"/layouts/menu_layout.html", "/account_otp.html", mock.Anything).Return(nil).Once()

	client := newStubApiClient(true)
	client.updateErr = apiError("AUTHENTICATION_FAILED")

	rr := httptest.NewRecorder()
	HandleAccountOtpPost(httpHelper, client).ServeHTTP(rr,
		otpPostRequest(url.Values{"password": {"wrong"}}))

	bind := bindOf(t, httpHelper)
	assert.Equal(t, true, bind["otpEnabled"])
	assert.NotContains(t, bind, "base64Image")
	assert.NotContains(t, bind, "secretKey")
	assert.Zero(t, client.enrollmentGET)
}

// A successful enable redirects, and the request it sent carries only the password and the code.
func TestHandleAccountOtpPost_EnableSendsOnlyThePasswordAndTheCode(t *testing.T) {
	httpHelper := mocks_handler_helpers.NewHttpHelper(t)

	client := newStubApiClient(false)

	rr := httptest.NewRecorder()
	HandleAccountOtpPost(httpHelper, client).ServeHTTP(rr,
		otpPostRequest(url.Values{"password": {"P4ss!word"}, "otp": {"123456"}}))

	assert.Equal(t, http.StatusFound, rr.Code)
	require.NotNil(t, client.updateReq)
	assert.True(t, client.updateReq.Enabled)
	assert.Equal(t, "P4ss!word", client.updateReq.Password)
	assert.Equal(t, "123456", client.updateReq.OtpCode)
	assert.NotContains(t, mustJSON(t, client.updateReq), "secretKey",
		"the wire form must carry no secret, which is the whole of the console's half of #247")
}
