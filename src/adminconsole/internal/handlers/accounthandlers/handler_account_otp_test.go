package accounthandlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
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
// which a mocked RenderTemplate cannot see; that lives in adminconsole/internal/renderintegration.

const (
	testBase64Image = "aW1hZ2UtYnl0ZXM="
	testSecretKey   = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	accountOTPPath  = "/account/otp"
)

// stubApiClient implements accountOTPAPI, the port both OTP handlers take.
type stubApiClient struct {
	profile *api.UserResponse

	enrollment    *api.AccountOTPEnrollmentResponse
	enrollmentErr error
	enrollmentGET int

	updateErr error
	updateReq *api.UpdateAccountOTPRequest

	// recoveryCodes is what an enable answers with beside the user (#257 decision 8).
	recoveryCodes []string

	// remaining is what GET /api/v1/account/otp/recovery-codes answers, and remainingGET how many
	// times it was asked (#257 decision 9).
	remaining    int
	remainingGET int

	// newSet is what POST /api/v1/account/otp/recovery-codes answers, or newSetErr its refusal;
	// newSetReq is the request it was sent.
	newSet    []string
	newSetErr error
	newSetReq *api.CreateAccountRecoveryCodesRequest
}

// GetAccountRecoveryCodes answers the count of unused codes.
func (s *stubApiClient) GetAccountRecoveryCodes(_ context.Context, accessToken string) (*api.AccountRecoveryCodesResponse, error) {
	s.remainingGET++
	return &api.AccountRecoveryCodesResponse{Remaining: s.remaining}, nil
}

// CreateAccountRecoveryCodes refuses a user without OTP, as POST
// /api/v1/account/otp/recovery-codes does.
func (s *stubApiClient) CreateAccountRecoveryCodes(_ context.Context, accessToken string,
	request *api.CreateAccountRecoveryCodesRequest) (*api.CreateAccountRecoveryCodesResponse, error) {

	s.newSetReq = request
	if s.newSetErr != nil {
		return nil, s.newSetErr
	}
	if !s.profile.OTPEnabled {
		return nil, &apiclient.APIError{Code: "OTP_NOT_ENABLED", Message: "User does not have OTP enabled",
			StatusCode: http.StatusBadRequest}
	}
	return &api.CreateAccountRecoveryCodesResponse{RecoveryCodes: s.newSet}, nil
}

func (s *stubApiClient) GetAccountProfile(_ context.Context, accessToken string) (*api.UserResponse, error) {
	return s.profile, nil
}

// GetAccountOTPEnrollment refuses a user who has OTP, as GET /api/v1/account/otp/enrollment does.
func (s *stubApiClient) GetAccountOTPEnrollment(_ context.Context, accessToken string) (*api.AccountOTPEnrollmentResponse, error) {
	s.enrollmentGET++
	if s.enrollmentErr != nil {
		return nil, s.enrollmentErr
	}
	if s.profile.OTPEnabled {
		return nil, otpAlreadyEnabled()
	}
	return s.enrollment, nil
}

// UpdateAccountOTP answers a request for the state the user is already in as PUT
// /api/v1/account/otp does, with the 400 that names it, so a case about a stale form can assert
// what the console asked for and what it did with the refusal.
func (s *stubApiClient) UpdateAccountOTP(_ context.Context, accessToken string,
	request *api.UpdateAccountOTPRequest) (*api.UpdateAccountOTPResponse, error) {

	s.updateReq = request
	if s.updateErr != nil {
		return nil, s.updateErr
	}
	if request.Enabled && s.profile.OTPEnabled {
		return nil, otpAlreadyEnabled()
	}
	if !request.Enabled && !s.profile.OTPEnabled {
		return nil, &apiclient.APIError{Code: "OTP_NOT_ENABLED", Message: "User does not have OTP enabled",
			StatusCode: http.StatusBadRequest}
	}
	response := &api.UpdateAccountOTPResponse{User: *s.profile}
	if request.Enabled {
		response.RecoveryCodes = s.recoveryCodes
	}
	return response, nil
}

func otpAlreadyEnabled() error {
	return &apiclient.APIError{Code: "OTP_ALREADY_ENABLED", Message: "OTP is already enabled",
		StatusCode: http.StatusBadRequest}
}

func newStubApiClient(otpEnabled bool) *stubApiClient {
	return &stubApiClient{
		profile: &api.UserResponse{Id: 7, OTPEnabled: otpEnabled},
		enrollment: &api.AccountOTPEnrollmentResponse{
			Base64Image: testBase64Image,
			SecretKey:   testSecretKey,
		},
	}
}

// otpPostRequest builds a submission carrying the access token the handler reads out of the request
// context, without which it answers 500 before reaching anything these cases are about.
func otpPostRequest(form url.Values) *http.Request {
	return handlertest.Request(http.MethodPost, accountOTPPath,
		handlertest.WithAccessToken(), handlertest.WithForm(form))
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

func apiError(code string) error {
	return &apiclient.APIError{Code: code, Message: "the API said so", StatusCode: http.StatusBadRequest}
}

// Every way the enrolment form can be redrawn must carry a QR code and a seed, fetched from the API
// rather than read back off the submission. An empty one is a page the user cannot enrol from.
func TestHandleOtpPost_EveryEnrollmentRerenderCarriesTheQRAndTheSeed(t *testing.T) {
	testCases := []struct {
		name      string
		form      url.Values
		updateErr error
	}{
		{
			name: "a blank code, refused by the console itself",
			form: url.Values{"otpAction": {"enable"}, "password": {"P4ss!word"}, "otp": {""}},
		},
		{
			name:      "a wrong password, refused by the API",
			form:      url.Values{"otpAction": {"enable"}, "password": {"wrong"}, "otp": {"123456"}},
			updateErr: apiError("AUTHENTICATION_FAILED"),
		},
		{
			name:      "a wrong OTP code",
			form:      url.Values{"otpAction": {"enable"}, "password": {"P4ss!word"}, "otp": {"123456"}},
			updateErr: apiError("INVALID_OTP_CODE"),
		},
		{
			name:      "no pending enrolment, or one that expired",
			form:      url.Values{"otpAction": {"enable"}, "password": {"P4ss!word"}, "otp": {"123456"}},
			updateErr: apiError("OTP_ENROLLMENT_NOT_PENDING"),
		},
		{
			name:      "a secretKey refusal, which this client cannot provoke but must still explain",
			form:      url.Values{"otpAction": {"enable"}, "password": {"P4ss!word"}, "otp": {"123456"}},
			updateErr: apiError("SECRET_KEY_NOT_ACCEPTED"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := handlersmocks.NewHttpHelper(t)
			handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/account_otp.html").Once()

			client := newStubApiClient(false)
			client.updateErr = tc.updateErr

			rr := httptest.NewRecorder()
			HandleOtpPost(httpHelper, client, consoleBaseURL).ServeHTTP(rr, otpPostRequest(tc.form))

			bind := handlertest.Bind(t, httpHelper)
			assert.Equal(t, testBase64Image, bind["base64Image"],
				"an enrolment form with no QR code cannot be enrolled from")
			assert.Equal(t, testSecretKey, bind["secretKey"])
			assert.Equal(t, false, bind["otpEnabled"])
			assert.NotEmpty(t, bind["error"])

			assert.Equal(t, 1, client.enrollmentGET,
				"the seed comes from the API on every rerender, since the form no longer carries it")

			if tc.updateErr != nil {
				require.NotNil(t, client.updateReq)
				assert.NotContains(t, mustJSON(t, client.updateReq), "secretKey",
					"the console must send no secret at all")
			}
		})
	}
}

// An enrolment that succeeded elsewhere while this form was open reloads the page instead of
// redrawing the form. Redrawing it would call the enrolment endpoint, which refuses for the same
// reason, turning a race that resolved correctly into an error page.
func TestHandleOtpPost_AlreadyEnabledReloadsRatherThanRedrawing(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)

	client := newStubApiClient(false)
	client.updateErr = apiError("OTP_ALREADY_ENABLED")

	rr := httptest.NewRecorder()
	HandleOtpPost(httpHelper, client, consoleBaseURL).ServeHTTP(rr,
		otpPostRequest(url.Values{"otpAction": {"enable"}, "password": {"P4ss!word"}, "otp": {"123456"}}))

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Contains(t, rr.Header().Get("Location"), "/account/otp")
	assert.Zero(t, client.enrollmentGET,
		"a user who is already enrolled must not be handed a fresh enrolment")
	httpHelper.AssertNotCalled(t, "RenderTemplate",
		mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// The disable form has no QR code and no seed, and must not acquire one: fetching an enrolment for
// a user who has OTP enabled is refused by the API.
func TestHandleOtpPost_DisableErrorFetchesNoEnrollment(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/account_otp.html").Once()

	client := newStubApiClient(true)
	client.updateErr = apiError("AUTHENTICATION_FAILED")

	rr := httptest.NewRecorder()
	HandleOtpPost(httpHelper, client, consoleBaseURL).ServeHTTP(rr,
		otpPostRequest(url.Values{"otpAction": {"disable"}, "password": {"wrong"}}))

	bind := handlertest.Bind(t, httpHelper)
	assert.Equal(t, true, bind["otpEnabled"])
	assert.NotContains(t, bind, "base64Image")
	assert.NotContains(t, bind, "secretKey")
	assert.Zero(t, client.enrollmentGET)
}

// A successful enable with no set to show redirects, and the request it sent carries only the
// password and the code.
func TestHandleOtpPost_EnableSendsOnlyThePasswordAndTheCode(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)

	client := newStubApiClient(false)

	rr := httptest.NewRecorder()
	HandleOtpPost(httpHelper, client, consoleBaseURL).ServeHTTP(rr,
		otpPostRequest(url.Values{"otpAction": {"enable"}, "password": {"P4ss!word"}, "otp": {"123456"}}))

	assert.Equal(t, http.StatusFound, rr.Code)
	require.NotNil(t, client.updateReq)
	assert.True(t, client.updateReq.Enabled)
	assert.Equal(t, "P4ss!word", client.updateReq.Password)
	assert.Equal(t, "123456", client.updateReq.OtpCode)
	assert.NotContains(t, mustJSON(t, client.updateReq), "secretKey",
		"the wire form must carry no secret, which is the whole of the console's half of #247")
}

// A 409 CONCURRENT_UPDATE from the API is an account changed under the request: another tab or
// client enabled and disabled OTP, or replaced the authenticator, between the API's read and its
// write, and nothing was saved (#471 decision 2). It is something the user can act on by trying
// again, so the page shows the API's sentence on the form rather than sending it to the generic
// error page, on both the disable form and the enrolment form.
func TestHandleOtpPost_AConcurrentUpdateIsShownOnTheForm(t *testing.T) {
	const message = "The account was changed by another request after it was loaded. Nothing was saved: reload it and make the change again."
	concurrentUpdate := &apiclient.APIError{Code: "CONCURRENT_UPDATE", Message: message, StatusCode: http.StatusConflict}

	testCases := []struct {
		name       string
		otpEnabled bool
		form       url.Values
	}{
		{name: "disabling", otpEnabled: true, form: url.Values{"otpAction": {"disable"}, "password": {"P4ss!word"}}},
		{name: "enabling", otpEnabled: false, form: url.Values{"otpAction": {"enable"}, "password": {"P4ss!word"}, "otp": {"123456"}}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := handlersmocks.NewHttpHelper(t)
			handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/account_otp.html").Once()

			client := newStubApiClient(tc.otpEnabled)
			client.updateErr = concurrentUpdate

			rr := httptest.NewRecorder()
			HandleOtpPost(httpHelper, client, consoleBaseURL).ServeHTTP(rr, otpPostRequest(tc.form))

			bind := handlertest.Bind(t, httpHelper)
			assert.Equal(t, message, bind["error"])
			assert.Equal(t, tc.otpEnabled, bind["otpEnabled"])
			httpHelper.AssertNotCalled(t, "InternalServerError", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// Each form says what it does, and the console asks the auth server for that and nothing else. The
// page used to ignore which form was posted and ask for the inverse of the user's stored state, so
// an enrolment form left open in one tab and posted after enrolling in another switched the second
// factor off with nothing but the password (#562 decision 8). A form that no longer matches the
// account changes nothing: the auth server refuses it, and the page reloads to show the account as
// it is now.
func TestHandleOtpPost_AStaleFormNeverSwitchesTheOtherWay(t *testing.T) {
	testCases := []struct {
		name        string
		otpEnabled  bool
		form        url.Values
		wantEnabled bool
	}{
		{
			name:        "an enrolment form posted by a user who has since enrolled",
			otpEnabled:  true,
			form:        url.Values{"otpAction": {"enable"}, "password": {"P4ss!word"}, "otp": {"123456"}},
			wantEnabled: true,
		},
		{
			name:        "a disable form posted by a user who has since disabled",
			otpEnabled:  false,
			form:        url.Values{"otpAction": {"disable"}, "password": {"P4ss!word"}},
			wantEnabled: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := handlersmocks.NewHttpHelper(t)
			client := newStubApiClient(tc.otpEnabled)

			rr := httptest.NewRecorder()
			HandleOtpPost(httpHelper, client, consoleBaseURL).ServeHTTP(rr, otpPostRequest(tc.form))

			require.NotNil(t, client.updateReq, "the console asks the auth server, which decides")
			assert.Equal(t, tc.wantEnabled, client.updateReq.Enabled,
				"the console asks for what the posted form says, never the inverse of the stored state")

			assert.Equal(t, http.StatusFound, rr.Code, "the refusal reloads the page")
			assert.Equal(t, consoleBaseURL+accountOTPPath, rr.Header().Get("Location"))
			assert.Zero(t, client.enrollmentGET)
			httpHelper.AssertNotCalled(t, "RenderTemplate",
				mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// A stale enrolment form the console refuses itself, for a blank code, or the auth server refuses
// for the password before it looks at the state, is redrawn by fetching the enrolment, which the
// auth server refuses for a user who has OTP. That is the same mismatch, and it reloads the page
// rather than showing the error page.
func TestHandleOtpPost_AStaleEnrolmentFormRefusedOnItsOwnTermsReloads(t *testing.T) {
	testCases := []struct {
		name      string
		form      url.Values
		updateErr error
	}{
		{
			name: "a blank code",
			form: url.Values{"otpAction": {"enable"}, "password": {"P4ss!word"}, "otp": {""}},
		},
		{
			name:      "a wrong password",
			form:      url.Values{"otpAction": {"enable"}, "password": {"wrong"}, "otp": {"123456"}},
			updateErr: apiError("AUTHENTICATION_FAILED"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := handlersmocks.NewHttpHelper(t)
			client := newStubApiClient(true)
			client.updateErr = tc.updateErr

			rr := httptest.NewRecorder()
			HandleOtpPost(httpHelper, client, consoleBaseURL).ServeHTTP(rr, otpPostRequest(tc.form))

			if client.updateReq != nil {
				assert.True(t, client.updateReq.Enabled, "an enrolment form never asks to disable")
			}
			assert.Equal(t, http.StatusFound, rr.Code)
			assert.Equal(t, consoleBaseURL+accountOTPPath, rr.Header().Get("Location"))
			httpHelper.AssertNotCalled(t, "InternalServerError", mock.Anything, mock.Anything, mock.Anything)
			httpHelper.AssertNotCalled(t, "RenderTemplate",
				mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// A post that names neither form, or names something else, asks the auth server for nothing and
// reloads the page.
func TestHandleOtpPost_APostNamingNeitherFormChangesNothing(t *testing.T) {
	testCases := []struct {
		name       string
		otpEnabled bool
		form       url.Values
	}{
		{name: "no otpAction, OTP on", otpEnabled: true, form: url.Values{"password": {"P4ss!word"}}},
		{name: "no otpAction, OTP off", otpEnabled: false,
			form: url.Values{"password": {"P4ss!word"}, "otp": {"123456"}}},
		{name: "an otpAction naming neither", otpEnabled: true,
			form: url.Values{"otpAction": {"toggle"}, "password": {"P4ss!word"}}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := handlersmocks.NewHttpHelper(t)
			client := newStubApiClient(tc.otpEnabled)

			rr := httptest.NewRecorder()
			HandleOtpPost(httpHelper, client, consoleBaseURL).ServeHTTP(rr, otpPostRequest(tc.form))

			assert.Nil(t, client.updateReq, "nothing is asked of the auth server")
			assert.Equal(t, http.StatusFound, rr.Code)
			assert.Equal(t, consoleBaseURL+accountOTPPath, rr.Header().Get("Location"))
			httpHelper.AssertNotCalled(t, "RenderTemplate",
				mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// The auth server allows five wrong passwords per user per 15 minutes on the two-factor
// authentication change and answers the sixth 429 TOO_MANY_REQUESTS, whatever the rate limiter
// switch says. This page sent every code it did not name to the generic handler, so five mistyped
// passwords ended on the 500 page. It now redraws the form, the disable form and the enrolment
// form alike, with the console's own rate-limit sentence in the page's language, not the API's
// English one (#559 decision 10).
func TestHandleOtpPost_ARateLimitIsShownOnTheForm(t *testing.T) {
	rateLimited := &apiclient.APIError{Code: "TOO_MANY_REQUESTS",
		Message: "Too many requests. Please try again later.", StatusCode: http.StatusTooManyRequests}

	testCases := []struct {
		name       string
		otpEnabled bool
		form       url.Values
	}{
		{name: "disabling", otpEnabled: true, form: url.Values{"otpAction": {"disable"}, "password": {"wrong"}}},
		{name: "enabling", otpEnabled: false,
			form: url.Values{"otpAction": {"enable"}, "password": {"wrong"}, "otp": {"123456"}}},
	}
	languages := []struct{ name, tag, want string }{
		{"with no language", "",
			"Too many requests have come from this browser, or for this account, in a short time. Please wait a few minutes and try again."},
		{"in pt-BR", "pt-BR",
			"Chegaram muitas solicitações deste navegador, ou para esta conta, em pouco tempo. Aguarde alguns minutos e tente novamente."},
	}

	for _, tc := range testCases {
		for _, language := range languages {
			t.Run(tc.name+" "+language.name, func(t *testing.T) {
				httpHelper := handlersmocks.NewHttpHelper(t)
				handlertest.RefuseInternalServerError(t, httpHelper)
				handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/account_otp.html").Once()

				client := newStubApiClient(tc.otpEnabled)
				client.updateErr = rateLimited

				req := handlertest.Request(http.MethodPost, accountOTPPath, handlertest.WithAccessToken(),
					handlertest.WithLocale(language.tag), handlertest.WithForm(tc.form))
				HandleOtpPost(httpHelper, client, consoleBaseURL).ServeHTTP(httptest.NewRecorder(), req)

				bind := handlertest.Bind(t, httpHelper)
				assert.Equal(t, language.want, bind["error"])
				assert.Equal(t, tc.otpEnabled, bind["otpEnabled"])
				if !tc.otpEnabled {
					assert.Equal(t, testSecretKey, bind["secretKey"],
						"the enrolment form is redrawn with its seed, or the user cannot finish enrolling")
				}
			})
		}
	}
}

// OTP_CLOCK_AHEAD is the auth server refusing a code from the step after its current one, which only
// an authenticator whose clock runs ahead shows (#142). The user acts on it by fixing the device's
// time, so the page shows the API's sentence on the code field, with the QR code to retype from,
// rather than sending it to the generic error page.
func TestHandleOtpPost_AClockAheadRefusalIsShownOnTheCodeField(t *testing.T) {
	const message = "Your device's clock seems to be ahead. Check that its date and time are set automatically, then enter the code your app shows."

	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/account_otp.html").Once()

	client := newStubApiClient(false)
	client.updateErr = &apiclient.APIError{Code: "OTP_CLOCK_AHEAD", Message: message, StatusCode: http.StatusBadRequest}

	rr := httptest.NewRecorder()
	HandleOtpPost(httpHelper, client, consoleBaseURL).ServeHTTP(rr,
		otpPostRequest(url.Values{"otpAction": {"enable"}, "password": {"P4ss!word"}, "otp": {"123456"}}))

	bind := handlertest.Bind(t, httpHelper)
	assert.Equal(t, message, bind["error"])
	assert.Equal(t, "otp", bind["errorField"])
	assert.Equal(t, false, bind["otpEnabled"])
	assert.Equal(t, testBase64Image, bind["base64Image"])
	assert.Equal(t, testSecretKey, bind["secretKey"])
}

// Turning two-factor authentication on shows the set of recovery codes it created, once: in the
// response to the console's own POST, stored nowhere, so a reload of the page draws it without them
// (#257 decisions 1 and 14).
func TestHandleOtpPost_TurningOnShowsTheRecoveryCodesOnce(t *testing.T) {
	codes := []string{
		"7kq2-m9xh-4trw-b3np-j6vd-egac", "0123-4567-89ab-cdef-ghjk-mnpq",
		"rstv-wxyz-0123-4567-89ab-cdef", "ghjk-mnpq-rstv-wxyz-0123-4567",
		"89ab-cdef-ghjk-mnpq-rstv-wxyz", "aaaa-bbbb-cccc-dddd-eeee-ffff",
		"gggg-hhhh-jjjj-kkkk-mmmm-nnnn", "pppp-qqqq-rrrr-ssss-tttt-vvvv",
		"wwww-xxxx-yyyy-zzzz-0000-1111", "2222-3333-4444-5555-6666-7777",
	}
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/account_otp.html").Once()

	client := newStubApiClient(false)
	client.recoveryCodes = codes

	rr := httptest.NewRecorder()
	HandleOtpPost(httpHelper, client, consoleBaseURL).ServeHTTP(rr,
		otpPostRequest(url.Values{"otpAction": {"enable"}, "password": {"P4ss!word"}, "otp": {"123456"}}))

	assert.Empty(t, rr.Header().Get("Location"), "the page is the answer, not a redirect to one")
	bind := handlertest.Bind(t, httpHelper)
	assert.Equal(t, codes, bind["recoveryCodes"], "the set the API created, in its order")
	assert.Equal(t, true, bind["otpEnabled"], "drawn on the page of an account that now has two-factor authentication")
	assert.NotContains(t, bind, "error")
	assert.Zero(t, client.enrollmentGET, "an enrolled user is not offered another enrolment")

	// The page drawn afresh shows no codes: they were shown once.
	reload := handlersmocks.NewHttpHelper(t)
	handlertest.ExpectRender(reload, "/layouts/menu_layout.html", "/account_otp.html").Once()
	client.profile.OTPEnabled = true
	HandleOtpGet(reload, client).ServeHTTP(httptest.NewRecorder(),
		handlertest.Request(http.MethodGet, accountOTPPath, handlertest.WithAccessToken()))
	assert.NotContains(t, handlertest.Bind(t, reload), "recoveryCodes")
}

// testRecoveryCodes is a set of ten codes in the shape the auth server draws them.
var testRecoveryCodes = []string{
	"7kq2-m9xh-4trw-b3np-j6vd-egac", "0123-4567-89ab-cdef-ghjk-mnpq",
	"rstv-wxyz-0123-4567-89ab-cdef", "ghjk-mnpq-rstv-wxyz-0123-4567",
	"89ab-cdef-ghjk-mnpq-rstv-wxyz", "aaaa-bbbb-cccc-dddd-eeee-ffff",
	"gggg-hhhh-jjjj-kkkk-mmmm-nnnn", "pppp-qqqq-rrrr-ssss-tttt-vvvv",
	"wwww-xxxx-yyyy-zzzz-0000-1111", "2222-3333-4444-5555-6666-7777",
}

// The page of an account with two-factor authentication says how many of its recovery codes are
// unused, read from the auth server each time it is drawn (#257 decision 9).
func TestHandleOtpGet_ShowsHowManyRecoveryCodesAreLeft(t *testing.T) {
	for _, remaining := range []int{7, 1, 0} {
		httpHelper := handlersmocks.NewHttpHelper(t)
		handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/account_otp.html").Once()

		client := newStubApiClient(true)
		client.remaining = remaining
		HandleOtpGet(httpHelper, client).ServeHTTP(httptest.NewRecorder(),
			handlertest.Request(http.MethodGet, accountOTPPath, handlertest.WithAccessToken()))

		bind := handlertest.Bind(t, httpHelper)
		assert.Equal(t, remaining, bind["recoveryCodesRemaining"])
		assert.NotContains(t, bind, "recoveryCodes", "the codes themselves are never shown again")
	}
}

// An account without an authenticator has no codes, and its page asks for no count.
func TestHandleOtpGet_AskForNoCountWithoutAnAuthenticator(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/account_otp.html").Once()

	client := newStubApiClient(false)
	HandleOtpGet(httpHelper, client).ServeHTTP(httptest.NewRecorder(),
		handlertest.Request(http.MethodGet, accountOTPPath, handlertest.WithAccessToken()))

	assert.Zero(t, client.remainingGET)
	assert.NotContains(t, handlertest.Bind(t, httpHelper), "recoveryCodesRemaining")
}

// Getting a new set sends the password alone and shows the set the auth server answered, once, in
// the response to this POST and stored nowhere (#257 decision 8).
func TestHandleOtpPost_ANewSetOfRecoveryCodesIsShownOnce(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/account_otp.html").Once()

	client := newStubApiClient(true)
	client.newSet = testRecoveryCodes

	rr := httptest.NewRecorder()
	HandleOtpPost(httpHelper, client, consoleBaseURL).ServeHTTP(rr,
		otpPostRequest(url.Values{"otpAction": {"recovery-codes"}, "password": {"P4ss!word"}}))

	assert.Empty(t, rr.Header().Get("Location"), "the page is the answer, not a redirect to one")
	require.NotNil(t, client.newSetReq)
	assert.JSONEq(t, `{"password":"P4ss!word"}`, mustJSON(t, client.newSetReq))
	assert.Nil(t, client.updateReq, "a new set leaves the authenticator as it is")
	bind := handlertest.Bind(t, httpHelper)
	assert.Equal(t, testRecoveryCodes, bind["recoveryCodes"], "the new set, in its order")
	assert.Equal(t, true, bind["otpEnabled"])
	assert.Equal(t, 10, bind["recoveryCodesRemaining"], "all ten of the new set are unused")
	assert.NotContains(t, bind, "recoveryCodesError")
	assert.NotContains(t, bind, "error")
}

// A wrong password is shown on the new-set form's password field, with the count still drawn and no
// new set; the disable form above it is left without an error.
func TestHandleOtpPost_ANewSetRefusedForThePasswordIsShownOnItsForm(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/account_otp.html").Once()

	client := newStubApiClient(true)
	client.remaining = 3
	client.newSetErr = &apiclient.APIError{Code: "AUTHENTICATION_FAILED",
		Message: "That password isn't right. Try again.", StatusCode: http.StatusBadRequest}

	HandleOtpPost(httpHelper, client, consoleBaseURL).ServeHTTP(httptest.NewRecorder(),
		otpPostRequest(url.Values{"otpAction": {"recovery-codes"}, "password": {"wrong"}}))

	bind := handlertest.Bind(t, httpHelper)
	assert.Equal(t, "That password isn't right. Try again.", bind["recoveryCodesError"])
	assert.Equal(t, 3, bind["recoveryCodesRemaining"], "the old set still stands, and its count is drawn")
	assert.Equal(t, true, bind["otpEnabled"])
	assert.NotContains(t, bind, "recoveryCodes")
	assert.NotContains(t, bind, "error", "the disable form was not the one posted")
}

// A rate limit on the new set is the console's own sentence, in the page's language.
func TestHandleOtpPost_ANewSetRateLimitedIsShownOnItsForm(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/account_otp.html").Once()

	client := newStubApiClient(true)
	client.newSetErr = &apiclient.APIError{Code: "TOO_MANY_REQUESTS",
		Message: "Too many requests. Please try again later.", StatusCode: http.StatusTooManyRequests}

	HandleOtpPost(httpHelper, client, consoleBaseURL).ServeHTTP(httptest.NewRecorder(),
		otpPostRequest(url.Values{"otpAction": {"recovery-codes"}, "password": {"wrong"}}))

	bind := handlertest.Bind(t, httpHelper)
	assert.Equal(t,
		"Too many requests have come from this browser, or for this account, in a short time. Please wait a few minutes and try again.",
		bind["recoveryCodesError"])
}

// A new-set form posted after two-factor authentication was turned off in another tab is stale: the
// page reloads and draws the account as it is now.
func TestHandleOtpPost_ANewSetForAnAccountWithoutAnAuthenticatorReloads(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)

	client := newStubApiClient(false)
	rr := httptest.NewRecorder()
	HandleOtpPost(httpHelper, client, consoleBaseURL).ServeHTTP(rr,
		otpPostRequest(url.Values{"otpAction": {"recovery-codes"}, "password": {"P4ss!word"}}))

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, consoleBaseURL+"/account/otp", rr.Header().Get("Location"))
	httpHelper.AssertNotCalled(t, "RenderTemplate",
		mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// The disable form redrawn with its refusal draws the count of the recovery codes too, since the
// page of an account with two-factor authentication always says it.
func TestHandleOtpPost_ADisableRefusalStillDrawsTheCount(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/account_otp.html").Once()

	client := newStubApiClient(true)
	client.remaining = 4
	client.updateErr = apiError("AUTHENTICATION_FAILED")

	HandleOtpPost(httpHelper, client, consoleBaseURL).ServeHTTP(httptest.NewRecorder(),
		otpPostRequest(url.Values{"otpAction": {"disable"}, "password": {"wrong"}}))

	bind := handlertest.Bind(t, httpHelper)
	assert.Equal(t, 4, bind["recoveryCodesRemaining"])
	assert.NotContains(t, bind, "recoveryCodesError")
}
