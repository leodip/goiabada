package accounthandlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
)

// A refused code is drawn on the verification form with its sentence and the code as typed,
// whatever refused it: the code itself, email switched off since the page was drawn, or too many
// attempts, which is the user's to wait out (RFC 6585 section 4), answered the 500 page until
// #562 decision 7, and is drawn with the console's rate-limit sentence (#559 decision 10). The page is told whether email is on, so it can draw the form or not; the
// sentence is drawn either way (the template's half is in renderintegration).
func TestHandleEmailVerificationPost_ARefusalIsDrawnWithItsSentence(t *testing.T) {
	testCases := []struct {
		name        string
		smtpEnabled bool
		refusal     *apiclient.APIError
		// want is the sentence drawn, the API's own when empty.
		want string
	}{
		{
			name:        "a code the API calls expired",
			smtpEnabled: true,
			refusal:     &apiclient.APIError{Code: "INVALID_OR_EXPIRED_VERIFICATION_CODE", Message: "That code isn't right, or it has expired. Send a new one if you need to.", StatusCode: http.StatusBadRequest},
		},
		{
			name:        "email switched off since the page was drawn",
			smtpEnabled: false,
			refusal:     &apiclient.APIError{Code: "SMTP_NOT_ENABLED", Message: "SMTP is not enabled", StatusCode: http.StatusBadRequest},
		},
		{
			name:        "too many attempts",
			smtpEnabled: true,
			refusal:     &apiclient.APIError{Code: "TOO_MANY_REQUESTS", Message: "Too many requests. Please wait and try again later.", StatusCode: http.StatusTooManyRequests},
			want:        "Too many requests have come from this browser, or for this account, in a short time. Please wait a few minutes and try again.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := handlersmocks.NewHttpHelper(t)
			handlertest.RefuseInternalServerError(t, httpHelper)
			handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/account_email_verification.html").Once()

			rec := httptest.NewRecorder()
			HandleEmailVerificationPost(httpHelper, newFlashTestStore(), verificationRefusingApiClient{err: tc.refusal}, consoleBaseURL).
				ServeHTTP(rec, handlertest.Request(http.MethodPost, "/account/email-verification",
					handlertest.WithAccessToken(), handlertest.WithSettings(publicSettings(tc.smtpEnabled)),
					handlertest.WithForm(url.Values{"verificationCode": {"ABC123"}})))

			bind := handlertest.Bind(t, httpHelper)
			want := tc.want
			if want == "" {
				want = tc.refusal.Message
			}
			assert.Equal(t, want, bind["error"])
			assert.Equal(t, "ABC123", bind["verificationCode"], "the code as typed")
			assert.Equal(t, tc.smtpEnabled, bind["smtpEnabled"])
			assert.Empty(t, rec.Header().Get("Location"), "drawn again, not redirected")
		})
	}
}
