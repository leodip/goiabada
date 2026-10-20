package adminsettingshandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
)

// sendTestRefusedAPI refuses the test send with sendErr, and is called for nothing else.
type sendTestRefusedAPI struct {
	sendErr error
}

func (*sendTestRefusedAPI) GetSettingsEmail(context.Context, string) (*api.SettingsEmailResponse, error) {
	panic("unexpected call to GetSettingsEmail")
}

func (a *sendTestRefusedAPI) SendTestEmail(context.Context, string, *api.SendTestEmailRequest) error {
	return a.sendErr
}

func (*sendTestRefusedAPI) UpdateSettingsEmail(context.Context, string, *api.UpdateSettingsEmailRequest) (*api.SettingsEmailResponse, error) {
	panic("unexpected call to UpdateSettingsEmail")
}

// The send-test-email page routes the API's refusals on status, as every other form does. It
// routed on three codes, VALIDATION_ERROR, SMTP_NOT_ENABLED and SEND_FAILED, and sent anything else
// to the 500 page, while the API answers a malformed destination 400 validator.email.invalid_format
// and the address field is free text: that refusal, translated or not, could never be read. A 400
// or a 409 now redraws the form with the API's sentence whatever its code, a 429 with the console's
// own rate-limit sentence, and every other status keeps its answer (#559 decisions 5 and 10).
func TestHandleEmailSendTestPost_RoutesTheAPIsRefusalsOnStatus(t *testing.T) {
	const rateLimitedPortuguese = "Chegaram muitas solicitações deste navegador, ou para esta conta, em pouco tempo. Aguarde alguns minutos e tente novamente."

	testCases := []struct {
		name         string
		err          *apiclient.APIError
		wantRendered string
		wantNotFound bool
		want500      bool
	}{
		{
			name:         "a catalog-keyed 400 redraws the form with the API's sentence",
			err:          &apiclient.APIError{Code: "validator.email.invalid_format", Message: "Informe um endereço de e-mail válido.", StatusCode: http.StatusBadRequest},
			wantRendered: "Informe um endereço de e-mail válido.",
		},
		{
			name:         "a VALIDATION_ERROR 400 still redraws the form",
			err:          &apiclient.APIError{Code: "VALIDATION_ERROR", Message: "Enter the address to send the test email to.", StatusCode: http.StatusBadRequest},
			wantRendered: "Enter the address to send the test email to.",
		},
		{
			name:         "SMTP_NOT_ENABLED still redraws the form",
			err:          &apiclient.APIError{Code: "SMTP_NOT_ENABLED", Message: "SMTP is not enabled", StatusCode: http.StatusBadRequest},
			wantRendered: "SMTP is not enabled",
		},
		{
			name:         "SEND_FAILED still redraws the form",
			err:          &apiclient.APIError{Code: "SEND_FAILED", Message: "Unable to send email: connection refused", StatusCode: http.StatusBadRequest},
			wantRendered: "Unable to send email: connection refused",
		},
		{
			name:         "a 409 redraws the form with the API's sentence",
			err:          &apiclient.APIError{Code: "CONCURRENT_UPDATE", Message: "Another change won.", StatusCode: http.StatusConflict},
			wantRendered: "Another change won.",
		},
		{
			name:         "a 429 redraws the form with the console's rate-limit sentence, not the API's",
			err:          &apiclient.APIError{Code: "TOO_MANY_REQUESTS", Message: "Too many requests. Please try again later.", StatusCode: http.StatusTooManyRequests},
			wantRendered: rateLimitedPortuguese,
		},
		{
			name:         "a 404 is answered with the 404 page",
			err:          &apiclient.APIError{Code: "NOT_FOUND", Message: "Settings not found", StatusCode: http.StatusNotFound},
			wantNotFound: true,
		},
		{
			name:    "a 500 from the API stays a 500",
			err:     &apiclient.APIError{Code: "INTERNAL_SERVER_ERROR", Message: "the database is on fire", StatusCode: http.StatusInternalServerError},
			want500: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := handlersmocks.NewHttpHelper(t)
			switch {
			case tc.wantNotFound:
				httpHelper.On("NotFound", mock.Anything, mock.Anything).Return().Once()
			case tc.want500:
				httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Return().Once()
			default:
				handlertest.RefuseInternalServerError(t, httpHelper)
				handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_settings_email_sendtest.html").Once()
			}

			req := handlertest.Request(http.MethodPost, "/admin/settings/email/send-test-email",
				handlertest.WithAccessToken(), handlertest.WithLocale("pt-BR"),
				handlertest.WithForm(url.Values{"destinationEmail": {"not-an-address"}}))
			HandleEmailSendTestPost(httpHelper, nil, &sendTestRefusedAPI{sendErr: tc.err}, consoleBaseURL).
				ServeHTTP(httptest.NewRecorder(), req)

			httpHelper.AssertExpectations(t)
			if tc.wantRendered != "" {
				bind := handlertest.Bind(t, httpHelper)
				assert.Equal(t, tc.wantRendered, bind["error"])
				assert.Equal(t, "not-an-address", bind["destinationEmail"],
					"the form is redrawn with the address the administrator typed")
			}
		})
	}
}
