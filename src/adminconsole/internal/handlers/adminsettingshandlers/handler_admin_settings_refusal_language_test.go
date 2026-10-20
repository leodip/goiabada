package adminsettingshandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
)

// refusingSettingsApiClient panics on every call: each refusal below happens before the console
// calls the API at all.
type refusingSettingsApiClient struct{}

func (*refusingSettingsApiClient) GetSettingsEmail(context.Context, string) (*api.SettingsEmailResponse, error) {
	panic("unexpected call to GetSettingsEmail")
}

func (*refusingSettingsApiClient) SendTestEmail(context.Context, string, *api.SendTestEmailRequest) error {
	panic("unexpected call to SendTestEmail")
}

func (*refusingSettingsApiClient) UpdateSettingsEmail(context.Context, string, *api.UpdateSettingsEmailRequest) (*api.SettingsEmailResponse, error) {
	panic("unexpected call to UpdateSettingsEmail")
}

func (*refusingSettingsApiClient) GetAuditEventTypes(context.Context, string) (*api.GetAuditEventTypesResponse, error) {
	panic("unexpected call to GetAuditEventTypes")
}

func (*refusingSettingsApiClient) GetAuditLogsPaginated(context.Context, string, int, int, string, string) (*api.GetAuditLogsResponse, error) {
	panic("unexpected call to GetAuditLogsPaginated")
}

func (*refusingSettingsApiClient) GetSettingsAuditLogs(context.Context, string) (*api.SettingsAuditLogsResponse, error) {
	panic("unexpected call to GetSettingsAuditLogs")
}

func (*refusingSettingsApiClient) UpdateSettingsAuditLogs(context.Context, string, *api.UpdateSettingsAuditLogsRequest) (*api.SettingsAuditLogsResponse, error) {
	panic("unexpected call to UpdateSettingsAuditLogs")
}

// The settings pages' own refusals come from the catalog in the language the page is rendered in:
// English with no language on the request, word for word what they said before, and Portuguese
// under pt-BR (#559 decision 4).
func TestAdminSettingsPages_RefuseInThePagesLanguage(t *testing.T) {
	testCases := []struct {
		name       string
		template   string
		handler    func(httpHelper *handlersmocks.HttpHelper) http.HandlerFunc
		target     string
		form       url.Values
		english    string
		portuguese string
	}{
		{
			name:     "a test email with no destination",
			template: "/admin_settings_email_sendtest.html",
			handler: func(h *handlersmocks.HttpHelper) http.HandlerFunc {
				return HandleEmailSendTestPost(h, nil, &refusingSettingsApiClient{}, consoleBaseURL)
			},
			target:     "/admin/settings/email/send-test-email",
			form:       url.Values{"destinationEmail": {""}},
			english:    "Destination email is required.",
			portuguese: "O e-mail de destino é obrigatório.",
		},
		{
			name:     "a retention that is not a number",
			template: "/admin_settings_audit_logs.html",
			handler: func(h *handlersmocks.HttpHelper) http.HandlerFunc {
				return HandleAuditLogsPost(h, nil, &refusingSettingsApiClient{}, consoleBaseURL)
			},
			target:     "/admin/settings/audit-logs",
			form:       url.Values{"auditLogRetentionDays": {"ninety"}},
			english:    "Enter the retention as a whole number of days.",
			portuguese: "Informe a retenção como um número inteiro de dias.",
		},
	}

	for _, testCase := range testCases {
		for _, language := range []struct{ name, tag, want string }{
			{"with no language", "", testCase.english},
			{"in pt-BR", "pt-BR", testCase.portuguese},
		} {
			t.Run(testCase.name+" "+language.name, func(t *testing.T) {
				httpHelper := handlersmocks.NewHttpHelper(t)
				handlertest.RefuseInternalServerError(t, httpHelper)
				handlertest.ExpectRender(httpHelper, mock.Anything, testCase.template).Once()

				req := handlertest.Request(http.MethodPost, testCase.target,
					handlertest.WithAccessToken(), handlertest.WithLocale(language.tag),
					handlertest.WithForm(testCase.form))
				testCase.handler(httpHelper).ServeHTTP(httptest.NewRecorder(), req)

				assert.Equal(t, language.want, handlertest.Bind(t, httpHelper)["error"])
			})
		}
	}
}
