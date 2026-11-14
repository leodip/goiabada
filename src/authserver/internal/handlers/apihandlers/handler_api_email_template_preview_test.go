package apihandlers

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/accountvalidation"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/emaildelivery"
	accounthandlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/accounthandlers/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/render"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/web"
	"github.com/leodip/goiabada/core/errs"
)

// The admin API's preview and test send of an email template (#818 decisions 11 and 12), through
// the handlers with the real email renderer: the email a recipient would get, with the server's
// sample values, in the language the path names and the brand the request chooses; the refusals a
// save gives; and, for the test send, authserver:manage, SMTP, the send and its audit entry.

// The sample values every preview and test send are drawn with (#818 decision 11).
const (
	sampleName      = "Jane Doe"
	sampleCode      = "ABCD1234"
	sampleLink      = "https://example.invalid/sample-link"
	sampleCodesLeft = "3"
)

// chosenBrandId is the brand a request chooses, which datamocks answers as a dark Plum brand.
const chosenBrandId = int64(7)

// previewBrands is the renderer's brand reader: a light Plum default brand.
func previewBrands() *testEmailBrands {
	plum := record.NewBrand("Default", record.BrandAppearanceLight, "plum")
	return &testEmailBrands{defaultBrand: &plum}
}

func sampleRenderer() *render.Renderer {
	return render.New(web.TemplateFS(), web.StaticFS(), previewBrands())
}

// darkBrandDatabase answers chosenBrandId as a dark Plum brand.
func darkBrandDatabase(t *testing.T) *datamocks.Database {
	database := datamocks.NewDatabase(t)
	dark := record.NewBrand("Night", record.BrandAppearanceDark, "plum")
	dark.Id = chosenBrandId
	database.On("GetBrandById", mock.Anything, (*sql.Tx)(nil), chosenBrandId).Return(&dark, nil).Maybe()
	return database
}

// sampleRequest is a POST of body to the preview or the test send of email in lang, from a caller
// holding scope and reading acceptLanguage, with the settings middleware.Settings would have put
// on it.
func sampleRequest(t *testing.T, scope, email, lang, acceptLanguage string, settings *record.Settings, body map[string]any) *http.Request {
	t.Helper()
	encoded, err := json.Marshal(body)
	require.NoError(t, err)
	r := emailTemplateRequest(http.MethodPost, scope, email, lang, string(encoded))
	r = r.WithContext(reqctx.WithSettings(r.Context(), settings))
	return inRequestLanguage(r, acceptLanguage)
}

func acmeSettings() *record.Settings {
	return &record.Settings{AppName: "Acme Portal", SMTPEnabled: true}
}

func serveJSON(t *testing.T, handler http.Handler, r *http.Request) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, r)
	var body map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	return rr, body
}

func htmlDoc(t *testing.T, html string) *goquery.Document {
	t.Helper()
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	require.NoError(t, err)
	return doc
}

// --- preview -------------------------------------------------------------------------------------

// The preview is the real email: the subject, the HTML and the plain-text part the server would
// send, in the language the path names whatever the caller reads, with the sample values, the
// settings' app name and the link's real lifetime in that language.
func TestEmailTemplatePreview_AnswersTheEmailWithTheSampleValues(t *testing.T) {
	r := sampleRequest(t, "authserver:admin-read", "password_reset_link", "de", "en", acmeSettings(), map[string]any{
		"subject":     "Neues Passwort für {{app_name}}",
		"buttonLabel": "Jetzt ändern",
		"body":        "Hallo {{name}}, der Link gilt {{expiry}}:\n\n{{button}}\n\n{{link}}",
	})

	rr, body := serveJSON(t, HandleEmailTemplatePreviewPost(datamocks.NewDatabase(t), sampleRenderer()), r)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Equal(t, "Neues Passwort für Acme Portal", body["subject"])
	doc := htmlDoc(t, body["html"].(string))
	assert.Equal(t, "de", doc.Find("html").AttrOr("lang", ""))
	assert.Equal(t, "Neues Passwort für Acme Portal", doc.Find("title").Text())
	button := doc.Find("[data-email-button] a")
	assert.Equal(t, "Jetzt ändern", strings.TrimSpace(button.Text()))
	assert.Equal(t, sampleLink, button.AttrOr("href", ""))
	assert.True(t, strings.HasPrefix(body["text"].(string), "Hallo "+sampleName+", der Link gilt 5 Minuten:\n\n"+sampleLink+"\n"),
		"the plain-text part leaves the button out: %q", body["text"])
	// Drawn in the default brand, light Plum.
	assert.Equal(t, "light", doc.Find(`meta[name="color-scheme"]`).AttrOr("content", ""))
}

// Each email that offers {{expiry}} says its own link's or code's real lifetime, the verification
// code shows the sample code, and the recovery code notice the sample number of codes left, each
// in its built-in English text.
func TestEmailTemplatePreview_EachEmailsSampleValues(t *testing.T) {
	for _, tc := range []struct {
		email, subject string
		sentences      []string
	}{
		{"password_reset_link", "Password reset", []string{"The link expires in 5 minutes."}},
		{"activation_link", "Activate your account", []string{"The link expires in 5 minutes."}},
		{"new_user_setup", "Acme Portal - create a password for your new account", []string{"The link works for 24 hours."}},
		{"verification_code", "Email verification - code " + sampleCode,
			[]string{sampleCode, "The code expires in 5 minutes.", "You can enter your code here: " + sampleLink}},
		{"recovery_code_used", "A recovery code was used to sign in", []string{"Hello " + sampleName + ",", "Unused recovery codes left: " + sampleCodesLeft + "."}},
	} {
		t.Run(tc.email, func(t *testing.T) {
			builtIn := readBuiltInText(t, tc.email, "en")
			r := sampleRequest(t, "authserver:manage-settings", tc.email, "en", "", acmeSettings(), builtIn)

			rr, body := serveJSON(t, HandleEmailTemplatePreviewPost(datamocks.NewDatabase(t), sampleRenderer()), r)

			require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
			assert.Equal(t, tc.subject, body["subject"])
			for _, sentence := range tc.sentences {
				assert.Contains(t, body["text"], sentence)
			}
		})
	}
}

// The preview is drawn in the brand the request chooses, and in the default brand without one.
func TestEmailTemplatePreview_IsDrawnInTheChosenBrand(t *testing.T) {
	r := sampleRequest(t, "authserver:admin-read", "otp_enabled", "en", "", acmeSettings(), map[string]any{
		"subject": "Two-factor on", "body": "Hello {{name}}.", "brandId": chosenBrandId,
	})

	rr, body := serveJSON(t, HandleEmailTemplatePreviewPost(darkBrandDatabase(t), sampleRenderer()), r)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	doc := htmlDoc(t, body["html"].(string))
	assert.Equal(t, "dark", doc.Find(`meta[name="color-scheme"]`).AttrOr("content", ""), "the chosen brand is dark")
	assert.Equal(t, "Hello "+sampleName+".", strings.TrimSpace(body["text"].(string)))
}

func TestEmailTemplatePreview_AnUnknownBrandIsA400(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("GetBrandById", mock.Anything, (*sql.Tx)(nil), int64(99)).Return(nil, nil)
	r := sampleRequest(t, "authserver:admin-read", "otp_enabled", "en", "", acmeSettings(), map[string]any{
		"subject": "Two-factor on", "body": "Hello {{name}}.", "brandId": 99,
	})

	rr, body := serveJSON(t, HandleEmailTemplatePreviewPost(database, sampleRenderer()), r)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Equal(t, "handler.email_template.brand_not_found", body["error_code"])
	assert.Equal(t, "/brandId", body["error_field"])
	assert.Equal(t, "The brand does not exist.", body["error_description"])
}

func TestEmailTemplatePreview_ABrandThatCannotBeReadIsA500(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("GetBrandById", mock.Anything, (*sql.Tx)(nil), chosenBrandId).Return(nil, errs.New("database down"))
	r := sampleRequest(t, "authserver:admin-read", "otp_enabled", "en", "", acmeSettings(), map[string]any{
		"subject": "Two-factor on", "body": "Hello {{name}}.", "brandId": chosenBrandId,
	})

	rr, _ := serveJSON(t, HandleEmailTemplatePreviewPost(database, sampleRenderer()), r)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

// A text a save would refuse is refused by the preview with the same answer, in the caller's
// language.
func TestEmailTemplatePreview_ATextASaveWouldRefuseIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name, acceptLanguage string
		text                 map[string]any
		field, code, message string
	}{
		{"a placeholder the email does not offer", "", map[string]any{"subject": "Your code", "body": "Your code is {{otp}}."},
			"/body", "handler.email_template.unknown_placeholder",
			"This email does not offer {{otp}}. It offers {{app_name}}, {{name}}, {{code}}, {{link}}, {{expiry}}."},
		{"a required placeholder missing, in German", "de", map[string]any{"subject": "Ihr Code", "body": "Ihr Code folgt."},
			"/body", "handler.email_template.required_placeholder_missing", ""},
		{"the link in the subject", "", map[string]any{"subject": "Open {{link}}", "body": "{{code}}"},
			"/subject", "handler.email_template.placeholder_not_in_subject", ""},
		{"a button label on an email with no button", "", map[string]any{"subject": "Code", "buttonLabel": "Go", "body": "{{code}}"},
			"/buttonLabel", "handler.email_template.no_button", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := sampleRequest(t, "authserver:admin-read", "verification_code", "fr", tc.acceptLanguage, acmeSettings(), tc.text)

			rr, body := serveJSON(t, HandleEmailTemplatePreviewPost(datamocks.NewDatabase(t), sampleRenderer()), r)

			assert.Equal(t, http.StatusBadRequest, rr.Code)
			assert.Equal(t, tc.code, body["error_code"])
			assert.Equal(t, tc.field, body["error_field"])
			if tc.message != "" {
				assert.Equal(t, tc.message, body["error_description"])
			}
			if tc.acceptLanguage == "de" {
				assert.Contains(t, body["error_description"], "{{code}}")
				assert.NotContains(t, body["error_description"], "The body", "the refusal is in the caller's language")
			}
		})
	}
}

// A body with nothing to read besides the button is refused, whatever brand it is drawn in
// (#818 decision 17).
func TestEmailTemplatePreview_ABodyThatIsOnlyTheButtonIsRefused(t *testing.T) {
	r := sampleRequest(t, "authserver:admin-read", "welcome", "en", "", acmeSettings(), map[string]any{
		"subject": "Welcome", "buttonLabel": "Start", "body": "{{button}}",
	})

	rr, body := serveJSON(t, HandleEmailTemplatePreviewPost(datamocks.NewDatabase(t), sampleRenderer()), r)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Equal(t, "handler.email_template.nothing_to_read", body["error_code"])
}

func TestEmailTemplatePreview_AnUnknownEmailOrLanguageIsA404(t *testing.T) {
	for _, path := range [][2]string{{"no_such_email", "en"}, {"welcome", "fr-CA"}, {"welcome", "nl"}} {
		r := sampleRequest(t, "authserver:admin-read", path[0], path[1], "", acmeSettings(), map[string]any{"subject": "S", "body": "B"})

		rr, body := serveJSON(t, HandleEmailTemplatePreviewPost(datamocks.NewDatabase(t), sampleRenderer()), r)

		assert.Equalf(t, http.StatusNotFound, rr.Code, "%v", path)
		assert.Equalf(t, "NOT_FOUND", body["error_code"], "%v", path)
	}
}

func TestEmailTemplatePreview_ABodyThatDoesNotParseIsA400(t *testing.T) {
	r := emailTemplateRequest(http.MethodPost, "authserver:admin-read", "welcome", "en", "{not json")
	r = r.WithContext(reqctx.WithSettings(r.Context(), acmeSettings()))

	rr, body := serveJSON(t, HandleEmailTemplatePreviewPost(datamocks.NewDatabase(t), sampleRenderer()), r)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Equal(t, "INVALID_REQUEST_BODY", body["error_code"])
}

// --- test send -----------------------------------------------------------------------------------

func sendTestHandler(database *datamocks.Database, emailSender *accounthandlersmocks.EmailSender, auditLogger *handlersmocks.AuditLogger) http.Handler {
	return HandleEmailTemplateSendTestPost(database, accountvalidation.NewEmailValidator(nil), emailSender, sampleRenderer(), auditLogger)
}

// A test send sends the text in the request to the typed address, as a recipient would get it: in
// the language being edited, in the chosen brand, with the preview's sample values and nothing in
// its subject marking it as a test. It answers whether the message went over TLS, and is audited as
// sent_test_email with the email template and the language.
func TestEmailTemplateSendTest_SendsTheTextToTheAddress(t *testing.T) {
	database := darkBrandDatabase(t)
	emailSender := accounthandlersmocks.NewEmailSender(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	var sent *emaildelivery.SendEmailInput
	emailSender.On("SendEmail", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { sent = args.Get(2).(*emaildelivery.SendEmailInput) }).
		Return(emaildelivery.SendResult{Encrypted: true}, nil).Once()
	details := captureAuditDetails(auditLogger, "sent_test_email")

	r := sampleRequest(t, "authserver:manage", "password_reset_link", "it", "en", acmeSettings(), map[string]any{
		"to":          "Ana.Lima@Example.COM",
		"subject":     "Nuova password per {{app_name}}",
		"buttonLabel": "Cambia",
		"body":        "Ciao {{name}}, il link vale {{expiry}}: {{link}}\n\n{{button}}",
		"brandId":     chosenBrandId,
	})
	rr, _ := serveJSON(t, sendTestHandler(database, emailSender, auditLogger), r)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.JSONEq(t, `{"success":true,"encrypted":true}`, rr.Body.String())
	require.NotNil(t, sent)
	assert.Equal(t, "Ana.Lima@Example.COM", sent.To)
	assert.Equal(t, "Nuova password per Acme Portal", sent.Subject)
	doc := htmlDoc(t, sent.HtmlBody)
	assert.Equal(t, "it", doc.Find("html").AttrOr("lang", ""))
	assert.Equal(t, "dark", doc.Find(`meta[name="color-scheme"]`).AttrOr("content", ""))
	assert.Equal(t, "Ciao "+sampleName+", il link vale 5 minuti: "+sampleLink, strings.TrimSpace(doc.Find("main p").First().Text()))
	assert.Equal(t, "Cambia", strings.TrimSpace(doc.Find("[data-email-button] a").Text()))
	assert.Equal(t, map[string]interface{}{
		"logged_in_user": grantCaller,
		"email_digest":   lowercaseAddressDigest("ana.lima@example.com"),
		"email_template": "password_reset_link",
		"language":       "it",
	}, *details)
}

// Sending text nobody has saved to an address someone typed takes the scope a save takes (#818
// decision 12): any caller below authserver:manage is refused under the settings ceiling, sends
// nothing and leaves one administrator_change_refused record.
func TestEmailTemplateSendTest_EveryCallerBelowManageIsRefused(t *testing.T) {
	for _, scope := range []string{
		"authserver:manage-settings",
		"authserver:admin-read authserver:manage-users authserver:manage-clients authserver:manage-settings",
	} {
		t.Run(scope, func(t *testing.T) {
			emailSender := accounthandlersmocks.NewEmailSender(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			records := recordLoggedEvents(auditLogger)

			r := sampleRequest(t, scope, "otp_enabled", "en", "", acmeSettings(), map[string]any{
				"to": "admin@example.com", "subject": "Two-factor on", "body": "Hello {{name}}.",
			})
			rr := httptest.NewRecorder()
			sendTestHandler(datamocks.NewDatabase(t), emailSender, auditLogger).ServeHTTP(rr, r)

			code, description := decodeErrorEnvelope(t, rr)
			assertManageScopeRequired(t, rr, rr.Code, code, description)
			emailSender.AssertNotCalled(t, "SendEmail", mock.Anything, mock.Anything, mock.Anything)
			require.Len(t, *records, 1)
			assert.Equal(t, "administrator_change_refused", (*records)[0].event)
			assert.Equal(t, "settings", (*records)[0].details["ceiling"])
		})
	}
}

// With SMTP off a test send is refused as the SMTP test is, and nothing is sent.
func TestEmailTemplateSendTest_SMTPOffIsRefused(t *testing.T) {
	r := sampleRequest(t, "authserver:manage", "otp_enabled", "en", "", &record.Settings{AppName: "Acme Portal"}, map[string]any{
		"to": "admin@example.com", "subject": "Two-factor on", "body": "Hello {{name}}.",
	})

	rr, body := serveJSON(t, sendTestHandler(datamocks.NewDatabase(t), accounthandlersmocks.NewEmailSender(t), handlersmocks.NewAuditLogger(t)), r)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Equal(t, "SMTP_NOT_ENABLED", body["error_code"])
	assert.Equal(t, "SMTP is not enabled", body["error_description"])
}

// The request's own refusals: an address missing or not an address, a text a save would refuse,
// and a brand that is not there. Nothing is sent or audited.
func TestEmailTemplateSendTest_Refusals(t *testing.T) {
	for _, tc := range []struct {
		name        string
		request     map[string]any
		code, field string
	}{
		{"no address", map[string]any{"subject": "S", "body": "Hello {{name}}."},
			"handler.settings_email.destination_required", ""},
		{"not an address", map[string]any{"to": "not-an-address", "subject": "S", "body": "Hello {{name}}."},
			"validator.email.invalid_format", ""},
		{"a placeholder the email does not offer", map[string]any{"to": "admin@example.com", "subject": "S", "body": "Hello {{code}}."},
			"handler.email_template.unknown_placeholder", "/body"},
		{"a brand that is not there", map[string]any{"to": "admin@example.com", "subject": "S", "body": "Hello {{name}}.", "brandId": 99},
			"handler.email_template.brand_not_found", "/brandId"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			database.On("GetBrandById", mock.Anything, (*sql.Tx)(nil), int64(99)).Return(nil, nil).Maybe()
			r := sampleRequest(t, "authserver:manage", "otp_enabled", "en", "", acmeSettings(), tc.request)

			rr, body := serveJSON(t, sendTestHandler(database, accounthandlersmocks.NewEmailSender(t), handlersmocks.NewAuditLogger(t)), r)

			assert.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
			assert.Equal(t, tc.code, body["error_code"])
			if tc.field != "" {
				assert.Equal(t, tc.field, body["error_field"])
			}
		})
	}
}

// A send that fails answers the fixed message the SMTP test does, and is not audited.
func TestEmailTemplateSendTest_AFailedSendAnswersTheFixedMessage(t *testing.T) {
	emailSender := accounthandlersmocks.NewEmailSender(t)
	emailSender.On("SendEmail", mock.Anything, mock.Anything, mock.Anything).
		Return(emaildelivery.SendResult{}, leakyRelayError(errors.New("boom"))).Once()
	r := sampleRequest(t, "authserver:manage", "otp_enabled", "en", "", acmeSettings(), map[string]any{
		"to": "admin@example.com", "subject": "Two-factor on", "body": "Hello {{name}}.",
	})

	rr, body := serveJSON(t, sendTestHandler(datamocks.NewDatabase(t), emailSender, handlersmocks.NewAuditLogger(t)), r)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Equal(t, "SEND_FAILED", body["error_code"])
	assert.NotContains(t, rr.Body.String(), "192.0.2.25")
}

func TestEmailTemplateSendTest_AnUnknownEmailOrLanguageIsA404(t *testing.T) {
	for _, path := range [][2]string{{"no_such_email", "en"}, {"welcome", "pt"}} {
		r := sampleRequest(t, "authserver:manage", path[0], path[1], "", acmeSettings(), map[string]any{
			"to": "admin@example.com", "subject": "S", "body": "B",
		})

		rr, body := serveJSON(t, sendTestHandler(datamocks.NewDatabase(t), accounthandlersmocks.NewEmailSender(t), handlersmocks.NewAuditLogger(t)), r)

		assert.Equalf(t, http.StatusNotFound, rr.Code, "%v", path)
		assert.Equalf(t, "NOT_FOUND", body["error_code"], "%v", path)
	}
}
