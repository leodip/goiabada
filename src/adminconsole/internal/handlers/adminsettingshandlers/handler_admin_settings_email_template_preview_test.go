package adminsettingshandlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	handlersmocks "github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/httpmw"
	"github.com/leodip/goiabada/core/oauth"
)

// The editor's preview and Send test email (#818 decisions 11 and 12): the text in the form, saved
// or not, goes to the admin API's preview, whose subject and plain-text part the editor shows and
// whose HTML the one framed route answers as a document of its own, and to its test send.

const (
	previewAuthServerOrigin = "https://auth.example:8443"

	// framePolicy is the framed route's Content-Security-Policy, written out here as the agreement
	// states it: nothing is loaded but images from the auth server, style attributes are the one
	// style admitted, no form or base address works, only the console may frame it, and it runs
	// sandboxed whoever loads it.
	framePolicy = "default-src 'none'; style-src-attr 'unsafe-inline'; img-src https://auth.example:8443; " +
		"base-uri 'none'; form-action 'none'; frame-ancestors 'self'; sandbox"

	// consoleDefaultPolicy is what every other console response carries, as
	// server_security_headers_test.go states it.
	consoleDefaultPolicy = "script-src 'self'; style-src 'self' https://auth.example:8443; " +
		"img-src 'self' data: https://auth.example:8443; font-src 'self' https://auth.example:8443; " +
		"object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
)

func brandId(id int64) *int64 { return &id }

func previewRequest(target, email, language, body string, options ...handlertest.Option) *http.Request {
	options = append([]handlertest.Option{handlertest.WithBody(strings.NewReader(body)),
		handlertest.WithContentType("application/json")}, options...)
	return emailTemplateRequest(http.MethodPost, target, email, language, options...)
}

// The preview sends the text in the form, the subject and the button label trimmed as a save sends
// them and the body as typed, with the brand chosen, to the email and the language the address
// names, and answers the subject and the plain-text part the editor shows beside the frame.
func TestHandleEmailTemplatePreviewPost_AnswersTheSubjectAndThePlainText(t *testing.T) {
	fake := &fakeEmailTemplatesAPI{email: passwordResetLink(), preview: &api.PreviewEmailTemplateResponse{
		Subject: "Mot de passe oublié ?", Html: "<!DOCTYPE html><html><head></head><body>Bonjour Jane Doe</body></html>",
		Text: "Bonjour Jane Doe,\n\nhttps://example.invalid/sample-link"}}
	rec := httptest.NewRecorder()

	HandleEmailTemplatePreviewPost(render.New(nil, nil), fake).ServeHTTP(rec, previewRequest(
		"/admin/settings/email/templates/password_reset_link/fr/preview", "password_reset_link", "fr",
		`{"subject":"  Mot de passe oublié ?  ","buttonLabel":" Réinitialiser ","body":"Bonjour {{name}},\r\n\r\n{{link}}\r\n","brandId":4}`))

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "password_reset_link", fake.previewedEmail)
	assert.Equal(t, "fr", fake.previewedLang)
	assert.Equal(t, &api.PreviewEmailTemplateRequest{Subject: "Mot de passe oublié ?", ButtonLabel: "Réinitialiser",
		Body: "Bonjour {{name}},\r\n\r\n{{link}}\r\n", BrandId: brandId(4)}, fake.previewed)
	assert.JSONEq(t, `{"subject":"Mot de passe oublié ?","text":"Bonjour Jane Doe,\n\nhttps://example.invalid/sample-link"}`,
		rec.Body.String(), "the HTML is the framed route's to answer")
}

// With no brand chosen the preview is drawn in the default brand, which the API picks when it is
// sent none.
func TestHandleEmailTemplatePreviewPost_NoBrandIsTheDefaultBrand(t *testing.T) {
	fake := &fakeEmailTemplatesAPI{email: passwordResetLink(), preview: &api.PreviewEmailTemplateResponse{Subject: "S", Text: "T"}}

	HandleEmailTemplatePreviewPost(render.New(nil, nil), fake).ServeHTTP(httptest.NewRecorder(), previewRequest(
		"/x", "password_reset_link", "fr", `{"subject":"S","body":"{{link}}"}`))

	require.NotNil(t, fake.previewed)
	assert.Nil(t, fake.previewed.BrandId)
}

// A text a save would refuse is refused by the preview with the API's sentence, as JSON, which the
// editor shows where the preview is.
func TestHandleEmailTemplatePreviewPost_ARefusalIsAnsweredAsJSON(t *testing.T) {
	fake := &fakeEmailTemplatesAPI{email: passwordResetLink(), writeErr: &apiclient.APIError{
		Code: "handler.email_template.unknown_placeholder", Message: "Le corps utilise {{nom}}, que cet e-mail ne propose pas.",
		StatusCode: http.StatusBadRequest, Field: "/body"}}
	rec := httptest.NewRecorder()

	HandleEmailTemplatePreviewPost(render.New(nil, nil), fake).ServeHTTP(rec, previewRequest(
		"/x", "password_reset_link", "fr", `{"subject":"S","body":"{{nom}}"}`))

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var answer map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &answer))
	assert.Equal(t, "Le corps utilise {{nom}}, que cet e-mail ne propose pas.", answer["error_description"])
}

// The framed route answers the email's HTML as a document of its own, under a policy stricter than
// any console page's but for style attributes, which the console alone may frame; the frame's
// links open nothing, since the sandbox opens no new window. It overrides what the console's
// SecurityHeaders set for every other answer.
func TestHandleEmailTemplatePreviewFramePost_AnswersTheEmailAsADocumentOfItsOwn(t *testing.T) {
	const html = "<!DOCTYPE html>\n<html lang=\"fr\">\n\n<head>\n  <meta charset=\"UTF-8\">\n  <title>Mot de passe oublié ?</title>\n</head>\n" +
		"<body style=\"margin: 0;\"><p>Bonjour Jane Doe,</p><a href=\"https://example.invalid/sample-link\">lien</a></body>\n</html>"
	fake := &fakeEmailTemplatesAPI{email: passwordResetLink(), preview: &api.PreviewEmailTemplateResponse{Subject: "S", Html: html, Text: "T"}}
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handler := httpmw.SecurityHeaders(false, previewAuthServerOrigin)(
		HandleEmailTemplatePreviewFramePost(httpHelper, fake, []string{previewAuthServerOrigin}))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, emailTemplateRequest(http.MethodPost, "/admin/settings/email/templates/password_reset_link/fr/preview-frame",
		"password_reset_link", "fr", handlertest.WithForm(url.Values{
			"subject": {"  Mot de passe oublié ?  "}, "buttonLabel": {" Réinitialiser "},
			"body": {"Bonjour {{name}},\r\n\r\n{{link}}"}, "brandId": {"4"},
		})))

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, []string{framePolicy}, rec.Header().Values("Content-Security-Policy"))
	assert.Equal(t, []string{"SAMEORIGIN"}, rec.Header().Values("X-Frame-Options"))
	assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "same-origin", rec.Header().Get("Referrer-Policy"))
	assert.Equal(t, "text/html; charset=utf-8", rec.Header().Get("Content-Type"))
	assert.Equal(t, "<!DOCTYPE html>\n<html lang=\"fr\">\n\n<head><base target=\"_blank\">\n  <meta charset=\"UTF-8\">\n  <title>Mot de passe oublié ?</title>\n</head>\n"+
		"<body style=\"margin: 0;\"><p>Bonjour Jane Doe,</p><a href=\"https://example.invalid/sample-link\">lien</a></body>\n</html>",
		rec.Body.String(), "the email as the API drew it, its links opening a window the sandbox refuses")

	assert.Equal(t, "password_reset_link", fake.previewedEmail)
	assert.Equal(t, "fr", fake.previewedLang)
	assert.Equal(t, &api.PreviewEmailTemplateRequest{Subject: "Mot de passe oublié ?", ButtonLabel: "Réinitialiser",
		Body: "Bonjour {{name}},\r\n\r\n{{link}}", BrandId: brandId(4)}, fake.previewed)
}

// Every other console answer keeps the console's own headers: the framed route's policy is set on
// its own answers only.
func TestHandleEmailTemplatePreviewFramePost_OtherAnswersKeepTheConsolesHeaders(t *testing.T) {
	handler := httpmw.SecurityHeaders(false, previewAuthServerOrigin)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/admin/settings/email/templates/password_reset_link/fr/preview", nil))

	assert.Equal(t, []string{consoleDefaultPolicy}, rec.Header().Values("Content-Security-Policy"))
	assert.Equal(t, "DENY", rec.Header().Get("X-Frame-Options"))
}

// A text the API refuses, which the editor's JSON preview has already said, leaves the frame
// empty rather than drawing the console's page in it; the answer keeps the frame's own policy.
func TestHandleEmailTemplatePreviewFramePost_ARefusalLeavesTheFrameEmpty(t *testing.T) {
	fake := &fakeEmailTemplatesAPI{email: passwordResetLink(), writeErr: &apiclient.APIError{
		Code: "handler.email_template.unknown_placeholder", Message: "Le corps utilise {{nom}}.",
		StatusCode: http.StatusBadRequest, Field: "/body"}}
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	rec := httptest.NewRecorder()

	HandleEmailTemplatePreviewFramePost(httpHelper, fake, []string{previewAuthServerOrigin}).ServeHTTP(rec,
		emailTemplateRequest(http.MethodPost, "/x", "password_reset_link", "fr", handlertest.WithForm(url.Values{
			"subject": {"S"}, "body": {"{{nom}}"},
		})))

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Empty(t, rec.Body.String())
	assert.Equal(t, framePolicy, rec.Header().Get("Content-Security-Policy"))
	require.NotNil(t, fake.previewed)
	assert.Nil(t, fake.previewed.BrandId, "no brand chosen is the default brand")
}

// Send test email sends the text in the form, saved or not, to the address typed, in the brand
// chosen for the preview, and answers the sentence the editor shows: the address it went to, and
// that it went unencrypted when it did.
func TestHandleEmailTemplateSendTestPost_SendsTheTextAndSaysWhereItWent(t *testing.T) {
	for name, tc := range map[string]struct {
		encrypted bool
		want      string
	}{
		"over TLS": {true, "E-mail de teste enviado para jane@example.com."},
		"unencrypted": {false, "E-mail de teste enviado para jane@example.com. Ele foi enviado sem criptografia: o servidor SMTP " +
			"não ofereceu STARTTLS, ou a mudança para TLS falhou. O log do servidor de autenticação registra o motivo."},
	} {
		t.Run(name, func(t *testing.T) {
			fake := &fakeEmailTemplatesAPI{email: passwordResetLink(), sendTestAnswer: &api.SendTestEmailResponse{Success: true, Encrypted: tc.encrypted}}
			rec := httptest.NewRecorder()

			HandleEmailTemplateSendTestPost(render.New(nil, nil), fake).ServeHTTP(rec, previewRequest(
				"/admin/settings/email/templates/password_reset_link/pt-BR/send-test", "password_reset_link", "pt-BR",
				`{"to":" jane@example.com ","subject":" Senha ","buttonLabel":" Redefinir ","body":"Olá {{name}},\n\n{{link}}","brandId":4}`,
				handlertest.WithLocale("pt-BR")))

			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			assert.Equal(t, "password_reset_link", fake.sentTestEmail)
			assert.Equal(t, "pt-BR", fake.sentTestLang)
			assert.Equal(t, &api.SendTestEmailTemplateRequest{To: "jane@example.com", Subject: "Senha", ButtonLabel: "Redefinir",
				Body: "Olá {{name}},\n\n{{link}}", BrandId: brandId(4)}, fake.sentTest)
			var answer map[string]any
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &answer))
			assert.Equal(t, tc.want, answer["message"])
		})
	}
}

// A send the API refuses, a text a save would refuse, SMTP off or a failed send, is answered as
// JSON with the API's sentence.
func TestHandleEmailTemplateSendTestPost_ARefusalIsAnsweredAsJSON(t *testing.T) {
	fake := &fakeEmailTemplatesAPI{email: passwordResetLink(), writeErr: &apiclient.APIError{
		Code: "SEND_FAILED", Message: "The SMTP server refused the message.", StatusCode: http.StatusBadRequest}}
	rec := httptest.NewRecorder()

	HandleEmailTemplateSendTestPost(render.New(nil, nil), fake).ServeHTTP(rec, previewRequest(
		"/x", "password_reset_link", "fr", `{"to":"jane@example.com","subject":"S","body":"{{link}}"}`))

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "The SMTP server refused the message.")
}

// The editor draws the preview's brand selector from every brand, the default one named in the
// first choice, and fills Send test email's address with the signed-in administrator's own; with
// SMTP off the send is disabled.
func TestHandleEmailTemplateGet_BindsThePreviewAndTheTestSend(t *testing.T) {
	for _, smtpEnabled := range []bool{true, false} {
		fake := &fakeEmailTemplatesAPI{email: passwordResetLink(), brands: []api.BrandResponse{
			{Id: 1, Name: "Goiabada", IsDefault: true}, {Id: 4, Name: "Acme"},
		}}
		httpHelper := handlersmocks.NewHttpHelper(t)
		handlertest.RefuseInternalServerError(t, httpHelper)
		handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_settings_email_template.html").Once()

		HandleEmailTemplateGet(httpHelper, newSettingsTestStore(), fake).ServeHTTP(httptest.NewRecorder(),
			emailTemplateRequest(http.MethodGet, "/admin/settings/email/templates/password_reset_link/fr", "password_reset_link", "fr",
				handlertest.WithJwtInfo(oauthclient.JwtInfo{
					TokenResponse: oauth.TokenResponse{AccessToken: handlertest.AccessToken},
					IdToken:       &oauth.JwtToken{Claims: jwt.MapClaims{"email": "admin@example.com"}},
				}),
				handlertest.WithSettings(&api.PublicSettingsResponse{AppName: "Test", SMTPEnabled: smtpEnabled})))

		bind := handlertest.Bind(t, httpHelper)
		assert.Equal(t, []BrandOption{{Id: 1, Name: "Goiabada"}, {Id: 4, Name: "Acme"}}, bind["brands"])
		assert.Equal(t, "Goiabada", bind["defaultBrandName"])
		assert.Equal(t, "admin@example.com", bind["testAddress"])
		assert.Equal(t, smtpEnabled, bind["smtpEnabled"])
	}
}
