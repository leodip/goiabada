package renderintegration

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers/adminsettingshandlers"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/sessionkeys"
	web "github.com/leodip/goiabada/adminconsole/web"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/leodip/goiabada/core/sessionstore/sessiontest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The Email templates tab (#818 decision 14), drawn by the real handlers, templates, funcmap and
// layout, in pt-BR, from the DTOs the API client hands the handlers.

// emailTemplatesAPI is the auth server as the email templates pages reach it: the list, one email,
// and a save it refuses.
type emailTemplatesAPI struct {
	list    []api.EmailTemplateSummaryResponse
	email   *api.EmailTemplateResponse
	refusal error
}

func (a *emailTemplatesAPI) GetEmailTemplates(context.Context, string) ([]api.EmailTemplateSummaryResponse, error) {
	return a.list, nil
}

func (a *emailTemplatesAPI) GetEmailTemplate(context.Context, string, string) (*api.EmailTemplateResponse, error) {
	return a.email, nil
}

func (a *emailTemplatesAPI) SaveEmailTemplate(context.Context, string, string, string,
	*api.SaveEmailTemplateRequest) (*api.EmailTemplateLanguageResponse, error) {
	return nil, a.refusal
}

func (a *emailTemplatesAPI) ResetEmailTemplate(context.Context, string, string, string) error {
	return a.refusal
}

func emailTemplatesStore(t *testing.T) sessionstore.Store {
	t.Helper()
	store, err := sessionstore.NewServerSideStore(sessiontest.NewMemoryBackend(), sessionkeys.JWT, false,
		sessionstore.BrowserSessionCookie, sessionstore.KeyPair{
			AuthenticationKey: []byte("12345678901234567890123456789012"),
			EncryptionKey:     []byte("abcdefghijklmnopqrstuvwxyz123456"),
		}, nil)
	require.NoError(t, err)
	return store
}

// summary is one email as the list gives it, every language at the built-in text but those named.
func summary(id string, statuses map[string]string) api.EmailTemplateSummaryResponse {
	s := api.EmailTemplateSummaryResponse{Id: id}
	for _, tag := range []string{"en", "de", "es", "fr", "it", "pt-BR"} {
		status := "default"
		if named, ok := statuses[tag]; ok {
			status = named
		}
		s.Languages = append(s.Languages, api.EmailTemplateLanguageStatusResponse{Language: tag, Status: status})
	}
	return s
}

// The nineteen emails as the API lists them.
func allEmailSummaries() []api.EmailTemplateSummaryResponse {
	ids := []string{"password_reset_link", "activation_link", "welcome", "registration_existing_account", "new_user_setup",
		"verification_code", "test", "email_address_changed", "password_changed", "password_changed_by_administrator",
		"password_reset", "otp_enabled", "otp_disabled", "otp_disabled_by_administrator", "otp_lockout",
		"recovery_code_used", "recovery_codes_replaced", "account_deleted", "account_deleted_by_administrator"}
	list := make([]api.EmailTemplateSummaryResponse, 0, len(ids))
	for _, id := range ids {
		switch id {
		case "password_reset_link":
			list = append(list, summary(id, map[string]string{"fr": "edited", "pt-BR": "invalid"}))
		case "welcome":
			list = append(list, summary(id, map[string]string{"de": "edited"}))
		default:
			list = append(list, summary(id, nil))
		}
	}
	return list
}

// rowOf answers the table row whose first cell links to the email named.
func rowOf(t *testing.T, out, email string) string {
	t.Helper()
	row := regexp.MustCompile(`(?s)<tr>\s*<td[^>]*>\s*<a class="text-link" href="/admin/settings/email/templates/` +
		regexp.QuoteMeta(email) + `">.*?</tr>`).FindString(out)
	require.NotEmpty(t, row, "a row links to %s", email)
	return row
}

// The list is the third tab under Email: the nineteen emails in their six groups, each named, with
// the sentence saying when it is sent, a tag for each edited language and "Needs attention" for an
// invalid one, and the link to Branding for how they look.
func TestRender_AdminSettingsEmailTemplates(t *testing.T) {
	out := servePage(t, adminsettingshandlers.HandleEmailTemplatesGet(render.New(web.TemplateFS(), web.StaticFS()),
		&emailTemplatesAPI{list: allEmailSummaries()}), http.MethodGet, "/admin/settings/email/templates")

	assert.Contains(t, out, `<a class="tab-item" href="/admin/settings/email">Configuração</a>`)
	assert.Contains(t, out, `<a class="tab-item" href="/admin/settings/email/send-test-email">Enviar e-mail de teste</a>`)
	assert.Contains(t, out, `<a class="tab-item" href="/admin/settings/email/templates" aria-current="page">Modelos de e-mail</a>`)
	assert.Contains(t, out, `href="/admin/settings/email" aria-current="page"`, "the sidebar marks Email")
	assert.Contains(t, out, `<a class="text-link" href="/admin/settings/branding">Ir para Marca</a>`)

	var headings []string
	for _, m := range regexp.MustCompile(`<h2 class="panel-title" id="emailGroup-[a-z_]+">([^<]+)</h2>`).FindAllStringSubmatch(out, -1) {
		headings = append(headings, m[1])
	}
	assert.Equal(t, []string{"Cadastro", "Senha", "Verificação de e-mail", "Autenticação de dois fatores", "Conta", "E-mail de teste"}, headings)
	assert.Equal(t, 19, strings.Count(out, `<a class="text-link" href="/admin/settings/email/templates/`), "every email is listed once")

	reset := rowOf(t, out, "password_reset_link")
	assert.Contains(t, reset, ">Link de redefinição de senha</a>")
	assert.Contains(t, reset, "Enviado quando alguém pede para redefinir uma senha esquecida.")
	assert.Contains(t, reset, `<span class="tag tag-note">français (French)</span>`)
	assert.Contains(t, reset, `<span class="tag tag-caution">português (Brasil) (Portuguese (Brazil)): requer atenção</span>`)
	assert.NotContains(t, reset, "English", "a language at the built-in text has no tag")

	welcome := rowOf(t, out, "welcome")
	assert.Contains(t, welcome, `<span class="tag tag-note">Deutsch (German)</span>`)
	assert.NotContains(t, welcome, "tag-caution")

	plain := rowOf(t, out, "otp_lockout")
	assert.Contains(t, plain, ">Autenticador desativado</a>")
	assert.Contains(t, plain, "Texto integrado")
	assert.NotContains(t, plain, `class="tag`)
}

// emailTemplate is the password reset link email as the API reads it: a button, five placeholders,
// French edited and Brazilian Portuguese invalid.
func emailTemplate() *api.EmailTemplateResponse {
	builtIn := api.EmailTemplateTextResponse{Subject: "Redefinição de senha", ButtonLabel: strPtr("Redefinir senha"),
		Body: "Olá {{name}},\n\n{{button}}\n\n{{link}}"}
	language := func(tag, status string) api.EmailTemplateLanguageResponse {
		return api.EmailTemplateLanguageResponse{Language: tag, Status: status, BuiltInText: builtIn, EditorText: builtIn,
			EditedFields: []string{}, Problems: []api.EmailTemplateProblemResponse{}}
	}
	ptBR := language("pt-BR", "invalid")
	ptBR.EditorText = api.EmailTemplateTextResponse{Subject: "Sua senha <b>", ButtonLabel: strPtr("Redefinir"),
		Body: "Olá {{nome}},\n\n<script>alert(1)</script>"}
	ptBR.EditedFields = []string{"subject", "buttonLabel", "body"}
	ptBR.Problems = []api.EmailTemplateProblemResponse{
		{Field: "body", Rule: "unknown_placeholder", Placeholder: "nome", Message: "O corpo usa {{nome}}, que este e-mail não oferece."},
		{Field: "body", Rule: "required_placeholder_missing", Placeholder: "link", Message: "O corpo precisa de {{link}}."},
	}
	return &api.EmailTemplateResponse{
		Id: "password_reset_link", HasButton: true,
		Placeholders: []api.EmailTemplatePlaceholderResponse{
			{Name: "app_name", InSubject: true}, {Name: "name", InSubject: true}, {Name: "link", Required: true},
			{Name: "button"}, {Name: "expiry", InSubject: true},
		},
		Languages: []api.EmailTemplateLanguageResponse{
			language("en", "default"), language("de", "default"), language("es", "default"),
			language("fr", "edited"), language("it", "default"), ptBR,
		},
	}
}

func strPtr(s string) *string { return &s }

func serveEditor(t *testing.T, apiClient *emailTemplatesAPI, language string) string {
	t.Helper()
	return servePage(t, adminsettingshandlers.HandleEmailTemplateGet(render.New(web.TemplateFS(), web.StaticFS()),
		emailTemplatesStore(t), apiClient), http.MethodGet, "/admin/settings/email/templates/"+apiClient.email.Id+"/"+language,
		handlertest.WithPathValue("email", apiClient.email.Id), handlertest.WithPathValue("language", language))
}

// The editor of one language: the email's name and when it is sent, the six languages with the
// edited ones marked, the editor's text in the fields, escaped, a button for each placeholder, the
// required one marked, and the formatting the body takes.
func TestRender_AdminSettingsEmailTemplate(t *testing.T) {
	out := serveEditor(t, &emailTemplatesAPI{email: emailTemplate()}, "fr")

	assert.Contains(t, out, `<h1 class="page-title" id="page-title">Link de redefinição de senha</h1>`)
	assert.Contains(t, out, "Enviado quando alguém pede para redefinir uma senha esquecida.")
	assert.Contains(t, out, `href="/admin/settings/email/templates">`, "the eyebrow links back to the list")
	assert.Contains(t, out, `href="/admin/settings/email" aria-current="page"`, "the sidebar marks Email")

	nav := regexp.MustCompile(`(?s)<nav class="tab-bar" id="emailTemplateLanguages".*?</nav>`).FindString(out)
	require.NotEmpty(t, nav, "the language selector is drawn")
	assert.Contains(t, nav, `aria-label="Idioma"`)
	assert.Equal(t, 6, strings.Count(nav, `class="tab-item"`))
	assert.Contains(t, nav, `href="/admin/settings/email/templates/password_reset_link/fr" aria-current="page">français (French) <span class="tag tag-note">Editado</span></a>`)
	assert.Contains(t, nav, `href="/admin/settings/email/templates/password_reset_link/pt-BR">português (Brasil) (Portuguese (Brazil)) <span class="tag tag-caution">Requer atenção</span></a>`)
	assert.Contains(t, nav, `href="/admin/settings/email/templates/password_reset_link/en">English</a>`)

	assert.Contains(t, out, `<form class="panel" id="emailTemplateForm" method="post" action="/admin/settings/email/templates/password_reset_link/fr" novalidate>`)
	assert.Regexp(t, `<input class="control" id="subject" type="text" name="subject" value="Redefinição de senha"`, out)
	assert.Regexp(t, `<input class="control" id="buttonLabel" type="text" name="buttonLabel" value="Redefinir senha"`, out)
	assert.Contains(t, out, ">Olá {{name}},\n\n{{button}}\n\n{{link}}</textarea>")
	assert.Contains(t, out, `data-placeholder="link" data-in-subject="false"`)
	assert.Contains(t, out, `data-placeholder="app_name" data-in-subject="true"`)
	assert.Equal(t, 5, strings.Count(out, `data-placeholder="`), "a button for each placeholder the email offers")
	assert.Regexp(t, `(?s)data-placeholder="link"[^>]*>\s*<span class="font-mono">\{\{link\}\}</span>\s*<span class="cell-secondary">obrigatório</span>`, out)
	assert.NotRegexp(t, `(?s)data-placeholder="name"[^>]*>\s*<span class="font-mono">\{\{name\}\}</span>\s*<span class="cell-secondary">`, out)
	assert.Contains(t, out, "**negrito**, *itálico*, [texto do link](endereço)")
	assert.Contains(t, out, `src="/static/pages/email-template-editor.js`)
	assert.Contains(t, out, `<script type="application/json" id="emailTemplateSaved">`)

	assert.Contains(t, out, `action="/admin/settings/email/templates/password_reset_link/fr/reset" data-confirm-dialog="confirmReset"`,
		"an edited language can be reset, asked first")
	assert.Contains(t, out, `id="confirmReset_modalDialog"`)
	assert.Contains(t, out, `id="discardChanges_modalDialog"`)
	assert.NotContains(t, out, `id="emailTemplateProblems"`, "a valid edit has no warning")
}

// A language at the built-in text has nothing to reset, and an email without a button no label.
func TestRender_AdminSettingsEmailTemplate_TheBuiltInTextOfAnEmailWithoutAButton(t *testing.T) {
	email := emailTemplate()
	email.Id, email.HasButton = "account_deleted", false
	email.Placeholders = email.Placeholders[:2]
	for i := range email.Languages {
		email.Languages[i].EditorText.ButtonLabel = nil
		email.Languages[i].BuiltInText.ButtonLabel = nil
	}
	out := serveEditor(t, &emailTemplatesAPI{email: email}, "en")

	assert.Contains(t, out, `<h1 class="page-title" id="page-title">Conta excluída</h1>`)
	assert.NotContains(t, out, `id="buttonLabel"`)
	assert.NotContains(t, out, "/reset", "nothing to reset")
	assert.NotContains(t, out, "confirmReset")
}

// An invalid edit opens with the stored edit in the form, escaped, and a warning saying the built-in
// text is being sent and what is wrong, in the words a save would use; the field each problem is
// about is marked.
func TestRender_AdminSettingsEmailTemplate_AnInvalidEditNeedsAttention(t *testing.T) {
	out := serveEditor(t, &emailTemplatesAPI{email: emailTemplate()}, "pt-BR")

	warning := regexp.MustCompile(`(?s)<div class="notice notice-caution" id="emailTemplateProblems">.*?</div>`).FindString(out)
	require.NotEmpty(t, warning, "the warning is drawn")
	assert.Contains(t, warning, "por isso este e-mail está sendo enviado neste idioma com o texto integrado")
	assert.Contains(t, warning, "<li>O corpo usa {{nome}}, que este e-mail não oferece.</li>")
	assert.Contains(t, warning, "<li>O corpo precisa de {{link}}.</li>")

	assert.Contains(t, out, `value="Sua senha &lt;b&gt;"`)
	assert.Contains(t, out, ">Olá {{nome}},\n\n&lt;script&gt;alert(1)&lt;/script&gt;</textarea>")
	assert.Regexp(t, `<textarea[^>]*id="body"[^>]*aria-describedby="emailTemplateProblems bodyHint" aria-invalid="true"`, out)
	assert.NotRegexp(t, `<input[^>]*id="subject"[^>]*aria-invalid`, out, "no problem is about the subject")
	assert.Contains(t, out, `/password_reset_link/pt-BR/reset" data-confirm-dialog="confirmReset"`, "an invalid edit can be reset")
}

// A refused save is drawn on the editor with the API's sentence, the text as typed, and the field
// it names marked, described by the notice and focused.
func TestRender_AdminSettingsEmailTemplate_ARefusedSave(t *testing.T) {
	const refusal = "O assunto usa {{link}}, que o assunto não aceita."
	apiClient := &emailTemplatesAPI{email: emailTemplate(), refusal: &apiclient.APIError{
		Code: "handler.email_template.placeholder_not_in_subject", Message: refusal,
		StatusCode: http.StatusBadRequest, Field: "/subject"}}

	out := serveRefusal(t, adminsettingshandlers.HandleEmailTemplatePost(render.New(web.TemplateFS(), web.StaticFS()),
		emailTemplatesStore(t), apiClient, "https://console.example"),
		"/admin/settings/email/templates/password_reset_link/fr",
		url.Values{"subject": {"Clique {{link}}"}, "buttonLabel": {"Ir"}, "body": {"Corpo"}},
		handlertest.WithPathValue("email", "password_reset_link"), handlertest.WithPathValue("language", "fr"))

	assert.Contains(t, out, `<div class="notice notice-danger" role="alert" id="emailTemplate-error">`)
	assert.Contains(t, out, refusal)
	assert.Regexp(t, `<input class="control" id="subject" type="text" name="subject" value="Clique {{link}}"[^>]*aria-describedby="emailTemplate-error subjectHint" aria-invalid="true" autofocus>`, out)
	assert.NotRegexp(t, `<textarea[^>]*id="body"[^>]*aria-invalid`, out)
	assert.Contains(t, out, ">Corpo</textarea>")
}

// The Branding list says the emails are drawn in the brands too, and links to the email templates
// for what they say.
func TestRender_AdminSettingsBranding_LinksToTheEmailTemplates(t *testing.T) {
	out := renderMenuPageAt(t, "/admin/settings/branding", "/admin_settings_branding.html", map[string]interface{}{
		"brands": []adminsettingshandlers.BrandRow{},
	})

	assert.Contains(t, out, "Os e-mails também são exibidos nestas marcas")
	assert.Contains(t, out, `<a class="text-link" href="/admin/settings/email/templates">Ir para Modelos de e-mail</a>`)
}
