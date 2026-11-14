package adminsettingshandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	handlersmocks "github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
)

// The Email templates tab (#818 decision 14): the editor opens in the console's language, a save
// sends the language's whole text and comes back with a notice, a reset removes the edit, and a
// refusal is drawn on the form with the text as typed.

// fakeEmailTemplatesAPI is the admin API the editor calls: it answers the email it holds, records
// each write, and refuses every write with writeErr when one is set.
type fakeEmailTemplatesAPI struct {
	email    *api.EmailTemplateResponse
	writeErr error

	saved       *api.SaveEmailTemplateRequest
	savedEmail  string
	savedLang   string
	resetEmail  string
	resetLang   string
	resetCalled int
	savedCalled int

	// The preview and the test send: what each answers, and what each was sent.
	brands         []api.BrandResponse
	preview        *api.PreviewEmailTemplateResponse
	sendTestAnswer *api.SendTestEmailResponse
	previewed      *api.PreviewEmailTemplateRequest
	previewedEmail string
	previewedLang  string
	sentTest       *api.SendTestEmailTemplateRequest
	sentTestEmail  string
	sentTestLang   string
}

func (f *fakeEmailTemplatesAPI) GetAllBrands(context.Context, string) ([]api.BrandResponse, error) {
	return f.brands, nil
}

func (f *fakeEmailTemplatesAPI) PreviewEmailTemplate(_ context.Context, _ string, email, language string,
	request *api.PreviewEmailTemplateRequest) (*api.PreviewEmailTemplateResponse, error) {
	f.previewedEmail, f.previewedLang, f.previewed = email, language, request
	if f.writeErr != nil {
		return nil, f.writeErr
	}
	return f.preview, nil
}

func (f *fakeEmailTemplatesAPI) SendTestEmailTemplate(_ context.Context, _ string, email, language string,
	request *api.SendTestEmailTemplateRequest) (*api.SendTestEmailResponse, error) {
	f.sentTestEmail, f.sentTestLang, f.sentTest = email, language, request
	if f.writeErr != nil {
		return nil, f.writeErr
	}
	return f.sendTestAnswer, nil
}

func (f *fakeEmailTemplatesAPI) GetEmailTemplate(_ context.Context, _ string, email string) (*api.EmailTemplateResponse, error) {
	if f.email == nil || f.email.Id != email {
		return nil, &apiclient.APIError{Code: "NOT_FOUND", Message: "Email template not found", StatusCode: http.StatusNotFound}
	}
	return f.email, nil
}

func (f *fakeEmailTemplatesAPI) SaveEmailTemplate(_ context.Context, _ string, email, language string,
	request *api.SaveEmailTemplateRequest) (*api.EmailTemplateLanguageResponse, error) {
	f.savedCalled++
	f.savedEmail, f.savedLang, f.saved = email, language, request
	if f.writeErr != nil {
		return nil, f.writeErr
	}
	return &api.EmailTemplateLanguageResponse{Language: language, Status: api.EmailTemplateStatusEdited}, nil
}

func (f *fakeEmailTemplatesAPI) ResetEmailTemplate(_ context.Context, _ string, email, language string) error {
	f.resetCalled++
	f.resetEmail, f.resetLang = email, language
	return f.writeErr
}

func label(s string) *string { return &s }

// passwordResetLink is the password reset link email as the API reads it, with a button, an edit
// in French and the built-in text elsewhere.
func passwordResetLink() *api.EmailTemplateResponse {
	language := func(tag, status, subject string) api.EmailTemplateLanguageResponse {
		builtIn := api.EmailTemplateTextResponse{Subject: "Password reset", ButtonLabel: label("Reset password"), Body: "Hello {{name}},\n\n{{button}}\n\n{{link}}"}
		editor := builtIn
		editor.Subject = subject
		return api.EmailTemplateLanguageResponse{Language: tag, Status: status, BuiltInText: builtIn, EditorText: editor,
			EditedFields: []string{}, Problems: []api.EmailTemplateProblemResponse{}}
	}
	return &api.EmailTemplateResponse{
		Id: "password_reset_link", HasButton: true,
		Placeholders: []api.EmailTemplatePlaceholderResponse{
			{Name: "app_name", InSubject: true}, {Name: "name", InSubject: true},
			{Name: "link", Required: true}, {Name: "button"}, {Name: "expiry", InSubject: true},
		},
		Languages: []api.EmailTemplateLanguageResponse{
			language("en", "default", "Password reset"), language("de", "default", "Password reset"),
			language("es", "default", "Password reset"), language("fr", "edited", "Mot de passe oublié ?"),
			language("it", "default", "Password reset"), language("pt-BR", "default", "Password reset"),
		},
	}
}

// accountDeleted is a notice with no button.
func accountDeleted() *api.EmailTemplateResponse {
	email := passwordResetLink()
	email.Id, email.HasButton = "account_deleted", false
	email.Placeholders = []api.EmailTemplatePlaceholderResponse{{Name: "app_name", InSubject: true}, {Name: "name", InSubject: true}}
	return email
}

func emailTemplateRequest(method, target, email, language string, options ...handlertest.Option) *http.Request {
	options = append([]handlertest.Option{handlertest.WithAccessToken(), handlertest.WithPathValue("email", email)}, options...)
	if language != "" {
		options = append(options, handlertest.WithPathValue("language", language))
	}
	return handlertest.Request(method, target, options...)
}

// cookiesFrom carries the cookies a response set onto the next request, as a browser following its
// redirect does.
func cookiesFrom(req *http.Request, from *httptest.ResponseRecorder) *http.Request {
	for _, cookie := range from.Result().Cookies() {
		req.AddCookie(cookie)
	}
	return req
}

// The editor opens in the built-in language matching the one the console is read in, as an email's
// language is matched, and in English when none matches (#818 decision 14).
func TestHandleEmailTemplateOpenGet_OpensTheLanguageTheConsoleIsReadIn(t *testing.T) {
	for locale, want := range map[string]string{
		"fr":    "/admin/settings/email/templates/password_reset_link/fr",
		"pt-BR": "/admin/settings/email/templates/password_reset_link/pt-BR",
		"de":    "/admin/settings/email/templates/password_reset_link/de",
		"en":    "/admin/settings/email/templates/password_reset_link/en",
		"nl":    "/admin/settings/email/templates/password_reset_link/en",
	} {
		t.Run(locale, func(t *testing.T) {
			httpHelper := handlersmocks.NewHttpHelper(t)
			handlertest.RefuseInternalServerError(t, httpHelper)
			rec := httptest.NewRecorder()

			HandleEmailTemplateOpenGet(httpHelper, &fakeEmailTemplatesAPI{email: passwordResetLink()}, consoleBaseURL).ServeHTTP(rec,
				emailTemplateRequest(http.MethodGet, "/admin/settings/email/templates/password_reset_link", "password_reset_link", "",
					handlertest.WithLocale(locale)))

			assert.Equal(t, http.StatusFound, rec.Code)
			assert.Equal(t, consoleBaseURL+want, rec.Header().Get("Location"))
		})
	}
}

// An address naming no email, or no language of the email, is the 404 page.
func TestHandleEmailTemplateGet_AnUnknownEmailOrLanguageIsNotFound(t *testing.T) {
	for name, path := range map[string][2]string{
		"an unknown email":                  {"password_reset", "fr"},
		"a language that is not one of six": {"password_reset_link", "nl"},
		"a language tag in another case":    {"password_reset_link", "pt-br"},
	} {
		t.Run(name, func(t *testing.T) {
			httpHelper := handlersmocks.NewHttpHelper(t)
			httpHelper.On("NotFound", mock.Anything, mock.Anything).Return().Once()

			HandleEmailTemplateGet(httpHelper, newSettingsTestStore(), &fakeEmailTemplatesAPI{email: passwordResetLink()}).ServeHTTP(
				httptest.NewRecorder(), emailTemplateRequest(http.MethodGet, "/x", path[0], path[1]))

			httpHelper.AssertExpectations(t)
		})
	}
}

// A save sends the language's whole text, the subject and the button label trimmed and the body as
// typed, to the email and the language the address names, and comes back to the editor, which says
// it was saved, once.
func TestHandleEmailTemplatePost_SavesTheTextAndSaysSo(t *testing.T) {
	store := newSettingsTestStore()
	apiClient := &fakeEmailTemplatesAPI{email: passwordResetLink()}
	const pagePath = "/admin/settings/email/templates/password_reset_link/fr"

	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	rec := httptest.NewRecorder()
	HandleEmailTemplatePost(httpHelper, store, apiClient, consoleBaseURL).ServeHTTP(rec,
		emailTemplateRequest(http.MethodPost, pagePath, "password_reset_link", "fr", handlertest.WithForm(url.Values{
			"subject":     {"  Mot de passe oublié ?  "},
			"buttonLabel": {" Réinitialiser "},
			"body":        {"  Bonjour {{name}},\r\n\r\n{{button}}\r\n\r\n{{link}}\r\n"},
		})))

	require.Equal(t, http.StatusFound, rec.Code)
	assert.Equal(t, consoleBaseURL+pagePath, rec.Header().Get("Location"))
	assert.Equal(t, 1, apiClient.savedCalled)
	assert.Equal(t, "password_reset_link", apiClient.savedEmail)
	assert.Equal(t, "fr", apiClient.savedLang)
	assert.Equal(t, &api.SaveEmailTemplateRequest{
		Subject:     "Mot de passe oublié ?",
		ButtonLabel: "Réinitialiser",
		Body:        "  Bonjour {{name}},\r\n\r\n{{button}}\r\n\r\n{{link}}\r\n",
	}, apiClient.saved)

	for i, want := range []bool{true, false} {
		page := handlersmocks.NewHttpHelper(t)
		handlertest.RefuseInternalServerError(t, page)
		handlertest.ExpectRender(page, "/layouts/menu_layout.html", "/admin_settings_email_template.html").Once()
		next := cookiesFrom(emailTemplateRequest(http.MethodGet, pagePath, "password_reset_link", "fr"), rec)
		got := httptest.NewRecorder()
		HandleEmailTemplateGet(page, store, apiClient).ServeHTTP(got, next)
		assert.Equal(t, want, handlertest.Bind(t, page)["savedNotice"], "visit %d", i+1)
		rec = got
	}
}

// An email without a button sends no button label, whatever the form holds.
func TestHandleEmailTemplatePost_AnEmailWithoutAButtonSendsNoLabel(t *testing.T) {
	apiClient := &fakeEmailTemplatesAPI{email: accountDeleted()}
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)

	HandleEmailTemplatePost(httpHelper, newSettingsTestStore(), apiClient, consoleBaseURL).ServeHTTP(httptest.NewRecorder(),
		emailTemplateRequest(http.MethodPost, "/x", "account_deleted", "en", handlertest.WithForm(url.Values{
			"subject": {"Bye"}, "buttonLabel": {"Click"}, "body": {"Hello {{name}}"},
		})))

	require.NotNil(t, apiClient.saved)
	assert.Empty(t, apiClient.saved.ButtonLabel)
}

// A save to an address naming no language of the email is the 404 page, and nothing is saved.
func TestHandleEmailTemplatePost_AnUnknownLanguageSavesNothing(t *testing.T) {
	apiClient := &fakeEmailTemplatesAPI{email: passwordResetLink()}
	httpHelper := handlersmocks.NewHttpHelper(t)
	httpHelper.On("NotFound", mock.Anything, mock.Anything).Return().Once()

	HandleEmailTemplatePost(httpHelper, newSettingsTestStore(), apiClient, consoleBaseURL).ServeHTTP(httptest.NewRecorder(),
		emailTemplateRequest(http.MethodPost, "/x", "password_reset_link", "nl", handlertest.WithForm(url.Values{
			"subject": {"Hi"}, "body": {"{{link}}"},
		})))

	httpHelper.AssertExpectations(t)
	assert.Equal(t, 0, apiClient.savedCalled)
}

// A refused save is drawn on the editor with the API's sentence, the text as typed, and the field
// the refusal names, read off its error_field.
func TestHandleEmailTemplatePost_ARefusalIsDrawnOnTheFormAsTyped(t *testing.T) {
	for pointer, field := range map[string]string{"/subject": "subject", "/buttonLabel": "buttonLabel", "/body": "body", "": ""} {
		t.Run(field, func(t *testing.T) {
			apiClient := &fakeEmailTemplatesAPI{email: passwordResetLink(), writeErr: &apiclient.APIError{
				Code: "handler.email_template.unknown_placeholder", Message: "O corpo usa {{nome}}.",
				StatusCode: http.StatusBadRequest, Field: pointer}}
			httpHelper := handlersmocks.NewHttpHelper(t)
			handlertest.RefuseInternalServerError(t, httpHelper)
			handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_settings_email_template.html").Once()

			HandleEmailTemplatePost(httpHelper, newSettingsTestStore(), apiClient, consoleBaseURL).ServeHTTP(httptest.NewRecorder(),
				emailTemplateRequest(http.MethodPost, "/x", "password_reset_link", "pt-BR", handlertest.WithForm(url.Values{
					"subject": {"Senha"}, "buttonLabel": {"Redefinir"}, "body": {"Olá {{nome}}"},
				})))

			bind := handlertest.Bind(t, httpHelper)
			assert.Equal(t, "O corpo usa {{nome}}.", bind["error"])
			assert.Equal(t, field, bind["errorField"])
			assert.Equal(t, EmailTemplateText{Subject: "Senha", ButtonLabel: "Redefinir", Body: "Olá {{nome}}"}, bind["form"],
				"the form is drawn as typed")
			assert.Equal(t, EmailTemplateText{Subject: "Password reset", ButtonLabel: "Reset password",
				Body: "Hello {{name}},\n\n{{button}}\n\n{{link}}"}, bind["saved"],
				"the text saved is what leaving the page would discard the form for")
		})
	}
}

// A reset removes the language's edit and comes back to the editor, which says the built-in text
// was restored.
func TestHandleEmailTemplateResetPost_RemovesTheEditAndSaysSo(t *testing.T) {
	store := newSettingsTestStore()
	apiClient := &fakeEmailTemplatesAPI{email: passwordResetLink()}
	const pagePath = "/admin/settings/email/templates/password_reset_link/fr"

	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	rec := httptest.NewRecorder()
	HandleEmailTemplateResetPost(httpHelper, store, apiClient, consoleBaseURL).ServeHTTP(rec,
		emailTemplateRequest(http.MethodPost, pagePath+"/reset", "password_reset_link", "fr"))

	require.Equal(t, http.StatusFound, rec.Code)
	assert.Equal(t, consoleBaseURL+pagePath, rec.Header().Get("Location"))
	assert.Equal(t, 1, apiClient.resetCalled)
	assert.Equal(t, "password_reset_link", apiClient.resetEmail)
	assert.Equal(t, "fr", apiClient.resetLang)
	assert.Equal(t, 0, apiClient.savedCalled)

	page := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, page)
	handlertest.ExpectRender(page, "/layouts/menu_layout.html", "/admin_settings_email_template.html").Once()
	HandleEmailTemplateGet(page, store, apiClient).ServeHTTP(httptest.NewRecorder(),
		cookiesFrom(emailTemplateRequest(http.MethodGet, pagePath, "password_reset_link", "fr"), rec))
	bind := handlertest.Bind(t, page)
	assert.Equal(t, true, bind["resetNotice"])
	assert.Equal(t, false, bind["savedNotice"])
}

// A refused reset is drawn on the editor with the text as stored.
func TestHandleEmailTemplateResetPost_ARefusalIsDrawnOnTheEditor(t *testing.T) {
	apiClient := &fakeEmailTemplatesAPI{email: passwordResetLink(), writeErr: &apiclient.APIError{
		Code: "CONCURRENT_UPDATE", Message: "Outra alteração venceu.", StatusCode: http.StatusConflict}}
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_settings_email_template.html").Once()

	HandleEmailTemplateResetPost(httpHelper, newSettingsTestStore(), apiClient, consoleBaseURL).ServeHTTP(httptest.NewRecorder(),
		emailTemplateRequest(http.MethodPost, "/x", "password_reset_link", "fr"))

	bind := handlertest.Bind(t, httpHelper)
	assert.Equal(t, "Outra alteração venceu.", bind["error"])
	assert.Equal(t, EmailTemplateText{Subject: "Mot de passe oublié ?", ButtonLabel: "Reset password",
		Body: "Hello {{name}},\n\n{{button}}\n\n{{link}}"}, bind["form"])
}
