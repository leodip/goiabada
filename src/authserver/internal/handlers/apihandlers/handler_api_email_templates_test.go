package apihandlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The admin API's email templates (#818 decisions 7 to 10, 13 and 17), through the handlers with
// the generated database mock: the list and the read with each language's status, the save's
// refusals, what it stores and audits, the reset, and the settings ceiling on both writes.

// The 19 emails, by the identifiers #818 decision 6 fixes.
var emailTemplateIds = []string{
	"password_reset_link", "activation_link", "welcome", "registration_existing_account", "new_user_setup",
	"verification_code", "test",
	"email_address_changed", "password_changed", "password_changed_by_administrator", "password_reset",
	"otp_enabled", "otp_disabled", "otp_disabled_by_administrator", "otp_lockout",
	"recovery_code_used", "recovery_codes_replaced", "account_deleted", "account_deleted_by_administrator",
}

// The six built-in languages, English first.
var emailTemplateLanguages = []string{"en", "de", "es", "fr", "it", "pt-BR"}

// emailTemplateTx is the transaction a save and a reset run their write in: the write is enlisted
// in RunInTransaction, which retries a deadlock victim, and never made outside it with nil.
var emailTemplateTx = &sql.Tx{}

func nullString(s string) sql.NullString { return sql.NullString{String: s, Valid: true} }

// emailTemplateRequest is an admin API request from grantCaller holding scope, with body when it
// is not empty and the {email} and {language} path values the route would set.
func emailTemplateRequest(method, scope, email, lang, body string) *http.Request {
	r := httptest.NewRequest(method, "/api/v1/admin/email-templates", strings.NewReader(body))
	if email != "" {
		r.SetPathValue("email", email)
	}
	if lang != "" {
		r.SetPathValue("language", lang)
	}
	return setTokenContextWithClaims(r, map[string]interface{}{"scope": scope, "sub": grantCaller})
}

func serveEmailTemplate(handler http.Handler, r *http.Request) (*httptest.ResponseRecorder, map[string]any) {
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, r)
	var body map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	return rr, body
}

func saveBody(t *testing.T, subject, buttonLabel, body string) string {
	t.Helper()
	encoded, err := json.Marshal(map[string]string{"subject": subject, "buttonLabel": buttonLabel, "body": body})
	require.NoError(t, err)
	return string(encoded)
}

// languageOf is the language lang of a read's email.
func languageOf(t *testing.T, email map[string]any, lang string) map[string]any {
	t.Helper()
	for _, l := range email["languages"].([]any) {
		if l.(map[string]any)["language"] == lang {
			return l.(map[string]any)
		}
	}
	t.Fatalf("no language %s in %v", lang, email)
	return nil
}

// The built-in English password reset link email, as Goiabada ships it.
const (
	resetLinkSubjectEn = "Password reset"
	resetLinkButtonEn  = "Reset password"
	resetLinkBodyStart = "Hello {{name}},\n\nYou can reset your password by clicking the link below:\n\n{{button}}\n\n{{link}}\n\n"
)

// --- list ----------------------------------------------------------------------------------------

func TestEmailTemplatesGet_ListsEveryEmailWithEachLanguagesStatus(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("GetAllEmailTemplates", mock.Anything, (*sql.Tx)(nil)).Return([]record.EmailTemplate{
		{EmailTemplate: "password_reset_link", Language: "fr", Subject: nullString("Votre nouveau mot de passe")},
		// The welcome email offers no {{name}}, so this edit is invalid.
		{EmailTemplate: "welcome", Language: "de", Body: nullString("Hallo {{name}}, willkommen.")},
		// Rows no running release sends are not listed.
		{EmailTemplate: "retired_email", Language: "en", Subject: nullString("Old")},
		{EmailTemplate: "welcome", Language: "fr-CA", Subject: nullString("Bienvenue")},
	}, nil)

	rr, body := serveEmailTemplate(HandleEmailTemplatesGet(database), emailTemplateRequest(http.MethodGet, "authserver:admin-read", "", "", ""))

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var ids []string
	statuses := map[string]map[string]string{}
	for _, e := range body["emailTemplates"].([]any) {
		email := e.(map[string]any)
		id := email["id"].(string)
		ids = append(ids, id)
		statuses[id] = map[string]string{}
		var langs []string
		for _, l := range email["languages"].([]any) {
			lang := l.(map[string]any)
			langs = append(langs, lang["language"].(string))
			statuses[id][lang["language"].(string)] = lang["status"].(string)
		}
		assert.Equal(t, emailTemplateLanguages, langs, id)
	}
	assert.ElementsMatch(t, emailTemplateIds, ids)
	assert.Len(t, ids, 19)

	assert.Equal(t, "edited", statuses["password_reset_link"]["fr"])
	assert.Equal(t, "default", statuses["password_reset_link"]["en"])
	assert.Equal(t, "invalid", statuses["welcome"]["de"])
	assert.Equal(t, "default", statuses["welcome"]["fr"])
	assert.Equal(t, "default", statuses["test"]["pt-BR"])
}

func TestEmailTemplatesGet_AFailedReadIsA500(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("GetAllEmailTemplates", mock.Anything, (*sql.Tx)(nil)).Return(nil, errs.New("database down"))

	rr, _ := serveEmailTemplate(HandleEmailTemplatesGet(database), emailTemplateRequest(http.MethodGet, "authserver:admin-read", "", "", ""))

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

// --- read ----------------------------------------------------------------------------------------

func TestEmailTemplateGet_AnswersThePlaceholdersAndEachLanguage(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("GetAllEmailTemplates", mock.Anything, (*sql.Tx)(nil)).Return([]record.EmailTemplate{
		{EmailTemplate: "password_reset_link", Language: "fr", Subject: nullString("Votre nouveau mot de passe")},
		{EmailTemplate: "password_reset_link", Language: "de", Body: nullString("Hallo {{full_name}}.\n\n{{button}}")},
		{EmailTemplate: "welcome", Language: "en", Subject: nullString("Another email's edit")},
	}, nil)

	rr, body := serveEmailTemplate(HandleEmailTemplateGet(database),
		emailTemplateRequest(http.MethodGet, "authserver:manage-settings", "password_reset_link", "", ""))

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	email := body["emailTemplate"].(map[string]any)
	assert.Equal(t, "password_reset_link", email["id"])
	assert.Equal(t, true, email["hasButton"])
	assert.Equal(t, []any{
		map[string]any{"name": "app_name", "required": false, "inSubject": true},
		map[string]any{"name": "name", "required": false, "inSubject": true},
		map[string]any{"name": "link", "required": true, "inSubject": false},
		map[string]any{"name": "button", "required": false, "inSubject": false},
		map[string]any{"name": "expiry", "required": false, "inSubject": true},
	}, email["placeholders"])
	var langs []string
	for _, l := range email["languages"].([]any) {
		langs = append(langs, l.(map[string]any)["language"].(string))
	}
	assert.Equal(t, emailTemplateLanguages, langs)

	t.Run("a language with no edit gives the built-in text twice", func(t *testing.T) {
		en := languageOf(t, email, "en")
		assert.Equal(t, "default", en["status"])
		builtIn := en["builtInText"].(map[string]any)
		assert.Equal(t, resetLinkSubjectEn, builtIn["subject"])
		assert.Equal(t, resetLinkButtonEn, builtIn["buttonLabel"])
		assert.True(t, strings.HasPrefix(builtIn["body"].(string), resetLinkBodyStart), builtIn["body"])
		assert.Equal(t, builtIn, en["editorText"])
		assert.Equal(t, []any{}, en["editedFields"])
		assert.Equal(t, []any{}, en["problems"])
	})

	t.Run("an edit is laid over the built-in text", func(t *testing.T) {
		fr := languageOf(t, email, "fr")
		assert.Equal(t, "edited", fr["status"])
		editor := fr["editorText"].(map[string]any)
		builtIn := fr["builtInText"].(map[string]any)
		assert.Equal(t, "Votre nouveau mot de passe", editor["subject"])
		assert.Equal(t, "Réinitialiser le mot de passe", editor["buttonLabel"])
		assert.Equal(t, builtIn["body"], editor["body"])
		assert.NotEqual(t, "Votre nouveau mot de passe", builtIn["subject"])
		assert.Equal(t, []any{"subject"}, fr["editedFields"])
		assert.Equal(t, []any{}, fr["problems"])
	})

	t.Run("an invalid edit is given as stored, with its problems", func(t *testing.T) {
		de := languageOf(t, email, "de")
		assert.Equal(t, "invalid", de["status"])
		editor := de["editorText"].(map[string]any)
		assert.Equal(t, "Hallo {{full_name}}.\n\n{{button}}", editor["body"])
		assert.Equal(t, "Passwort zurücksetzen", editor["subject"])
		assert.Equal(t, []any{"body"}, de["editedFields"])
		assert.Equal(t, []any{
			map[string]any{"field": "body", "rule": "unknown_placeholder", "placeholder": "full_name",
				"message": "This email does not offer {{full_name}}. It offers {{app_name}}, {{name}}, {{link}}, {{button}}, {{expiry}}."},
			map[string]any{"field": "body", "rule": "required_placeholder_missing", "placeholder": "link",
				"message": "The body must use {{link}}, which this email cannot do without. It offers {{app_name}}, {{name}}, {{link}}, {{button}}, {{expiry}}."},
		}, de["problems"])
	})
}

func TestEmailTemplateGet_AnEmailWithoutAButtonHasNoButtonLabel(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("GetAllEmailTemplates", mock.Anything, (*sql.Tx)(nil)).Return(nil, nil)

	rr, body := serveEmailTemplate(HandleEmailTemplateGet(database),
		emailTemplateRequest(http.MethodGet, "authserver:admin-read", "password_changed", "", ""))

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	email := body["emailTemplate"].(map[string]any)
	assert.Equal(t, false, email["hasButton"])
	en := languageOf(t, email, "en")
	assert.NotContains(t, en["builtInText"], "buttonLabel")
	assert.NotContains(t, en["editorText"], "buttonLabel")
}

// A problem's sentence is in the caller's language, as a save's refusal is.
func TestEmailTemplateGet_AProblemIsInTheCallersLanguage(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("GetAllEmailTemplates", mock.Anything, (*sql.Tx)(nil)).Return([]record.EmailTemplate{
		{EmailTemplate: "password_changed", Language: "en", Subject: nullString("{{link}} changed")},
	}, nil)
	r := emailTemplateRequest(http.MethodGet, "authserver:admin-read", "password_changed", "", "")
	r = r.WithContext(i18n.WithLocale(r.Context(), true, "pt-BR"))

	rr, body := serveEmailTemplate(HandleEmailTemplateGet(database), r)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	en := languageOf(t, body["emailTemplate"].(map[string]any), "en")
	assert.Equal(t, []any{map[string]any{"field": "subject", "rule": "unknown_placeholder", "placeholder": "link",
		"message": "Este e-mail não oferece {{link}}. Ele oferece {{app_name}}, {{name}}."}}, en["problems"])
}

func TestEmailTemplateGet_AnUnknownEmailIsA404(t *testing.T) {
	for _, id := range []string{"no_such_email", "Password_Reset_Link", "password_reset_link "} {
		t.Run(id, func(t *testing.T) {
			database := datamocks.NewDatabase(t)

			rr, body := serveEmailTemplate(HandleEmailTemplateGet(database), emailTemplateRequest(http.MethodGet, "authserver:admin-read", id, "", ""))

			assert.Equal(t, http.StatusNotFound, rr.Code)
			assert.Equal(t, "NOT_FOUND", body["error_code"])
			database.AssertNotCalled(t, "GetAllEmailTemplates", mock.Anything, mock.Anything)
		})
	}
}

// --- save ----------------------------------------------------------------------------------------

func TestEmailTemplatePut_AnUnknownEmailOrLanguageIsA404(t *testing.T) {
	for _, c := range []struct{ email, lang string }{
		{"no_such_email", "en"},
		{"password_reset_link", "fr-CA"},
		{"password_reset_link", "pt-br"},
		{"password_reset_link", "EN"},
		{"password_reset_link", "nl"},
	} {
		t.Run(c.email+"/"+c.lang, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)

			rr, body := serveEmailTemplate(HandleEmailTemplatePut(database, auditLogger),
				emailTemplateRequest(http.MethodPut, "authserver:manage-settings", c.email, c.lang, "{"))

			assert.Equal(t, http.StatusNotFound, rr.Code)
			assert.Equal(t, "NOT_FOUND", body["error_code"])
			auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

func TestEmailTemplatePut_ABodyThatDoesNotParseIsA400(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	rr, body := serveEmailTemplate(HandleEmailTemplatePut(database, auditLogger),
		emailTemplateRequest(http.MethodPut, "authserver:manage", "password_reset_link", "en", "{"))

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Equal(t, "INVALID_REQUEST_BODY", body["error_code"])
}

// Each rule a save holds a text to is refused 400, naming the field in error_field and the rule in
// error_code, before anything is written or audited, and even for a caller the ceiling refuses.
func TestEmailTemplatePut_Refusals(t *testing.T) {
	const resetBody = "Hello {{name}}.\n\n{{button}}\n\n{{link}}"
	resetOffers := "It offers {{app_name}}, {{name}}, {{link}}, {{button}}, {{expiry}}."
	cases := []struct {
		name                 string
		email                string
		subject, label, body string
		code, field, message string
	}{
		{"a blank subject", "password_reset_link", " \t", "Reset", resetBody,
			"handler.email_template.subject_required", "/subject", "Subject is required."},
		{"a 201-character subject", "password_reset_link", strings.Repeat("é", 201), "Reset", resetBody,
			"handler.email_template.subject_too_long", "/subject", "The subject cannot exceed 200 characters."},
		{"a subject on two lines", "password_reset_link", "Reset\nyour password", "Reset", resetBody,
			"handler.email_template.subject_not_one_line", "/subject", "The subject must be on one line."},
		{"the link in the subject", "password_reset_link", "Open {{link}}", "Reset", resetBody,
			"handler.email_template.placeholder_not_in_subject", "/subject",
			"The subject cannot use {{link}}. In the subject, this email offers {{app_name}}, {{name}}, {{expiry}}."},
		{"a placeholder the subject's email does not offer", "password_reset_link", "Hi {{full_name}}", "Reset", resetBody,
			"handler.email_template.unknown_placeholder", "/subject", "This email does not offer {{full_name}}. " + resetOffers},
		{"a blank button label", "password_reset_link", "Reset", "  ", resetBody,
			"handler.email_template.button_label_required", "/buttonLabel", "Button label is required."},
		{"a 61-character button label", "password_reset_link", "Reset", strings.Repeat("a", 61), resetBody,
			"handler.email_template.button_label_too_long", "/buttonLabel", "The button label cannot exceed 60 characters."},
		{"a button label for an email without a button", "password_changed", "Changed", "Open", "Hello {{name}}.",
			"handler.email_template.no_button", "/buttonLabel", "This email has no button, so it takes no button label."},
		{"a body past 20,000 characters", "password_changed", "Changed", "", strings.Repeat("ü", 20_001),
			"handler.email_template.body_too_long", "/body", "The body cannot exceed 20000 characters."},
		{"a placeholder the email does not offer", "password_reset_link", "Reset", "Reset", "Hi {{full_name}}.\n\n{{link}}",
			"handler.email_template.unknown_placeholder", "/body", "This email does not offer {{full_name}}. " + resetOffers},
		{"the required link missing, the button not counting", "password_reset_link", "Reset", "Reset", "Hello.\n\n{{button}}",
			"handler.email_template.required_placeholder_missing", "/body",
			"The body must use {{link}}, which this email cannot do without. " + resetOffers},
		{"the button inside a sentence", "password_reset_link", "Reset", "Reset", "Press {{button}} now.\n\n{{link}}",
			"handler.email_template.button_not_alone", "/body", "Put {{button}} on a line of its own."},
		{"the link as part of a longer destination", "password_reset_link", "Reset", "Reset",
			"[Reset](https://example.test/?next={{link}})",
			"handler.email_template.placeholder_in_link_destination", "/body",
			"A link's address can hold a placeholder only as {{link}} on its own, the whole address. This one holds {{link}}."},
		{"nothing to read besides the button", "welcome", "Welcome", "Activate", "{{button}}",
			"handler.email_template.nothing_to_read", "/body", "The body needs something to read besides the button."},
		{"an empty list, which draws nothing to read", "password_changed", "Changed", "", "- ",
			"handler.email_template.nothing_to_read", "/body", "The body needs something to read besides the button."},
		{"the button and a link with no label whose address is dropped", "welcome", "Welcome", "Activate",
			"{{button}}\n\n[ ](relative)",
			"handler.email_template.nothing_to_read", "/body", "The body needs something to read besides the button."},
	}
	for _, c := range cases {
		for _, scope := range []string{"authserver:manage", "authserver:manage-settings"} {
			t.Run(c.name+"/"+scope, func(t *testing.T) {
				database := datamocks.NewDatabase(t)
				auditLogger := handlersmocks.NewAuditLogger(t)

				rr, body := serveEmailTemplate(HandleEmailTemplatePut(database, auditLogger),
					emailTemplateRequest(http.MethodPut, scope, c.email, "en", saveBody(t, c.subject, c.label, c.body)))

				assert.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
				assert.Equal(t, c.code, body["error_code"])
				assert.Equal(t, c.field, body["error_field"])
				assert.Equal(t, c.message, body["error_description"])
				auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
			})
		}
	}
}

func TestEmailTemplatePut_ARefusalIsInTheCallersLanguage(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	r := emailTemplateRequest(http.MethodPut, "authserver:manage", "password_changed", "de", saveBody(t, "", "", "Hallo."))
	r = r.WithContext(i18n.WithLocale(r.Context(), true, "pt-BR"))

	rr, body := serveEmailTemplate(HandleEmailTemplatePut(database, auditLogger), r)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Equal(t, "handler.email_template.subject_required", body["error_code"])
	assert.Equal(t, "O assunto é obrigatório.", body["error_description"])
}

// A save stores only the fields that differ from the built-in text of its language, audits which
// it holds, and answers the language as the read gives it.
func TestEmailTemplatePut_StoresOnlyWhatDiffersFromTheBuiltInText(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	records := recordLoggedEvents(auditLogger)
	var saved *record.EmailTemplate
	datamocks.ExpectRunInTransaction(database, emailTemplateTx)
	database.On("SaveEmailTemplate", mock.Anything, emailTemplateTx, mock.AnythingOfType("*record.EmailTemplate")).
		Run(func(args mock.Arguments) { saved = args.Get(2).(*record.EmailTemplate) }).Return(nil).Once()

	builtInBody := readBuiltInBody(t, "password_reset_link", "en")
	rr, body := serveEmailTemplate(HandleEmailTemplatePut(database, auditLogger),
		emailTemplateRequest(http.MethodPut, "authserver:manage", "password_reset_link", "en",
			saveBody(t, "Choose a new password", resetLinkButtonEn, builtInBody)))

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	require.NotNil(t, saved)
	assert.Equal(t, "password_reset_link", saved.EmailTemplate)
	assert.Equal(t, "en", saved.Language)
	assert.Equal(t, nullString("Choose a new password"), saved.Subject)
	assert.False(t, saved.ButtonLabel.Valid, "the built-in label is left to follow later releases")
	assert.False(t, saved.Body.Valid, "the built-in body is left to follow later releases")

	assert.Equal(t, "en", body["language"])
	assert.Equal(t, "edited", body["status"])
	assert.Equal(t, []any{"subject"}, body["editedFields"])
	assert.Equal(t, "Choose a new password", body["editorText"].(map[string]any)["subject"])
	assert.Equal(t, resetLinkSubjectEn, body["builtInText"].(map[string]any)["subject"])
	assert.Equal(t, []any{}, body["problems"])

	require.Len(t, *records, 1)
	assert.Equal(t, "updated_email_template", (*records)[0].event)
	assert.Equal(t, map[string]interface{}{
		"email_template": "password_reset_link",
		"language":       "en",
		"edited_fields":  []string{"subject"},
		"logged_in_user": grantCaller,
	}, (*records)[0].details)
}

func TestEmailTemplatePut_EveryFieldEdited(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	records := recordLoggedEvents(auditLogger)
	var saved *record.EmailTemplate
	datamocks.ExpectRunInTransaction(database, emailTemplateTx)
	database.On("SaveEmailTemplate", mock.Anything, emailTemplateTx, mock.AnythingOfType("*record.EmailTemplate")).
		Run(func(args mock.Arguments) { saved = args.Get(2).(*record.EmailTemplate) }).Return(nil).Once()

	rr, body := serveEmailTemplate(HandleEmailTemplatePut(database, auditLogger),
		emailTemplateRequest(http.MethodPut, "authserver:manage", "password_reset_link", "pt-BR",
			saveBody(t, "Nova senha", "Escolher", "Olá {{name}}.\n\n{{button}}\n\n{{link}}")))

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Equal(t, nullString("Nova senha"), saved.Subject)
	assert.Equal(t, nullString("Escolher"), saved.ButtonLabel)
	assert.Equal(t, nullString("Olá {{name}}.\n\n{{button}}\n\n{{link}}"), saved.Body)
	assert.Equal(t, []any{"subject", "buttonLabel", "body"}, body["editedFields"])
	require.Len(t, *records, 1)
	assert.Equal(t, []string{"subject", "button_label", "body"}, (*records)[0].details["edited_fields"])
}

// A save whose text is the built-in one removes the edit, as a reset does, and is audited as one
// when there was an edit to remove.
func TestEmailTemplatePut_TheBuiltInTextRemovesTheEdit(t *testing.T) {
	for _, existed := range []bool{true, false} {
		name := "with an edit"
		if !existed {
			name = "with none"
		}
		t.Run(name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			records := &[]loggedEvent{}
			if existed {
				records = recordLoggedEvents(auditLogger)
			}
			datamocks.ExpectRunInTransaction(database, emailTemplateTx)
			database.On("DeleteEmailTemplate", mock.Anything, emailTemplateTx, "password_changed", "it").Return(existed, nil).Once()

			rr, body := serveEmailTemplate(HandleEmailTemplatePut(database, auditLogger),
				emailTemplateRequest(http.MethodPut, "authserver:manage", "password_changed", "it",
					saveBody(t, readBuiltInSubject(t, "password_changed", "it"), "", readBuiltInBody(t, "password_changed", "it"))))

			require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
			database.AssertNotCalled(t, "SaveEmailTemplate", mock.Anything, mock.Anything, mock.Anything)
			assert.Equal(t, "default", body["status"])
			assert.Equal(t, []any{}, body["editedFields"])
			if existed {
				require.Len(t, *records, 1)
				assert.Equal(t, "reset_email_template", (*records)[0].event)
				assert.Equal(t, map[string]interface{}{
					"email_template": "password_changed", "language": "it", "logged_in_user": grantCaller,
				}, (*records)[0].details)
			} else {
				auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
			}
		})
	}
}

func TestEmailTemplatePut_AFailedWriteIsA500AndNotAudited(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	datamocks.ExpectRunInTransaction(database, emailTemplateTx)
	database.On("SaveEmailTemplate", mock.Anything, emailTemplateTx, mock.Anything).Return(errs.New("database down")).Once()

	rr, _ := serveEmailTemplate(HandleEmailTemplatePut(database, auditLogger),
		emailTemplateRequest(http.MethodPut, "authserver:manage", "password_changed", "en", saveBody(t, "Changed", "", "Hello.")))

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}

// --- reset ---------------------------------------------------------------------------------------

func TestEmailTemplateDelete_RemovesTheEditAndAuditsIt(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	records := recordLoggedEvents(auditLogger)
	datamocks.ExpectRunInTransaction(database, emailTemplateTx)
	database.On("DeleteEmailTemplate", mock.Anything, emailTemplateTx, "verification_code", "fr").Return(true, nil).Once()

	rr, _ := serveEmailTemplate(HandleEmailTemplateDelete(database, auditLogger),
		emailTemplateRequest(http.MethodDelete, "authserver:manage", "verification_code", "fr", ""))

	assert.Equal(t, http.StatusNoContent, rr.Code)
	assert.Empty(t, rr.Body.String())
	require.Len(t, *records, 1)
	assert.Equal(t, "reset_email_template", (*records)[0].event)
	assert.Equal(t, map[string]interface{}{
		"email_template": "verification_code", "language": "fr", "logged_in_user": grantCaller,
	}, (*records)[0].details)
}

func TestEmailTemplateDelete_AResetWithNoEditIsA204AndLogsNothing(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	datamocks.ExpectRunInTransaction(database, emailTemplateTx)
	database.On("DeleteEmailTemplate", mock.Anything, emailTemplateTx, "verification_code", "fr").Return(false, nil).Once()

	rr, _ := serveEmailTemplate(HandleEmailTemplateDelete(database, auditLogger),
		emailTemplateRequest(http.MethodDelete, "authserver:manage", "verification_code", "fr", ""))

	assert.Equal(t, http.StatusNoContent, rr.Code)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}

func TestEmailTemplateDelete_AnUnknownEmailOrLanguageIsA404(t *testing.T) {
	for _, c := range []struct{ email, lang string }{{"no_such_email", "en"}, {"welcome", "fr-CA"}, {"welcome", ""}} {
		t.Run(c.email+"/"+c.lang, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)

			rr, body := serveEmailTemplate(HandleEmailTemplateDelete(database, auditLogger),
				emailTemplateRequest(http.MethodDelete, "authserver:manage-settings", c.email, c.lang, ""))

			assert.Equal(t, http.StatusNotFound, rr.Code)
			assert.Equal(t, "NOT_FOUND", body["error_code"])
			auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// --- the settings ceiling --------------------------------------------------------------------------

// What an email says is reserved as where it goes is (#818 decision 9): a save or a reset by any
// caller below authserver:manage is refused 403 MANAGE_SCOPE_REQUIRED, writes nothing and leaves
// one administrator_change_refused record naming the settings ceiling.
func TestEmailTemplateWrites_EveryCallerBelowManageIsRefused(t *testing.T) {
	writes := []struct {
		name    string
		method  string
		body    string
		handler func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger) http.Handler
	}{
		{"save", http.MethodPut, `{"subject":"Changed","buttonLabel":"","body":"Hello {{name}}."}`,
			func(d *datamocks.Database, a *handlersmocks.AuditLogger) http.Handler {
				return HandleEmailTemplatePut(d, a)
			}},
		{"reset", http.MethodDelete, "",
			func(d *datamocks.Database, a *handlersmocks.AuditLogger) http.Handler {
				return HandleEmailTemplateDelete(d, a)
			}},
	}
	callers := []string{
		"authserver:manage-settings",
		"authserver:admin-read authserver:manage-users authserver:manage-clients authserver:manage-settings authserver:browser-sessions",
		"authserver:manage-account other:manage",
	}
	for _, write := range writes {
		for _, scope := range callers {
			t.Run(write.name+"/"+scope, func(t *testing.T) {
				database := datamocks.NewDatabase(t)
				auditLogger := handlersmocks.NewAuditLogger(t)
				records := recordLoggedEvents(auditLogger)

				rr := httptest.NewRecorder()
				write.handler(database, auditLogger).ServeHTTP(rr,
					emailTemplateRequest(write.method, scope, "password_changed", "en", write.body))

				code, description := decodeErrorEnvelope(t, rr)
				assertManageScopeRequired(t, rr, rr.Code, code, description)
				database.AssertNotCalled(t, "SaveEmailTemplate", mock.Anything, mock.Anything, mock.Anything)
				database.AssertNotCalled(t, "DeleteEmailTemplate", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
				require.Len(t, *records, 1)
				assert.Equal(t, "administrator_change_refused", (*records)[0].event)
				assert.Equal(t, "settings", (*records)[0].details["ceiling"])
				assert.Equal(t, write.method, (*records)[0].details["method"])
				assert.Equal(t, grantCaller, (*records)[0].details["logged_in_user"])
				assert.NotContains(t, (*records)[0].details, "target_kind")
			})
		}
	}
}

// readBuiltInSubject and readBuiltInBody read a built-in text through the read operation, as an
// administrator's editor does before sending it back unchanged.
func readBuiltInSubject(t *testing.T, email, lang string) string {
	t.Helper()
	return readBuiltInText(t, email, lang)["subject"].(string)
}

func readBuiltInBody(t *testing.T, email, lang string) string {
	t.Helper()
	return readBuiltInText(t, email, lang)["body"].(string)
}

func readBuiltInText(t *testing.T, email, lang string) map[string]any {
	t.Helper()
	database := datamocks.NewDatabase(t)
	database.On("GetAllEmailTemplates", mock.Anything, (*sql.Tx)(nil)).Return(nil, nil)
	rr, body := serveEmailTemplate(HandleEmailTemplateGet(database), emailTemplateRequest(http.MethodGet, "authserver:admin-read", email, "", ""))
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	return languageOf(t, body["emailTemplate"].(map[string]any), lang)["builtInText"].(map[string]any)
}
