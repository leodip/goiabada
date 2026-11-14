package render

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/emailtemplate"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/web"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/logging/logtest"
)

// An email is sent with its administrator's edit in the recipient's language (#818 decisions 7, 8
// and 16): the edited fields laid over the built-in text; the built-in text, all of it, while the
// edit breaks a rule, with a warning; and the built-in text, with an error, when the edit cannot be
// read.

// editsStub answers the edits it holds by email and language, or err, and records each read.
type editsStub struct {
	edits map[[2]string]*record.EmailTemplate
	err   error
	reads [][2]string
}

func (s *editsStub) GetEmailTemplate(_ context.Context, _ *sql.Tx, emailTemplate, language string) (*record.EmailTemplate, error) {
	s.reads = append(s.reads, [2]string{emailTemplate, language})
	if s.err != nil {
		return nil, s.err
	}
	return s.edits[[2]string{emailTemplate, language}], nil
}

// stored is an edit of email in lang with the fields given, the others NULL.
func stored(email, lang string, subject, buttonLabel, body *string) *record.EmailTemplate {
	field := func(s *string) sql.NullString {
		if s == nil {
			return sql.NullString{}
		}
		return sql.NullString{String: *s, Valid: true}
	}
	return &record.EmailTemplate{
		Id: 1, EmailTemplate: email, Language: lang,
		Subject: field(subject), ButtonLabel: field(buttonLabel), Body: field(body),
	}
}

func ptr(s string) *string { return &s }

// sentEmail is an email as its recipient reads it: the subject, the title, the language it is
// marked with, the text of its card and its button's labels.
type sentEmail struct {
	subject, title, lang, main string
	buttons                    []string
}

// renderWithEdits renders email for a recipient reading locale through a renderer that reads its
// edits from edits.
func renderWithEdits(t *testing.T, edits EmailTemplateReader, email *emailtemplate.Email, locale string) sentEmail {
	t.Helper()
	ctx := reqctx.WithSettings(context.Background(), &record.Settings{AppName: "Acme Portal"})
	ctx = i18n.WithLocale(ctx, true, locale, "en")
	req := httptest.NewRequest(http.MethodPost, "/", nil).WithContext(ctx)
	message, err := New(web.TemplateFS(), web.StaticFS(), nil).WithBaseURL(emailBaseURL).WithEmailTemplates(edits).
		RenderEmail(req, email, definitionValues)
	require.NoError(t, err)
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(message.HTML))
	require.NoError(t, err)
	lang, _ := doc.Find("html").Attr("lang")
	sent := sentEmail{subject: message.Subject, title: doc.Find("title").Text(), lang: lang, main: doc.Find("main").Text()}
	for _, button := range readEmailAction(t, message.HTML).buttons {
		sent.buttons = append(sent.buttons, button.label)
	}
	return sent
}

// A subject edited alone is sent with the built-in body and button of its language, which follow
// later releases; the edit is read for the language the recipient's matches, fr-CA reading fr.
func TestRenderEmail_SendsTheEditedFieldsOverTheBuiltInText(t *testing.T) {
	edits := &editsStub{edits: map[[2]string]*record.EmailTemplate{
		{"password_reset_link", "fr"}: stored("password_reset_link", "fr", ptr("Votre lien Acme"), nil, nil),
	}}

	sent := renderWithEdits(t, edits, emailtemplate.PasswordResetLink, "fr-CA")

	assert.Equal(t, [][2]string{{"password_reset_link", "fr"}}, edits.reads)
	assert.Equal(t, "Votre lien Acme", sent.subject)
	assert.Equal(t, "Votre lien Acme", sent.title, "the title is the subject sent")
	assert.Equal(t, "fr", sent.lang)
	assert.Contains(t, sent.main, "Bonjour Ana,")
	assert.Contains(t, sent.main, "Pour réinitialiser votre mot de passe, cliquez sur le lien ci-dessous")
	assert.Equal(t, []string{"Réinitialiser le mot de passe"}, sent.buttons)
}

// An edited body and button label are drawn with the email's values, in the brand's button.
func TestRenderEmail_SendsAnEditedBodyAndButtonLabel(t *testing.T) {
	edits := &editsStub{edits: map[[2]string]*record.EmailTemplate{
		{"password_reset_link", "en"}: stored("password_reset_link", "en", nil, ptr("Choose a password"),
			ptr("Hi {{name}}, this link lasts {{expiry}}:\n\n{{button}}\n\n{{link}}")),
	}}

	sent := renderWithEdits(t, edits, emailtemplate.PasswordResetLink, "en")

	assert.Equal(t, "Password reset", sent.subject)
	assert.Contains(t, sent.main, "Hi Ana, this link lasts 5 minutes:")
	assert.NotContains(t, sent.main, "You can reset your password by clicking the link below")
	assert.Equal(t, []string{"Choose a password"}, sent.buttons)
}

// An edit in one language is never another language's: a recipient reading English gets the built-in
// English text beside a German edit.
func TestRenderEmail_AnEditInAnotherLanguageIsNotSent(t *testing.T) {
	edits := &editsStub{edits: map[[2]string]*record.EmailTemplate{
		{"password_reset_link", "de"}: stored("password_reset_link", "de", ptr("Neues Passwort"), nil, nil),
	}}

	sent := renderWithEdits(t, edits, emailtemplate.PasswordResetLink, "en-GB")

	assert.Equal(t, [][2]string{{"password_reset_link", "en"}}, edits.reads)
	assert.Equal(t, "Password reset", sent.subject)
	assert.Contains(t, sent.main, "You can reset your password by clicking the link below:")
}

// An edit a save would refuse today sends the built-in text of its language, every field of it,
// although its subject alone is fine, and logs one warning naming the email and the language and
// never the text.
func TestRenderEmail_AnInvalidEditSendsTheBuiltInTextAndWarns(t *testing.T) {
	for _, tc := range []struct {
		name    string
		edit    *record.EmailTemplate
		problem string
	}{
		{"a name the email no longer offers", stored("password_reset_link", "de", ptr("Neues Passwort für Sie"), nil,
			ptr("Hallo {{full_name}}, {{link}}")), "body: unknown_placeholder"},
		{"the required link missing", stored("password_reset_link", "de", ptr("Neues Passwort für Sie"), nil,
			ptr("Hallo {{name}}.\n\n{{button}}")), "body: required_placeholder_missing"},
		{"a button label past its limit", stored("password_reset_link", "de", ptr("Neues Passwort für Sie"),
			ptr(strings.Repeat("Ä", 61)), nil), "button_label: too_long"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := logtest.CaptureSlog(t)
			edits := &editsStub{edits: map[[2]string]*record.EmailTemplate{{"password_reset_link", "de"}: tc.edit}}

			sent := renderWithEdits(t, edits, emailtemplate.PasswordResetLink, "de-AT")

			assert.Equal(t, "Passwort zurücksetzen", sent.subject, "the built-in subject, not the valid edited one")
			assert.Contains(t, sent.main, "Öffnen Sie diesen Link, um Ihr Passwort zurückzusetzen:")
			assert.Contains(t, sent.main, "Guten Tag Ana,")
			assert.Equal(t, []string{"Passwort zurücksetzen"}, sent.buttons)

			records := logs.Records()
			require.Len(t, records, 1)
			assert.Equal(t, slog.LevelWarn, records[0].Level)
			assert.Contains(t, records[0].Message, "built-in text")
			assert.Equal(t, "password_reset_link", records[0].Attrs["email_template"])
			assert.Equal(t, "de", records[0].Attrs["language"])
			assert.Equal(t, []string{tc.problem}, records[0].Attrs["problems"], "the rules broken, by field")
			text := logs.Text()
			assert.NotContains(t, text, "Neues Passwort", "the log never holds the edit's text")
			assert.NotContains(t, text, "Hallo")
			assert.NotContains(t, text, "ÄÄÄ")
		})
	}
}

// A stored edit whose body draws nothing to read besides the button, such as an empty list, is
// invalid as a save would find it (#818 decisions 8 and 17): its email is sent with the built-in text
// of its language, every field of it, so a brand with no footer still sends a message with text, and
// a warning names the rule.
func TestRenderEmail_AnEditThatDrawsNothingToReadSendsTheBuiltInText(t *testing.T) {
	for _, body := range []string{"- ", "{{button}}\n\n- ", "{{button}}\n\n[ ](relative)", "&NewLine;"} {
		t.Run(body, func(t *testing.T) {
			logs := logtest.CaptureSlog(t)
			edits := &editsStub{edits: map[[2]string]*record.EmailTemplate{
				{"welcome", "en"}: stored("welcome", "en", ptr("Hi there"), ptr("Open"), ptr(body)),
			}}

			sent := renderWithEdits(t, edits, emailtemplate.Welcome, "en")

			assert.Equal(t, "Welcome!", sent.subject, "the built-in subject, not the valid edited one")
			assert.Contains(t, sent.main, "Congratulations! Your account has been created.")
			assert.Equal(t, []string{"Sign in"}, sent.buttons)
			records := logs.Records()
			require.Len(t, records, 1)
			assert.Equal(t, slog.LevelWarn, records[0].Level)
			assert.Equal(t, []string{"body: nothing_to_read"}, records[0].Attrs["problems"])
		})
	}
}

// An edit that cannot be read, the database briefly unreachable, sends the built-in text and logs an
// error naming the email, the language and the cause: a reset link in the built-in wording is
// better than none.
func TestRenderEmail_AnEditThatCannotBeReadSendsTheBuiltInText(t *testing.T) {
	logs := logtest.CaptureSlog(t)
	edits := &editsStub{err: errs.New("database unreachable")}

	sent := renderWithEdits(t, edits, emailtemplate.AccountDeleted, "es-AR")

	assert.Equal(t, "Se ha eliminado tu cuenta", sent.subject)
	assert.Equal(t, "es", sent.lang)
	records := logs.Records()
	require.Len(t, records, 1)
	assert.Equal(t, slog.LevelError, records[0].Level)
	assert.Contains(t, records[0].Message, "built-in text")
	assert.Equal(t, "account_deleted", records[0].Attrs["email_template"])
	assert.Equal(t, "es", records[0].Attrs["language"])
	assert.Contains(t, logs.Text(), "database unreachable")
}

// No edit, the usual case, sends the built-in text and logs nothing.
func TestRenderEmail_NoEditSendsTheBuiltInTextQuietly(t *testing.T) {
	logs := logtest.CaptureSlog(t)
	edits := &editsStub{}

	sent := renderWithEdits(t, edits, emailtemplate.VerificationCode, "pt-BR")

	assert.Equal(t, [][2]string{{"verification_code", "pt-BR"}}, edits.reads)
	assert.Equal(t, "pt-BR", sent.lang)
	assert.Empty(t, logs.Records())
}
