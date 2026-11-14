package integration

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/record"
)

// An email is sent with its administrator's edit in the recipient's language (#818 decisions 7 and
// 8), read here from the mailbox after a real forgot-password request: the edited fields reach the
// subject, the HTML and the plain-text part, over the built-in text of the fields left alone; an edit
// in another language is not sent; and an invalid edit, or an edit removed, sends the built-in text.

// saveEmailTemplateEdit stores an edit of email in lang, with the fields given and the others left
// as the built-in text, and removes it when the test ends, since edits are global.
func saveEmailTemplateEdit(t *testing.T, email, lang string, subject, buttonLabel, body string) {
	t.Helper()
	field := func(s string) sql.NullString { return sql.NullString{String: s, Valid: s != ""} }
	edit := &record.EmailTemplate{
		EmailTemplate: email, Language: lang,
		Subject: field(subject), ButtonLabel: field(buttonLabel), Body: field(body),
	}
	require.NoError(t, database.SaveEmailTemplate(context.Background(), nil, edit))
	t.Cleanup(func() {
		_, err := database.DeleteEmailTemplate(context.Background(), nil, email, lang)
		assert.NoError(t, err)
	})
}

// resetLinkEmailSent asks for a reset for user and reads the email it is sent: its subject, its
// button's label, and its plain-text part with the reset link named <link>.
func resetLinkEmailSent(t *testing.T, user *record.User) (subject, button, text string) {
	t.Helper()
	requestResetAt(t, createHttpClient(t), appConfig.AuthServer.BaseURL+"/forgot-password", user.Email)
	message := onlyMailTo(t, user.Email)
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(message.HTML))
	require.NoError(t, err)
	return message.Subject, strings.TrimSpace(doc.Find("[data-email-button] a").Text()), resetLinkText(message)
}

func TestEmailTemplateEdits_AreSentInTheRecipientsLanguage(t *testing.T) {
	useMailpitSMTP(t)

	t.Run("an edit reaches the subject, the button and both parts, over the built-in text", func(t *testing.T) {
		saveEmailTemplateEdit(t, "password_reset_link", "en", "Choose a new password for {{app_name}}", "Choose a password",
			"Hi {{name}}, someone asked to reset your password.\n\n{{button}}\n\nOr open {{link}} within {{expiry}}.")
		user := resetLinkUser(t, "Ana", "en-GB")
		settings, err := database.GetSettingsById(context.Background(), nil, 1)
		require.NoError(t, err)

		subject, button, text := resetLinkEmailSent(t, user)

		assert.Equal(t, "Choose a new password for "+settings.AppName, subject)
		assert.Equal(t, "Choose a password", button)
		assert.True(t, strings.HasPrefix(text, "Hi Ana, someone asked to reset your password.\n\n"+
			"Or open <link> within 5 minutes.\n"), text)
		assert.NotContains(t, text, "You can reset your password by clicking the link below")
	})

	t.Run("an edit of the subject alone leaves the built-in body and button", func(t *testing.T) {
		saveEmailTemplateEdit(t, "password_reset_link", "fr", "Votre nouveau mot de passe", "", "")
		user := resetLinkUser(t, "Camille", "fr-CA")

		subject, button, text := resetLinkEmailSent(t, user)

		assert.Equal(t, "Votre nouveau mot de passe", subject)
		assert.Equal(t, "Réinitialiser le mot de passe", button)
		assert.True(t, strings.HasPrefix(text, "Bonjour Camille,\n\n"), text)
		assert.Contains(t, text, "\n\nLe lien expire dans 5 minutes.\n\n")
	})

	t.Run("an edit in another language is not sent", func(t *testing.T) {
		saveEmailTemplateEdit(t, "password_reset_link", "de", "Neues Passwort", "", "")
		user := resetLinkUser(t, "Ana", "en")

		subject, button, _ := resetLinkEmailSent(t, user)

		assert.Equal(t, "Password reset", subject)
		assert.Equal(t, "Reset password", button)
	})

	t.Run("an invalid edit sends the built-in text, every field of it", func(t *testing.T) {
		// The subject is fine; the body names a placeholder the email does not offer and drops the
		// link it cannot work without.
		saveEmailTemplateEdit(t, "password_reset_link", "de", "Neues Passwort", "Los",
			"Hallo {{full_name}}.\n\n{{button}}")
		user := resetLinkUser(t, "Lena", "de-AT")

		subject, button, text := resetLinkEmailSent(t, user)

		assert.Equal(t, "Passwort zurücksetzen", subject)
		assert.Equal(t, "Passwort zurücksetzen", button)
		assert.True(t, strings.HasPrefix(text, "Guten Tag Lena,\n\n"), text)
		assert.Contains(t, text, "<link>")
	})

	t.Run("an edit removed sends the built-in text again", func(t *testing.T) {
		saveEmailTemplateEdit(t, "password_reset_link", "it", "Nuova password", "", "")
		deleted, err := database.DeleteEmailTemplate(context.Background(), nil, "password_reset_link", "it")
		require.NoError(t, err)
		require.True(t, deleted)
		user := resetLinkUser(t, "Giulia", "it")

		subject, _, _ := resetLinkEmailSent(t, user)

		assert.Equal(t, "Reimpostazione della password", subject)
	})
}
