package integration

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/testutil/mailpit"
)

// The password reset link is sent from its built-in definition (#818), read here from the mailbox
// after a real forgot-password request: its subject, which is also its title, in the recipient's
// language, a regional one reading its language's text; a sentence saying how long the link lasts;
// and a greeting by name, or by address for a user with none.

// resetLinkUser creates a verified user who can ask for a password reset, with the name and the
// language and region given.
func resetLinkUser(t *testing.T, givenName, locale string) *record.User {
	t.Helper()
	passwordHashed, err := passwordhash.Hash(fake.Password(12) + "aA1!")
	require.NoError(t, err)
	user := &record.User{
		Subject:       fake.UUID(),
		Enabled:       true,
		Email:         plusAddress(),
		EmailVerified: true,
		PasswordHash:  passwordHashed,
		GivenName:     givenName,
		Locale:        locale,
	}
	require.NoError(t, database.CreateUser(context.Background(), nil, user))
	return user
}

// readResetLinkEmail asks for a reset for user and reads the email it is sent: its subject, its
// title, the language it is marked with, and its plain-text part with the reset link named <link>.
func readResetLinkEmail(t *testing.T, user *record.User) (subject, title, lang, text string) {
	t.Helper()
	requestResetAt(t, createHttpClient(t), appConfig.AuthServer.BaseURL+"/forgot-password", user.Email)
	message := onlyMailTo(t, user.Email)
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(message.HTML))
	require.NoError(t, err)
	lang, _ = doc.Find("html").Attr("lang")
	return message.Subject, doc.Find("title").Text(), lang, resetLinkText(message)
}

// resetLinkText is an email's plain-text part, its line endings as written here and its reset link
// named <link>, since its code is new on each reset.
func resetLinkText(message mailpit.Message) string {
	text := strings.ReplaceAll(message.Text, "\r\n", "\n")
	return regexp.MustCompile(regexp.QuoteMeta(appConfig.AuthServer.BaseURL)+`/reset-password\?\S+`).ReplaceAllString(text, "<link>")
}

func TestPasswordResetLinkEmail_IsSentFromItsDefinition(t *testing.T) {
	useMailpitSMTP(t)

	t.Run("a user with no name, in English, is greeted by their address", func(t *testing.T) {
		user := resetLinkUser(t, "", "")

		subject, title, lang, text := readResetLinkEmail(t, user)

		assert.Equal(t, "Password reset", subject)
		assert.Equal(t, "Password reset", title, "the title is the subject")
		assert.Equal(t, "en", lang)
		assert.True(t, strings.HasPrefix(text, "Hello "+user.Email+",\n\n"+
			"You can reset your password by clicking the link below:\n\n"+
			"<link>\n\n"+
			"The link expires in 5 minutes.\n\n"+
			"If you have trouble clicking the link, you can copy and paste it into your web browser.\n\n"+
			"In case you didn't request a password reset, kindly disregard this email.\n\n"+
			"Best regards,\n"), text)
	})

	t.Run("a user in Canadian French reads the French text", func(t *testing.T) {
		user := resetLinkUser(t, "Camille", "fr-CA")

		subject, title, lang, text := readResetLinkEmail(t, user)

		assert.Equal(t, "Réinitialisation du mot de passe", subject)
		assert.Equal(t, "Réinitialisation du mot de passe", title)
		assert.Equal(t, "fr", lang)
		assert.True(t, strings.HasPrefix(text, "Bonjour Camille,\n\n"), text)
		assert.Contains(t, text, "\n\nLe lien expire dans 5 minutes.\n\n")
	})

	t.Run("a user reading German reads the German text", func(t *testing.T) {
		user := resetLinkUser(t, "Lena", "de-AT")

		subject, _, lang, text := readResetLinkEmail(t, user)

		assert.Equal(t, "Passwort zurücksetzen", subject)
		assert.Equal(t, "de", lang)
		assert.True(t, strings.HasPrefix(text, "Guten Tag Lena,\n\n"), text)
		assert.Contains(t, text, "\n\nDer Link läuft nach 5 Minuten ab.\n\n")
	})
}
