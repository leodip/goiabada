package emailtemplate

import (
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The built-in languages, as the catalogs built into Goiabada are tagged.
var builtInLanguages = []string{"en", "de", "es", "fr", "id", "it", "pt-BR"}

func TestLanguages_AreTheBuiltInOnes(t *testing.T) {
	assert.Equal(t, builtInLanguages, Languages)
	// A catalog built in without email text would leave its readers on English emails.
	assert.Equal(t, i18n.CatalogTags(), Languages, "the email languages are the built-in catalogs")
}

// Every built-in email holds its text in each built-in language, passes its own rules in each (#818
// decision 8), and has a button label exactly when it offers the button (decision 5).
func TestBuiltIns_EveryTextPassesItsOwnRules(t *testing.T) {
	require.NotEmpty(t, BuiltIns())
	seen := map[string]bool{}
	for _, email := range BuiltIns() {
		assert.False(t, seen[email.ID], "%s is defined once", email.ID)
		seen[email.ID] = true
		require.Len(t, email.BuiltIn, len(builtInLanguages), "%s is written in each built-in language", email.ID)
		for _, lang := range builtInLanguages {
			t.Run(email.ID+"/"+lang, func(t *testing.T) {
				text, ok := email.BuiltIn[lang]
				require.True(t, ok)
				assert.Empty(t, email.Check(text))
				assert.NotEmpty(t, text.Subject)
				assert.Equal(t, email.HasButton(), text.ButtonLabel != "", "a button label exactly when the email offers the button")

				rendered, err := email.Render(lang, text, testValues, testLook)
				require.NoError(t, err)
				assert.NotContains(t, string(rendered.Body), "{{", "every placeholder is replaced")
				assert.NotContains(t, rendered.Subject, "{{")
			})
		}
	}
}

// The password reset link, in each built-in language: its subject, its button's label, its
// greeting and its expiry sentence, which reads the link's lifetime in that language.
func TestPasswordResetLink_InEachLanguage(t *testing.T) {
	assert.Equal(t, "password_reset_link", PasswordResetLink.ID)
	assert.Equal(t, []Placeholder{{Name: AppName}, {Name: Name}, {Name: Link, Required: true}, {Name: Button}, {Name: Expiry}},
		PasswordResetLink.Placeholders)

	for _, tc := range []struct {
		lang, subject, button, greeting, sentence, expiry string
	}{
		{"en", "Password reset", "Reset password", "Hello Ana,", "You can reset your password by clicking the link below:",
			"The link expires in 5 minutes."},
		{"de", "Passwort zurücksetzen", "Passwort zurücksetzen", "Guten Tag Ana,",
			"Öffnen Sie diesen Link, um Ihr Passwort zurückzusetzen:", "Der Link läuft nach 5 Minuten ab."},
		{"es", "Restablecimiento de contraseña", "Restablecer contraseña", "Hola, Ana:",
			"Para restablecer tu contraseña, abre este enlace:", "El enlace caduca en 5 minutos."},
		{"fr", "Réinitialisation du mot de passe", "Réinitialiser le mot de passe", "Bonjour Ana,",
			"Pour réinitialiser votre mot de passe, cliquez sur le lien ci-dessous :", "Le lien expire dans 5 minutes."},
		{"id", "Atur ulang kata sandi", "Atur ulang kata sandi", "Halo Ana,",
			"Anda dapat mengatur ulang kata sandi Anda melalui tautan di bawah ini:", "Tautan ini kedaluwarsa dalam 5 menit."},
		{"it", "Reimpostazione della password", "Reimposta la password", "Ciao Ana,",
			"Per reimpostare la password, apri questo link:", "Il link scade tra 5 minuti."},
		{"pt-BR", "Redefinição de senha", "Redefinir senha", "Olá Ana,",
			"Você pode redefinir sua senha clicando no link abaixo:", "O link expira em 5 minutos."},
	} {
		t.Run(tc.lang, func(t *testing.T) {
			text := PasswordResetLink.BuiltIn[tc.lang]
			assert.Equal(t, tc.subject, text.Subject)
			assert.Equal(t, tc.button, text.ButtonLabel)

			rendered, err := PasswordResetLink.Render(tc.lang, text, testValues, testLook)
			require.NoError(t, err)
			body := string(rendered.Body)
			assert.Equal(t, tc.subject, rendered.Subject)
			assert.True(t, strings.HasPrefix(body, "<p>"+tc.greeting+"</p>\n"), body)
			assert.Contains(t, body, "<p>"+tc.sentence+"</p>\n")
			assert.Contains(t, body, "<p>"+tc.expiry+"</p>\n")
			assert.Contains(t, body, ">"+tc.button+"</a>", "the button is labelled")
			assert.Contains(t, body, "<p>"+linkTo(escapedLink, escapedLink)+"</p>", "the URL is written out, to copy")
			assert.Contains(t, body, "<strong>", "the warning sentence stays bold")
			assert.Contains(t, body, "<br>\nAcme Portal</p>", "signed with the app name")
		})
	}
}

// The expiry reads as a duration with its unit, singular or plural, in the email's language.
func TestRender_TheExpiryInEachLanguage(t *testing.T) {
	for _, tc := range []struct {
		lang     string
		duration time.Duration
		want     string
	}{
		{"en", 5 * time.Minute, "5 minutes"},
		{"en", time.Minute, "1 minute"},
		{"en", 24 * time.Hour, "24 hours"},
		{"en", time.Hour, "1 hour"},
		{"en", 90 * time.Minute, "90 minutes"},
		{"de", 5 * time.Minute, "5 Minuten"},
		{"de", time.Minute, "1 Minute"},
		{"de", 24 * time.Hour, "24 Stunden"},
		{"de", time.Hour, "1 Stunde"},
		{"es", 5 * time.Minute, "5 minutos"},
		{"es", time.Minute, "1 minuto"},
		{"es", 24 * time.Hour, "24 horas"},
		{"es", time.Hour, "1 hora"},
		{"fr", 5 * time.Minute, "5 minutes"},
		{"fr", time.Minute, "1 minute"},
		{"fr", 24 * time.Hour, "24 heures"},
		{"fr", time.Hour, "1 heure"},
		{"id", 5 * time.Minute, "5 menit"},
		{"id", time.Minute, "1 menit"},
		{"id", 24 * time.Hour, "24 jam"},
		{"id", time.Hour, "1 jam"},
		{"id", 90 * time.Minute, "90 menit"},
		{"it", 5 * time.Minute, "5 minuti"},
		{"it", time.Minute, "1 minuto"},
		{"it", 24 * time.Hour, "24 ore"},
		{"it", time.Hour, "1 ora"},
		{"pt-BR", 5 * time.Minute, "5 minutos"},
		{"pt-BR", time.Minute, "1 minuto"},
		{"pt-BR", 24 * time.Hour, "24 horas"},
		{"pt-BR", time.Hour, "1 hora"},
	} {
		t.Run(tc.lang+"/"+tc.want, func(t *testing.T) {
			values := testValues
			values.Expiry = tc.duration
			rendered, err := everything.Render(tc.lang, Text{Subject: "{{expiry}}", ButtonLabel: "Go", Body: "{{expiry}}"}, values, testLook)
			require.NoError(t, err)
			assert.Equal(t, tc.want, rendered.Subject)
			assert.Equal(t, "<p>"+tc.want+"</p>\n", string(rendered.Body))
		})
	}
}

// The recipient's language picks one of the built-in languages as an email's copy was picked
// before: a regional variant reads its language's text, and a language with none reads English.
func TestLanguage_MatchesTheRecipientsLanguage(t *testing.T) {
	for locale, want := range map[string]string{
		"en": "en", "en-GB": "en", "de": "de", "de-AT": "de", "es-MX": "es", "fr-CA": "fr", "fr-CH": "fr",
		"it-CH": "it", "id": "id", "id-ID": "id", "in": "id", "ms": "en", "pt-BR": "pt-BR", "pt": "pt-BR", "nl": "en", "sv-SE": "en", "": "en", "not a tag!": "en",
		"pt-PT": "pt-BR",
		// A language with no text reads English, never a neighbour the matcher rates close: Galician
		// and Basque would otherwise read Spanish.
		"gl": "en", "eu": "en",
	} {
		t.Run(locale, func(t *testing.T) {
			assert.Equal(t, want, Language(locale))
		})
	}
}

// {{name}} is never empty: a user with no name is greeted by the address the email is sent to.
func TestRecipientName_FallsBackToTheAddress(t *testing.T) {
	assert.Equal(t, "Ana Silva", RecipientName("Ana Silva", "ana@example.com"))
	assert.Equal(t, "ana@example.com", RecipientName("", "ana@example.com"))
	assert.Equal(t, "ana@example.com", RecipientName("  ", "ana@example.com"))
}
