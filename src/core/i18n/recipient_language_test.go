package i18n

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// An email to an existing user is written in their page language, else their language and region,
// else English, subject and body alike, read here through a message of each catalog; the language
// of whoever's request sent it plays no part (#631). The request each case starts from asks for
// German and Italian, which always lose.
func TestWithRecipientLanguage_ChosenThenLanguageAndRegionThenEnglish(t *testing.T) {
	tests := []struct {
		name         string
		pageLanguage string
		locale       string
		wantTitle    string
		wantLocale   string
	}{
		{"the chosen language over Language and region", "pt-BR", "fr", "Redefina sua senha", "pt-BR"},
		{"the chosen language with no Language and region", "es", "", "Restablece tu contraseña", "es"},
		{"English chosen over Language and region", "en", "pt-BR", "Reset your password", "en"},
		{"Automatic: Language and region", "", "fr", "Réinitialiser votre mot de passe", "fr"},
		{"Automatic: a regional Language and region keeps its own tag for the body copy", "", "es-MX", "Restablece tu contraseña", "es-MX"},
		{"Automatic: a Language and region with no catalog keeps its tag, in English", "", "ja", "Reset your password", "ja"},
		{"Automatic with no Language and region: English", "", "", "Reset your password", "en"},
		{"a choice naming no catalog is Automatic: Language and region", "ja", "fr", "Réinitialiser votre mot de passe", "fr"},
		{"a choice naming no catalog is Automatic: English", "pt-br", "", "Reset your password", "en"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sender := throughLocale(t, nil, "/forgot-password?ui_locales=de", "it")
			require.Equal(t, "Passwort zurücksetzen", T(sender, "forgot_password.title"))

			ctx := WithRecipientLanguage(sender, tt.pageLanguage, tt.locale)
			assert.Equal(t, tt.wantTitle, T(ctx, "forgot_password.title"))
			assert.Equal(t, tt.wantLocale, LocaleTag(ctx), "the body copy is chosen from this tag")
		})
	}
}

// A page drawn for a known user carries that user's page language, which no WithLocale moves. An
// email sent from such a page (a forgot-password request from a signed-in browser, say) goes to
// someone else, and is written in the recipient's language, not the signed-in user's.
func TestWithRecipientLanguage_ReplacesThePageLanguageOfWhoeverSentIt(t *testing.T) {
	tests := []struct {
		name         string
		pageLanguage string
		locale       string
		wantTitle    string
	}{
		{"the recipient's chosen language", "es", "fr", "Restablece tu contraseña"},
		{"the recipient's Language and region", "", "fr", "Réinitialiser votre mot de passe"},
		{"English for a recipient with neither", "", "", "Reset your password"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sender := WithPageLanguage(throughLocale(t, nil, "/forgot-password", "it"), "de")
			require.Equal(t, "Passwort zurücksetzen", T(sender, "forgot_password.title"))

			ctx := WithRecipientLanguage(sender, tt.pageLanguage, tt.locale)
			assert.Equal(t, tt.wantTitle, T(ctx, "forgot_password.title"))
		})
	}
}

// An operator's override-only catalog can be a recipient's chosen language while it is loaded. Once
// it is gone, the choice counts as Automatic: Language and region, not English.
func TestWithRecipientLanguage_AVanishedCatalogCountsAsAutomatic(t *testing.T) {
	saved := installed.Load()
	t.Cleanup(func() { installed.Store(saved) })

	require.NoError(t, LoadBundle(overridesDir(t, map[string]string{
		"active.nl.toml": "\"forgot_password.title\" = \"Wachtwoord herstellen\"\n",
	})))
	sender := throughLocale(t, nil, "/forgot-password", "it")
	loaded := WithRecipientLanguage(sender, "nl", "fr")
	assert.Equal(t, "Wachtwoord herstellen", T(loaded, "forgot_password.title"))
	assert.Equal(t, "nl", LocaleTag(loaded))

	// The operator removes the catalog and the process starts again.
	require.NoError(t, LoadBundle(""))
	sender = throughLocale(t, nil, "/forgot-password", "it")
	vanished := WithRecipientLanguage(sender, "nl", "fr")
	assert.Equal(t, "Réinitialiser votre mot de passe", T(vanished, "forgot_password.title"))
	assert.Equal(t, "fr", LocaleTag(vanished))
}
