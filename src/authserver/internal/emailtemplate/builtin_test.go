package emailtemplate

import (
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The built-in languages, as the catalogs built into Goiabada are tagged.
var builtInLanguages = []string{"en", "de", "es", "fr", "id", "it", "ja", "pl", "pt-BR", "ru", "zh-Hans"}

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
		{"ja", "パスワードの再設定", "パスワードを再設定", "Ana 様",
			"以下のリンクから、パスワードを再設定できます。", "このリンクの有効期限は 5 分です。"},
		{"pl", "Resetowanie hasła", "Zresetuj hasło", "Dzień dobry Ana,",
			"Aby zresetować hasło, kliknij poniższy link:", "Link wygaśnie za 5 minut."},
		{"pt-BR", "Redefinição de senha", "Redefinir senha", "Olá Ana,",
			"Você pode redefinir sua senha clicando no link abaixo:", "O link expira em 5 minutos."},
		{"ru", "Сброс пароля", "Сбросить пароль", "Здравствуйте, Ana!",
			"Чтобы сбросить пароль, перейдите по ссылке ниже:", "Срок действия ссылки истечет через 5 минут."},
		{"zh-Hans", "重置密码", "重置密码", "Ana，您好：", "您可以点击下面的链接重置密码：", "该链接将在5分钟后过期。"},
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
			assert.Contains(t, body, signature(tc.lang), "signed with the app name")
		})
	}
}

// The expiry reads as a duration with its unit in the email's language, the unit's name the one of
// the count's CLDR plural category there (#665 decision 2): one for 1, and for 0 in French and
// Portuguese (Brazil), which no lifetime is but CLDR's tables give; other for every other count.
func TestRender_TheExpiryInEachLanguage(t *testing.T) {
	for _, tc := range []struct {
		lang     string
		duration time.Duration
		want     string
	}{
		{"en", 5 * time.Minute, "5 minutes"},
		{"en", time.Minute, "1 minute"},
		{"en", 2 * time.Minute, "2 minutes"},
		{"en", 21 * time.Minute, "21 minutes"},
		{"en", 22 * time.Minute, "22 minutes"},
		{"en", 101 * time.Minute, "101 minutes"},
		{"en", 0, "0 minutes"},
		{"en", 24 * time.Hour, "24 hours"},
		{"en", time.Hour, "1 hour"},
		{"en", 2 * time.Hour, "2 hours"},
		{"en", 21 * time.Hour, "21 hours"},
		{"en", 90 * time.Minute, "90 minutes"},
		{"en", 61 * time.Second, "2 minutes"},
		{"de", 5 * time.Minute, "5 Minuten"},
		{"de", time.Minute, "1 Minute"},
		{"de", 21 * time.Minute, "21 Minuten"},
		{"de", 0, "0 Minuten"},
		{"de", 24 * time.Hour, "24 Stunden"},
		{"de", time.Hour, "1 Stunde"},
		{"de", 21 * time.Hour, "21 Stunden"},
		{"es", 5 * time.Minute, "5 minutos"},
		{"es", time.Minute, "1 minuto"},
		{"es", 21 * time.Minute, "21 minutos"},
		{"es", 0, "0 minutos"},
		{"es", 24 * time.Hour, "24 horas"},
		{"es", time.Hour, "1 hora"},
		{"fr", 5 * time.Minute, "5 minutes"},
		{"fr", time.Minute, "1 minute"},
		{"fr", 2 * time.Minute, "2 minutes"},
		{"fr", 21 * time.Minute, "21 minutes"},
		{"fr", 0, "0 minute"},
		{"fr", 24 * time.Hour, "24 heures"},
		{"fr", time.Hour, "1 heure"},
		{"fr", 2 * time.Hour, "2 heures"},
		{"id", 5 * time.Minute, "5 menit"},
		{"id", time.Minute, "1 menit"},
		{"id", 24 * time.Hour, "24 jam"},
		{"id", time.Hour, "1 jam"},
		{"id", 90 * time.Minute, "90 menit"},
		{"it", 5 * time.Minute, "5 minuti"},
		{"it", time.Minute, "1 minuto"},
		{"it", 21 * time.Minute, "21 minuti"},
		{"it", 0, "0 minuti"},
		{"it", 24 * time.Hour, "24 ore"},
		{"it", time.Hour, "1 ora"},
		// Japanese has one form, other, and a space between the number and its unit (#662 decision 6).
		{"ja", 5 * time.Minute, "5 分"},
		{"ja", time.Minute, "1 分"},
		{"ja", 30 * time.Minute, "30 分"},
		{"ja", 0, "0 分"},
		{"ja", 90 * time.Minute, "90 分"},
		{"ja", time.Hour, "1 時間"},
		{"ja", 24 * time.Hour, "24 時間"},
		{"ja", 48 * time.Hour, "48 時間"},
		// Polish writes the unit in the accusative the expiry sentences take (#665 decision 3): one
		// for 1, few for 2 to 4 and 22 to 24, many for 0, 5 to 21 and 25 on.
		{"pl", time.Minute, "1 minutę"},
		{"pl", 2 * time.Minute, "2 minuty"},
		{"pl", 4 * time.Minute, "4 minuty"},
		{"pl", 5 * time.Minute, "5 minut"},
		{"pl", 12 * time.Minute, "12 minut"},
		{"pl", 21 * time.Minute, "21 minut"},
		{"pl", 22 * time.Minute, "22 minuty"},
		{"pl", 0, "0 minut"},
		{"pl", time.Hour, "1 godzinę"},
		{"pl", 2 * time.Hour, "2 godziny"},
		{"pl", 5 * time.Hour, "5 godzin"},
		{"pl", 24 * time.Hour, "24 godziny"},
		{"pl", 48 * time.Hour, "48 godzin"},
		{"pt-BR", 5 * time.Minute, "5 minutos"},
		{"pt-BR", time.Minute, "1 minuto"},
		{"pt-BR", 2 * time.Minute, "2 minutos"},
		{"pt-BR", 0, "0 minuto"},
		{"pt-BR", 24 * time.Hour, "24 horas"},
		{"pt-BR", time.Hour, "1 hora"},
		// Russian writes the unit in the accusative the expiry sentences take (#666 decision 5): one
		// for 1, 21 and 31, few for 2 to 4 and 22 to 24, many for 0, 5 to 20 and 25 to 30.
		{"ru", time.Minute, "1 минуту"},
		{"ru", 2 * time.Minute, "2 минуты"},
		{"ru", 4 * time.Minute, "4 минуты"},
		{"ru", 5 * time.Minute, "5 минут"},
		{"ru", 11 * time.Minute, "11 минут"},
		{"ru", 21 * time.Minute, "21 минуту"},
		{"ru", 22 * time.Minute, "22 минуты"},
		{"ru", 25 * time.Minute, "25 минут"},
		{"ru", 0, "0 минут"},
		{"ru", time.Hour, "1 час"},
		{"ru", 2 * time.Hour, "2 часа"},
		{"ru", 5 * time.Hour, "5 часов"},
		{"ru", 21 * time.Hour, "21 час"},
		{"ru", 24 * time.Hour, "24 часа"},
		{"ru", 48 * time.Hour, "48 часов"},
		// Simplified Chinese has one form, other, and joins the number to its unit (#663 decision 4).
		{"zh-Hans", 5 * time.Minute, "5分钟"},
		{"zh-Hans", time.Minute, "1分钟"},
		{"zh-Hans", 30 * time.Minute, "30分钟"},
		{"zh-Hans", 0, "0分钟"},
		{"zh-Hans", 90 * time.Minute, "90分钟"},
		{"zh-Hans", time.Hour, "1小时"},
		{"zh-Hans", 24 * time.Hour, "24小时"},
		{"zh-Hans", 48 * time.Hour, "48小时"},
		// A language with no unit names reads English's, by English's rule, even where its own
		// rule differs: French Canadian's 0 is one, English's other.
		{"nl", time.Minute, "1 minute"},
		{"nl", 24 * time.Hour, "24 hours"},
		{"fr-CA", 0, "0 minutes"},
		{"fr-CA", time.Minute, "1 minute"},
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

// A language whose entry joins a number to its unit with no space writes them joined, in hours and
// in minutes, in the subject and the body (#663 decision 4). Korean stands in, as a language that
// writes "30분" and that no built-in entry names yet.
func TestRender_TheExpiryJoinedAsTheLanguagesEntrySays(t *testing.T) {
	expiryLanguages["ko"] = expiryNames{"", map[string]expiryUnit{"other": {"분", "시간"}}}
	t.Cleanup(func() { delete(expiryLanguages, "ko") })
	for duration, want := range map[time.Duration]string{
		5 * time.Minute:  "5분",
		30 * time.Minute: "30분",
		90 * time.Minute: "90분",
		time.Hour:        "1시간",
		24 * time.Hour:   "24시간",
	} {
		t.Run(want, func(t *testing.T) {
			values := testValues
			values.Expiry = duration
			rendered, err := everything.Render("ko", Text{Subject: "{{expiry}}", ButtonLabel: "Go", Body: "{{expiry}}"}, values, testLook)
			require.NoError(t, err)
			assert.Equal(t, want, rendered.Subject)
			assert.Equal(t, "<p>"+want+"</p>\n", string(rendered.Body))
		})
	}
}

// Each language's units name exactly the plural categories its whole counts reach, so every count
// finds its name and no name waits on a count that never comes.
func TestExpiryUnits_NameEachCategoryTheLanguagesCountsReach(t *testing.T) {
	require.ElementsMatch(t, Languages, slices.Collect(maps.Keys(expiryLanguages)), "every email language has its unit names")
	for _, lang := range Languages {
		reached := map[string]bool{}
		for count := 0; count <= 1000; count++ {
			reached[i18n.PluralCategory(lang, count)] = true
		}
		units := expiryLanguages[lang].units
		assert.ElementsMatch(t, slices.Collect(maps.Keys(reached)), slices.Collect(maps.Keys(units)), "%s's unit names", lang)
		for category, unit := range units {
			assert.NotEmpty(t, unit.minute, "%s %s minute", lang, category)
			assert.NotEmpty(t, unit.hour, "%s %s hour", lang, category)
		}
	}
}

// The recipient's language picks one of the built-in languages as an email's copy was picked
// before: a regional variant reads its language's text, and a language with none reads English.
func TestLanguage_MatchesTheRecipientsLanguage(t *testing.T) {
	for locale, want := range map[string]string{
		"en": "en", "en-GB": "en", "de": "de", "de-AT": "de", "es-MX": "es", "fr-CA": "fr", "fr-CH": "fr",
		"it-CH": "it", "id": "id", "id-ID": "id", "in": "id", "ms": "en", "pt-BR": "pt-BR", "pt": "pt-BR", "nl": "en", "sv-SE": "en", "": "en", "not a tag!": "en",
		"pt-PT": "pt-BR", "pl": "pl", "pl-PL": "pl",
		"ru": "ru", "ru-RU": "ru", "ru-KZ": "ru", "ru-UA": "ru",
		// Ukrainian reads English, not Russian, though the matcher rates them close.
		"uk": "en", "uk-UA": "en",
		"ja": "ja", "ja-JP": "ja",
		// Traditional Chinese and Korean read English, not Japanese or Simplified Chinese.
		"zh-TW": "en", "zh-HK": "en", "zh-Hant": "en", "ko": "en", "ko-KR": "en",
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

// Every email's built-in Russian text writes е, never ё (#666 decision 4): in its subject, its body
// and its button's label.
func TestBuiltIns_RussianWritesENeverYo(t *testing.T) {
	for _, email := range BuiltIns() {
		text, ok := email.BuiltIn["ru"]
		if !assert.Truef(t, ok, "%s has Russian text", email.ID) {
			continue
		}
		for part, value := range map[string]string{"subject": text.Subject, "body": text.Body, "button label": text.ButtonLabel} {
			assert.Falsef(t, spellsYo(value), "%s: the Russian %s says %q; Russian is written with е, never ё", email.ID, part, value)
		}
	}
}

// spellsYo reports whether s holds ё or Ё, as one character or as е and its combining diaeresis.
func spellsYo(s string) bool {
	return strings.ContainsAny(s, "ёЁ") || strings.Contains(s, "е\u0308") || strings.Contains(s, "Е\u0308")
}

func TestSpellsYo(t *testing.T) {
	for _, v := range []string{"Срок истёк.", "ЁЛКА", "е\u0308ще"} {
		assert.Truef(t, spellsYo(v), "%q spells ё", v)
	}
	for _, v := range []string{"Срок истек.", "Еще раз", "Hello"} {
		assert.Falsef(t, spellsYo(v), "%q does not spell ё", v)
	}
}

// signature is how a body in lang signs off: a closing phrase with the app name on the next line, or
// in Japanese and Simplified Chinese, which close with no phrase (#662 decision 3, #663 decision 5),
// the app name alone in its paragraph.
func signature(lang string) string {
	if lang == "ja" || lang == "zh-Hans" {
		return "</p>\n<p>Acme Portal</p>"
	}
	return "<br>\nAcme Portal</p>"
}

// Every Japanese email that offers {{name}} opens with "{{name}} 様" alone on its line, and the four
// that offer none open with their text; each that closes does so with the app name alone, with no
// closing phrase; and each bold sentence is drawn bold, never as asterisks (#662 decision 3).
func TestBuiltIns_JapaneseGreetsByNameAndClosesWithTheAppName(t *testing.T) {
	for _, email := range BuiltIns() {
		t.Run(email.ID, func(t *testing.T) {
			text, ok := email.BuiltIn["ja"]
			require.Truef(t, ok, "%s has Japanese text", email.ID)
			offersName := slices.ContainsFunc(email.Placeholders, func(p Placeholder) bool { return p.Name == Name })
			first, _, _ := strings.Cut(text.Body, "\n")
			if offersName {
				assert.Equal(t, "{{name}} 様", first)
			} else {
				assert.NotContains(t, text.Body, "様", "an email that offers no name greets no one")
			}

			rendered, err := email.Render("ja", text, testValues, testLook)
			require.NoError(t, err)
			body := string(rendered.Body)
			if email.ID != "test" { // which, as in English, does not close
				assert.True(t, strings.HasSuffix(text.Body, "\n\n{{app_name}}"), "closes with the app name alone: %q", text.Body)
				assert.True(t, strings.HasSuffix(body, signature("ja")+"\n"), body)
			}
			assert.NotContains(t, body, "*", "every bold sentence is drawn bold")
			assert.Equal(t, strings.Count(text.Body, "**")/2, strings.Count(body, "<strong>"))
			if offersName {
				assert.True(t, strings.HasPrefix(body, "<p>Ana 様</p>\n"), body)
			}
		})
	}
}
