package emailtemplate

import (
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The twelve account notices are sent from their built-in definitions (#818): each is found by the
// identifier its log records carry (decision 6), offers the app name and the name, and the recovery
// code notice the codes left (decisions 3 and 4), and reads in each language as its template file
// read: its subject, its greeting and its bold warning sentence, signed with the app name.

// noticeText is what a notice reads in one language: its subject, its greeting to a user named Ana,
// and its warning sentence, the one in bold, or for the one notice with none, its first sentence.
type noticeText struct {
	subject, greeting, warning string
}

var noticeTexts = []struct {
	id    string
	langs map[string]noticeText
}{
	{"email_address_changed", map[string]noticeText{
		"en": {"Your email address was changed", "Hello Ana,",
			"If you didn't, someone else may know your password."},
		"de": {"Ihre E-Mail-Adresse wurde geändert", "Guten Tag Ana,",
			"Andernfalls kennt möglicherweise jemand Ihr Passwort."},
		"es": {"Tu dirección de correo electrónico ha cambiado", "Hola, Ana:",
			"Si no has sido tú, puede que otra persona conozca tu contraseña."},
		"fr": {"Votre adresse e-mail a été modifiée", "Bonjour Ana,",
			"Sinon, une autre personne connaît peut-être votre mot de passe."},
		"it": {"Il tuo indirizzo email è stato cambiato", "Ciao Ana,",
			"Altrimenti, qualcun altro potrebbe conoscere la tua password."},
		"pt-BR": {"Seu endereço de e-mail foi alterado", "Olá Ana,",
			"Se não foi você, outra pessoa pode saber a sua senha."},
	}},
	{"password_changed", map[string]noticeText{
		"en": {"Your password was changed", "Hello Ana,",
			"If you didn't, someone else may be using your account."},
		"de": {"Ihr Passwort wurde geändert", "Guten Tag Ana,",
			"Andernfalls verwendet möglicherweise jemand anderes Ihr Konto."},
		"es": {"Tu contraseña ha cambiado", "Hola, Ana:",
			"Si no has sido tú, puede que otra persona esté usando tu cuenta."},
		"fr": {"Votre mot de passe a été modifié", "Bonjour Ana,",
			"Sinon, une autre personne utilise peut-être votre compte."},
		"it": {"La tua password è stata cambiata", "Ciao Ana,",
			"Altrimenti, qualcun altro potrebbe usare il tuo account."},
		"pt-BR": {"Sua senha foi alterada", "Olá Ana,",
			"Se não foi você, outra pessoa pode estar usando a sua conta."},
	}},
	{"password_changed_by_administrator", map[string]noticeText{
		"en": {"An administrator changed your password", "Hello Ana,",
			"If you weren't expecting it, contact your administrator."},
		"de": {"Ihr Passwort wurde von der Administration geändert", "Guten Tag Ana,",
			"Falls Sie damit nicht gerechnet haben, wenden Sie sich an Ihre Administration."},
		"es": {"Un administrador ha cambiado tu contraseña", "Hola, Ana:",
			"Si no lo esperabas, contacta con tu administrador."},
		"fr": {"Un administrateur a modifié votre mot de passe", "Bonjour Ana,",
			"Si vous ne vous y attendiez pas, contactez votre administrateur."},
		"it": {"Un amministratore ha cambiato la tua password", "Ciao Ana,",
			"Se non te lo aspettavi, contatta il tuo amministratore."},
		"pt-BR": {"Um administrador alterou a sua senha", "Olá Ana,",
			"Se você não esperava por isso, entre em contato com o administrador."},
	}},
	{"password_reset", map[string]noticeText{
		"en": {"Your password was reset", "Hello Ana,",
			"If you didn't, someone else may be able to read your email and use your account."},
		"de": {"Ihr Passwort wurde zurückgesetzt", "Guten Tag Ana,",
			"Andernfalls kann möglicherweise jemand anderes Ihre E-Mails lesen und Ihr Konto verwenden."},
		"es": {"Tu contraseña se ha restablecido", "Hola, Ana:",
			"Si no has sido tú, puede que otra persona lea tu correo y esté usando tu cuenta."},
		"fr": {"Votre mot de passe a été réinitialisé", "Bonjour Ana,",
			"Sinon, une autre personne lit peut-être vos e-mails et utilise votre compte."},
		"it": {"La tua password è stata reimpostata", "Ciao Ana,",
			"Altrimenti, qualcun altro potrebbe leggere la tua email e usare il tuo account."},
		"pt-BR": {"Sua senha foi redefinida", "Olá Ana,",
			"Se não foi você, outra pessoa pode estar lendo o seu e-mail e usando a sua conta."},
	}},
	{"otp_enabled", map[string]noticeText{
		"en": {"Two-factor authentication was set up", "Hello Ana,",
			"If you didn't, someone else may know your password."},
		"de": {"Die Zwei-Faktor-Authentifizierung wurde eingerichtet", "Guten Tag Ana,",
			"Andernfalls kennt möglicherweise jemand Ihr Passwort."},
		"es": {"Se ha configurado la autenticación de dos factores", "Hola, Ana:", //nolint:misspell // "factores" is Spanish, not a misspelling of "factors"
			"Si no has sido tú, puede que otra persona conozca tu contraseña."},
		"fr": {"L’authentification à deux facteurs a été configurée", "Bonjour Ana,",
			"Sinon, une autre personne connaît peut-être votre mot de passe."},
		"it": {"L'autenticazione a due fattori è stata configurata", "Ciao Ana,",
			"Altrimenti, qualcun altro potrebbe conoscere la tua password."},
		"pt-BR": {"A autenticação de dois fatores foi configurada", "Olá Ana,",
			"Se não foi você, outra pessoa pode saber a sua senha."},
	}},
	{"otp_disabled", map[string]noticeText{
		"en": {"Two-factor authentication was turned off", "Hello Ana,",
			"If you didn't, someone else may know your password."},
		"de": {"Die Zwei-Faktor-Authentifizierung wurde deaktiviert", "Guten Tag Ana,",
			"Andernfalls kennt möglicherweise jemand Ihr Passwort."},
		"es": {"Se ha desactivado la autenticación de dos factores", "Hola, Ana:", //nolint:misspell // "factores" is Spanish, not a misspelling of "factors"
			"Si no has sido tú, puede que otra persona conozca tu contraseña."},
		"fr": {"L’authentification à deux facteurs a été désactivée", "Bonjour Ana,",
			"Sinon, une autre personne connaît peut-être votre mot de passe."},
		"it": {"L'autenticazione a due fattori è stata disattivata", "Ciao Ana,",
			"Altrimenti, qualcun altro potrebbe conoscere la tua password."},
		"pt-BR": {"A autenticação de dois fatores foi desativada", "Olá Ana,",
			"Se não foi você, outra pessoa pode saber a sua senha."},
	}},
	{"otp_disabled_by_administrator", map[string]noticeText{
		"en": {"An administrator turned off your two-factor authentication", "Hello Ana,",
			"If you weren't expecting it, contact your administrator."},
		"de": {"Ihre Zwei-Faktor-Authentifizierung wurde von der Administration deaktiviert", "Guten Tag Ana,",
			"Falls Sie damit nicht gerechnet haben, wenden Sie sich an Ihre Administration."},
		"es": {"Un administrador ha desactivado tu autenticación de dos factores", "Hola, Ana:", //nolint:misspell // "factores" is Spanish, not a misspelling of "factors"
			"Si no lo esperabas, contacta con tu administrador."},
		"fr": {"Un administrateur a désactivé votre authentification à deux facteurs", "Bonjour Ana,",
			"Si vous ne vous y attendiez pas, contactez votre administrateur."},
		"it": {"Un amministratore ha disattivato la tua autenticazione a due fattori", "Ciao Ana,",
			"Se non te lo aspettavi, contatta il tuo amministratore."},
		"pt-BR": {"Um administrador desativou a sua autenticação de dois fatores", "Olá Ana,",
			"Se você não esperava por isso, entre em contato com o administrador."},
	}},
	{"otp_lockout", map[string]noticeText{
		"en": {"Your authenticator was disabled after too many wrong codes", "Hello Ana,",
			"Those codes could only be entered after your password, so someone else may know it."},
		"de": {"Ihre Authenticator-App wurde nach zu vielen falschen Codes gesperrt", "Guten Tag Ana,",
			"Diese Codes konnten nur nach Ihrem Passwort eingegeben werden, also kennt möglicherweise jemand Ihr Passwort."},
		"es": {"Tu aplicación de autenticación se ha bloqueado tras demasiados códigos incorrectos", "Hola, Ana:",
			"Esos códigos solo se podían introducir después de tu contraseña, así que puede que otra persona la conozca."},
		"fr": {"Votre application d’authentification a été bloquée après trop de codes erronés", "Bonjour Ana,",
			"Ces codes ne pouvaient être saisis qu’après votre mot de passe, une autre personne le connaît donc peut-être."},
		"it": {"La tua app di autenticazione è stata bloccata dopo troppi codici errati", "Ciao Ana,",
			"Quei codici si potevano inserire solo dopo la password, quindi qualcun altro potrebbe conoscerla."},
		"pt-BR": {"Seu aplicativo autenticador foi bloqueado após muitos códigos errados", "Olá Ana,",
			"Esses códigos só podiam ser digitados depois da sua senha, então outra pessoa pode saber a sua senha."},
	}},
	{"recovery_code_used", map[string]noticeText{
		"en": {"A recovery code was used to sign in", "Hello Ana,",
			"If it wasn't you, someone else may know your password and have your recovery codes."},
		"de": {"Für die Anmeldung wurde ein Wiederherstellungscode verwendet", "Guten Tag Ana,",
			"Andernfalls kennt möglicherweise jemand Ihr Passwort und hat Ihre Wiederherstellungscodes."},
		"es": {"Se ha usado un código de recuperación para iniciar sesión", "Hola, Ana:",
			"Si no has sido tú, puede que otra persona conozca tu contraseña y tenga tus códigos de recuperación."},
		"fr": {"Un code de récupération a été utilisé pour vous connecter", "Bonjour Ana,",
			"Sinon, une autre personne connaît peut-être votre mot de passe et possède vos codes de récupération."},
		"it": {"È stato usato un codice di recupero per accedere", "Ciao Ana,",
			"Altrimenti, qualcun altro potrebbe conoscere la tua password e avere i tuoi codici di recupero."},
		"pt-BR": {"Um código de recuperação foi usado para entrar", "Olá Ana,",
			"Se não foi você, outra pessoa pode saber a sua senha e ter os seus códigos de recuperação."},
	}},
	{"recovery_codes_replaced", map[string]noticeText{
		"en": {"Your recovery codes were replaced", "Hello Ana,",
			"If you didn't, someone else may know your password."},
		"de": {"Ihre Wiederherstellungscodes wurden ersetzt", "Guten Tag Ana,",
			"Andernfalls kennt möglicherweise jemand Ihr Passwort."},
		"es": {"Se han sustituido tus códigos de recuperación", "Hola, Ana:",
			"Si no has sido tú, puede que otra persona conozca tu contraseña."},
		"fr": {"Vos codes de récupération ont été remplacés", "Bonjour Ana,",
			"Sinon, une autre personne connaît peut-être votre mot de passe."},
		"it": {"I tuoi codici di recupero sono stati sostituiti", "Ciao Ana,",
			"Altrimenti, qualcun altro potrebbe conoscere la tua password."},
		"pt-BR": {"Seus códigos de recuperação foram substituídos", "Olá Ana,",
			"Se não foi você, outra pessoa pode saber a sua senha."},
	}},
	{"account_deleted", map[string]noticeText{
		"en": {"Your account was deleted", "Hello Ana,",
			"If you didn't, someone else knew your password."},
		"de": {"Ihr Konto wurde gelöscht", "Guten Tag Ana,",
			"Andernfalls kannte jemand anderes Ihr Passwort."},
		"es": {"Se ha eliminado tu cuenta", "Hola, Ana:",
			"Si no has sido tú, otra persona conocía tu contraseña."},
		"fr": {"Votre compte a été supprimé", "Bonjour Ana,",
			"Sinon, une autre personne connaissait votre mot de passe."},
		"it": {"Il tuo account è stato eliminato", "Ciao Ana,", //nolint:misspell // "eliminato" is Italian, not a misspelling of "elimination"
			"Altrimenti, qualcun altro conosceva la tua password."},
		"pt-BR": {"Sua conta foi excluída", "Olá Ana,",
			"Se não foi você, outra pessoa sabia a sua senha."},
	}},
	{"account_deleted_by_administrator", map[string]noticeText{
		"en": {"An administrator deleted your account", "Hello Ana,",
			"An administrator deleted your Acme Portal account. You can no longer sign in with it."},
		"de": {"Ihr Konto wurde von der Administration gelöscht", "Guten Tag Ana,",
			"Die Administration hat Ihr Konto bei Acme Portal gelöscht. Sie können sich damit nicht mehr anmelden."},
		"es": {"Un administrador ha eliminado tu cuenta", "Hola, Ana:",
			"Un administrador ha eliminado tu cuenta de Acme Portal. Ya no puedes iniciar sesión con ella."},
		"fr": {"Un administrateur a supprimé votre compte", "Bonjour Ana,",
			"Un administrateur a supprimé votre compte Acme Portal. Vous ne pouvez plus vous y connecter."},
		"it": {"Un amministratore ha eliminato il tuo account", "Ciao Ana,", //nolint:misspell // "eliminato" is Italian, not a misspelling of "elimination"
			"Un amministratore ha eliminato il tuo account Acme Portal. Non puoi più accedere con questo account."}, //nolint:misspell // "eliminato" is Italian, not a misspelling of "elimination"
		"pt-BR": {"Um administrador excluiu a sua conta", "Olá Ana,",
			"Um administrador excluiu a sua conta Acme Portal. Você não pode mais entrar com ela."},
	}},
}

func TestBuiltIns_TheTwelveNotices(t *testing.T) {
	for _, tc := range noticeTexts {
		t.Run(tc.id, func(t *testing.T) {
			email := builtInByID(t, tc.id)
			want := []Placeholder{{Name: AppName}, {Name: Name}}
			if tc.id == "recovery_code_used" {
				want = append(want, Placeholder{Name: CodesLeft})
			}
			assert.Equal(t, want, email.Placeholders)
			assert.False(t, email.HasButton(), "a notice draws no button")
			require.Len(t, tc.langs, len(builtInLanguages))

			for lang, text := range tc.langs {
				t.Run(lang, func(t *testing.T) {
					subject, body := renderedIn(t, email, lang, testValues)
					assert.Equal(t, text.subject, subject)
					doc, err := goquery.NewDocumentFromReader(strings.NewReader(body))
					require.NoError(t, err)
					assert.Equal(t, text.greeting, doc.Find("p").First().Text())
					if tc.id == "account_deleted_by_administrator" {
						assert.Equal(t, text.warning, doc.Find("p").Eq(1).Text())
					} else {
						assert.Equal(t, text.warning, doc.Find("strong").Text(), "the warning sentence stays bold")
					}
					assert.True(t, strings.HasSuffix(body, "<br>\nAcme Portal</p>\n"), "signed with the app name: %s", body)
					assert.Zero(t, doc.Find("a").Length(), "a notice carries no link")
				})
			}
		})
	}
}

// The recovery code notice gives the codes left as a number, in one sentence and one advice
// sentence that read the same for any count (#818 decision 4): the wording that changed with none,
// one or more left is given up.
func TestRecoveryCodeUsed_OneWordingForEveryCount(t *testing.T) {
	for _, tc := range []struct {
		lang, left, advice string
	}{
		{"en", "Unused recovery codes left: %s.",
			"If you still have the app, get a new set of recovery codes there, so you can still sign in if you lose it."},
		{"de", "Verbleibende unbenutzte Wiederherstellungscodes: %s.",
			"Haben Sie die App noch, erstellen Sie dort einen neuen Satz Wiederherstellungscodes, damit Sie sich weiterhin anmelden können, falls Sie sie verlieren."},
		{"es", "Códigos de recuperación sin usar restantes: %s.",
			"Si aún tienes la aplicación, obtén allí un nuevo conjunto de códigos de recuperación, para poder iniciar sesión si la pierdes."},
		{"fr", "Codes de récupération inutilisés restants : %s.",
			"Si vous avez toujours l’application, obtenez un nouveau jeu de codes de récupération dans les paramètres de votre compte, pour pouvoir vous connecter si vous la perdez."},
		{"it", "Codici di recupero inutilizzati rimasti: %s.",
			"Se hai ancora l'app, ottieni lì un nuovo set di codici di recupero, per poter accedere se la perdi."},
		{"pt-BR", "Códigos de recuperação sem uso restantes: %s.",
			"Se você ainda tem o aplicativo, gere lá um novo conjunto de códigos de recuperação, para poder entrar se perdê-lo."},
	} {
		for _, left := range []struct {
			count int
			text  string
		}{{0, "0"}, {1, "1"}, {9, "9"}} {
			t.Run(tc.lang+"/"+left.text, func(t *testing.T) {
				values := testValues
				values.CodesLeft = left.count
				_, body := renderedIn(t, builtInByID(t, "recovery_code_used"), tc.lang, values)
				assert.Contains(t, body, strings.Replace(tc.left, "%s", left.text, 1)+"</p>")
				assert.Contains(t, body, tc.advice+"</p>")
			})
		}
	}
}

// Every one of the 19 emails is sent from its built-in definition, by the identifiers of decision 6.
func TestBuiltIns_AreTheNineteenEmails(t *testing.T) {
	var ids []string
	for _, email := range BuiltIns() {
		ids = append(ids, email.ID)
	}
	assert.ElementsMatch(t, []string{
		"password_reset_link", "activation_link", "welcome", "registration_existing_account",
		"verification_code", "new_user_setup", "test",
		"email_address_changed", "password_changed", "password_changed_by_administrator", "password_reset",
		"otp_enabled", "otp_disabled", "otp_disabled_by_administrator", "otp_lockout", "recovery_code_used",
		"recovery_codes_replaced", "account_deleted", "account_deleted_by_administrator",
	}, ids)
}
