package emailtemplate

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The registration, setup, verification and test emails are sent from their built-in definitions
// (#818): each is found by its identifier (decision 6), offers the placeholders decisions 3 and 4
// give it, and reads in each language as its template file read, the expiry sentence of the
// activation link and the setup email now reading the lifetime, and the verification code gaining
// one.

// builtInByID answers the built-in definition whose identifier is id, failing the test when there
// is none.
func builtInByID(t *testing.T, id string) *Email {
	t.Helper()
	for _, email := range BuiltIns() {
		if email.ID == id {
			return email
		}
	}
	require.Failf(t, "no built-in definition", "there is no built-in email %q", id)
	return nil
}

// renderedIn renders email's built-in text in lang with values, in testLook, and answers the subject
// and the body.
func renderedIn(t *testing.T, email *Email, lang string, values Values) (string, string) {
	t.Helper()
	text, ok := email.BuiltIn[lang]
	require.True(t, ok, "%s is written in %s", email.ID, lang)
	rendered, err := email.Render(lang, text, values, testLook)
	require.NoError(t, err)
	return rendered.Subject, string(rendered.Body)
}

// The identifiers and placeholders of decisions 3, 4 and 6.
func TestBuiltIns_TheRegistrationSetupVerificationAndTestEmails(t *testing.T) {
	for _, tc := range []struct {
		id           string
		placeholders []Placeholder
	}{
		{"activation_link", []Placeholder{{Name: AppName}, {Name: Link, Required: true}, {Name: Button}, {Name: Expiry}}},
		{"welcome", []Placeholder{{Name: AppName}, {Name: Link}, {Name: Button}}},
		{"registration_existing_account", []Placeholder{{Name: AppName}, {Name: Link}}},
		{"new_user_setup", []Placeholder{{Name: AppName}, {Name: Name}, {Name: Link, Required: true}, {Name: Button}, {Name: Expiry}}},
		{"verification_code", []Placeholder{{Name: AppName}, {Name: Name}, {Name: Code, Required: true}, {Name: Link}, {Name: Expiry}}},
		{"test", []Placeholder{{Name: AppName}}},
	} {
		t.Run(tc.id, func(t *testing.T) {
			assert.Equal(t, tc.placeholders, builtInByID(t, tc.id).Placeholders)
		})
	}
}

// The activation link: its subject, its button, the sentence that says what the link does, and the
// one that says how long it lasts, which reads the link's lifetime.
func TestActivationLink_InEachLanguage(t *testing.T) {
	email := builtInByID(t, "activation_link")
	// A lifetime the text has never said, so a sentence that wrote today's five minutes out would fail.
	values := testValues
	values.Expiry = 10 * time.Minute
	for _, tc := range []struct {
		lang, subject, button, greeting, sentence, expiry string
	}{
		{"en", "Activate your account", "Activate account", "Hello,",
			"To finish creating your Acme Portal account, click the link below and choose a password:",
			"The link expires in 10 minutes. If you have trouble clicking it, copy and paste it into your web browser."},
		{"de", "Aktivieren Sie Ihr Konto", "Konto aktivieren", "Guten Tag,",
			"Öffnen Sie diesen Link und wählen Sie ein Passwort, um Ihr Konto bei Acme Portal fertig einzurichten:",
			"Der Link läuft nach 10 Minuten ab. Falls er sich nicht öffnen lässt, kopieren Sie ihn und fügen Sie ihn in die Adresszeile Ihres Browsers ein."},
		{"es", "Activa tu cuenta", "Activar cuenta", "Hola:",
			"Para terminar de crear tu cuenta de Acme Portal, abre este enlace y elige una contraseña:",
			"El enlace caduca en 10 minutos. Si no puedes abrirlo, copia y pega la dirección en tu navegador."},
		{"fr", "Activez votre compte", "Activer le compte", "Bonjour,",
			"Pour terminer la création de votre compte Acme Portal, cliquez sur le lien ci-dessous et choisissez un mot de passe\u00a0:",
			"Le lien expire dans 10 minutes. S’il ne s’ouvre pas, copiez-le et collez-le dans votre navigateur."},
		{"it", "Attiva il tuo account", "Attiva l'account", "Ciao,",
			"Per completare la creazione del tuo account Acme Portal, apri questo link e scegli una password:",
			"Il link scade tra 10 minuti. Se non riesci ad aprirlo, copialo e incollalo nel browser."},
		{"pt-BR", "Ative sua conta", "Ativar conta", "Olá,",
			"Para terminar de criar sua conta no Acme Portal, clique no link abaixo e escolha uma senha:",
			"O link expira em 10 minutos. Se tiver problemas para clicar nele, copie e cole o endereço no seu navegador."}, //nolint:misspell // the pt-BR text: "problemas" is Portuguese, not a misspelling of "problems"
	} {
		t.Run(tc.lang, func(t *testing.T) {
			assert.Equal(t, tc.button, email.BuiltIn[tc.lang].ButtonLabel)
			subject, body := renderedIn(t, email, tc.lang, values)
			assert.Equal(t, tc.subject, subject)
			assert.True(t, strings.HasPrefix(body, "<p>"+tc.greeting+"</p>\n"), body)
			assert.Contains(t, body, "<p>"+tc.sentence+"</p>\n")
			assert.Contains(t, body, ">"+tc.button+"</a>", "the button is labelled")
			assert.Contains(t, body, "<p>"+linkTo(escapedLink, escapedLink)+"</p>", "the URL is written out, to copy")
			assert.Contains(t, body, "<p>"+tc.expiry+"</p>\n")
			assert.Contains(t, body, "<br>\nAcme Portal</p>", "signed with the app name")
		})
	}
}

// The welcome email: its subject, its button and its first two sentences.
func TestWelcome_InEachLanguage(t *testing.T) {
	email := builtInByID(t, "welcome")
	for _, tc := range []struct {
		lang, subject, button, first, second string
	}{
		{"en", "Welcome!", "Sign in", "Congratulations! Your account has been created.", "You can login by clicking the link below:"},
		{"de", "Willkommen!", "Anmelden", "Ihr Konto wurde erstellt.", "Über diesen Link können Sie sich anmelden:"},
		{"es", "¡Te damos la bienvenida!", "Iniciar sesión", "¡Tu cuenta ya está creada!", "Puedes iniciar sesión desde este enlace:"},
		{"fr", "Bienvenue\u00a0!", "Se connecter", "Bienvenue\u00a0! Votre compte a été créé.",
			"Pour vous connecter, cliquez sur le lien ci-dessous\u00a0:"},
		{"it", "Benvenuto!", "Accedi", "Il tuo account è stato creato.", "Puoi accedere aprendo questo link:"},
		{"pt-BR", "Bem-vindo(a)!", "Entrar", "Parabéns! Sua conta foi criada.", "Você pode entrar clicando no link abaixo:"},
	} {
		t.Run(tc.lang, func(t *testing.T) {
			assert.Equal(t, tc.button, email.BuiltIn[tc.lang].ButtonLabel)
			subject, body := renderedIn(t, email, tc.lang, testValues)
			assert.Equal(t, tc.subject, subject)
			assert.True(t, strings.HasPrefix(body, "<p>"+tc.first+"</p>\n<p>"+tc.second+"</p>\n"), body)
			assert.Contains(t, body, ">"+tc.button+"</a>", "the button is labelled")
			assert.Contains(t, body, "<p>"+linkTo(escapedLink, escapedLink)+"</p>", "the URL is written out, to copy")
			assert.Contains(t, body, "<br>\nAcme Portal</p>", "signed with the app name")
		})
	}
}

// The notice that the address already has an account: its subject, the sentence that says no
// account was created, and the one that ends with the link to reset the password.
func TestRegistrationExistingAccount_InEachLanguage(t *testing.T) {
	email := builtInByID(t, "registration_existing_account")
	for _, tc := range []struct {
		lang, subject, greeting, sentence, linkSentence string
	}{
		{"en", "You already have an account", "Hello,",
			"Someone, possibly you, tried to create a new Acme Portal account with this email address. This address already has an account, so no new account was created.",
			"If it was you, sign in with your existing account. If you don't remember your password, you can reset it here: "},
		{"de", "Sie haben bereits ein Konto", "Guten Tag,",
			"Jemand hat versucht, mit dieser E-Mail-Adresse ein neues Konto bei Acme Portal zu erstellen. Möglicherweise waren Sie das selbst. Für diese Adresse gibt es bereits ein Konto. Daher wurde kein neues Konto erstellt.",
			"Falls Sie die Anfrage gestellt haben, melden Sie sich mit Ihrem bestehenden Konto an. Wenn Sie Ihr Passwort vergessen haben, können Sie es hier zurücksetzen: "},
		{"es", "Ya tienes una cuenta", "Hola:",
			"Alguien, quizá tú, ha intentado crear una cuenta de Acme Portal con esta dirección de correo electrónico. La dirección ya tiene una cuenta, por lo que no se ha creado otra.",
			"Si has sido tú, inicia sesión con tu cuenta existente. Si no recuerdas tu contraseña, puedes restablecerla aquí: "},
		{"fr", "Vous avez déjà un compte", "Bonjour,",
			"Une personne, peut-être vous, a essayé de créer un compte Acme Portal avec cette adresse e-mail. Cette adresse correspond déjà à un compte. Aucun nouveau compte n’a donc été créé.",
			"Si c’était vous, connectez-vous à votre compte existant. Si vous avez oublié votre mot de passe, vous pouvez le réinitialiser ici\u00a0: "}, //nolint:misspell // the fr text: "existant" is French, not a misspelling of "existent"
		{"it", "Hai già un account", "Ciao,",
			"Qualcuno, forse tu, ha provato a creare un nuovo account Acme Portal con questo indirizzo email. L'indirizzo ha già un account, quindi non ne è stato creato uno nuovo.",
			"Se hai fatto tu la richiesta, accedi con il tuo account esistente. Se non ricordi la password, puoi reimpostarla qui: "},
		{"pt-BR", "Você já tem uma conta", "Olá,",
			"Alguém, possivelmente você, tentou criar uma nova conta no Acme Portal com este endereço de e-mail. Este endereço já tem uma conta, então nenhuma conta nova foi criada.",
			"Se foi você, entre com sua conta existente. Se não se lembra da sua senha, pode redefini-la aqui: "},
	} {
		t.Run(tc.lang, func(t *testing.T) {
			assert.Empty(t, email.BuiltIn[tc.lang].ButtonLabel, "the notice has no button")
			subject, body := renderedIn(t, email, tc.lang, testValues)
			assert.Equal(t, tc.subject, subject)
			assert.True(t, strings.HasPrefix(body, "<p>"+tc.greeting+"</p>\n"), body)
			assert.Contains(t, body, "<p>"+tc.sentence+"</p>\n")
			assert.Contains(t, body, "<p>"+tc.linkSentence+linkTo(escapedLink, escapedLink)+"</p>\n")
			assert.NotContains(t, body, "<table", "no button")
		})
	}
}

// The setup email of a user an administrator created: its subject, which names the app, its button,
// its greeting, and the bold sentence that says how long the link works, reading the lifetime.
func TestNewUserSetup_InEachLanguage(t *testing.T) {
	email := builtInByID(t, "new_user_setup")
	values := testValues
	values.Expiry = 48 * time.Hour // not the 24 hours the text used to say
	for _, tc := range []struct {
		lang, subject, button, greeting, sentence, lasts string
	}{
		{"en", "Acme Portal - create a password for your new account", "Create password", "Hello Ana,",
			"You can create your password by clicking the link below:", "The link works for 48 hours. If it has expired,"},
		{"de", "Acme Portal – Passwort für Ihr neues Konto festlegen", "Passwort festlegen", "Guten Tag Ana,",
			"Öffnen Sie diesen Link, um Ihr Passwort festzulegen:", "Der Link ist 48 Stunden gültig. Falls er abgelaufen ist,"},
		{"es", "Acme Portal - crea una contraseña para tu nueva cuenta", "Crear contraseña", "Hola, Ana:",
			"Para crear tu contraseña, abre este enlace:", "El enlace es válido durante 48 horas. Si ha caducado,"},
		{"fr", "Acme Portal - créez un mot de passe pour votre nouveau compte", "Créer le mot de passe", "Bonjour Ana,",
			"Pour créer votre mot de passe, cliquez sur le lien ci-dessous\u00a0:", "Le lien est valable 48 heures. S’il a expiré,"},
		{"it", "Acme Portal - crea una password per il tuo nuovo account", "Crea la password", "Ciao Ana,",
			"Per creare la tua password, apri questo link:", "Il link è valido per 48 ore. Se è scaduto,"},
		{"pt-BR", "Acme Portal - crie uma senha para sua nova conta", "Criar senha", "Olá Ana,",
			"Você pode criar sua senha clicando no link abaixo:", "O link funciona por 48 horas. Se ele tiver expirado,"},
	} {
		t.Run(tc.lang, func(t *testing.T) {
			assert.Equal(t, tc.button, email.BuiltIn[tc.lang].ButtonLabel)
			subject, body := renderedIn(t, email, tc.lang, values)
			assert.Equal(t, tc.subject, subject)
			assert.True(t, strings.HasPrefix(body, "<p>"+tc.greeting+"</p>\n"), body)
			assert.Contains(t, body, "<p>"+tc.sentence+"</p>\n")
			assert.Contains(t, body, ">"+tc.button+"</a>", "the button is labelled")
			assert.Contains(t, body, "<p>"+linkTo(escapedLink, escapedLink)+"</p>", "the URL is written out, to copy")
			assert.Contains(t, body, "<p><strong>"+tc.lasts, "the lifetime sentence stays bold")
			assert.Contains(t, body, "<br>\nAcme Portal</p>", "signed with the app name")
		})
	}
}

// The verification code: its subject, which holds the code, its greeting, the code in its box, the
// new sentence that says how long the code lasts, and the sentence that ends with the link.
func TestVerificationCode_InEachLanguage(t *testing.T) {
	email := builtInByID(t, "verification_code")
	values := testValues
	values.Expiry = 10 * time.Minute
	for _, tc := range []struct {
		lang, subject, greeting, sentence, expiry, linkSentence string
	}{
		{"en", "Email verification - code 482915", "Hello Ana,", "This is your email verification code:",
			"The code expires in 10 minutes.", "You can enter your code here: "},
		{"de", "E-Mail-Bestätigung – Code 482915", "Guten Tag Ana,", "Mit diesem Code können Sie Ihre E-Mail-Adresse bestätigen:",
			"Der Code läuft nach 10 Minuten ab.", "Geben Sie den Code hier ein: "},
		{"es", "Verificación del correo - código 482915", "Hola, Ana:", "Este es tu código de verificación del correo electrónico:",
			"El código caduca en 10 minutos.", "Puedes escribir el código aquí: "},
		{"fr", "Vérification de l’adresse e-mail - code 482915", "Bonjour Ana,", "Voici votre code de vérification de l’adresse e-mail\u00a0:",
			"Le code expire dans 10 minutes.", "Vous pouvez saisir ce code ici\u00a0: "},
		{"it", "Verifica email - codice 482915", "Ciao Ana,", "Ecco il tuo codice di verifica dell'indirizzo email:",
			"Il codice scade tra 10 minuti.", "Puoi inserire il codice qui: "},
		{"pt-BR", "Verificação de e-mail - código 482915", "Olá Ana,", "Este é o seu código de verificação de e-mail:",
			"O código expira em 10 minutos.", "Você pode inserir o código aqui: "},
	} {
		t.Run(tc.lang, func(t *testing.T) {
			assert.Empty(t, email.BuiltIn[tc.lang].ButtonLabel, "the email has no button")
			subject, body := renderedIn(t, email, tc.lang, values)
			assert.Equal(t, tc.subject, subject)
			assert.True(t, strings.HasPrefix(body, "<p>"+tc.greeting+"</p>\n<p>"+tc.sentence+"</p>\n<p style="), body)
			assert.Contains(t, body, `text-align: center;">482915</p>`, "the code is boxed")
			assert.Contains(t, body, "<p>"+tc.expiry+"</p>\n")
			assert.Contains(t, body, "<p>"+tc.linkSentence+linkTo(escapedLink, escapedLink)+"</p>\n")
			assert.Contains(t, body, "<br>\nAcme Portal</p>", "signed with the app name")
		})
	}
}

// The test email: its subject, which names the app, and its two sentences.
func TestTestEmail_InEachLanguage(t *testing.T) {
	email := builtInByID(t, "test")
	for _, tc := range []struct {
		lang, subject, first, second string
	}{
		{"en", "Acme Portal - test email", "This is a test email from Acme Portal.",
			"It was sent from the email settings to check that email can be sent. If you can read it, there is nothing else to do."},
		{"de", "Acme Portal – Test-E-Mail", "Dies ist eine Test-E-Mail von Acme Portal.",
			"Sie wurde aus den E-Mail-Einstellungen gesendet, um zu prüfen, ob E-Mails versendet werden können. Wenn Sie sie lesen können, ist nichts weiter zu tun."},
		{"es", "Acme Portal - correo de prueba", "Este es un correo de prueba enviado por Acme Portal.",
			"Se envió desde la configuración de correo para comprobar que se pueden enviar correos. Si puedes leerlo, no tienes que hacer nada más."},
		{"fr", "Acme Portal - e-mail de test", "Ceci est un e-mail de test envoyé par Acme Portal.",
			"Il a été envoyé depuis les paramètres des e-mails pour vérifier que l’envoi d’e-mails fonctionne. Si vous pouvez le lire, vous n’avez rien d’autre à faire."},
		{"it", "Acme Portal - email di prova", "Questa è un’email di prova inviata da Acme Portal.",
			"È stata inviata dalle impostazioni email per verificare che l’invio delle email funzioni. Se riesci a leggerla, non devi fare altro."},
		{"pt-BR", "Acme Portal - e-mail de teste", "Este é um e-mail de teste enviado por Acme Portal.",
			"Ele foi enviado pelas configurações de e-mail para verificar se o envio de e-mails funciona. Se você consegue lê-lo, não precisa fazer mais nada."},
	} {
		t.Run(tc.lang, func(t *testing.T) {
			subject, body := renderedIn(t, email, tc.lang, testValues)
			assert.Equal(t, tc.subject, subject)
			assert.Equal(t, "<p>"+tc.first+"</p>\n<p>"+tc.second+"</p>\n", body)
		})
	}
}
