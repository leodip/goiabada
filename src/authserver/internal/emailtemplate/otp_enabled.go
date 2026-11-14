package emailtemplate

// OTPEnabled tells a user an authenticator was set up for their account, with the set of recovery
// codes it came with.
var OTPEnabled = &Email{
	ID: "otp_enabled",
	Placeholders: []Placeholder{
		{Name: AppName}, {Name: Name},
	},
	BuiltIn: map[string]Text{
		"en": {
			Subject: "Two-factor authentication was set up",
			Body: `Hello {{name}},

Two-factor authentication was set up on your {{app_name}} account. Signing in to apps that use two-factor authentication now asks for a code from the authenticator app that was set up. It came with a new set of recovery codes, which sign you in if you lose that app.

If you set it up, you don't need to do anything. Keep your recovery codes somewhere safe.

**If you didn't, someone else may know your password.** Choose a new password with "Forgot your password?" on the sign-in page, then sign in and check your two-factor authentication settings, or contact your administrator.

Best regards,
{{app_name}}`,
		},
		"de": {
			Subject: "Die Zwei-Faktor-Authentifizierung wurde eingerichtet",
			Body: `Guten Tag {{name}},

Für Ihr Konto bei {{app_name}} wurde die Zwei-Faktor-Authentifizierung eingerichtet. Bei der Anmeldung bei Apps, die Zwei-Faktor-Authentifizierung verwenden, wird jetzt ein Code aus der eingerichteten Authenticator-App abgefragt. Dazu wurde ein neuer Satz Wiederherstellungscodes erstellt, mit dem Sie sich anmelden können, falls Sie diese App verlieren.

Falls Sie sie selbst eingerichtet haben, brauchen Sie nichts zu tun. Bewahren Sie Ihre Wiederherstellungscodes sicher auf.

**Andernfalls kennt möglicherweise jemand Ihr Passwort.** Wählen Sie auf der Anmeldeseite über „Passwort vergessen?“ ein neues Passwort, melden Sie sich dann an und prüfen Sie Ihre Einstellungen zur Zwei-Faktor-Authentifizierung. Sie können sich auch an Ihre Administration wenden.

Mit freundlichen Grüßen
{{app_name}}`,
		},
		//nolint:misspell // the es text: "factores" is Spanish, not a misspelling of "factors"
		"es": {
			Subject: "Se ha configurado la autenticación de dos factores",
			Body: `Hola, {{name}}:

Se ha configurado la autenticación de dos factores en tu cuenta de {{app_name}}. Ahora, al iniciar sesión en las aplicaciones que usan la autenticación de dos factores, se pide un código de la aplicación de autenticación configurada. Viene con un nuevo conjunto de códigos de recuperación, que te permiten iniciar sesión si pierdes esa aplicación.

Si la has configurado tú, no necesitas hacer nada. Guarda tus códigos de recuperación en un lugar seguro.

**Si no has sido tú, puede que otra persona conozca tu contraseña.** Elige una contraseña nueva con «¿Olvidaste tu contraseña?» en la página de inicio de sesión. Después, inicia sesión y revisa la configuración de la autenticación de dos factores, o contacta con tu administrador.

Un saludo,
{{app_name}}`,
		},
		"fr": {
			Subject: "L’authentification à deux facteurs a été configurée",
			Body: `Bonjour {{name}},

L’authentification à deux facteurs a été configurée sur votre compte {{app_name}}. La connexion aux applications qui utilisent l’authentification à deux facteurs demande désormais un code de l’application d’authentification configurée. Un nouveau jeu de codes de récupération a été créé avec elle. Il vous permet de vous connecter si vous perdez cette application.

Si vous l’avez configurée, vous n’avez rien à faire. Conservez vos codes de récupération en lieu sûr.

**Sinon, une autre personne connaît peut-être votre mot de passe.** Choisissez un nouveau mot de passe avec « Mot de passe oublié ? » sur la page de connexion, puis connectez-vous et vérifiez vos paramètres d’authentification à deux facteurs, ou contactez votre administrateur.

Cordialement,
{{app_name}}`,
		},
		"it": {
			Subject: "L'autenticazione a due fattori è stata configurata",
			Body: `Ciao {{name}},

L'autenticazione a due fattori è stata configurata sul tuo account {{app_name}}. Ora l'accesso alle app che usano l'autenticazione a due fattori chiede un codice dell'app di autenticazione configurata. Insieme è stato creato un nuovo set di codici di recupero, che ti permettono di accedere se perdi quell'app.

Se l'hai configurata tu, non devi fare nulla. Conserva i codici di recupero in un posto sicuro.

**Altrimenti, qualcun altro potrebbe conoscere la tua password.** Scegli una nuova password con «Hai dimenticato la password?» nella pagina di accesso, poi accedi e controlla le impostazioni dell'autenticazione a due fattori, oppure contatta il tuo amministratore.

Un saluto,
{{app_name}}`,
		},
		"pt-BR": {
			Subject: "A autenticação de dois fatores foi configurada",
			Body: `Olá {{name}},

A autenticação de dois fatores foi configurada na sua conta {{app_name}}. Agora, para entrar em aplicativos que usam a autenticação de dois fatores, é pedido um código do aplicativo autenticador configurado. Ela veio com um novo conjunto de códigos de recuperação, que permitem entrar se você perder esse aplicativo.

Se foi você quem a configurou, não é preciso fazer nada. Guarde seus códigos de recuperação em um lugar seguro.

**Se não foi você, outra pessoa pode saber a sua senha.** Escolha uma nova senha em "Esqueceu sua senha?" na página de entrada, depois entre na sua conta e confira as configurações de autenticação de dois fatores, ou entre em contato com o administrador.

Atenciosamente,
{{app_name}}`,
		},
	},
}
