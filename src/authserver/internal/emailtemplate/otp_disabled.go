package emailtemplate

// OTPDisabled tells a user they turned two-factor authentication off on the Account pages.
var OTPDisabled = &Email{
	ID: "otp_disabled",
	Placeholders: []Placeholder{
		{Name: AppName}, {Name: Name},
	},
	BuiltIn: map[string]Text{
		"en": {
			Subject: "Two-factor authentication was turned off",
			Body: `Hello {{name}},

Two-factor authentication was turned off for your {{app_name}} account from your account settings. Your authenticator app and your recovery codes no longer work for signing in.

If you made this change, you don't need to do anything.

**If you didn't, someone else may know your password.** Choose a new password with "Forgot your password?" on the sign-in page, then sign in and set up two-factor authentication again, or contact your administrator.

Best regards,
{{app_name}}`,
		},
		"de": {
			Subject: "Die Zwei-Faktor-Authentifizierung wurde deaktiviert",
			Body: `Guten Tag {{name}},

Die Zwei-Faktor-Authentifizierung Ihres Kontos bei {{app_name}} wurde in Ihren Kontoeinstellungen deaktiviert. Ihre Authenticator-App und Ihre Wiederherstellungscodes funktionieren für die Anmeldung nicht mehr.

Falls Sie diese Änderung selbst vorgenommen haben, brauchen Sie nichts zu tun.

**Andernfalls kennt möglicherweise jemand Ihr Passwort.** Wählen Sie auf der Anmeldeseite über „Passwort vergessen?“ ein neues Passwort, melden Sie sich dann an und richten Sie die Zwei-Faktor-Authentifizierung erneut ein. Sie können sich auch an Ihre Administration wenden.

Mit freundlichen Grüßen
{{app_name}}`,
		},
		//nolint:misspell // the es text: "factores" is Spanish, not a misspelling of "factors"
		"es": {
			Subject: "Se ha desactivado la autenticación de dos factores",
			Body: `Hola, {{name}}:

La autenticación de dos factores de tu cuenta de {{app_name}} se ha desactivado desde la configuración de tu cuenta. Tu aplicación de autenticación y tus códigos de recuperación ya no sirven para iniciar sesión.

Si has hecho este cambio, no necesitas hacer nada.

**Si no has sido tú, puede que otra persona conozca tu contraseña.** Elige una contraseña nueva con «¿Olvidaste tu contraseña?» en la página de inicio de sesión. Después, inicia sesión y vuelve a configurar la autenticación de dos factores, o contacta con tu administrador.

Un saludo,
{{app_name}}`,
		},
		"fr": {
			Subject: "L’authentification à deux facteurs a été désactivée",
			Body: `Bonjour {{name}},

L’authentification à deux facteurs de votre compte {{app_name}} a été désactivée depuis les paramètres de votre compte. Votre application d’authentification et vos codes de récupération ne permettent plus de vous connecter.

Si vous avez effectué cette modification, vous n’avez rien à faire.

**Sinon, une autre personne connaît peut-être votre mot de passe.** Choisissez un nouveau mot de passe avec « Mot de passe oublié ? » sur la page de connexion, puis connectez-vous et configurez à nouveau l’authentification à deux facteurs, ou contactez votre administrateur.

Cordialement,
{{app_name}}`,
		},
		"it": {
			Subject: "L'autenticazione a due fattori è stata disattivata",
			Body: `Ciao {{name}},

L'autenticazione a due fattori del tuo account {{app_name}} è stata disattivata dalle impostazioni del tuo account. L'app di autenticazione e i codici di recupero non servono più per accedere.

Se hai effettuato tu la modifica, non devi fare nulla.

**Altrimenti, qualcun altro potrebbe conoscere la tua password.** Scegli una nuova password con «Hai dimenticato la password?» nella pagina di accesso, poi accedi e configura di nuovo l'autenticazione a due fattori, oppure contatta il tuo amministratore.

Un saluto,
{{app_name}}`,
		},
		"pt-BR": {
			Subject: "A autenticação de dois fatores foi desativada",
			Body: `Olá {{name}},

A autenticação de dois fatores da sua conta {{app_name}} foi desativada nas configurações da sua conta. O seu aplicativo autenticador e os seus códigos de recuperação não servem mais para entrar.

Se foi você quem fez essa alteração, não é preciso fazer nada.

**Se não foi você, outra pessoa pode saber a sua senha.** Escolha uma nova senha em "Esqueceu sua senha?" na página de entrada, depois entre na sua conta e configure a autenticação de dois fatores novamente, ou entre em contato com o administrador.

Atenciosamente,
{{app_name}}`,
		},
	},
}
