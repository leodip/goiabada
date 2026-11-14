package emailtemplate

// PasswordChanged tells a user their password was changed on the Account pages.
var PasswordChanged = &Email{
	ID: "password_changed",
	Placeholders: []Placeholder{
		{Name: AppName}, {Name: Name},
	},
	BuiltIn: map[string]Text{
		"en": {
			Subject: "Your password was changed",
			Body: `Hello {{name}},

The password for your {{app_name}} account was changed from your account settings.

If you made this change, you don't need to do anything.

**If you didn't, someone else may be using your account.** Choose a new password with "Forgot your password?" on the sign-in page, then sign in and check your two-factor authentication settings, or contact your administrator.

Best regards,
{{app_name}}`,
		},
		"de": {
			Subject: "Ihr Passwort wurde geändert",
			Body: `Guten Tag {{name}},

Das Passwort Ihres Kontos bei {{app_name}} wurde in Ihren Kontoeinstellungen geändert.

Falls Sie diese Änderung selbst vorgenommen haben, brauchen Sie nichts zu tun.

**Andernfalls verwendet möglicherweise jemand anderes Ihr Konto.** Wählen Sie auf der Anmeldeseite über „Passwort vergessen?“ ein neues Passwort, melden Sie sich dann an und prüfen Sie Ihre Einstellungen zur Zwei-Faktor-Authentifizierung. Sie können sich auch an Ihre Administration wenden.

Mit freundlichen Grüßen
{{app_name}}`,
		},
		//nolint:misspell // the es text: "factores" is Spanish, not a misspelling of "factors"
		"es": {
			Subject: "Tu contraseña ha cambiado",
			Body: `Hola, {{name}}:

La contraseña de tu cuenta de {{app_name}} se ha cambiado desde la configuración de tu cuenta.

Si has hecho este cambio, no necesitas hacer nada.

**Si no has sido tú, puede que otra persona esté usando tu cuenta.** Elige una contraseña nueva con «¿Olvidaste tu contraseña?» en la página de inicio de sesión. Después, inicia sesión y revisa la configuración de la autenticación de dos factores, o contacta con tu administrador.

Un saludo,
{{app_name}}`,
		},
		"fr": {
			Subject: "Votre mot de passe a été modifié",
			Body: `Bonjour {{name}},

Le mot de passe de votre compte {{app_name}} a été modifié depuis les paramètres de votre compte.

Si vous avez effectué cette modification, vous n’avez rien à faire.

**Sinon, une autre personne utilise peut-être votre compte.** Choisissez un nouveau mot de passe avec « Mot de passe oublié ? » sur la page de connexion, puis connectez-vous et vérifiez vos paramètres d’authentification à deux facteurs, ou contactez votre administrateur.

Cordialement,
{{app_name}}`,
		},
		"it": {
			Subject: "La tua password è stata cambiata",
			Body: `Ciao {{name}},

La password del tuo account {{app_name}} è stata cambiata dalle impostazioni del tuo account.

Se hai effettuato tu la modifica, non devi fare nulla.

**Altrimenti, qualcun altro potrebbe usare il tuo account.** Scegli una nuova password con «Hai dimenticato la password?» nella pagina di accesso, poi accedi e controlla le impostazioni dell'autenticazione a due fattori, oppure contatta il tuo amministratore.

Un saluto,
{{app_name}}`,
		},
		"pt-BR": {
			Subject: "Sua senha foi alterada",
			Body: `Olá {{name}},

A senha da sua conta {{app_name}} foi alterada nas configurações da sua conta.

Se foi você quem fez essa alteração, não é preciso fazer nada.

**Se não foi você, outra pessoa pode estar usando a sua conta.** Escolha uma nova senha em "Esqueceu sua senha?" na página de entrada, depois entre na sua conta e confira as configurações de autenticação de dois fatores, ou entre em contato com o administrador.

Atenciosamente,
{{app_name}}`,
		},
	},
}
