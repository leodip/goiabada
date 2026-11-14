package emailtemplate

// PasswordChangedByAdministrator tells a user an administrator replaced their password.
var PasswordChangedByAdministrator = &Email{
	ID: "password_changed_by_administrator",
	Placeholders: []Placeholder{
		{Name: AppName}, {Name: Name},
	},
	BuiltIn: map[string]Text{
		"en": {
			Subject: "An administrator changed your password",
			Body: `Hello {{name}},

An administrator changed the password for your {{app_name}} account.

If you asked for this, you don't need to do anything.

**If you weren't expecting it, contact your administrator.** You can also choose a new password with "Forgot your password?" on the sign-in page, then sign in and check your two-factor authentication settings.

Best regards,
{{app_name}}`,
		},
		"de": {
			Subject: "Ihr Passwort wurde von der Administration geändert",
			Body: `Guten Tag {{name}},

Die Administration hat das Passwort Ihres Kontos bei {{app_name}} geändert.

Falls Sie darum gebeten haben, brauchen Sie nichts zu tun.

**Falls Sie damit nicht gerechnet haben, wenden Sie sich an Ihre Administration.** Sie können auch auf der Anmeldeseite über „Passwort vergessen?“ ein neues Passwort wählen, sich dann anmelden und Ihre Einstellungen zur Zwei-Faktor-Authentifizierung prüfen.

Mit freundlichen Grüßen
{{app_name}}`,
		},
		//nolint:misspell // the es text: "factores" is Spanish, not a misspelling of "factors"
		"es": {
			Subject: "Un administrador ha cambiado tu contraseña",
			Body: `Hola, {{name}}:

Un administrador ha cambiado la contraseña de tu cuenta de {{app_name}}.

Si lo habías pedido, no necesitas hacer nada.

**Si no lo esperabas, contacta con tu administrador.** También puedes elegir una contraseña nueva con «¿Olvidaste tu contraseña?» en la página de inicio de sesión. Después, inicia sesión y revisa la configuración de la autenticación de dos factores.

Un saludo,
{{app_name}}`,
		},
		"fr": {
			Subject: "Un administrateur a modifié votre mot de passe",
			Body: `Bonjour {{name}},

Un administrateur a modifié le mot de passe de votre compte {{app_name}}.

Si vous l’aviez demandé, vous n’avez rien à faire.

**Si vous ne vous y attendiez pas, contactez votre administrateur.** Vous pouvez aussi choisir un nouveau mot de passe avec « Mot de passe oublié ? » sur la page de connexion, puis vous connecter et vérifier vos paramètres d’authentification à deux facteurs.

Cordialement,
{{app_name}}`,
		},
		"it": {
			Subject: "Un amministratore ha cambiato la tua password",
			Body: `Ciao {{name}},

Un amministratore ha cambiato la password del tuo account {{app_name}}.

Se l'avevi chiesto tu, non devi fare nulla.

**Se non te lo aspettavi, contatta il tuo amministratore.** Puoi anche scegliere una nuova password con «Hai dimenticato la password?» nella pagina di accesso, poi accedere e controllare le impostazioni dell'autenticazione a due fattori.

Un saluto,
{{app_name}}`,
		},
		"pt-BR": {
			Subject: "Um administrador alterou a sua senha",
			Body: `Olá {{name}},

Um administrador alterou a senha da sua conta {{app_name}}.

Se você pediu essa alteração, não é preciso fazer nada.

**Se você não esperava por isso, entre em contato com o administrador.** Você também pode escolher uma nova senha em "Esqueceu sua senha?" na página de entrada, depois entrar na sua conta e conferir as configurações de autenticação de dois fatores.

Atenciosamente,
{{app_name}}`,
		},
	},
}
