package emailtemplate

// PasswordReset tells a user their password was reset through a forgot-password link.
var PasswordReset = &Email{
	ID: "password_reset",
	Placeholders: []Placeholder{
		{Name: AppName}, {Name: Name},
	},
	BuiltIn: map[string]Text{
		"en": {
			Subject: "Your password was reset",
			Body: `Hello {{name}},

The password for your {{app_name}} account was reset with a link sent to this email address.

If you reset it, you don't need to do anything.

**If you didn't, someone else may be able to read your email and use your account.** Secure your email account, then choose a new password with "Forgot your password?" on the sign-in page, sign in and check your two-factor authentication settings, or contact your administrator.

Best regards,
{{app_name}}`,
		},
		"de": {
			Subject: "Ihr Passwort wurde zurückgesetzt",
			Body: `Guten Tag {{name}},

Das Passwort Ihres Kontos bei {{app_name}} wurde über einen Link zurückgesetzt, der an diese E-Mail-Adresse gesendet wurde.

Falls Sie es selbst zurückgesetzt haben, brauchen Sie nichts zu tun.

**Andernfalls kann möglicherweise jemand anderes Ihre E-Mails lesen und Ihr Konto verwenden.** Sichern Sie Ihr E-Mail-Konto, wählen Sie dann auf der Anmeldeseite über „Passwort vergessen?“ ein neues Passwort, melden Sie sich an und prüfen Sie Ihre Einstellungen zur Zwei-Faktor-Authentifizierung. Sie können sich auch an Ihre Administration wenden.

Mit freundlichen Grüßen
{{app_name}}`,
		},
		//nolint:misspell // the es text: "factores" is Spanish, not a misspelling of "factors"
		"es": {
			Subject: "Tu contraseña se ha restablecido",
			Body: `Hola, {{name}}:

La contraseña de tu cuenta de {{app_name}} se ha restablecido con un enlace enviado a esta dirección de correo electrónico.

Si la has restablecido tú, no necesitas hacer nada.

**Si no has sido tú, puede que otra persona lea tu correo y esté usando tu cuenta.** Protege tu cuenta de correo electrónico y elige una contraseña nueva con «¿Olvidaste tu contraseña?» en la página de inicio de sesión. Después, inicia sesión y revisa la configuración de la autenticación de dos factores, o contacta con tu administrador.

Un saludo,
{{app_name}}`,
		},
		"fr": {
			Subject: "Votre mot de passe a été réinitialisé",
			Body: `Bonjour {{name}},

Le mot de passe de votre compte {{app_name}} a été réinitialisé avec un lien envoyé à cette adresse e-mail.

Si vous l’avez réinitialisé vous-même, vous n’avez rien à faire.

**Sinon, une autre personne lit peut-être vos e-mails et utilise votre compte.** Sécurisez votre messagerie, puis choisissez un nouveau mot de passe avec « Mot de passe oublié ? » sur la page de connexion, connectez-vous et vérifiez vos paramètres d’authentification à deux facteurs, ou contactez votre administrateur.

Cordialement,
{{app_name}}`,
		},
		"it": {
			Subject: "La tua password è stata reimpostata",
			Body: `Ciao {{name}},

La password del tuo account {{app_name}} è stata reimpostata con un link inviato a questo indirizzo email.

Se l'hai reimpostata tu, non devi fare nulla.

**Altrimenti, qualcun altro potrebbe leggere la tua email e usare il tuo account.** Proteggi il tuo account email, poi scegli una nuova password con «Hai dimenticato la password?» nella pagina di accesso, accedi e controlla le impostazioni dell'autenticazione a due fattori, oppure contatta il tuo amministratore.

Un saluto,
{{app_name}}`,
		},
		"pt-BR": {
			Subject: "Sua senha foi redefinida",
			Body: `Olá {{name}},

A senha da sua conta {{app_name}} foi redefinida com um link enviado para este endereço de e-mail.

Se foi você quem redefiniu, não é preciso fazer nada.

**Se não foi você, outra pessoa pode estar lendo o seu e-mail e usando a sua conta.** Proteja a sua conta de e-mail, depois escolha uma nova senha em "Esqueceu sua senha?" na página de entrada, entre na sua conta e confira as configurações de autenticação de dois fatores, ou entre em contato com o administrador.

Atenciosamente,
{{app_name}}`,
		},
	},
}
