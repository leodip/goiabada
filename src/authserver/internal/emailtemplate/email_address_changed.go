package emailtemplate

// EmailAddressChanged is the notice an account's previous address receives when the account's
// address is changed. It names neither the new address nor carries a link.
var EmailAddressChanged = &Email{
	ID: "email_address_changed",
	Placeholders: []Placeholder{
		{Name: AppName}, {Name: Name},
	},
	BuiltIn: map[string]Text{
		"en": {
			Subject: "Your email address was changed",
			Body: `Hello {{name}},

The email address for your {{app_name}} account was changed, so this address will no longer receive messages about it, including password reset links.

If you made this change, you don't need to do anything.

**If you didn't, someone else may know your password.** Sign in, change your password, and set your email address back, or contact your administrator.

Best regards,
{{app_name}}`,
		},
		"de": {
			Subject: "Ihre E-Mail-Adresse wurde geändert",
			Body: `Guten Tag {{name}},

Die E-Mail-Adresse Ihres Kontos bei {{app_name}} wurde geändert. An diese Adresse werden daher keine Nachrichten zu Ihrem Konto mehr gesendet, auch keine Links zum Zurücksetzen des Passworts.

Falls Sie diese Änderung selbst vorgenommen haben, brauchen Sie nichts zu tun.

**Andernfalls kennt möglicherweise jemand Ihr Passwort.** Melden Sie sich an, ändern Sie Ihr Passwort und stellen Sie Ihre bisherige E-Mail-Adresse wieder her. Sie können sich auch an Ihre Administration wenden.

Mit freundlichen Grüßen
{{app_name}}`,
		},
		"es": {
			Subject: "Tu dirección de correo electrónico ha cambiado",
			Body: `Hola, {{name}}:

La dirección de correo electrónico de tu cuenta de {{app_name}} ha cambiado. Esta dirección dejará de recibir mensajes sobre tu cuenta, incluidos los enlaces para restablecer la contraseña.

Si has hecho este cambio, no necesitas hacer nada.

**Si no has sido tú, puede que otra persona conozca tu contraseña.** Inicia sesión, cambia tu contraseña y restablece tu dirección de correo electrónico, o contacta con tu administrador.

Un saludo,
{{app_name}}`,
		},
		"fr": {
			Subject: "Votre adresse e-mail a été modifiée",
			Body: `Bonjour {{name}},

L’adresse e-mail de votre compte {{app_name}} a été modifiée. Cette adresse ne recevra donc plus les messages concernant ce compte, y compris les liens de réinitialisation du mot de passe.

Si vous avez effectué cette modification, vous n’avez rien à faire.

**Sinon, une autre personne connaît peut-être votre mot de passe.** Connectez-vous, changez votre mot de passe et rétablissez votre adresse e-mail, ou contactez votre administrateur.

Cordialement,
{{app_name}}`,
		},
		"it": {
			Subject: "Il tuo indirizzo email è stato cambiato",
			Body: `Ciao {{name}},

L'indirizzo email del tuo account {{app_name}} è stato cambiato. Questo indirizzo non riceverà più messaggi sull'account, compresi i link per reimpostare la password.

Se hai effettuato tu la modifica, non devi fare nulla.

**Altrimenti, qualcun altro potrebbe conoscere la tua password.** Accedi, cambia la password e ripristina il tuo indirizzo email, oppure contatta il tuo amministratore.

Un saluto,
{{app_name}}`,
		},
		"pt-BR": {
			Subject: "Seu endereço de e-mail foi alterado",
			Body: `Olá {{name}},

O endereço de e-mail da sua conta {{app_name}} foi alterado, então este endereço não receberá mais mensagens sobre ela, incluindo links de redefinição de senha.

Se foi você quem fez essa alteração, não é preciso fazer nada.

**Se não foi você, outra pessoa pode saber a sua senha.** Entre na sua conta, altere a sua senha e restaure o seu endereço de e-mail, ou entre em contato com o administrador.

Atenciosamente,
{{app_name}}`,
		},
	},
}
