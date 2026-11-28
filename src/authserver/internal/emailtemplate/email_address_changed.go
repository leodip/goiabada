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
		"id": {
			Subject: "Alamat email Anda telah diubah",
			Body: `Halo {{name}},

Alamat email akun {{app_name}} Anda telah diubah, sehingga alamat ini tidak akan lagi menerima pesan tentang akun tersebut, termasuk tautan pengaturan ulang kata sandi.

Jika Anda yang melakukan perubahan ini, Anda tidak perlu melakukan apa pun.

**Jika bukan Anda, orang lain mungkin mengetahui kata sandi Anda.** Masuk, ubah kata sandi Anda, dan kembalikan alamat email Anda, atau hubungi administrator Anda.

Salam,
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
		"ja": {
			Subject: "メールアドレスが変更されました",
			Body: `{{name}} 様

{{app_name}} のアカウントのメールアドレスが変更されました。今後、パスワード再設定用のリンクを含め、このアカウントに関するメールはこのアドレスに届きません。

この変更をご自身で行った場合は、対応は不要です。

**ご自身で行っていない場合は、第三者があなたのパスワードを知っている可能性があります**。ログインしてパスワードを変更し、メールアドレスを元に戻すか、管理者にお問い合わせください。

{{app_name}}`,
		},
		//nolint:misspell // the pl text: "adres" is Polish, not a misspelling of "address"
		"pl": {
			Subject: "Zmieniono Twój adres e-mail",
			Body: `Dzień dobry {{name}},

Adres e-mail Twojego konta w {{app_name}} został zmieniony, więc na ten adres nie będą już przychodzić wiadomości o tym koncie, w tym linki do resetowania hasła.

Jeśli to Twoja zmiana, nie musisz nic robić.

**Jeśli nie, ktoś inny może znać Twoje hasło.** Zaloguj się, zmień hasło i przywróć swój adres e-mail albo skontaktuj się z administratorem.

Pozdrawiamy
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
		"ru": {
			Subject: "Ваш адрес электронной почты изменен",
			Body: `Здравствуйте, {{name}}!

Адрес электронной почты вашего аккаунта в {{app_name}} изменен, поэтому на этот адрес больше не будут приходить письма об аккаунте, в том числе ссылки для сброса пароля.

Если это изменение внесли вы, ничего делать не нужно.

**Если нет, возможно, ваш пароль известен кому-то еще.** Войдите, смените пароль и верните прежний адрес электронной почты или обратитесь к администратору.

С уважением,
{{app_name}}`,
		},
		"zh-Hans": {
			Subject: "您的电子邮件地址已更改",
			Body: `{{name}}，您好：

您的 {{app_name}} 账户的电子邮件地址已更改，因此此地址将不再收到与该账户有关的电子邮件，包括密码重置链接。

如果这是您本人所做的更改，则无需进行任何操作。

**如果不是您本人操作，可能有其他人知道您的密码**。请登录，更改密码并改回您的电子邮件地址，或联系您的管理员。

{{app_name}}`,
		},
	},
}
