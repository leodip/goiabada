package emailtemplate

// PasswordResetLink is the email forgot password sends a verified, enabled account: the link that
// resets its password, as the brand's button and as the URL to copy, and how long it lasts.
var PasswordResetLink = &Email{
	ID: "password_reset_link",
	Placeholders: []Placeholder{
		{Name: AppName}, {Name: Name}, {Name: Link, Required: true}, {Name: Button}, {Name: Expiry},
	},
	BuiltIn: map[string]Text{
		"en": {
			Subject:     "Password reset",
			ButtonLabel: "Reset password",
			Body: `Hello {{name}},

You can reset your password by clicking the link below:

{{button}}

{{link}}

The link expires in {{expiry}}.

If you have trouble clicking the link, you can copy and paste it into your web browser.

**In case you didn't request a password reset, kindly disregard this email.**

Best regards,
{{app_name}}`,
		},
		"de": {
			Subject:     "Passwort zurücksetzen",
			ButtonLabel: "Passwort zurücksetzen",
			Body: `Guten Tag {{name}},

Öffnen Sie diesen Link, um Ihr Passwort zurückzusetzen:

{{button}}

{{link}}

Der Link läuft nach {{expiry}} ab.

Falls sich der Link nicht öffnen lässt, kopieren Sie ihn und fügen Sie ihn in die Adresszeile Ihres Browsers ein.

**Falls Sie das Zurücksetzen nicht angefordert haben, können Sie diese E-Mail ignorieren.**

Mit freundlichen Grüßen
{{app_name}}`,
		},
		"es": {
			Subject:     "Restablecimiento de contraseña",
			ButtonLabel: "Restablecer contraseña",
			Body: `Hola, {{name}}:

Para restablecer tu contraseña, abre este enlace:

{{button}}

{{link}}

El enlace caduca en {{expiry}}.

Si no puedes abrirlo, copia y pega la dirección en tu navegador.

**Si no has solicitado restablecer tu contraseña, puedes ignorar este correo.**

Un saludo,
{{app_name}}`,
		},
		"fr": {
			Subject:     "Réinitialisation du mot de passe",
			ButtonLabel: "Réinitialiser le mot de passe",
			Body: "Bonjour {{name}},\n\n" +
				"Pour réinitialiser votre mot de passe, cliquez sur le lien ci-dessous :\n\n" +
				"{{button}}\n\n" +
				"{{link}}\n\n" +
				"Le lien expire dans {{expiry}}.\n\n" +
				"Si le lien ne s’ouvre pas, copiez-le et collez-le dans votre navigateur.\n\n" +
				"**Si vous n’avez pas demandé à réinitialiser votre mot de passe, ignorez cet e-mail.**\n\n" +
				"Cordialement,\n" +
				"{{app_name}}",
		},
		"id": {
			Subject:     "Atur ulang kata sandi",
			ButtonLabel: "Atur ulang kata sandi",
			Body: `Halo {{name}},

Anda dapat mengatur ulang kata sandi Anda melalui tautan di bawah ini:

{{button}}

{{link}}

Tautan ini kedaluwarsa dalam {{expiry}}.

Jika tautan tidak dapat dibuka, salin dan tempel tautan tersebut ke browser Anda.

**Jika Anda tidak meminta pengaturan ulang kata sandi, abaikan email ini.**

Salam,
{{app_name}}`,
		},
		"it": {
			Subject:     "Reimpostazione della password",
			ButtonLabel: "Reimposta la password",
			Body: `Ciao {{name}},

Per reimpostare la password, apri questo link:

{{button}}

{{link}}

Il link scade tra {{expiry}}.

Se non riesci ad aprire il link, copialo e incollalo nel browser.

**Se non hai richiesto di reimpostare la password, ignora questa email.**

Un saluto,
{{app_name}}`,
		},
		"ja": {
			Subject:     "パスワードの再設定",
			ButtonLabel: "パスワードを再設定",
			Body: `{{name}} 様

以下のリンクから、パスワードを再設定できます。

{{button}}

{{link}}

このリンクの有効期限は {{expiry}}です。

リンクをクリックできない場合は、コピーしてブラウザーのアドレスバーに貼り付けてください。

**パスワードの再設定を依頼していない場合は、このメールを無視してください。**

{{app_name}}`,
		},
		"pl": {
			Subject:     "Resetowanie hasła",
			ButtonLabel: "Zresetuj hasło",
			Body: `Dzień dobry {{name}},

Aby zresetować hasło, kliknij poniższy link:

{{button}}

{{link}}

Link wygaśnie za {{expiry}}.

Jeśli nie możesz kliknąć linku, skopiuj go i wklej w pasku adresu przeglądarki.

**Jeśli prośba o zresetowanie hasła nie pochodziła od Ciebie, zignoruj tę wiadomość.**

Pozdrawiamy
{{app_name}}`,
		},
		//nolint:misspell // the pt-BR text: "problemas" is Portuguese, not a misspelling of "problems"
		"pt-BR": {
			Subject:     "Redefinição de senha",
			ButtonLabel: "Redefinir senha",
			Body: `Olá {{name}},

Você pode redefinir sua senha clicando no link abaixo:

{{button}}

{{link}}

O link expira em {{expiry}}.

Se tiver problemas para clicar no link, copie e cole o endereço no seu navegador.

**Caso você não tenha solicitado a redefinição da senha, desconsidere este e-mail.**

Atenciosamente,
{{app_name}}`,
		},
		"ru": {
			Subject:     "Сброс пароля",
			ButtonLabel: "Сбросить пароль",
			Body: `Здравствуйте, {{name}}!

Чтобы сбросить пароль, перейдите по ссылке ниже:

{{button}}

{{link}}

Срок действия ссылки истечет через {{expiry}}.

Если ссылка не открывается, скопируйте ее и вставьте в адресную строку браузера.

**Если вы не запрашивали сброс пароля, просто проигнорируйте это письмо.**

С уважением,
{{app_name}}`,
		},
	},
}
