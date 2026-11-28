package emailtemplate

// VerificationCode is the email that sends an account the code that verifies its address, boxed,
// how long it lasts, and the link to the page it is entered on.
var VerificationCode = &Email{
	ID: "verification_code",
	Placeholders: []Placeholder{
		{Name: AppName}, {Name: Name}, {Name: Code, Required: true}, {Name: Link}, {Name: Expiry},
	},
	BuiltIn: map[string]Text{
		"en": {
			Subject: "Email verification - code {{code}}",
			Body: `Hello {{name}},

This is your email verification code:

{{code}}

The code expires in {{expiry}}.

You can enter your code here: {{link}}

Best regards,
{{app_name}}`,
		},
		"de": {
			Subject: "E-Mail-Bestätigung – Code {{code}}",
			Body: `Guten Tag {{name}},

Mit diesem Code können Sie Ihre E-Mail-Adresse bestätigen:

{{code}}

Der Code läuft nach {{expiry}} ab.

Geben Sie den Code hier ein: {{link}}

Mit freundlichen Grüßen
{{app_name}}`,
		},
		"es": {
			Subject: "Verificación del correo - código {{code}}",
			Body: `Hola, {{name}}:

Este es tu código de verificación del correo electrónico:

{{code}}

El código caduca en {{expiry}}.

Puedes escribir el código aquí: {{link}}

Un saludo,
{{app_name}}`,
		},
		"fr": {
			Subject: "Vérification de l’adresse e-mail - code {{code}}",
			Body: "Bonjour {{name}},\n\n" +
				"Voici votre code de vérification de l’adresse e-mail :\n\n" +
				"{{code}}\n\n" +
				"Le code expire dans {{expiry}}.\n\n" +
				"Vous pouvez saisir ce code ici : {{link}}\n\n" +
				"Cordialement,\n" +
				"{{app_name}}",
		},
		"id": {
			Subject: "Verifikasi email - kode {{code}}",
			Body: `Halo {{name}},

Ini kode verifikasi email Anda:

{{code}}

Kode ini kedaluwarsa dalam {{expiry}}.

Anda dapat memasukkan kode Anda di sini: {{link}}

Salam,
{{app_name}}`,
		},
		"it": {
			Subject: "Verifica email - codice {{code}}",
			Body: `Ciao {{name}},

Ecco il tuo codice di verifica dell'indirizzo email:

{{code}}

Il codice scade tra {{expiry}}.

Puoi inserire il codice qui: {{link}}

Un saluto,
{{app_name}}`,
		},
		"ja": {
			Subject: "メールアドレスの確認コード：{{code}}",
			Body: `{{name}} 様

メールアドレスの確認コードは次のとおりです。

{{code}}

このコードの有効期限は {{expiry}}です。

コードはこちらで入力できます：{{link}}

{{app_name}}`,
		},
		"pl": {
			Subject: "Weryfikacja adresu e-mail – kod {{code}}",
			Body: `Dzień dobry {{name}},

Oto Twój kod weryfikacyjny adresu e-mail:

{{code}}

Kod wygaśnie za {{expiry}}.

Kod możesz wpisać tutaj: {{link}}

Pozdrawiamy
{{app_name}}`,
		},
		"pt-BR": {
			Subject: "Verificação de e-mail - código {{code}}",
			Body: `Olá {{name}},

Este é o seu código de verificação de e-mail:

{{code}}

O código expira em {{expiry}}.

Você pode inserir o código aqui: {{link}}

Atenciosamente,
{{app_name}}`,
		},
		"ru": {
			Subject: "Подтверждение адреса электронной почты — код {{code}}",
			Body: `Здравствуйте, {{name}}!

Ваш код подтверждения адреса электронной почты:

{{code}}

Срок действия кода истечет через {{expiry}}.

Ввести код можно здесь: {{link}}

С уважением,
{{app_name}}`,
		},
		"zh-Hans": {
			Subject: "电子邮件地址验证码：{{code}}",
			Body: `{{name}}，您好：

您的电子邮件地址验证码是：

{{code}}

该验证码将在{{expiry}}后过期。

您可以在此输入验证码：{{link}}

{{app_name}}`,
		},
	},
}
