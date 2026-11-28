package emailtemplate

// TestEmail is the email Send test email sends from the email settings, to check that email can be
// sent.
var TestEmail = &Email{
	ID: "test",
	Placeholders: []Placeholder{
		{Name: AppName},
	},
	BuiltIn: map[string]Text{
		"en": {
			Subject: "{{app_name}} - test email",
			Body: `This is a test email from {{app_name}}.

It was sent from the email settings to check that email can be sent. If you can read it, there is nothing else to do.`,
		},
		"de": {
			Subject: "{{app_name}} – Test-E-Mail",
			Body: `Dies ist eine Test-E-Mail von {{app_name}}.

Sie wurde aus den E-Mail-Einstellungen gesendet, um zu prüfen, ob E-Mails versendet werden können. Wenn Sie sie lesen können, ist nichts weiter zu tun.`,
		},
		"es": {
			Subject: "{{app_name}} - correo de prueba",
			Body: `Este es un correo de prueba enviado por {{app_name}}.

Se envió desde la configuración de correo para comprobar que se pueden enviar correos. Si puedes leerlo, no tienes que hacer nada más.`,
		},
		"fr": {
			Subject: "{{app_name}} - e-mail de test",
			Body: "Ceci est un e-mail de test envoyé par {{app_name}}.\n\n" +
				"Il a été envoyé depuis les paramètres des e-mails pour vérifier que l’envoi d’e-mails fonctionne. Si vous pouvez le lire, vous n’avez rien d’autre à faire.",
		},
		"id": {
			Subject: "{{app_name}} - email uji coba",
			Body: `Ini adalah email uji coba dari {{app_name}}.

Email ini dikirim dari pengaturan email untuk memeriksa bahwa email dapat dikirim. Jika Anda dapat membacanya, tidak ada lagi yang perlu dilakukan.`,
		},
		"it": {
			Subject: "{{app_name}} - email di prova",
			Body: `Questa è un’email di prova inviata da {{app_name}}.

È stata inviata dalle impostazioni email per verificare che l’invio delle email funzioni. Se riesci a leggerla, non devi fare altro.`,
		},
		"ja": {
			Subject: "【{{app_name}}】テストメール",
			Body: `これは {{app_name}} からのテストメールです。

メールを送信できるかを確認するため、メール設定から送信されました。このメールが読めれば、ほかに行うことはありません。`,
		},
		"pl": {
			Subject: "{{app_name}} – testowa wiadomość e-mail",
			Body: `To jest testowa wiadomość e-mail z {{app_name}}.

Została wysłana z ustawień poczty e-mail, aby sprawdzić, czy wysyłanie wiadomości działa. Jeśli możesz ją przeczytać, nie musisz nic więcej robić.

Pozdrawiamy
{{app_name}}`,
		},
		"pt-BR": {
			Subject: "{{app_name}} - e-mail de teste",
			Body: `Este é um e-mail de teste enviado por {{app_name}}.

Ele foi enviado pelas configurações de e-mail para verificar se o envio de e-mails funciona. Se você consegue lê-lo, não precisa fazer mais nada.`,
		},
		"ru": {
			Subject: "{{app_name}} — тестовое письмо",
			Body: `Это тестовое письмо от {{app_name}}.

Оно отправлено из настроек электронной почты, чтобы проверить, что письма отправляются. Если вы его читаете, больше ничего делать не нужно.`,
		},
		"zh-Hans": {
			Subject: "【{{app_name}}】测试电子邮件",
			Body: `这是一封来自 {{app_name}} 的测试电子邮件。

它是从电子邮件设置中发送的，用于检查能否发送电子邮件。如果您能阅读此电子邮件，则无需进行其他操作。`,
		},
	},
}
