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
		"it": {
			Subject: "{{app_name}} - email di prova",
			Body: `Questa è un’email di prova inviata da {{app_name}}.

È stata inviata dalle impostazioni email per verificare che l’invio delle email funzioni. Se riesci a leggerla, non devi fare altro.`,
		},
		"pt-BR": {
			Subject: "{{app_name}} - e-mail de teste",
			Body: `Este é um e-mail de teste enviado por {{app_name}}.

Ele foi enviado pelas configurações de e-mail para verificar se o envio de e-mails funciona. Se você consegue lê-lo, não precisa fazer mais nada.`,
		},
	},
}
