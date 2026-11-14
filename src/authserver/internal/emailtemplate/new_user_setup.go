package emailtemplate

// NewUserSetup is the email an administrator has sent a user they create with no password: the link
// that sets it, as the brand's button and as the URL to copy, and how long it works.
var NewUserSetup = &Email{
	ID: "new_user_setup",
	Placeholders: []Placeholder{
		{Name: AppName}, {Name: Name}, {Name: Link, Required: true}, {Name: Button}, {Name: Expiry},
	},
	BuiltIn: map[string]Text{
		"en": {
			Subject:     "{{app_name}} - create a password for your new account",
			ButtonLabel: "Create password",
			Body: `Hello {{name}},

You can create your password by clicking the link below:

{{button}}

{{link}}

If you have trouble clicking the link, you can copy and paste it into your web browser.

**The link works for {{expiry}}. If it has expired, contact your administrator, who can set your password or let you request a new link from the sign-in page.**

Best regards,
{{app_name}}`,
		},
		"de": {
			Subject:     "{{app_name}} – Passwort für Ihr neues Konto festlegen",
			ButtonLabel: "Passwort festlegen",
			Body: `Guten Tag {{name}},

Öffnen Sie diesen Link, um Ihr Passwort festzulegen:

{{button}}

{{link}}

Falls sich der Link nicht öffnen lässt, kopieren Sie ihn und fügen Sie ihn in die Adresszeile Ihres Browsers ein.

**Der Link ist {{expiry}} gültig. Falls er abgelaufen ist, wenden Sie sich an Ihre Administration. Sie kann Ihr Passwort festlegen oder Ihnen ermöglichen, über die Anmeldeseite einen neuen Link anzufordern.**

Mit freundlichen Grüßen
{{app_name}}`,
		},
		"es": {
			Subject:     "{{app_name}} - crea una contraseña para tu nueva cuenta",
			ButtonLabel: "Crear contraseña",
			Body: `Hola, {{name}}:

Para crear tu contraseña, abre este enlace:

{{button}}

{{link}}

Si no puedes abrirlo, copia y pega la dirección en tu navegador.

**El enlace es válido durante {{expiry}}. Si ha caducado, contacta con tu administrador, que puede establecer tu contraseña o permitirte solicitar otro enlace desde la página de inicio de sesión.**

Un saludo,
{{app_name}}`,
		},
		"fr": {
			Subject:     "{{app_name}} - créez un mot de passe pour votre nouveau compte",
			ButtonLabel: "Créer le mot de passe",
			Body: "Bonjour {{name}},\n\n" +
				"Pour créer votre mot de passe, cliquez sur le lien ci-dessous :\n\n" +
				"{{button}}\n\n" +
				"{{link}}\n\n" +
				"Si le lien ne s’ouvre pas, copiez-le et collez-le dans votre navigateur.\n\n" +
				"**Le lien est valable {{expiry}}. S’il a expiré, contactez votre administrateur. Il pourra définir votre mot de passe ou vous permettre de demander un nouveau lien depuis la page de connexion.**\n\n" +
				"Cordialement,\n" +
				"{{app_name}}",
		},
		"it": {
			Subject:     "{{app_name}} - crea una password per il tuo nuovo account",
			ButtonLabel: "Crea la password",
			Body: `Ciao {{name}},

Per creare la tua password, apri questo link:

{{button}}

{{link}}

Se non riesci ad aprire il link, copialo e incollalo nel browser.

**Il link è valido per {{expiry}}. Se è scaduto, contatta il tuo amministratore: può impostare la password oppure permetterti di richiedere un nuovo link dalla pagina di accesso.**

Un saluto,
{{app_name}}`,
		},
		//nolint:misspell // the pt-BR text: "problemas" is Portuguese, not a misspelling of "problems"
		"pt-BR": {
			Subject:     "{{app_name}} - crie uma senha para sua nova conta",
			ButtonLabel: "Criar senha",
			Body: `Olá {{name}},

Você pode criar sua senha clicando no link abaixo:

{{button}}

{{link}}

Se tiver problemas para clicar no link, copie e cole o endereço no seu navegador.

**O link funciona por {{expiry}}. Se ele tiver expirado, fale com o administrador, que pode definir a sua senha ou permitir que você solicite um novo link na página de entrada.**

Atenciosamente,
{{app_name}}`,
		},
	},
}
