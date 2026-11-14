package emailtemplate

// ActivationLink is the email registration with verification sends an address that has no account:
// the link that creates the account once its holder chooses a password, as the brand's button and as
// the URL to copy, and how long it lasts.
var ActivationLink = &Email{
	ID: "activation_link",
	Placeholders: []Placeholder{
		{Name: AppName}, {Name: Link, Required: true}, {Name: Button}, {Name: Expiry},
	},
	BuiltIn: map[string]Text{
		"en": {
			Subject:     "Activate your account",
			ButtonLabel: "Activate account",
			Body: `Hello,

To finish creating your {{app_name}} account, click the link below and choose a password:

{{button}}

{{link}}

The link expires in {{expiry}}. If you have trouble clicking it, copy and paste it into your web browser.

If you didn't ask to create an account, ignore this message: no account is created unless the link is used.

Best regards,
{{app_name}}`,
		},
		"de": {
			Subject:     "Aktivieren Sie Ihr Konto",
			ButtonLabel: "Konto aktivieren",
			Body: `Guten Tag,

Öffnen Sie diesen Link und wählen Sie ein Passwort, um Ihr Konto bei {{app_name}} fertig einzurichten:

{{button}}

{{link}}

Der Link läuft nach {{expiry}} ab. Falls er sich nicht öffnen lässt, kopieren Sie ihn und fügen Sie ihn in die Adresszeile Ihres Browsers ein.

Falls Sie kein Konto erstellen wollten, ignorieren Sie diese Nachricht. Es wird kein Konto erstellt, solange der Link nicht verwendet wird.

Mit freundlichen Grüßen
{{app_name}}`,
		},
		"es": {
			Subject:     "Activa tu cuenta",
			ButtonLabel: "Activar cuenta",
			Body: `Hola:

Para terminar de crear tu cuenta de {{app_name}}, abre este enlace y elige una contraseña:

{{button}}

{{link}}

El enlace caduca en {{expiry}}. Si no puedes abrirlo, copia y pega la dirección en tu navegador.

Si no has solicitado crear una cuenta, puedes ignorar este mensaje: la cuenta no se creará si no se usa el enlace.

Un saludo,
{{app_name}}`,
		},
		"fr": {
			Subject:     "Activez votre compte",
			ButtonLabel: "Activer le compte",
			Body: "Bonjour,\n\n" +
				"Pour terminer la création de votre compte {{app_name}}, cliquez sur le lien ci-dessous et choisissez un mot de passe :\n\n" +
				"{{button}}\n\n" +
				"{{link}}\n\n" +
				"Le lien expire dans {{expiry}}. S’il ne s’ouvre pas, copiez-le et collez-le dans votre navigateur.\n\n" +
				"Si vous n’avez pas demandé à créer un compte, ignorez ce message : aucun compte ne sera créé tant que le lien ne sera pas utilisé.\n\n" +
				"Cordialement,\n" +
				"{{app_name}}",
		},
		"it": {
			Subject:     "Attiva il tuo account",
			ButtonLabel: "Attiva l'account",
			Body: `Ciao,

Per completare la creazione del tuo account {{app_name}}, apri questo link e scegli una password:

{{button}}

{{link}}

Il link scade tra {{expiry}}. Se non riesci ad aprirlo, copialo e incollalo nel browser.

Se non hai chiesto di creare un account, ignora questo messaggio: non viene creato alcun account finché il link non viene usato.

Un saluto,
{{app_name}}`,
		},
		//nolint:misspell // the pt-BR text: "problemas" is Portuguese, not a misspelling of "problems"
		"pt-BR": {
			Subject:     "Ative sua conta",
			ButtonLabel: "Ativar conta",
			Body: `Olá,

Para terminar de criar sua conta no {{app_name}}, clique no link abaixo e escolha uma senha:

{{button}}

{{link}}

O link expira em {{expiry}}. Se tiver problemas para clicar nele, copie e cole o endereço no seu navegador.

Se você não pediu para criar uma conta, ignore esta mensagem: nenhuma conta é criada a menos que o link seja usado.

Atenciosamente,
{{app_name}}`,
		},
	},
}
