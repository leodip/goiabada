package emailtemplate

// Welcome is the email registration without verification sends the account it created: a link to
// sign in, as the brand's button and as the URL to copy.
var Welcome = &Email{
	ID: "welcome",
	Placeholders: []Placeholder{
		{Name: AppName}, {Name: Link}, {Name: Button},
	},
	BuiltIn: map[string]Text{
		"en": {
			Subject:     "Welcome!",
			ButtonLabel: "Sign in",
			Body: `Congratulations! Your account has been created.

You can login by clicking the link below:

{{button}}

{{link}}

If you have trouble clicking the link, you can copy and paste it into your web browser.

Best regards,
{{app_name}}`,
		},
		"de": {
			Subject:     "Willkommen!",
			ButtonLabel: "Anmelden",
			Body: `Ihr Konto wurde erstellt.

Über diesen Link können Sie sich anmelden:

{{button}}

{{link}}

Falls sich der Link nicht öffnen lässt, kopieren Sie ihn und fügen Sie ihn in die Adresszeile Ihres Browsers ein.

Mit freundlichen Grüßen
{{app_name}}`,
		},
		"es": {
			Subject:     "¡Te damos la bienvenida!",
			ButtonLabel: "Iniciar sesión",
			Body: `¡Tu cuenta ya está creada!

Puedes iniciar sesión desde este enlace:

{{button}}

{{link}}

Si no puedes abrirlo, copia y pega la dirección en tu navegador.

Un saludo,
{{app_name}}`,
		},
		"fr": {
			Subject:     "Bienvenue !",
			ButtonLabel: "Se connecter",
			Body: "Bienvenue ! Votre compte a été créé.\n\n" +
				"Pour vous connecter, cliquez sur le lien ci-dessous :\n\n" +
				"{{button}}\n\n" +
				"{{link}}\n\n" +
				"Si le lien ne s’ouvre pas, copiez-le et collez-le dans votre navigateur.\n\n" +
				"Cordialement,\n" +
				"{{app_name}}",
		},
		"it": {
			Subject:     "Benvenuto!",
			ButtonLabel: "Accedi",
			Body: `Il tuo account è stato creato.

Puoi accedere aprendo questo link:

{{button}}

{{link}}

Se non riesci ad aprire il link, copialo e incollalo nel browser.

Un saluto,
{{app_name}}`,
		},
		//nolint:misspell // the pt-BR text: "problemas" is Portuguese, not a misspelling of "problems"
		"pt-BR": {
			Subject:     "Bem-vindo(a)!",
			ButtonLabel: "Entrar",
			Body: `Parabéns! Sua conta foi criada.

Você pode entrar clicando no link abaixo:

{{button}}

{{link}}

Se tiver problemas para clicar no link, copie e cole o endereço no seu navegador.

Atenciosamente,
{{app_name}}`,
		},
	},
}
