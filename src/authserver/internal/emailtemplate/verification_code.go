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
	},
}
