package emailtemplate

// RegistrationExistingAccount is the notice registration with verification sends a verified, enabled
// account whose address someone tried to register: nothing was created, and the link resets the
// password.
var RegistrationExistingAccount = &Email{
	ID: "registration_existing_account",
	Placeholders: []Placeholder{
		{Name: AppName}, {Name: Link},
	},
	BuiltIn: map[string]Text{
		"en": {
			Subject: "You already have an account",
			Body: `Hello,

Someone, possibly you, tried to create a new {{app_name}} account with this email address. This address already has an account, so no new account was created.

If it was you, sign in with your existing account. If you don't remember your password, you can reset it here: {{link}}

If it wasn't you, you can ignore this message. Your account has not been changed.

Best regards,
{{app_name}}`,
		},
		"de": {
			Subject: "Sie haben bereits ein Konto",
			Body: `Guten Tag,

Jemand hat versucht, mit dieser E-Mail-Adresse ein neues Konto bei {{app_name}} zu erstellen. Möglicherweise waren Sie das selbst. Für diese Adresse gibt es bereits ein Konto. Daher wurde kein neues Konto erstellt.

Falls Sie die Anfrage gestellt haben, melden Sie sich mit Ihrem bestehenden Konto an. Wenn Sie Ihr Passwort vergessen haben, können Sie es hier zurücksetzen: {{link}}

Andernfalls können Sie diese Nachricht ignorieren. Ihr Konto wurde nicht geändert.

Mit freundlichen Grüßen
{{app_name}}`,
		},
		"es": {
			Subject: "Ya tienes una cuenta",
			Body: `Hola:

Alguien, quizá tú, ha intentado crear una cuenta de {{app_name}} con esta dirección de correo electrónico. La dirección ya tiene una cuenta, por lo que no se ha creado otra.

Si has sido tú, inicia sesión con tu cuenta existente. Si no recuerdas tu contraseña, puedes restablecerla aquí: {{link}}

Si no has sido tú, puedes ignorar este mensaje. Tu cuenta no ha cambiado.

Un saludo,
{{app_name}}`,
		},
		//nolint:misspell // the fr text: "existant" is French, not a misspelling of "existent"
		"fr": {
			Subject: "Vous avez déjà un compte",
			Body: "Bonjour,\n\n" +
				"Une personne, peut-être vous, a essayé de créer un compte {{app_name}} avec cette adresse e-mail. Cette adresse correspond déjà à un compte. Aucun nouveau compte n’a donc été créé.\n\n" +
				"Si c’était vous, connectez-vous à votre compte existant. Si vous avez oublié votre mot de passe, vous pouvez le réinitialiser ici : {{link}}\n\n" +
				"Sinon, vous pouvez ignorer ce message. Votre compte n’a pas été modifié.\n\n" +
				"Cordialement,\n" +
				"{{app_name}}",
		},
		//nolint:misspell // the it text: "modificato" is Italian, not a misspelling of "modification"
		"it": {
			Subject: "Hai già un account",
			Body: `Ciao,

Qualcuno, forse tu, ha provato a creare un nuovo account {{app_name}} con questo indirizzo email. L'indirizzo ha già un account, quindi non ne è stato creato uno nuovo.

Se hai fatto tu la richiesta, accedi con il tuo account esistente. Se non ricordi la password, puoi reimpostarla qui: {{link}}

Altrimenti, puoi ignorare questo messaggio. Il tuo account non è stato modificato.

Un saluto,
{{app_name}}`,
		},
		"pt-BR": {
			Subject: "Você já tem uma conta",
			Body: `Olá,

Alguém, possivelmente você, tentou criar uma nova conta no {{app_name}} com este endereço de e-mail. Este endereço já tem uma conta, então nenhuma conta nova foi criada.

Se foi você, entre com sua conta existente. Se não se lembra da sua senha, pode redefini-la aqui: {{link}}

Se não foi você, pode ignorar esta mensagem. Sua conta não foi alterada.

Atenciosamente,
{{app_name}}`,
		},
	},
}
