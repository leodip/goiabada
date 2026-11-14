package emailtemplate

// AccountDeletedByAdministrator tells a user an administrator deleted their account, naming no
// administrator.
var AccountDeletedByAdministrator = &Email{
	ID: "account_deleted_by_administrator",
	Placeholders: []Placeholder{
		{Name: AppName}, {Name: Name},
	},
	BuiltIn: map[string]Text{
		"en": {
			Subject: "An administrator deleted your account",
			Body: `Hello {{name}},

An administrator deleted your {{app_name}} account. You can no longer sign in with it.

If you didn't expect this, contact your administrator.

Best regards,
{{app_name}}`,
		},
		"de": {
			Subject: "Ihr Konto wurde von der Administration gelöscht",
			Body: `Guten Tag {{name}},

Die Administration hat Ihr Konto bei {{app_name}} gelöscht. Sie können sich damit nicht mehr anmelden.

Falls Sie damit nicht gerechnet haben, wenden Sie sich an Ihre Administration.

Mit freundlichen Grüßen
{{app_name}}`,
		},
		"es": {
			Subject: "Un administrador ha eliminado tu cuenta",
			Body: `Hola, {{name}}:

Un administrador ha eliminado tu cuenta de {{app_name}}. Ya no puedes iniciar sesión con ella.

Si no lo esperabas, contacta con tu administrador.

Un saludo,
{{app_name}}`,
		},
		"fr": {
			Subject: "Un administrateur a supprimé votre compte",
			Body: `Bonjour {{name}},

Un administrateur a supprimé votre compte {{app_name}}. Vous ne pouvez plus vous y connecter.

Si vous ne vous y attendiez pas, contactez votre administrateur.

Cordialement,
{{app_name}}`,
		},
		//nolint:misspell // the it text: "eliminato" is Italian, not a misspelling of "elimination"
		"it": {
			Subject: "Un amministratore ha eliminato il tuo account",
			Body: `Ciao {{name}},

Un amministratore ha eliminato il tuo account {{app_name}}. Non puoi più accedere con questo account.

Se non te lo aspettavi, contatta il tuo amministratore.

Un saluto,
{{app_name}}`,
		},
		"pt-BR": {
			Subject: "Um administrador excluiu a sua conta",
			Body: `Olá {{name}},

Um administrador excluiu a sua conta {{app_name}}. Você não pode mais entrar com ela.

Se você não esperava por isso, entre em contato com o administrador.

Atenciosamente,
{{app_name}}`,
		},
	},
}
