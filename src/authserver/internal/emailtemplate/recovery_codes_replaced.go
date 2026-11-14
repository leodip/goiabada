package emailtemplate

// RecoveryCodesReplaced tells a user a new set of recovery codes was made on the Account pages,
// which voids the old set.
var RecoveryCodesReplaced = &Email{
	ID: "recovery_codes_replaced",
	Placeholders: []Placeholder{
		{Name: AppName}, {Name: Name},
	},
	BuiltIn: map[string]Text{
		"en": {
			Subject: "Your recovery codes were replaced",
			Body: `Hello {{name}},

A new set of recovery codes was made for your {{app_name}} account from your account settings. Your previous recovery codes no longer work, used or not.

If you made it, you don't need to do anything. Keep the new codes somewhere safe.

**If you didn't, someone else may know your password.** Choose a new password with "Forgot your password?" on the sign-in page, then sign in and get a new set of recovery codes in your account settings, or contact your administrator.

Best regards,
{{app_name}}`,
		},
		"de": {
			Subject: "Ihre Wiederherstellungscodes wurden ersetzt",
			Body: `Guten Tag {{name}},

Für Ihr Konto bei {{app_name}} wurde in Ihren Kontoeinstellungen ein neuer Satz Wiederherstellungscodes erstellt. Ihre bisherigen Wiederherstellungscodes funktionieren nicht mehr, ob benutzt oder nicht.

Falls Sie ihn selbst erstellt haben, brauchen Sie nichts zu tun. Bewahren Sie die neuen Codes sicher auf.

**Andernfalls kennt möglicherweise jemand Ihr Passwort.** Wählen Sie auf der Anmeldeseite über „Passwort vergessen?“ ein neues Passwort, melden Sie sich dann an und erstellen Sie in Ihren Kontoeinstellungen einen neuen Satz Wiederherstellungscodes. Sie können sich auch an Ihre Administration wenden.

Mit freundlichen Grüßen
{{app_name}}`,
		},
		"es": {
			Subject: "Se han sustituido tus códigos de recuperación",
			Body: `Hola, {{name}}:

Se ha creado un nuevo conjunto de códigos de recuperación para tu cuenta de {{app_name}} desde la configuración de tu cuenta. Tus códigos de recuperación anteriores ya no sirven, los hayas usado o no.

Si lo has creado tú, no necesitas hacer nada. Guarda los códigos nuevos en un lugar seguro.

**Si no has sido tú, puede que otra persona conozca tu contraseña.** Elige una contraseña nueva con «¿Olvidaste tu contraseña?» en la página de inicio de sesión. Después, inicia sesión y crea un nuevo conjunto de códigos de recuperación en la configuración de tu cuenta, o contacta con tu administrador.

Un saludo,
{{app_name}}`,
		},
		"fr": {
			Subject: "Vos codes de récupération ont été remplacés",
			Body: `Bonjour {{name}},

Un nouveau jeu de codes de récupération a été créé pour votre compte {{app_name}} depuis les paramètres de votre compte. Vos anciens codes de récupération ne fonctionnent plus, qu’ils aient été utilisés ou non.

Si vous l’avez créé, vous n’avez rien à faire. Conservez les nouveaux codes en lieu sûr.

**Sinon, une autre personne connaît peut-être votre mot de passe.** Choisissez un nouveau mot de passe avec « Mot de passe oublié ? » sur la page de connexion, puis connectez-vous et créez un nouveau jeu de codes de récupération dans les paramètres de votre compte, ou contactez votre administrateur.

Cordialement,
{{app_name}}`,
		},
		"it": {
			Subject: "I tuoi codici di recupero sono stati sostituiti",
			Body: `Ciao {{name}},

Dalle impostazioni del tuo account {{app_name}} è stato creato un nuovo set di codici di recupero. I codici di recupero precedenti non funzionano più, usati o no.

Se l'hai creato tu, non devi fare nulla. Conserva i nuovi codici in un posto sicuro.

**Altrimenti, qualcun altro potrebbe conoscere la tua password.** Scegli una nuova password con «Hai dimenticato la password?» nella pagina di accesso, poi accedi e crea un nuovo set di codici di recupero dalle impostazioni del tuo account, oppure contatta il tuo amministratore.

Un saluto,
{{app_name}}`,
		},
		"pt-BR": {
			Subject: "Seus códigos de recuperação foram substituídos",
			Body: `Olá {{name}},

Um novo conjunto de códigos de recuperação foi gerado para a sua conta {{app_name}} nas configurações da sua conta. Os seus códigos de recuperação anteriores não funcionam mais, usados ou não.

Se foi você quem o gerou, não é preciso fazer nada. Guarde os novos códigos em um lugar seguro.

**Se não foi você, outra pessoa pode saber a sua senha.** Escolha uma nova senha em "Esqueceu sua senha?" na página de entrada, depois entre na sua conta e gere um novo conjunto de códigos de recuperação nas configurações da sua conta, ou entre em contato com o administrador.

Atenciosamente,
{{app_name}}`,
		},
	},
}
