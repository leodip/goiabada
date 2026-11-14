package emailtemplate

// RecoveryCodeUsed tells a user a recovery code signed in, and how many unused codes are left, as
// {{codes_left}}, in one wording for every count (#818 decision 4).
var RecoveryCodeUsed = &Email{
	ID: "recovery_code_used",
	Placeholders: []Placeholder{
		{Name: AppName}, {Name: Name}, {Name: CodesLeft},
	},
	BuiltIn: map[string]Text{
		"en": {
			Subject: "A recovery code was used to sign in",
			Body: `Hello {{name}},

One of your recovery codes was used to sign in to your {{app_name}} account, in place of a code from your authenticator app. Each recovery code works once, so that one no longer works. Unused recovery codes left: {{codes_left}}.

If it was you and you no longer have your authenticator app, turn two-factor authentication off in your account settings and set up a new authenticator, which comes with a new set of recovery codes. If you still have the app, get a new set of recovery codes there, so you can still sign in if you lose it.

**If it wasn't you, someone else may know your password and have your recovery codes.** Choose a new password with "Forgot your password?" on the sign-in page, then sign in, turn two-factor authentication off and set up a new authenticator, or contact your administrator.

Best regards,
{{app_name}}`,
		},
		"de": {
			Subject: "Für die Anmeldung wurde ein Wiederherstellungscode verwendet",
			Body: `Guten Tag {{name}},

Bei der Anmeldung an Ihrem Konto bei {{app_name}} wurde einer Ihrer Wiederherstellungscodes anstelle eines Codes aus Ihrer Authenticator-App verwendet. Jeder Wiederherstellungscode funktioniert nur einmal, dieser also nicht mehr. Verbleibende unbenutzte Wiederherstellungscodes: {{codes_left}}.

Falls Sie das selbst waren und Ihre Authenticator-App nicht mehr haben, deaktivieren Sie in Ihren Kontoeinstellungen die Zwei-Faktor-Authentifizierung und richten Sie eine neue Authenticator-App ein. Dazu wird ein neuer Satz Wiederherstellungscodes erstellt. Haben Sie die App noch, erstellen Sie dort einen neuen Satz Wiederherstellungscodes, damit Sie sich weiterhin anmelden können, falls Sie sie verlieren.

**Andernfalls kennt möglicherweise jemand Ihr Passwort und hat Ihre Wiederherstellungscodes.** Wählen Sie auf der Anmeldeseite über „Passwort vergessen?“ ein neues Passwort, melden Sie sich dann an, deaktivieren Sie die Zwei-Faktor-Authentifizierung und richten Sie eine neue Authenticator-App ein. Sie können sich auch an Ihre Administration wenden.

Mit freundlichen Grüßen
{{app_name}}`,
		},
		//nolint:misspell // the es text: "factores" is Spanish, not a misspelling of "factors"
		"es": {
			Subject: "Se ha usado un código de recuperación para iniciar sesión",
			Body: `Hola, {{name}}:

Se ha usado uno de tus códigos de recuperación para iniciar sesión en tu cuenta de {{app_name}}, en lugar de un código de tu aplicación de autenticación. Cada código de recuperación sirve una sola vez, así que ese ya no sirve. Códigos de recuperación sin usar restantes: {{codes_left}}.

Si has sido tú y ya no tienes tu aplicación de autenticación, desactiva la autenticación de dos factores en la configuración de tu cuenta y configura una nueva aplicación de autenticación, que viene con un nuevo conjunto de códigos de recuperación. Si aún tienes la aplicación, obtén allí un nuevo conjunto de códigos de recuperación, para poder iniciar sesión si la pierdes.

**Si no has sido tú, puede que otra persona conozca tu contraseña y tenga tus códigos de recuperación.** Elige una contraseña nueva con «¿Olvidaste tu contraseña?» en la página de inicio de sesión. Después, inicia sesión, desactiva la autenticación de dos factores y configura una nueva aplicación de autenticación, o contacta con tu administrador.

Un saludo,
{{app_name}}`,
		},
		"fr": {
			Subject: "Un code de récupération a été utilisé pour vous connecter",
			Body: `Bonjour {{name}},

L’un de vos codes de récupération a été utilisé pour vous connecter à votre compte {{app_name}}, à la place d’un code de votre application d’authentification. Chaque code de récupération ne fonctionne qu’une fois, celui-ci ne fonctionne donc plus. Codes de récupération inutilisés restants : {{codes_left}}.

Si c’était vous et que vous n’avez plus votre application d’authentification, désactivez l’authentification à deux facteurs dans les paramètres de votre compte, puis configurez une nouvelle application d’authentification, fournie avec un nouveau jeu de codes de récupération. Si vous avez toujours l’application, obtenez un nouveau jeu de codes de récupération dans les paramètres de votre compte, pour pouvoir vous connecter si vous la perdez.

**Sinon, une autre personne connaît peut-être votre mot de passe et possède vos codes de récupération.** Choisissez un nouveau mot de passe avec « Mot de passe oublié ? » sur la page de connexion, puis connectez-vous, désactivez l’authentification à deux facteurs et configurez une nouvelle application d’authentification, ou contactez votre administrateur.

Cordialement,
{{app_name}}`,
		},
		"it": {
			Subject: "È stato usato un codice di recupero per accedere",
			Body: `Ciao {{name}},

Uno dei tuoi codici di recupero è stato usato per accedere al tuo account {{app_name}}, al posto di un codice dell'app di autenticazione. Ogni codice di recupero funziona una sola volta, quindi quello non funziona più. Codici di recupero inutilizzati rimasti: {{codes_left}}.

Se l'hai usato tu e non hai più l'app di autenticazione, disattiva l'autenticazione a due fattori dalle impostazioni del tuo account e configura una nuova app di autenticazione, che include un nuovo set di codici di recupero. Se hai ancora l'app, ottieni lì un nuovo set di codici di recupero, per poter accedere se la perdi.

**Altrimenti, qualcun altro potrebbe conoscere la tua password e avere i tuoi codici di recupero.** Scegli una nuova password con «Hai dimenticato la password?» nella pagina di accesso, poi accedi, disattiva l'autenticazione a due fattori e configura una nuova app di autenticazione, oppure contatta il tuo amministratore.

Un saluto,
{{app_name}}`,
		},
		"pt-BR": {
			Subject: "Um código de recuperação foi usado para entrar",
			Body: `Olá {{name}},

Um dos seus códigos de recuperação foi usado para entrar na sua conta {{app_name}}, no lugar de um código do aplicativo autenticador. Cada código de recuperação funciona uma única vez, então esse não funciona mais. Códigos de recuperação sem uso restantes: {{codes_left}}.

Se foi você e você não tem mais o aplicativo autenticador, desative a autenticação de dois fatores nas configurações da sua conta e configure um novo autenticador, que vem com um novo conjunto de códigos de recuperação. Se você ainda tem o aplicativo, gere lá um novo conjunto de códigos de recuperação, para poder entrar se perdê-lo.

**Se não foi você, outra pessoa pode saber a sua senha e ter os seus códigos de recuperação.** Escolha uma nova senha em "Esqueceu sua senha?" na página de entrada, depois entre na sua conta, desative a autenticação de dois fatores e configure um novo autenticador, ou entre em contato com o administrador.

Atenciosamente,
{{app_name}}`,
		},
	},
}
