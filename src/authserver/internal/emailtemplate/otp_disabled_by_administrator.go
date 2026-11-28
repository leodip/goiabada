package emailtemplate

// OTPDisabledByAdministrator tells a user an administrator turned their two-factor authentication
// off.
var OTPDisabledByAdministrator = &Email{
	ID: "otp_disabled_by_administrator",
	Placeholders: []Placeholder{
		{Name: AppName}, {Name: Name},
	},
	BuiltIn: map[string]Text{
		"en": {
			Subject: "An administrator turned off your two-factor authentication",
			Body: `Hello {{name}},

An administrator turned off two-factor authentication for your {{app_name}} account. Your authenticator app and your recovery codes no longer work for signing in.

If you asked for this, you don't need to do anything. You can set up a new authenticator in your account settings.

**If you weren't expecting it, contact your administrator.** You can also choose a new password with "Forgot your password?" on the sign-in page, then sign in and check your two-factor authentication settings.

Best regards,
{{app_name}}`,
		},
		"de": {
			Subject: "Ihre Zwei-Faktor-Authentifizierung wurde von der Administration deaktiviert",
			Body: `Guten Tag {{name}},

Die Administration hat die Zwei-Faktor-Authentifizierung Ihres Kontos bei {{app_name}} deaktiviert. Ihre Authenticator-App und Ihre Wiederherstellungscodes funktionieren für die Anmeldung nicht mehr.

Falls Sie darum gebeten haben, brauchen Sie nichts zu tun. In Ihren Kontoeinstellungen können Sie eine neue Authenticator-App einrichten.

**Falls Sie damit nicht gerechnet haben, wenden Sie sich an Ihre Administration.** Sie können auch auf der Anmeldeseite über „Passwort vergessen?“ ein neues Passwort wählen, sich dann anmelden und Ihre Einstellungen zur Zwei-Faktor-Authentifizierung prüfen.

Mit freundlichen Grüßen
{{app_name}}`,
		},
		//nolint:misspell // the es text: "factores" is Spanish, not a misspelling of "factors"
		"es": {
			Subject: "Un administrador ha desactivado tu autenticación de dos factores",
			Body: `Hola, {{name}}:

Un administrador ha desactivado la autenticación de dos factores de tu cuenta de {{app_name}}. Tu aplicación de autenticación y tus códigos de recuperación ya no sirven para iniciar sesión.

Si lo habías pedido, no necesitas hacer nada. Puedes configurar una nueva aplicación de autenticación desde la configuración de tu cuenta.

**Si no lo esperabas, contacta con tu administrador.** También puedes elegir una contraseña nueva con «¿Olvidaste tu contraseña?» en la página de inicio de sesión. Después, inicia sesión y revisa la configuración de la autenticación de dos factores.

Un saludo,
{{app_name}}`,
		},
		"fr": {
			Subject: "Un administrateur a désactivé votre authentification à deux facteurs",
			Body: `Bonjour {{name}},

Un administrateur a désactivé l’authentification à deux facteurs de votre compte {{app_name}}. Votre application d’authentification et vos codes de récupération ne permettent plus de vous connecter.

Si vous l’aviez demandé, vous n’avez rien à faire. Vous pouvez configurer une nouvelle application d’authentification dans les paramètres de votre compte.

**Si vous ne vous y attendiez pas, contactez votre administrateur.** Vous pouvez aussi choisir un nouveau mot de passe avec « Mot de passe oublié ? » sur la page de connexion, puis vous connecter et vérifier vos paramètres d’authentification à deux facteurs.

Cordialement,
{{app_name}}`,
		},
		"id": {
			Subject: "Administrator telah menonaktifkan autentikasi dua faktor Anda",
			Body: `Halo {{name}},

Administrator telah menonaktifkan autentikasi dua faktor untuk akun {{app_name}} Anda. Aplikasi autentikator dan kode pemulihan Anda tidak lagi dapat digunakan untuk masuk.

Jika Anda yang memintanya, Anda tidak perlu melakukan apa pun. Anda dapat menyiapkan aplikasi autentikator baru di pengaturan akun Anda.

**Jika Anda tidak mengharapkannya, hubungi administrator Anda.** Anda juga dapat memilih kata sandi baru melalui "Lupa kata sandi?" di halaman masuk, lalu masuk dan periksa pengaturan autentikasi dua faktor Anda.

Salam,
{{app_name}}`,
		},
		//nolint:misspell // the it text: "configurare" is Italian, not a misspelling of "configure"
		"it": {
			Subject: "Un amministratore ha disattivato la tua autenticazione a due fattori",
			Body: `Ciao {{name}},

Un amministratore ha disattivato l'autenticazione a due fattori del tuo account {{app_name}}. L'app di autenticazione e i codici di recupero non servono più per accedere.

Se l'avevi chiesto tu, non devi fare nulla. Puoi configurare una nuova app di autenticazione dalle impostazioni del tuo account.

**Se non te lo aspettavi, contatta il tuo amministratore.** Puoi anche scegliere una nuova password con «Hai dimenticato la password?» nella pagina di accesso, poi accedere e controllare le impostazioni dell'autenticazione a due fattori.

Un saluto,
{{app_name}}`,
		},
		"ja": {
			Subject: "管理者があなたの二要素認証を無効にしました",
			Body: `{{name}} 様

管理者が {{app_name}} のアカウントの二要素認証を無効にしました。認証アプリとリカバリーコードは、ログインに使用できなくなりました。

ご自身で依頼した場合は、対応は不要です。新しい認証アプリは、アカウント設定で設定できます。

**心当たりがない場合は、管理者にお問い合わせください**。ログインページの「パスワードをお忘れですか？」から新しいパスワードを設定し、ログインして二要素認証の設定を確認することもできます。

{{app_name}}`,
		},
		//nolint:misspell // the pl text: "nowe" is Polish, not a misspelling of "now"
		"pl": {
			Subject: "Administrator wyłączył Twoje uwierzytelnianie dwuskładnikowe",
			Body: `Dzień dobry {{name}},

Administrator wyłączył uwierzytelnianie dwuskładnikowe dla Twojego konta w {{app_name}}. Aplikacja uwierzytelniająca i kody odzyskiwania nie służą już do logowania.

Jeśli zmiana nastąpiła na Twoją prośbę, nie musisz nic robić. Nową aplikację uwierzytelniającą możesz skonfigurować w ustawieniach konta.

**Jeśli się tego nie spodziewasz, skontaktuj się z administratorem.** Możesz też ustawić nowe hasło za pomocą linku „Nie pamiętasz hasła?” na stronie logowania, a potem zalogować się i sprawdzić ustawienia uwierzytelniania dwuskładnikowego.

Pozdrawiamy
{{app_name}}`,
		},
		"pt-BR": {
			Subject: "Um administrador desativou a sua autenticação de dois fatores",
			Body: `Olá {{name}},

Um administrador desativou a autenticação de dois fatores da sua conta {{app_name}}. O seu aplicativo autenticador e os seus códigos de recuperação não servem mais para entrar.

Se você pediu essa alteração, não é preciso fazer nada. Você pode configurar um novo autenticador nas configurações da sua conta.

**Se você não esperava por isso, entre em contato com o administrador.** Você também pode escolher uma nova senha em "Esqueceu sua senha?" na página de entrada, depois entrar na sua conta e conferir as configurações de autenticação de dois fatores.

Atenciosamente,
{{app_name}}`,
		},
		"ru": {
			Subject: "Администратор отключил вашу двухфакторную аутентификацию",
			Body: `Здравствуйте, {{name}}!

Администратор отключил двухфакторную аутентификацию для вашего аккаунта в {{app_name}}. Приложение-аутентификатор и коды восстановления больше не подходят для входа.

Если вы об этом просили, ничего делать не нужно. Новое приложение-аутентификатор можно подключить в настройках аккаунта.

**Если вы этого не ожидали, обратитесь к администратору.** Вы также можете задать новый пароль через ссылку «Забыли пароль?» на странице входа, затем войти и проверить настройки двухфакторной аутентификации.

С уважением,
{{app_name}}`,
		},
	},
}
