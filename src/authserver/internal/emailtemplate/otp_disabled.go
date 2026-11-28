package emailtemplate

// OTPDisabled tells a user they turned two-factor authentication off on the Account pages.
var OTPDisabled = &Email{
	ID: "otp_disabled",
	Placeholders: []Placeholder{
		{Name: AppName}, {Name: Name},
	},
	BuiltIn: map[string]Text{
		"en": {
			Subject: "Two-factor authentication was turned off",
			Body: `Hello {{name}},

Two-factor authentication was turned off for your {{app_name}} account from your account settings. Your authenticator app and your recovery codes no longer work for signing in.

If you made this change, you don't need to do anything.

**If you didn't, someone else may know your password.** Choose a new password with "Forgot your password?" on the sign-in page, then sign in and set up two-factor authentication again, or contact your administrator.

Best regards,
{{app_name}}`,
		},
		"de": {
			Subject: "Die Zwei-Faktor-Authentifizierung wurde deaktiviert",
			Body: `Guten Tag {{name}},

Die Zwei-Faktor-Authentifizierung Ihres Kontos bei {{app_name}} wurde in Ihren Kontoeinstellungen deaktiviert. Ihre Authenticator-App und Ihre Wiederherstellungscodes funktionieren für die Anmeldung nicht mehr.

Falls Sie diese Änderung selbst vorgenommen haben, brauchen Sie nichts zu tun.

**Andernfalls kennt möglicherweise jemand Ihr Passwort.** Wählen Sie auf der Anmeldeseite über „Passwort vergessen?“ ein neues Passwort, melden Sie sich dann an und richten Sie die Zwei-Faktor-Authentifizierung erneut ein. Sie können sich auch an Ihre Administration wenden.

Mit freundlichen Grüßen
{{app_name}}`,
		},
		//nolint:misspell // the es text: "factores" is Spanish, not a misspelling of "factors"
		"es": {
			Subject: "Se ha desactivado la autenticación de dos factores",
			Body: `Hola, {{name}}:

La autenticación de dos factores de tu cuenta de {{app_name}} se ha desactivado desde la configuración de tu cuenta. Tu aplicación de autenticación y tus códigos de recuperación ya no sirven para iniciar sesión.

Si has hecho este cambio, no necesitas hacer nada.

**Si no has sido tú, puede que otra persona conozca tu contraseña.** Elige una contraseña nueva con «¿Olvidaste tu contraseña?» en la página de inicio de sesión. Después, inicia sesión y vuelve a configurar la autenticación de dos factores, o contacta con tu administrador.

Un saludo,
{{app_name}}`,
		},
		"fr": {
			Subject: "L’authentification à deux facteurs a été désactivée",
			Body: `Bonjour {{name}},

L’authentification à deux facteurs de votre compte {{app_name}} a été désactivée depuis les paramètres de votre compte. Votre application d’authentification et vos codes de récupération ne permettent plus de vous connecter.

Si vous avez effectué cette modification, vous n’avez rien à faire.

**Sinon, une autre personne connaît peut-être votre mot de passe.** Choisissez un nouveau mot de passe avec « Mot de passe oublié ? » sur la page de connexion, puis connectez-vous et configurez à nouveau l’authentification à deux facteurs, ou contactez votre administrateur.

Cordialement,
{{app_name}}`,
		},
		"id": {
			Subject: "Autentikasi dua faktor telah dinonaktifkan",
			Body: `Halo {{name}},

Autentikasi dua faktor untuk akun {{app_name}} Anda telah dinonaktifkan dari pengaturan akun Anda. Aplikasi autentikator dan kode pemulihan Anda tidak lagi dapat digunakan untuk masuk.

Jika Anda yang melakukan perubahan ini, Anda tidak perlu melakukan apa pun.

**Jika bukan Anda, orang lain mungkin mengetahui kata sandi Anda.** Pilih kata sandi baru melalui "Lupa kata sandi?" di halaman masuk, lalu masuk dan siapkan kembali autentikasi dua faktor, atau hubungi administrator Anda.

Salam,
{{app_name}}`,
		},
		"it": {
			Subject: "L'autenticazione a due fattori è stata disattivata",
			Body: `Ciao {{name}},

L'autenticazione a due fattori del tuo account {{app_name}} è stata disattivata dalle impostazioni del tuo account. L'app di autenticazione e i codici di recupero non servono più per accedere.

Se hai effettuato tu la modifica, non devi fare nulla.

**Altrimenti, qualcun altro potrebbe conoscere la tua password.** Scegli una nuova password con «Hai dimenticato la password?» nella pagina di accesso, poi accedi e configura di nuovo l'autenticazione a due fattori, oppure contatta il tuo amministratore.

Un saluto,
{{app_name}}`,
		},
		"ja": {
			Subject: "二要素認証が無効になりました",
			Body: `{{name}} 様

{{app_name}} のアカウントの二要素認証が、アカウント設定から無効にされました。認証アプリとリカバリーコードは、ログインに使用できなくなりました。

この変更をご自身で行った場合は、対応は不要です。

**ご自身で行っていない場合は、第三者があなたのパスワードを知っている可能性があります**。ログインページの「パスワードをお忘れですか？」から新しいパスワードを設定し、ログインしてもう一度二要素認証を設定するか、管理者にお問い合わせください。

{{app_name}}`,
		},
		//nolint:misspell // the pl text: "nowe" is Polish, not a misspelling of "now"
		"pl": {
			Subject: "Wyłączono uwierzytelnianie dwuskładnikowe",
			Body: `Dzień dobry {{name}},

W ustawieniach Twojego konta w {{app_name}} wyłączono uwierzytelnianie dwuskładnikowe. Aplikacja uwierzytelniająca i kody odzyskiwania nie służą już do logowania.

Jeśli to Twoja zmiana, nie musisz nic robić.

**Jeśli nie, ktoś inny może znać Twoje hasło.** Ustaw nowe hasło za pomocą linku „Nie pamiętasz hasła?” na stronie logowania, a potem zaloguj się i ponownie skonfiguruj uwierzytelnianie dwuskładnikowe albo skontaktuj się z administratorem.

Pozdrawiamy
{{app_name}}`,
		},
		"pt-BR": {
			Subject: "A autenticação de dois fatores foi desativada",
			Body: `Olá {{name}},

A autenticação de dois fatores da sua conta {{app_name}} foi desativada nas configurações da sua conta. O seu aplicativo autenticador e os seus códigos de recuperação não servem mais para entrar.

Se foi você quem fez essa alteração, não é preciso fazer nada.

**Se não foi você, outra pessoa pode saber a sua senha.** Escolha uma nova senha em "Esqueceu sua senha?" na página de entrada, depois entre na sua conta e configure a autenticação de dois fatores novamente, ou entre em contato com o administrador.

Atenciosamente,
{{app_name}}`,
		},
		"ru": {
			Subject: "Двухфакторная аутентификация отключена",
			Body: `Здравствуйте, {{name}}!

Двухфакторная аутентификация для вашего аккаунта в {{app_name}} отключена в настройках аккаунта. Приложение-аутентификатор и коды восстановления больше не подходят для входа.

Если это изменение внесли вы, ничего делать не нужно.

**Если нет, возможно, ваш пароль известен кому-то еще.** Задайте новый пароль через ссылку «Забыли пароль?» на странице входа, затем войдите и снова настройте двухфакторную аутентификацию или обратитесь к администратору.

С уважением,
{{app_name}}`,
		},
		"zh-Hans": {
			Subject: "双因素认证已关闭",
			Body: `{{name}}，您好：

您的 {{app_name}} 账户已通过账户设置关闭双因素认证。您的身份验证器应用和恢复代码已无法再用于登录。

如果这是您本人所做的更改，则无需进行任何操作。

**如果不是您本人操作，可能有其他人知道您的密码**。请在登录页面通过“忘记密码？”设置新密码，然后登录并重新设置双因素认证，或联系您的管理员。

{{app_name}}`,
		},
	},
}
