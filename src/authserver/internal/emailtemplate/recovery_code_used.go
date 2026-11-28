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
		"id": {
			Subject: "Kode pemulihan digunakan untuk masuk",
			Body: `Halo {{name}},

Salah satu kode pemulihan Anda digunakan untuk masuk ke akun {{app_name}} Anda, sebagai pengganti kode dari aplikasi autentikator Anda. Setiap kode pemulihan hanya berlaku sekali, jadi kode tersebut tidak dapat digunakan lagi. Sisa kode pemulihan yang belum digunakan: {{codes_left}}.

Jika itu Anda dan Anda tidak lagi memiliki aplikasi autentikator, nonaktifkan autentikasi dua faktor di pengaturan akun Anda dan siapkan aplikasi autentikator baru, yang disertai satu set kode pemulihan baru. Jika Anda masih memiliki aplikasi tersebut, buat satu set kode pemulihan baru di sana, agar Anda tetap dapat masuk jika aplikasi itu hilang.

**Jika bukan Anda, orang lain mungkin mengetahui kata sandi Anda dan memiliki kode pemulihan Anda.** Pilih kata sandi baru melalui "Lupa kata sandi?" di halaman masuk, lalu masuk, nonaktifkan autentikasi dua faktor dan siapkan aplikasi autentikator baru, atau hubungi administrator Anda.

Salam,
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
		"ja": {
			Subject: "ログインにリカバリーコードが使用されました",
			Body: `{{name}} 様

{{app_name}} のアカウントへのログインに、認証アプリのコードの代わりにリカバリーコードが使用されました。リカバリーコードはそれぞれ 1 回しか使用できないため、使用されたコードはもう使えません。未使用のリカバリーコードは残り {{codes_left}} 個です。

ご自身でログインし、認証アプリがもう手元にない場合は、アカウント設定で二要素認証を無効にしてから新しい認証アプリを設定してください。新しいリカバリーコードも発行されます。認証アプリがまだ手元にある場合は、紛失してもログインできるよう、アカウント設定で新しいリカバリーコードを取得してください。

**ご自身でない場合は、第三者があなたのパスワードを知っていて、リカバリーコードも持っている可能性があります**。ログインページの「パスワードをお忘れですか？」から新しいパスワードを設定し、ログインして二要素認証を無効にしてから新しい認証アプリを設定するか、管理者にお問い合わせください。

{{app_name}}`,
		},
		//nolint:misspell // the pl text: "nowe" is Polish, not a misspelling of "now"
		"pl": {
			Subject: "Do logowania użyto kodu odzyskiwania",
			Body: `Dzień dobry {{name}},

Do zalogowania się na Twoje konto w {{app_name}} użyto jednego z Twoich kodów odzyskiwania zamiast kodu z aplikacji uwierzytelniającej. Każdy kod odzyskiwania działa tylko raz, więc ten już nie działa. Pozostałe nieużyte kody odzyskiwania: {{codes_left}}.

Jeśli to Ty i nie masz już aplikacji uwierzytelniającej, wyłącz uwierzytelnianie dwuskładnikowe w ustawieniach konta i skonfiguruj nową aplikację uwierzytelniającą, z którą otrzymasz nowy zestaw kodów odzyskiwania. Jeśli nadal masz tę aplikację, wygeneruj nowy zestaw kodów odzyskiwania w ustawieniach konta, aby móc się zalogować, jeśli ją stracisz.

**Jeśli to nie Ty, ktoś inny może znać Twoje hasło i mieć Twoje kody odzyskiwania.** Ustaw nowe hasło za pomocą linku „Nie pamiętasz hasła?” na stronie logowania, a potem zaloguj się, wyłącz uwierzytelnianie dwuskładnikowe i skonfiguruj nową aplikację uwierzytelniającą albo skontaktuj się z administratorem.

Pozdrawiamy
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
		"ru": {
			Subject: "Для входа использован код восстановления",
			Body: `Здравствуйте, {{name}}!

Для входа в ваш аккаунт в {{app_name}} вместо кода из приложения-аутентификатора использован один из ваших кодов восстановления. Каждый код восстановления действует один раз, поэтому этот код больше не подходит. Осталось неиспользованных кодов восстановления: {{codes_left}}.

Если это были вы и у вас больше нет приложения-аутентификатора, отключите двухфакторную аутентификацию в настройках аккаунта и подключите новое приложение-аутентификатор: вместе с ним вы получите новый набор кодов восстановления. Если приложение у вас еще есть, создайте в настройках аккаунта новый набор кодов восстановления, чтобы сохранить возможность войти, если вы его потеряете.

**Если это были не вы, возможно, кто-то другой знает ваш пароль и имеет ваши коды восстановления.** Задайте новый пароль через ссылку «Забыли пароль?» на странице входа, затем войдите, отключите двухфакторную аутентификацию и подключите новое приложение-аутентификатор или обратитесь к администратору.

С уважением,
{{app_name}}`,
		},
		"zh-Hans": {
			Subject: "已使用恢复代码登录",
			Body: `{{name}}，您好：

有人使用您的一个恢复代码代替身份验证器应用中的一次性验证码，登录了您的 {{app_name}} 账户。每个恢复代码只能使用一次，因此该代码已失效。还剩{{codes_left}}个未使用的恢复代码。

如果是您本人，并且您已不再拥有身份验证器应用，请在账户设置中关闭双因素认证并设置新的身份验证器应用，届时会生成一组新的恢复代码。如果您仍拥有该应用，请在账户设置中获取一组新的恢复代码，以便在丢失该应用时仍能登录。

**如果不是您本人，可能有其他人知道您的密码并持有您的恢复代码**。请在登录页面通过“忘记密码？”设置新密码，然后登录，关闭双因素认证并设置新的身份验证器应用，或联系您的管理员。

{{app_name}}`,
		},
	},
}
