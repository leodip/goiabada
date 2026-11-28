package emailtemplate

// OTPLockout tells a user their authenticator was disabled after too many wrong codes in a row.
var OTPLockout = &Email{
	ID: "otp_lockout",
	Placeholders: []Placeholder{
		{Name: AppName}, {Name: Name},
	},
	BuiltIn: map[string]Text{
		"en": {
			Subject: "Your authenticator was disabled after too many wrong codes",
			Body: `Hello {{name}},

The authenticator app of your {{app_name}} account was disabled after too many wrong codes in a row were entered while signing in. Its codes are no longer accepted, even the right ones.

**Those codes could only be entered after your password, so someone else may know it.** Sign in with one of your recovery codes, change your password in your account settings, then turn two-factor authentication off and set up a new authenticator. If you have no recovery codes left, contact your administrator.

Best regards,
{{app_name}}`,
		},
		"de": {
			Subject: "Ihre Authenticator-App wurde nach zu vielen falschen Codes gesperrt",
			Body: `Guten Tag {{name}},

Die Authenticator-App Ihres Kontos bei {{app_name}} wurde gesperrt, nachdem bei der Anmeldung zu viele falsche Codes nacheinander eingegeben wurden. Ihre Codes werden nicht mehr akzeptiert, auch die richtigen nicht.

**Diese Codes konnten nur nach Ihrem Passwort eingegeben werden, also kennt möglicherweise jemand Ihr Passwort.** Melden Sie sich mit einem Ihrer Wiederherstellungscodes an, ändern Sie Ihr Passwort in Ihren Kontoeinstellungen, deaktivieren Sie dann die Zwei-Faktor-Authentifizierung und richten Sie eine neue Authenticator-App ein. Falls Sie keine Wiederherstellungscodes mehr haben, wenden Sie sich an Ihre Administration.

Mit freundlichen Grüßen
{{app_name}}`,
		},
		//nolint:misspell // the es text: "factores" is Spanish, not a misspelling of "factors"
		"es": {
			Subject: "Tu aplicación de autenticación se ha bloqueado tras demasiados códigos incorrectos",
			Body: `Hola, {{name}}:

La aplicación de autenticación de tu cuenta de {{app_name}} se ha bloqueado porque se introdujeron demasiados códigos incorrectos seguidos al iniciar sesión. Sus códigos ya no se aceptan, ni siquiera los correctos.

**Esos códigos solo se podían introducir después de tu contraseña, así que puede que otra persona la conozca.** Inicia sesión con uno de tus códigos de recuperación, cambia tu contraseña en la configuración de tu cuenta y, después, desactiva la autenticación de dos factores y configura una nueva aplicación de autenticación. Si no te queda ningún código de recuperación, contacta con tu administrador.

Un saludo,
{{app_name}}`,
		},
		"fr": {
			Subject: "Votre application d’authentification a été bloquée après trop de codes erronés",
			Body: `Bonjour {{name}},

L’application d’authentification de votre compte {{app_name}} a été bloquée après la saisie de trop de codes erronés à la suite lors de la connexion. Ses codes ne sont plus acceptés, même les bons.

**Ces codes ne pouvaient être saisis qu’après votre mot de passe, une autre personne le connaît donc peut-être.** Connectez-vous avec l’un de vos codes de récupération, changez votre mot de passe dans les paramètres de votre compte, puis désactivez l’authentification à deux facteurs et configurez une nouvelle application d’authentification. S’il ne vous reste aucun code de récupération, contactez votre administrateur.

Cordialement,
{{app_name}}`,
		},
		"id": {
			Subject: "Aplikasi autentikator Anda dinonaktifkan setelah terlalu banyak kode salah",
			Body: `Halo {{name}},

Aplikasi autentikator akun {{app_name}} Anda telah dinonaktifkan setelah terlalu banyak kode salah dimasukkan berturut-turut saat masuk. Kodenya tidak lagi diterima, termasuk kode yang benar.

**Kode tersebut hanya dapat dimasukkan setelah kata sandi Anda, jadi orang lain mungkin mengetahuinya.** Masuk dengan salah satu kode pemulihan Anda, ubah kata sandi Anda di pengaturan akun, lalu nonaktifkan autentikasi dua faktor dan siapkan aplikasi autentikator baru. Jika kode pemulihan Anda sudah habis, hubungi administrator Anda.

Salam,
{{app_name}}`,
		},
		"it": {
			Subject: "La tua app di autenticazione è stata bloccata dopo troppi codici errati",
			Body: `Ciao {{name}},

L'app di autenticazione del tuo account {{app_name}} è stata bloccata dopo troppi codici errati inseriti di seguito durante l'accesso. I suoi codici non vengono più accettati, nemmeno quelli giusti.

**Quei codici si potevano inserire solo dopo la password, quindi qualcun altro potrebbe conoscerla.** Accedi con uno dei tuoi codici di recupero, cambia la password dalle impostazioni del tuo account, poi disattiva l'autenticazione a due fattori e configura una nuova app di autenticazione. Se non ti restano codici di recupero, contatta il tuo amministratore.

Un saluto,
{{app_name}}`,
		},
		"ja": {
			Subject: "誤ったコードが続けて入力されたため、認証アプリが無効になりました",
			Body: `{{name}} 様

ログイン時に誤ったコードが続けて何度も入力されたため、{{app_name}} のアカウントの認証アプリが無効になりました。今後は、正しいコードであっても受け付けられません。

**これらのコードはパスワードの入力後にしか入力できないため、第三者があなたのパスワードを知っている可能性があります**。リカバリーコードのいずれかでログインし、アカウント設定でパスワードを変更してから、二要素認証を無効にして新しい認証アプリを設定してください。リカバリーコードが残っていない場合は、管理者にお問い合わせください。

{{app_name}}`,
		},
		"pl": {
			Subject: "Zablokowano Twoją aplikację uwierzytelniającą po zbyt wielu błędnych kodach",
			Body: `Dzień dobry {{name}},

Aplikacja uwierzytelniająca Twojego konta w {{app_name}} została zablokowana, ponieważ podczas logowania wpisano zbyt wiele błędnych kodów z rzędu. Jej kody nie są już akceptowane, nawet poprawne.

**Te kody można było wpisać dopiero po haśle, więc ktoś inny może znać Twoje hasło.** Zaloguj się jednym z kodów odzyskiwania, zmień hasło w ustawieniach konta, a potem wyłącz uwierzytelnianie dwuskładnikowe i skonfiguruj nową aplikację uwierzytelniającą. Jeśli nie masz już kodów odzyskiwania, skontaktuj się z administratorem.

Pozdrawiamy
{{app_name}}`,
		},
		"pt-BR": {
			Subject: "Seu aplicativo autenticador foi bloqueado após muitos códigos errados",
			Body: `Olá {{name}},

O aplicativo autenticador da sua conta {{app_name}} foi bloqueado depois que muitos códigos errados foram digitados seguidos ao entrar. Os códigos dele não são mais aceitos, nem os certos.

**Esses códigos só podiam ser digitados depois da sua senha, então outra pessoa pode saber a sua senha.** Entre com um dos seus códigos de recuperação, altere a sua senha nas configurações da sua conta, depois desative a autenticação de dois fatores e configure um novo autenticador. Se você não tiver mais códigos de recuperação, entre em contato com o administrador.

Atenciosamente,
{{app_name}}`,
		},
		"ru": {
			Subject: "Приложение-аутентификатор отключено из-за слишком большого числа неверных кодов",
			Body: `Здравствуйте, {{name}}!

Приложение-аутентификатор вашего аккаунта в {{app_name}} отключено: при входе слишком много раз подряд был введен неверный код. Его коды больше не принимаются, даже верные.

**Эти коды можно было ввести только после пароля, поэтому, возможно, ваш пароль известен кому-то еще.** Войдите с одним из кодов восстановления, смените пароль в настройках аккаунта, затем отключите двухфакторную аутентификацию и подключите новое приложение-аутентификатор. Если у вас не осталось кодов восстановления, обратитесь к администратору.

С уважением,
{{app_name}}`,
		},
	},
}
