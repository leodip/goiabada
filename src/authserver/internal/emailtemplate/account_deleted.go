package emailtemplate

// AccountDeleted tells a user they deleted their own account on the Account pages.
var AccountDeleted = &Email{
	ID: "account_deleted",
	Placeholders: []Placeholder{
		{Name: AppName}, {Name: Name},
	},
	BuiltIn: map[string]Text{
		"en": {
			Subject: "Your account was deleted",
			Body: `Hello {{name}},

Your {{app_name}} account was deleted from your account settings. You can no longer sign in with it, and apps can no longer get access to it.

If you made this change, you don't need to do anything.

**If you didn't, someone else knew your password.** Contact your administrator.

Best regards,
{{app_name}}`,
		},
		"de": {
			Subject: "Ihr Konto wurde gelöscht",
			Body: `Guten Tag {{name}},

Ihr Konto bei {{app_name}} wurde in Ihren Kontoeinstellungen gelöscht. Sie können sich damit nicht mehr anmelden, und Apps erhalten keinen Zugriff mehr darauf.

Falls Sie diese Änderung selbst vorgenommen haben, brauchen Sie nichts zu tun.

**Andernfalls kannte jemand anderes Ihr Passwort.** Wenden Sie sich an Ihre Administration.

Mit freundlichen Grüßen
{{app_name}}`,
		},
		"es": {
			Subject: "Se ha eliminado tu cuenta",
			Body: `Hola, {{name}}:

Tu cuenta de {{app_name}} se ha eliminado desde la configuración de tu cuenta. Ya no puedes iniciar sesión con ella, y las aplicaciones ya no pueden acceder a ella.

Si has hecho este cambio, no necesitas hacer nada.

**Si no has sido tú, otra persona conocía tu contraseña.** Contacta con tu administrador.

Un saludo,
{{app_name}}`,
		},
		"fr": {
			Subject: "Votre compte a été supprimé",
			Body: `Bonjour {{name}},

Votre compte {{app_name}} a été supprimé depuis les paramètres de votre compte. Vous ne pouvez plus vous y connecter, et les applications ne peuvent plus y accéder.

Si vous avez effectué cette modification, vous n’avez rien à faire.

**Sinon, une autre personne connaissait votre mot de passe.** Contactez votre administrateur.

Cordialement,
{{app_name}}`,
		},
		"id": {
			Subject: "Akun Anda telah dihapus",
			Body: `Halo {{name}},

Akun {{app_name}} Anda telah dihapus dari pengaturan akun Anda. Anda tidak dapat lagi masuk dengan akun tersebut, dan aplikasi tidak dapat lagi mengaksesnya.

Jika Anda yang melakukan perubahan ini, Anda tidak perlu melakukan apa pun.

**Jika bukan Anda, orang lain mengetahui kata sandi Anda.** Hubungi administrator Anda.

Salam,
{{app_name}}`,
		},
		//nolint:misspell // the it text: "eliminato" is Italian, not a misspelling of "elimination"
		"it": {
			Subject: "Il tuo account è stato eliminato",
			Body: `Ciao {{name}},

Il tuo account {{app_name}} è stato eliminato dalle impostazioni del tuo account. Non puoi più accedere con questo account e le app non possono più accedervi.

Se hai effettuato tu la modifica, non devi fare nulla.

**Altrimenti, qualcun altro conosceva la tua password.** Contatta il tuo amministratore.

Un saluto,
{{app_name}}`,
		},
		"ja": {
			Subject: "アカウントが削除されました",
			Body: `{{name}} 様

{{app_name}} のアカウントが、アカウント設定から削除されました。このアカウントではログインできなくなり、アプリケーションからこのアカウントにアクセスすることもできなくなりました。

この変更をご自身で行った場合は、対応は不要です。

**ご自身で行っていない場合は、第三者があなたのパスワードを知っていたことになります**。管理者にお問い合わせください。

{{app_name}}`,
		},
		"pl": {
			Subject: "Usunięto Twoje konto",
			Body: `Dzień dobry {{name}},

Twoje konto w {{app_name}} zostało usunięte w ustawieniach konta. Nie możesz się już na nie zalogować, a aplikacje nie mają już do niego dostępu.

Jeśli to Ty, nie musisz nic robić.

**Jeśli nie, ktoś inny znał Twoje hasło.** Skontaktuj się z administratorem.

Pozdrawiamy
{{app_name}}`,
		},
		"pt-BR": {
			Subject: "Sua conta foi excluída",
			Body: `Olá {{name}},

A sua conta {{app_name}} foi excluída nas configurações da sua conta. Você não pode mais entrar com ela, e os aplicativos não podem mais acessá-la.

Se foi você quem fez essa alteração, não é preciso fazer nada.

**Se não foi você, outra pessoa sabia a sua senha.** Entre em contato com o administrador.

Atenciosamente,
{{app_name}}`,
		},
		"ru": {
			Subject: "Ваш аккаунт удален",
			Body: `Здравствуйте, {{name}}!

Ваш аккаунт в {{app_name}} удален в настройках аккаунта. Войти в него больше нельзя, и приложения больше не могут получить к нему доступ.

Если это сделали вы, ничего делать не нужно.

**Если нет, значит, ваш пароль был известен кому-то еще.** Обратитесь к администратору.

С уважением,
{{app_name}}`,
		},
	},
}
