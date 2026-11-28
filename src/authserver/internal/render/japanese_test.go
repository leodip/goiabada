package render

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/leodip/goiabada/authserver/internal/emailtemplate"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/web"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/personname"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The sign-in page asked for in Japanese, through ui_locales or the browser, or listed after
// Chinese, is drawn in Japanese with its refusal (#662).
func TestJapanese_SignInPageUsesQueryOrJapaneseHeader(t *testing.T) {
	for _, tc := range []struct{ target, accept string }{
		{"/auth/pwd?ui_locales=ja", "en"},
		{"/auth/pwd?ui_locales=ja-JP", "en"},
		{"/auth/pwd", "ja-JP"},
		{"/auth/pwd", "zh-CN,ja;q=0.8"},
	} {
		t.Run(tc.target+tc.accept, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.target, nil)
			req.Header.Set("Accept-Language", tc.accept)
			req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{AppName: "Test"}))
			req = req.WithContext(i18n.ResolveRequestLocale(req.Context(), req))
			buf, err := New(web.TemplateFS(), web.StaticFS(), nil).RenderTemplateToBuffer(req,
				"layouts/auth_layout.html", "auth_pwd.html", map[string]interface{}{
					"error": i18n.NewLocalizedError(i18n.ErrCodeLoginAuthFailed, nil).Localize(req.Context()),
				})
			require.NoError(t, err)
			assert.Contains(t, buf.String(), `<html lang="ja"`)
			assert.Contains(t, buf.String(), `>ログイン</h1>`)
			assert.Contains(t, buf.String(), `>ログイン</button>`)
			assert.Contains(t, buf.String(), `for="email">メールアドレス</label>`)
			assert.Contains(t, buf.String(), `for="password">パスワード</label>`)
			assert.Contains(t, buf.String(), "認証に失敗しました。")
		})
	}
}

// Every email, sent from its built-in definition (#818), follows a recipient reading Japanese, in
// its own tag and in ja-JP: the subject, the language the email is marked with, and a sentence of
// the body, the activation link's and the verification code's saying how long they last, and the
// recovery code notice's giving the codes left.
func TestJapanese_EveryDefinedEmailFollowsTheRecipient(t *testing.T) {
	assertDefinedEmailsFollowTheRecipient(t, []string{"ja", "ja-JP"}, "ja", []definedEmail{
		{emailtemplate.ActivationLink, "アカウントの有効化", "このリンクの有効期限は 5 分です。"},
		{emailtemplate.RegistrationExistingAccount, "アカウントはすでに存在します", "このアドレスにはすでにアカウントがあるため、新しいアカウントは作成されていません。"},
		{emailtemplate.Welcome, "ようこそ！", "アカウントが作成されました。"},
		{emailtemplate.VerificationCode, "メールアドレスの確認コード：482915", "このコードの有効期限は 5 分です。"},
		{emailtemplate.NewUserSetup, "【Acme Portal】新しいアカウントのパスワードを作成してください", "以下のリンクから、パスワードを作成できます。"},
		{emailtemplate.TestEmail, "【Acme Portal】テストメール", "これは Acme Portal からのテストメールです。"},
		{emailtemplate.EmailAddressChanged, "メールアドレスが変更されました", "Acme Portal のアカウントのメールアドレスが変更されました。"},
		{emailtemplate.PasswordChanged, "パスワードが変更されました", "第三者があなたのアカウントを使用している可能性があります"},
		{emailtemplate.PasswordChangedByAdministrator, "管理者があなたのパスワードを変更しました", "管理者が Acme Portal のアカウントのパスワードを変更しました。"},
		{emailtemplate.PasswordReset, "パスワードが再設定されました", "第三者があなたのメールを読み、アカウントを使用できる可能性があります"},
		{emailtemplate.OTPEnabled, "二要素認証が設定されました", "あわせて新しいリカバリーコードが発行されました。"},
		{emailtemplate.OTPDisabled, "二要素認証が無効になりました", "ログインしてもう一度二要素認証を設定するか"},
		{emailtemplate.OTPDisabledByAdministrator, "管理者があなたの二要素認証を無効にしました", "新しい認証アプリは、アカウント設定で設定できます。"},
		{emailtemplate.RecoveryCodeUsed, "ログインにリカバリーコードが使用されました", "未使用のリカバリーコードは残り 3 個です。"},
		{emailtemplate.RecoveryCodesReplaced, "リカバリーコードが再発行されました", "以前のリカバリーコードは、使用済みかどうかにかかわらず使用できなくなりました。"},
		{emailtemplate.OTPLockout, "誤ったコードが続けて入力されたため、認証アプリが無効になりました", "リカバリーコードのいずれかでログインし"},
		{emailtemplate.AccountDeleted, "アカウントが削除されました", "第三者があなたのパスワードを知っていたことになります"},
		{emailtemplate.AccountDeletedByAdministrator, "管理者があなたのアカウントを削除しました", "管理者が Acme Portal のアカウントを削除しました。"},
		{emailtemplate.PasswordResetLink, "パスワードの再設定", "以下のリンクから、パスワードを再設定できます。"},
	})
}

// A recipient named 山田 太郎, whose page language is Automatic and whose Language and region is
// ja-JP, gets the Japanese email, whatever the sender's request read: greeted by their full name,
// family name first, and 様 on its own line, with {{expiry}} written with a half-width space after
// its number and none before the です that follows it, and closed with the app name alone (#662
// decisions 1, 3 and 6). The activation link, which offers no name, opens with its text.
func TestJapanese_ARecipientReadingJaJPIsGreetedByFullNameWithTheExpiryWritten(t *testing.T) {
	for _, tc := range []struct {
		expiry time.Duration
		unit   string
	}{
		{5 * time.Minute, "5 分"},
		{30 * time.Minute, "30 分"},
		{time.Hour, "1 時間"},
		{24 * time.Hour, "24 時間"},
	} {
		for _, email := range []struct {
			email             *emailtemplate.Email
			subject, greeting string
			sentence          string
		}{
			{emailtemplate.ActivationLink, "アカウントの有効化", "", "このリンクの有効期限は " + tc.unit + "です。"},
			{emailtemplate.PasswordResetLink, "パスワードの再設定", "山田太郎 様", "このリンクの有効期限は " + tc.unit + "です。"},
			{emailtemplate.VerificationCode, "メールアドレスの確認コード：482915", "山田太郎 様", "このコードの有効期限は " + tc.unit + "です。"},
			{emailtemplate.NewUserSetup, "【Acme Portal】新しいアカウントのパスワードを作成してください", "山田太郎 様", "このリンクの有効期間は " + tc.unit + "です。"},
		} {
			t.Run(email.email.ID+"/"+tc.expiry.String(), func(t *testing.T) {
				ctx := reqctx.WithSettings(context.Background(), &record.Settings{AppName: "Acme Portal"})
				sender := httptest.NewRequest(http.MethodPost, "/forgot-password?ui_locales=de", nil).WithContext(ctx)
				sender.Header.Set("Accept-Language", "it")
				ctx = i18n.WithRecipientLanguage(i18n.ResolveRequestLocale(ctx, sender), "", "ja-JP")
				values := definitionValues
				values.Name = personname.FullName("太郎", "", "山田")
				values.Expiry = tc.expiry

				message, err := New(web.TemplateFS(), web.StaticFS(), nil).WithBaseURL(emailBaseURL).
					RenderEmail(sender.WithContext(ctx), email.email, values)
				require.NoError(t, err)

				assert.Equal(t, email.subject, message.Subject)
				doc, err := goquery.NewDocumentFromReader(strings.NewReader(message.HTML))
				require.NoError(t, err)
				lang, _ := doc.Find("html").Attr("lang")
				assert.Equal(t, "ja", lang)
				paragraphs := doc.Find("main p")
				require.Positive(t, paragraphs.Length())
				first := strings.TrimSpace(paragraphs.First().Text())
				if email.greeting != "" {
					assert.Equal(t, email.greeting, first, "the greeting is the first paragraph, alone")
				} else {
					assert.NotContains(t, first, "様", "an email that offers no name opens with its text")
				}
				assert.Equal(t, "Acme Portal", strings.TrimSpace(paragraphs.Last().Text()), "the app name alone closes the email")
				body := doc.Find("main").Text()
				assert.Contains(t, body, email.sentence)
				assert.NotContains(t, body, "太郎 山田")
				assert.NotContains(t, message.HTML, "{{")
			})
		}
	}
}
