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

// The sign-in page asked for in Simplified Chinese, through ui_locales or the browser, or by what
// Chrome set to Chinese (Taiwan) sends, is drawn in Simplified Chinese with its refusal, and a
// request naming only Traditional Chinese reads English (#663 decision 3).
func TestSimplifiedChinese_SignInPageUsesQueryOrChineseHeader(t *testing.T) {
	for _, tc := range []struct {
		target, accept                   string
		lang, title, email, password, no string
	}{
		{"/auth/pwd?ui_locales=zh-Hans", "en", "zh-Hans", "登录", "电子邮件地址", "密码", "认证失败。"},
		{"/auth/pwd?ui_locales=zh", "en", "zh-Hans", "登录", "电子邮件地址", "密码", "认证失败。"},
		{"/auth/pwd?ui_locales=zh-CN", "en", "zh-Hans", "登录", "电子邮件地址", "密码", "认证失败。"},
		{"/auth/pwd", "zh-CN", "zh-Hans", "登录", "电子邮件地址", "密码", "认证失败。"},
		{"/auth/pwd", "zh-CN,zh;q=0.9,en;q=0.8", "zh-Hans", "登录", "电子邮件地址", "密码", "认证失败。"},
		{"/auth/pwd", "zh-SG", "zh-Hans", "登录", "电子邮件地址", "密码", "认证失败。"},
		{"/auth/pwd", "zh-Hans-HK", "zh-Hans", "登录", "电子邮件地址", "密码", "认证失败。"},
		{"/auth/pwd", "zh-TW,zh;q=0.9", "zh-Hans", "登录", "电子邮件地址", "密码", "认证失败。"},
		{"/auth/pwd", "zh-TW", "en", "Sign in", "Email", "Password", "Authentication failed."},
		{"/auth/pwd", "zh-HK", "en", "Sign in", "Email", "Password", "Authentication failed."},
		{"/auth/pwd", "zh-Hant", "en", "Sign in", "Email", "Password", "Authentication failed."},
		{"/auth/pwd", "zh-MY", "en", "Sign in", "Email", "Password", "Authentication failed."},
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
			assert.Contains(t, buf.String(), `<html lang="`+tc.lang+`"`)
			assert.Contains(t, buf.String(), `>`+tc.title+`</h1>`)
			assert.Contains(t, buf.String(), `>`+tc.title+`</button>`)
			assert.Contains(t, buf.String(), `for="email">`+tc.email+`</label>`)
			assert.Contains(t, buf.String(), `for="password">`+tc.password+`</label>`)
			assert.Contains(t, buf.String(), tc.no)
		})
	}
}

// Every email, sent from its built-in definition (#818), follows a recipient reading Simplified
// Chinese, in its own tag and in zh-CN and zh-SG: the subject, the language the email is marked
// with, and a sentence of the body, the activation link's and the verification code's saying how
// long they last with the number joined to its unit, and the recovery code notice's giving the
// codes left.
func TestSimplifiedChinese_EveryDefinedEmailFollowsTheRecipient(t *testing.T) {
	assertDefinedEmailsFollowTheRecipient(t, []string{"zh-Hans", "zh-CN", "zh-SG"}, "zh-Hans", []definedEmail{
		{emailtemplate.ActivationLink, "激活您的账户", "该链接将在5分钟后过期。"},
		{emailtemplate.RegistrationExistingAccount, "您已有账户", "此地址已有账户，因此未创建新账户。"},
		{emailtemplate.Welcome, "欢迎！", "恭喜！您的账户已创建。"},
		{emailtemplate.VerificationCode, "电子邮件地址验证码：482915", "该验证码将在5分钟后过期。"},
		{emailtemplate.NewUserSetup, "【Acme Portal】为您的新账户创建密码", "您可以点击下面的链接创建密码："},
		{emailtemplate.TestEmail, "【Acme Portal】测试电子邮件", "这是一封来自 Acme Portal 的测试电子邮件。"},
		{emailtemplate.EmailAddressChanged, "您的电子邮件地址已更改", "您的 Acme Portal 账户的电子邮件地址已更改"},
		{emailtemplate.PasswordChanged, "您的密码已更改", "可能有其他人正在使用您的账户"},
		{emailtemplate.PasswordChangedByAdministrator, "管理员更改了您的密码", "管理员更改了您的 Acme Portal 账户的密码。"},
		{emailtemplate.PasswordReset, "您的密码已重置", "可能有其他人能够阅读您的电子邮件并使用您的账户"},
		{emailtemplate.OTPEnabled, "已设置双因素认证", "同时还生成了一组新的恢复代码"},
		{emailtemplate.OTPDisabled, "双因素认证已关闭", "然后登录并重新设置双因素认证"},
		{emailtemplate.OTPDisabledByAdministrator, "管理员关闭了您的双因素认证", "您可以在账户设置中设置新的身份验证器应用。"},
		{emailtemplate.RecoveryCodeUsed, "已使用恢复代码登录", "还剩3个未使用的恢复代码。"},
		{emailtemplate.RecoveryCodesReplaced, "您的恢复代码已更换", "您之前的恢复代码无论是否使用过，都已失效。"},
		{emailtemplate.OTPLockout, "多次输入错误的一次性验证码后，您的身份验证器应用已被停用", "请使用您的一个恢复代码登录"},
		{emailtemplate.AccountDeleted, "您的账户已被删除", "说明有其他人知道您的密码"},
		{emailtemplate.AccountDeletedByAdministrator, "管理员删除了您的账户", "管理员删除了您的 Acme Portal 账户。"},
		{emailtemplate.PasswordResetLink, "重置密码", "您可以点击下面的链接重置密码："},
	})
}

// A recipient on Automatic whose Language and region is zh-TW or zh-HK gets the English email,
// whatever the sender's request read: there is no Traditional catalog (#663 decision 3).
func TestSimplifiedChinese_ARecipientReadingTraditionalChineseGetsEnglish(t *testing.T) {
	for _, locale := range []string{"zh-TW", "zh-HK"} {
		t.Run(locale, func(t *testing.T) {
			ctx := reqctx.WithSettings(context.Background(), &record.Settings{AppName: "Acme Portal"})
			sender := httptest.NewRequest(http.MethodPost, "/forgot-password?ui_locales=zh-Hans", nil).WithContext(ctx)
			ctx = i18n.WithRecipientLanguage(i18n.ResolveRequestLocale(ctx, sender), "", locale)

			message, err := New(web.TemplateFS(), web.StaticFS(), nil).WithBaseURL(emailBaseURL).
				RenderEmail(sender.WithContext(ctx), emailtemplate.PasswordResetLink, definitionValues)
			require.NoError(t, err)

			assert.Equal(t, "Password reset", message.Subject)
			assert.Contains(t, message.HTML, `<html lang="en">`)
			assert.Contains(t, message.HTML, "Hello Ana,")
			assert.NotContains(t, message.HTML, "您好")
		})
	}
}

// A recipient whose page language is Automatic and whose Language and region is zh-CN or zh-SG
// gets the Chinese email, whatever the sender's request read. A recipient named 王 and 小明 is
// greeted "王小明，您好：", family name first with no space, alone in the first paragraph; one with
// no name is greeted by the address the email is sent to. {{expiry}} is joined to the Chinese
// beside it, and the app name alone closes the email (#663 decisions 2, 4 and 5). The activation
// link, which offers no name, opens "您好：".
func TestSimplifiedChinese_ARecipientIsGreetedByNameWithTheExpiryJoined(t *testing.T) {
	recipients := []struct{ name, greeting string }{
		{personname.FullName("小明", "", "王"), "王小明，您好："},
		{emailtemplate.RecipientName("", "wang@example.com"), "wang@example.com，您好："},
	}
	for _, locale := range []string{"zh-CN", "zh-SG"} {
		for _, recipient := range recipients {
			for _, tc := range []struct {
				expiry time.Duration
				unit   string
			}{
				{5 * time.Minute, "5分钟"},
				{30 * time.Minute, "30分钟"},
				{time.Hour, "1小时"},
				{24 * time.Hour, "24小时"},
			} {
				for _, email := range []struct {
					email             *emailtemplate.Email
					subject, greeting string
					sentence          string
				}{
					{emailtemplate.ActivationLink, "激活您的账户", "您好：", "该链接将在" + tc.unit + "后过期。"},
					{emailtemplate.PasswordResetLink, "重置密码", recipient.greeting, "该链接将在" + tc.unit + "后过期。"},
					{emailtemplate.VerificationCode, "电子邮件地址验证码：482915", recipient.greeting, "该验证码将在" + tc.unit + "后过期。"},
					{emailtemplate.NewUserSetup, "【Acme Portal】为您的新账户创建密码", recipient.greeting, "该链接的有效期为" + tc.unit + "。"},
				} {
					t.Run(locale+"/"+recipient.greeting+"/"+email.email.ID+"/"+tc.expiry.String(), func(t *testing.T) {
						ctx := reqctx.WithSettings(context.Background(), &record.Settings{AppName: "Acme Portal"})
						sender := httptest.NewRequest(http.MethodPost, "/forgot-password?ui_locales=de", nil).WithContext(ctx)
						sender.Header.Set("Accept-Language", "it")
						ctx = i18n.WithRecipientLanguage(i18n.ResolveRequestLocale(ctx, sender), "", locale)
						values := definitionValues
						values.Name = recipient.name
						values.Expiry = tc.expiry

						message, err := New(web.TemplateFS(), web.StaticFS(), nil).WithBaseURL(emailBaseURL).
							RenderEmail(sender.WithContext(ctx), email.email, values)
						require.NoError(t, err)

						assert.Equal(t, email.subject, message.Subject)
						doc, err := goquery.NewDocumentFromReader(strings.NewReader(message.HTML))
						require.NoError(t, err)
						lang, _ := doc.Find("html").Attr("lang")
						assert.Equal(t, "zh-Hans", lang)
						paragraphs := doc.Find("main p")
						require.Positive(t, paragraphs.Length())
						assert.Equal(t, email.greeting, strings.TrimSpace(paragraphs.First().Text()), "the greeting is the first paragraph, alone")
						assert.Equal(t, "Acme Portal", strings.TrimSpace(paragraphs.Last().Text()), "the app name alone closes the email")
						body := doc.Find("main").Text()
						assert.Contains(t, body, email.sentence)
						assert.NotContains(t, body, "小明 王")
						assert.NotContains(t, message.HTML, "{{")
					})
				}
			}
		}
	}
}

// Each bold sentence of a Chinese email, which ends before its full-width 。 or with it at the end
// of its paragraph, is drawn bold, with no asterisk left in the email (#663).
func TestSimplifiedChinese_BoldSentencesBesideChinesePunctuationAreDrawnBold(t *testing.T) {
	for _, tc := range []struct {
		email *emailtemplate.Email
		bold  string
	}{
		{emailtemplate.NewUserSetup, "该链接的有效期为5分钟。如果链接已过期，请联系您的管理员，管理员可以为您设置密码，或让您从登录页面申请新的链接。"},
		{emailtemplate.PasswordResetLink, "如果您没有申请重置密码，请忽略此电子邮件。"},
		{emailtemplate.EmailAddressChanged, "如果不是您本人操作，可能有其他人知道您的密码"},
		{emailtemplate.PasswordChanged, "如果不是您本人操作，可能有其他人正在使用您的账户"},
		{emailtemplate.PasswordChangedByAdministrator, "如果您没有预料到此事，请联系您的管理员"},
		{emailtemplate.PasswordReset, "如果不是您本人操作，可能有其他人能够阅读您的电子邮件并使用您的账户"},
		{emailtemplate.OTPEnabled, "如果不是您本人操作，可能有其他人知道您的密码"},
		{emailtemplate.OTPDisabled, "如果不是您本人操作，可能有其他人知道您的密码"},
		{emailtemplate.OTPDisabledByAdministrator, "如果您没有预料到此事，请联系您的管理员"},
		{emailtemplate.RecoveryCodeUsed, "如果不是您本人，可能有其他人知道您的密码并持有您的恢复代码"},
		{emailtemplate.RecoveryCodesReplaced, "如果不是您本人操作，可能有其他人知道您的密码"},
		{emailtemplate.OTPLockout, "这些一次性验证码只有在输入密码之后才能输入，因此可能有其他人知道您的密码"},
		{emailtemplate.AccountDeleted, "如果不是您本人操作，说明有其他人知道您的密码"},
	} {
		t.Run(tc.email.ID, func(t *testing.T) {
			message := renderDefinition(t, tc.email, "zh-CN", nil)
			doc, err := goquery.NewDocumentFromReader(strings.NewReader(message.HTML))
			require.NoError(t, err)
			var drawn []string
			doc.Find("main strong").Each(func(_ int, s *goquery.Selection) { drawn = append(drawn, s.Text()) })
			assert.Equal(t, []string{tc.bold}, drawn)
			assert.NotContains(t, doc.Find("main").Text(), "**")
		})
	}
}
