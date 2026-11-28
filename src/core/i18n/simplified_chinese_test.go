package i18n

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A request asking for Simplified Chinese, through ui_locales or the browser's Accept-Language,
// reads the pages and the refusals in Simplified Chinese, a number joined to the Chinese beside it.
// So does what Chrome set to Chinese (Taiwan) sends, which lists a bare zh after zh-TW and so asks
// for any Chinese before English (#663 decisions 3 and 4).
func TestSimplifiedChinese_RequestPreferencesAndRefusals(t *testing.T) {
	for _, tc := range []struct{ target, accept string }{
		{"/auth/pwd?ui_locales=zh-Hans", "en"},
		{"/auth/pwd?ui_locales=zh", "en"},
		{"/auth/pwd?ui_locales=zh-CN", "en"},
		{"/auth/pwd", "zh-CN"},
		{"/auth/pwd", "zh-CN,zh;q=0.9,en;q=0.8"},
		{"/auth/pwd", "zh-SG"},
		{"/auth/pwd", "zh-Hans-HK"},
		{"/auth/pwd", "zh-TW,zh;q=0.9"},
	} {
		t.Run(tc.target+tc.accept, func(t *testing.T) {
			req := httptest.NewRequest("GET", tc.target, nil)
			req.Header.Set("Accept-Language", tc.accept)
			ctx := throughLocaleMiddleware(t, req).Context()
			assert.Equal(t, "zh-Hans", CatalogTag(ctx))
			assert.Equal(t, "登录", T(ctx, "auth.pwd.title"))
			assert.Equal(t, "登录", T(ctx, "auth.pwd.button"))
			assert.Equal(t, "忘记密码？", T(ctx, "auth.pwd.forgot_password"))
			assert.Equal(t, "认证失败。", NewLocalizedError(ErrCodeLoginAuthFailed, nil).Localize(ctx))
			assert.Equal(t, "两次输入的电子邮件地址不一致。", T(ctx, "adminconsole.refusal.account_email.confirmation_mismatch"))
			assert.Equal(t, "密码至少需要15个字符。", T(ctx, "validator.password.too_short", map[string]any{"min": 15}))
		})
	}
}

// A request naming only Traditional Chinese reads English: there is no Traditional catalog, and
// Simplified Chinese is not a stand-in for it. zh-MY alone counts as Traditional in the matcher's
// data, so it reads English too (#663 decision 3).
func TestSimplifiedChinese_TraditionalChineseAloneReadsEnglish(t *testing.T) {
	for _, accept := range []string{"zh-TW", "zh-HK", "zh-Hant", "zh-MY"} {
		t.Run(accept, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/auth/pwd", nil)
			req.Header.Set("Accept-Language", accept)
			ctx := throughLocaleMiddleware(t, req).Context()
			assert.Equal(t, "en", CatalogTag(ctx))
			assert.Equal(t, "Sign in", T(ctx, "auth.pwd.title"))
		})
	}
}

// Every Simplified tag reads the one Simplified Chinese catalog, and keeps its own tag for choosing
// an email's text.
func TestSimplifiedChinese_RegionalTagsUseTheBuiltInCatalog(t *testing.T) {
	for _, locale := range []string{"zh", "zh-CN", "zh-SG", "zh-Hans", "zh-Hans-HK"} {
		t.Run(locale, func(t *testing.T) {
			ctx := WithLocale(context.Background(), true, locale, "en")
			assert.Equal(t, "zh-Hans", CatalogTag(ctx))
			assert.Equal(t, locale, LocaleTag(ctx), "email copy selection retains the recipient’s regional tag")
			assert.Equal(t, "密码", T(ctx, "auth.pwd.password_label"))
		})
	}
}

// A known user whose page language is zh-Hans reads Simplified Chinese over a request asking for
// German and Italian.
func TestSimplifiedChinese_ThePageLanguageWinsOverTheRequest(t *testing.T) {
	ctx := WithPageLanguage(throughLocale(t, nil, "/forgot-password?ui_locales=de", "it"), "zh-Hans")
	assert.Equal(t, "zh-Hans", CatalogTag(ctx))
	assert.Equal(t, "重置密码", T(ctx, "forgot_password.title"))
}

// A recipient on Automatic whose Language and region is zh-CN or zh-SG gets Simplified Chinese,
// whatever the sender's request read, and one who chose zh-Hans gets it over their Language and
// region. One whose Language and region is zh-TW or zh-HK gets English (#663 decision 3).
func TestSimplifiedChinese_TheRecipientReadsSimplifiedChinese(t *testing.T) {
	for _, tc := range []struct{ name, pageLanguage, locale, catalog, title string }{
		{"Automatic, zh-CN", "", "zh-CN", "zh-Hans", "重置密码"},
		{"Automatic, zh-SG", "", "zh-SG", "zh-Hans", "重置密码"},
		{"zh-Hans chosen over French", "zh-Hans", "fr", "zh-Hans", "重置密码"},
		{"Automatic, zh-TW", "", "zh-TW", "en", "Reset your password"},
		{"Automatic, zh-HK", "", "zh-HK", "en", "Reset your password"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sender := throughLocale(t, nil, "/forgot-password?ui_locales=de", "it")
			require.Equal(t, "Passwort zurücksetzen", T(sender, "forgot_password.title"))

			ctx := WithRecipientLanguage(sender, tc.pageLanguage, tc.locale)
			assert.Equal(t, tc.catalog, CatalogTag(ctx))
			assert.Equal(t, tc.title, T(ctx, "forgot_password.title"))
		})
	}
}

// The user details page keeps client and token in Latin script, with a half-width space between
// each and the Chinese beside it and none before the full-width punctuation that follows, and the
// console's menu names the branding page as the page does (#663 decisions 1 and 4).
func TestSimplifiedChinese_UserDetailsAndBrandingMenuWording(t *testing.T) {
	ctx := WithLocale(context.Background(), true, "zh-CN", "en")
	assert.Equal(t, "已停用的用户无法登录，client 也无法续期其 token。", T(ctx, "adminconsole.admin_users.details.field.enabled_hint"))
	assert.Equal(t, "您正在停用此用户，因此该用户将无法登录，client 也将无法续期其 token。", T(ctx, "adminconsole.admin_users.details.disable_warning"))
	assert.Equal(t, "品牌", T(ctx, "adminconsole.admin_menu.settings_branding"))
	assert.Equal(t, "品牌", T(ctx, "adminconsole.admin_branding.list.title"))
}

// Every list and page that shows a user's subject identifier names it Subject, in Latin script, so
// the group members' and a permission's users' lists read as the users list does, and the users
// search names the subject in the same spelling. A client's web origins lead names its endpoint
// paths with a space on each side, where Chinese meets them.
func TestSimplifiedChinese_SubjectAndEndpointPaths(t *testing.T) {
	ctx := WithLocale(context.Background(), true, "zh-Hans", "en")
	for _, key := range []string{
		"adminconsole.admin_users.list.col_subject",
		"adminconsole.admin_users.delete.field.subject",
		"adminconsole.admin_users.details.field.subject",
		"adminconsole.admin_groups.members.col_subject",
		"adminconsole.admin_groups.members_add.col_subject",
		"adminconsole.admin_resources.users_with_permission.col_subject",
		"adminconsole.admin_resources.users_with_permission_add.col_subject",
	} {
		assert.Equal(t, "Subject", T(ctx, key), key)
	}
	assert.Equal(t, "姓名、电子邮件地址、用户名或 subject", T(ctx, "adminconsole.admin_users.list.search_placeholder"))
	assert.Equal(t,
		"如果此 client 在浏览器中运行，并调用 /auth/token、/auth/revoke、/auth/logout 或 /userinfo，请在此注册其源：协议、主机和可选的端口，其后不带任何内容，例如 https://www.example.com 或 https://myapp:8080。",
		T(ctx, "adminconsole.admin_clients.web_origins.lead"))
}
