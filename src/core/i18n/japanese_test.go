package i18n

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A request asking for Japanese, through ui_locales or the browser's Accept-Language, reads the
// pages and the refusals in Japanese, and so does one listing Japanese after Chinese or Korean
// (#662).
func TestJapanese_RequestPreferencesAndRefusals(t *testing.T) {
	for _, tc := range []struct{ target, accept string }{
		{"/auth/pwd?ui_locales=ja", "en"},
		{"/auth/pwd?ui_locales=ja-JP", "en"},
		{"/auth/pwd?ui_locales=zh%20ja", "en"},
		{"/auth/pwd", "ja-JP"},
		{"/auth/pwd", "ja-JP,ja;q=0.9,en;q=0.8"},
		{"/auth/pwd", "zh-CN,ja;q=0.9"},
		{"/auth/pwd", "ko-KR,ja;q=0.9"},
	} {
		t.Run(tc.target+tc.accept, func(t *testing.T) {
			req := httptest.NewRequest("GET", tc.target, nil)
			req.Header.Set("Accept-Language", tc.accept)
			ctx := throughLocaleMiddleware(t, req).Context()
			assert.Equal(t, "ja", CatalogTag(ctx))
			assert.Equal(t, "ログイン", T(ctx, "auth.pwd.title"))
			assert.Equal(t, "ログイン", T(ctx, "auth.pwd.button"))
			assert.Equal(t, "パスワードをお忘れですか？", T(ctx, "auth.pwd.forgot_password"))
			assert.Equal(t, "認証に失敗しました。", NewLocalizedError(ErrCodeLoginAuthFailed, nil).Localize(ctx))
			assert.Equal(t, "メールアドレスが一致しません。", T(ctx, "adminconsole.refusal.account_email.confirmation_mismatch"))
			assert.Equal(t, "パスワードは 15 文字以上にしてください。", T(ctx, "validator.password.too_short", map[string]any{"min": 15}))
		})
	}
}

// A request asking for Chinese or Korean alone reads English: Japanese is not a stand-in for them.
func TestJapanese_ChineseOrKoreanAloneReadEnglish(t *testing.T) {
	for _, accept := range []string{"zh", "zh-CN", "zh-TW", "ko", "ko-KR"} {
		t.Run(accept, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/auth/pwd", nil)
			req.Header.Set("Accept-Language", accept)
			ctx := throughLocaleMiddleware(t, req).Context()
			assert.Equal(t, "en", CatalogTag(ctx))
			assert.Equal(t, "Sign in", T(ctx, "auth.pwd.title"))
		})
	}
}

// Every regional tag of Japanese reads the one Japanese catalog, and keeps its own tag for choosing
// an email's text.
func TestJapanese_RegionalTagsUseTheBuiltInCatalog(t *testing.T) {
	for _, locale := range []string{"ja", "ja-JP", "ja-US"} {
		t.Run(locale, func(t *testing.T) {
			ctx := WithLocale(context.Background(), true, locale, "en")
			assert.Equal(t, "ja", CatalogTag(ctx))
			assert.Equal(t, locale, LocaleTag(ctx), "email copy selection retains the recipient’s regional tag")
			assert.Equal(t, "パスワード", T(ctx, "auth.pwd.password_label"))
		})
	}
}

// A known user whose page language is ja reads Japanese over a request asking for German and
// Italian.
func TestJapanese_ThePageLanguageWinsOverTheRequest(t *testing.T) {
	ctx := WithPageLanguage(throughLocale(t, nil, "/forgot-password?ui_locales=de", "it"), "ja")
	assert.Equal(t, "ja", CatalogTag(ctx))
	assert.Equal(t, "パスワードのリセット", T(ctx, "forgot_password.title"))
}

// A recipient on Automatic whose Language and region is ja or ja-JP gets Japanese, whatever the
// sender's request read; a recipient who chose ja gets it over their Language and region.
func TestJapanese_TheRecipientReadsJapanese(t *testing.T) {
	for _, tc := range []struct{ name, pageLanguage, locale string }{
		{"Automatic, ja-JP", "", "ja-JP"},
		{"Automatic, ja", "", "ja"},
		{"ja chosen over French", "ja", "fr"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sender := throughLocale(t, nil, "/forgot-password?ui_locales=de", "it")
			require.Equal(t, "Passwort zurücksetzen", T(sender, "forgot_password.title"))

			ctx := WithRecipientLanguage(sender, tc.pageLanguage, tc.locale)
			assert.Equal(t, "ja", CatalogTag(ctx))
			assert.Equal(t, "パスワードのリセット", T(ctx, "forgot_password.title"))
		})
	}
}

// The user details page keeps client and token in Latin script, with a half-width space between
// each and the Japanese beside it, and the console's menu names the branding page as the page does.
func TestJapanese_UserDetailsAndBrandingMenuWording(t *testing.T) {
	ctx := WithLocale(context.Background(), true, "ja", "en")
	assert.Equal(t, "無効なユーザーはログインできず、client もそのユーザーの token を更新できません。", T(ctx, "adminconsole.admin_users.details.field.enabled_hint"))
	assert.Equal(t, "ユーザーを無効にしようとしています。このユーザーはログインできなくなり、client もそのユーザーの token を更新できなくなります。", T(ctx, "adminconsole.admin_users.details.disable_warning"))
	assert.Equal(t, "ブランディング", T(ctx, "adminconsole.admin_menu.settings_branding"))
	assert.Equal(t, "ブランディング", T(ctx, "adminconsole.admin_branding.list.title"))
}

// Every list and page that shows a user's subject identifier names it Subject, in Latin script as
// the Russian catalog keeps it (#662 decision 4), so the group members' and a permission's users'
// lists read as the users list does, and the users search names the subject in the same spelling.
// The page that shows the most kept terms, a client's web origins, writes each endpoint path in
// 「」, so a narrow page can break the line between them: a run of paths joined by 、 alone has no
// break opportunity, and at 320 px it pushed the page sideways.
func TestJapanese_SubjectAndEndpointPaths(t *testing.T) {
	ctx := WithLocale(context.Background(), true, "ja", "en")
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
	assert.Equal(t, "名前、メールアドレス、ユーザー名、subject", T(ctx, "adminconsole.admin_users.list.search_placeholder"))
	assert.Equal(t,
		"この client がブラウザーで動作し、「/auth/token」「/auth/revoke」「/auth/logout」「/userinfo」を呼び出す場合は、ここにそのオリジンを登録してください。スキーム、ホスト、任意のポートで構成し、その後ろには何も付けません（例：https://www.example.com、https://myapp:8080）。",
		T(ctx, "adminconsole.admin_clients.web_origins.lead"))
}
