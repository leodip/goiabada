package i18n

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A request asking for Russian, through ui_locales or the browser's Accept-Language, reads the
// pages and the refusals in Russian (#666).
func TestRussian_RequestPreferencesAndRefusals(t *testing.T) {
	for _, tc := range []struct{ target, accept string }{
		{"/auth/pwd?ui_locales=ru", "en"},
		{"/auth/pwd?ui_locales=ru-RU", "en"},
		{"/auth/pwd", "ru-RU"},
		{"/auth/pwd", "ru-RU,ru;q=0.9,en;q=0.8"},
		{"/auth/pwd", "uk,ru;q=0.9"},
	} {
		t.Run(tc.target+tc.accept, func(t *testing.T) {
			req := httptest.NewRequest("GET", tc.target, nil)
			req.Header.Set("Accept-Language", tc.accept)
			ctx := throughLocaleMiddleware(t, req).Context()
			assert.Equal(t, "ru", CatalogTag(ctx))
			assert.Equal(t, "Вход", T(ctx, "auth.pwd.title"))
			assert.Equal(t, "Войти", T(ctx, "auth.pwd.button"))
			assert.Equal(t, "Ошибка аутентификации.", NewLocalizedError(ErrCodeLoginAuthFailed, nil).Localize(ctx))
			assert.Equal(t, "Адреса электронной почты не совпадают.", T(ctx, "adminconsole.refusal.account_email.confirmation_mismatch"))
			assert.Equal(t, "Минимальное количество символов пароля: 15.", T(ctx, "validator.password.too_short", map[string]any{"min": 15}))
		})
	}
}

// Every regional tag of Russian reads the one Russian catalog, and keeps its own tag for choosing
// an email's text.
func TestRussian_RegionalTagsUseTheBuiltInCatalog(t *testing.T) {
	for _, locale := range []string{"ru", "ru-RU", "ru-BY", "ru-KZ", "ru-KG", "ru-MD", "ru-UA"} {
		t.Run(locale, func(t *testing.T) {
			ctx := WithLocale(context.Background(), true, locale, "en")
			assert.Equal(t, "ru", CatalogTag(ctx))
			assert.Equal(t, locale, LocaleTag(ctx), "email copy selection retains the recipient’s regional tag")
			assert.Equal(t, "Пароль", T(ctx, "auth.pwd.password_label"))
		})
	}
}

// A known user whose page language is ru reads Russian over a request asking for German and
// Italian.
func TestRussian_ThePageLanguageWinsOverTheRequest(t *testing.T) {
	ctx := WithPageLanguage(throughLocale(t, nil, "/forgot-password?ui_locales=de", "it"), "ru")
	assert.Equal(t, "ru", CatalogTag(ctx))
	assert.Equal(t, "Сброс пароля", T(ctx, "forgot_password.title"))
}

// A recipient on Automatic whose Language and region is ru or a regional tag of it gets Russian,
// whatever the sender's request read; a recipient who chose ru gets it over their Language and
// region.
func TestRussian_TheRecipientReadsRussian(t *testing.T) {
	for _, tc := range []struct{ name, pageLanguage, locale string }{
		{"Automatic, ru-RU", "", "ru-RU"},
		{"Automatic, ru-KZ", "", "ru-KZ"},
		{"Automatic, ru", "", "ru"},
		{"ru chosen over French", "ru", "fr"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sender := throughLocale(t, nil, "/forgot-password?ui_locales=de", "it")
			require.Equal(t, "Passwort zurücksetzen", T(sender, "forgot_password.title"))

			ctx := WithRecipientLanguage(sender, tc.pageLanguage, tc.locale)
			assert.Equal(t, "ru", CatalogTag(ctx))
			assert.Equal(t, "Сброс пароля", T(ctx, "forgot_password.title"))
		})
	}
}

// The user details page writes clients, a kept English term, in the plural where several are the
// subject, and the console's menu names the branding page as the page does.
func TestRussian_UserDetailsAndBrandingMenuWording(t *testing.T) {
	ctx := WithLocale(context.Background(), true, "ru", "en")
	assert.Equal(t, "Отключенный пользователь не может войти, а clients не могут обновлять его token.", T(ctx, "adminconsole.admin_users.details.field.enabled_hint"))
	assert.Equal(t, "Вы отключаете пользователя, поэтому он не сможет войти, а clients не смогут обновлять его token.", T(ctx, "adminconsole.admin_users.details.disable_warning"))
	assert.Equal(t, "Брендинг", T(ctx, "adminconsole.admin_menu.settings_branding"))
	assert.Equal(t, "Брендинг", T(ctx, "adminconsole.admin_branding.list.title"))
}
