package renderintegration

import (
	"context"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/leodip/goiabada/adminconsole/internal/handlers/adminresourcehandlers"
	"github.com/leodip/goiabada/adminconsole/internal/handlers/adminsettingshandlers"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/web"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/palette"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// russianCounts are the counts a Russian counted phrase is read at: one for 1 and 21, few for 2 and
// 22, many for 5, 11 and 25, where Russian leaves Polish at 21 and agrees with it at 11.
var russianCounts = []int{1, 2, 5, 11, 21, 22, 25}

// A console page asked for in Russian, through ui_locales or the browser, is drawn in Russian (#666).
func TestRussian_AdminPageUsesQueryOrRussianHeader(t *testing.T) {
	for _, tc := range []struct{ target, accept string }{
		{"/admin/clients?ui_locales=ru", "en"},
		{"/admin/clients", "ru-RU"},
	} {
		t.Run(tc.target+tc.accept, func(t *testing.T) {
			req := handlertest.Request(http.MethodGet, tc.target,
				handlertest.WithSettings(&api.PublicSettingsResponse{AppName: "Test"}))
			req.Header.Set("Accept-Language", tc.accept)
			req = req.WithContext(i18n.ResolveRequestLocale(req.Context(), req))
			w := httptest.NewRecorder()
			err := render.New(web.TemplateFS(), web.StaticFS()).RenderTemplate(w, req,
				"layouts/menu_layout.html", "admin_clients.html", map[string]interface{}{})
			require.NoError(t, err)
			assert.Contains(t, w.Body.String(), `<html lang="ru"`)
			assert.Contains(t, w.Body.String(), `data-catalog-lang="ru"`)
			assert.Contains(t, w.Body.String(), "Новый client")
			assert.Contains(t, w.Body.String(), "Пока нет ни одного client.")
		})
	}
}

func TestRussian_ConsoleRefusalIsRenderedOnItsForm(t *testing.T) {
	req := handlertest.Request(http.MethodPost, "/admin/resources/7/delete",
		handlertest.WithAccessToken(), handlertest.WithPathValue("resourceId", "7"),
		handlertest.WithSettings(&api.PublicSettingsResponse{AppName: "Test"}),
		handlertest.WithLocale("ru-RU"),
		handlertest.WithForm(url.Values{"resourceIdentifier": {"shipping"}}))
	w := httptest.NewRecorder()
	adminresourcehandlers.HandleDeletePost(render.New(web.TemplateFS(), web.StaticFS()), resourceToDelete{}, "https://console.example.test").ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `lang="ru"`)
	assert.Contains(t, html.UnescapeString(w.Body.String()), "Это не идентификатор этого ресурса. Введите его так, как он показан выше.")
	assert.Contains(t, w.Body.String(), `aria-invalid="true"`)
}

// The account's sessions page in Russian: each instant day.month.year on a 24-hour clock, and how
// long ago it was in the form its count takes, one, few or many, at 1, 2, 5, 11, 21, 22 and 25.
func TestRussian_TheSessionsPageDrawsDatesAndRelativeTimes(t *testing.T) {
	// Each offset sits half a unit clear of its boundary, so no phrase changes while the case runs.
	now := time.Now().UTC()
	var sessions []render.SessionInfo
	var cells []string
	for i, tc := range []struct {
		count         int
		started, last string
	}{
		{1, "1 день назад", "1 минуту назад"},
		{2, "2 дня назад", "2 минуты назад"},
		{5, "5 дней назад", "5 минут назад"},
		{11, "11 дней назад", "11 минут назад"},
		{21, "21 день назад", "21 минуту назад"},
		{22, "22 дня назад", "22 минуты назад"},
		{25, "25 дней назад", "25 минут назад"},
	} {
		started := now.Add(-time.Duration(tc.count)*24*time.Hour - 12*time.Hour)
		last := now.Add(-time.Duration(tc.count)*time.Minute - 30*time.Second)
		sessions = append(sessions, render.SessionInfo{UserSessionID: int64(i + 1), Started: &started, LastAccessed: &last})
		cells = append(cells,
			`">`+started.Format("02.01.2006 15:04")+`<span class="cell-secondary">`+tc.started+`</span></td>`,
			`">`+last.Format("02.01.2006 15:04")+`<span class="cell-secondary">`+tc.last+`</span></td>`)
	}

	out := renderMenuPageIn(t, "/account_user_sessions.html", map[string]interface{}{"sessions": sessions}, "ru", true)

	for _, cell := range cells {
		assert.Contains(t, out, cell)
	}
}

// The account's two-factor page in Russian says how many recovery codes are unused, its verb
// agreeing with the count, and that none are in a sentence of its own.
func TestRussian_TheRecoveryCodesSectionCountsTheUnusedCodes(t *testing.T) {
	for _, tc := range []struct {
		remaining int
		want      string
	}{
		{1, "Не использован 1 из 10 ваших кодов восстановления."},
		{2, "Не использованы 2 из 10 ваших кодов восстановления."},
		{4, "Не использованы 4 из 10 ваших кодов восстановления."},
		{5, "Не использовано 5 из 10 ваших кодов восстановления."},
		{10, "Не использовано 10 из 10 ваших кодов восстановления."},
		{0, "У вас не осталось неиспользованных кодов восстановления."},
	} {
		t.Run(strconv.Itoa(tc.remaining), func(t *testing.T) {
			out := renderMenuPageIn(t, "/account_otp.html", map[string]interface{}{
				"otpEnabled":             true,
				"recoveryCodesRemaining": tc.remaining,
			}, "ru", true)
			assert.Contains(t, out, tc.want)
		})
	}
}

// russianBrands is the auth server's brands as the brand list and a brand's deletion read them: a
// brand per count, failing that many contrast pairs and drawn for that many clients, and the
// default brand.
type russianBrands struct{}

func (russianBrands) GetAllBrands(context.Context, string) ([]api.BrandResponse, error) {
	brands := []api.BrandResponse{{ID: 100, Name: "Основной", Appearance: "auto", Theme: "blueberry", IsDefault: true}}
	for _, count := range russianCounts {
		brand, _ := russianBrands{}.GetBrandByID(context.Background(), "", int64(count))
		brands = append(brands, *brand)
	}
	return brands, nil
}

func (russianBrands) GetBrandByID(_ context.Context, _ string, brandID int64) (*api.BrandResponse, error) {
	warnings := make([]api.BrandContrastWarning, brandID)
	for i := range warnings {
		warnings[i] = api.BrandContrastWarning{Mode: "light", Foreground: "text", Background: "surface", Ratio: 3, Minimum: 4.5}
	}
	return &api.BrandResponse{ID: brandID, Name: "Бренд " + strconv.FormatInt(brandID, 10), Appearance: "light",
		Theme: "plum", ClientCount: int(brandID), ContrastWarnings: warnings}, nil
}

func (russianBrands) DeleteBrand(context.Context, string, int64) error { return nil }

// The brand list in Russian marks each brand with how many of its pairs are below the contrast
// minimum, in the form the count takes.
func TestRussian_TheBrandListCountsTheFailingPairs(t *testing.T) {
	req := handlertest.Request(http.MethodGet, "/admin/settings/branding", handlertest.WithAccessToken(),
		handlertest.WithSettings(&api.PublicSettingsResponse{AppName: "Test"}), handlertest.WithLocale("ru-RU"))
	w := httptest.NewRecorder()
	adminsettingshandlers.HandleBrandingGet(render.New(web.TemplateFS(), web.StaticFS()), russianBrands{}).ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	out := w.Body.String()
	assert.Contains(t, out, `lang="ru"`)
	for _, want := range []string{
		"1 пара ниже минимального контраста",
		"2 пары ниже минимального контраста",
		"5 пар ниже минимального контраста",
		"11 пар ниже минимального контраста",
		"21 пара ниже минимального контраста",
		"22 пары ниже минимального контраста",
		"25 пар ниже минимального контраста",
	} {
		assert.Contains(t, out, `<span class="tag tag-caution ml-1">`+want+`</span>`)
	}
}

// A brand's deletion in Russian says how many clients use it, with client undeclined after a
// Russian noun, and that the default brand takes its place, in a sentence that needs no agreement
// with the count, so it reads right at 1 as at 21.
func TestRussian_ABrandsDeletionCountsItsClients(t *testing.T) {
	for _, count := range russianCounts {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			id := strconv.Itoa(count)
			req := handlertest.Request(http.MethodGet, "/admin/settings/branding/"+id+"/delete", handlertest.WithAccessToken(),
				handlertest.WithPathValue("brandId", id),
				handlertest.WithSettings(&api.PublicSettingsResponse{AppName: "Test"}), handlertest.WithLocale("ru-RU"))
			w := httptest.NewRecorder()
			adminsettingshandlers.HandleBrandDeleteGet(render.New(web.TemplateFS(), web.StaticFS()), russianBrands{}).ServeHTTP(w, req)
			require.Equal(t, http.StatusOK, w.Code)

			assert.Contains(t, html.UnescapeString(w.Body.String()), `<p class="page-lead">Бренд будет удален. Количество client с этим брендом: `+
				id+`. Вместо него будет использоваться бренд по умолчанию, Основной.</p>`)
		})
	}
}

// russianCustomBrand is the auth server holding brand count on a stored custom palette, failing
// count contrast pairs and drawn for count clients, as a brand's editor reads it.
type russianCustomBrand struct{}

func (russianCustomBrand) GetBrandThemes(context.Context, string) ([]api.BrandThemeResponse, error) {
	return nil, nil
}

func (russianCustomBrand) GetBrandByID(_ context.Context, _ string, brandID int64) (*api.BrandResponse, error) {
	light, dark := map[string]string{}, map[string]string{}
	for _, token := range palette.Tokens() {
		light[token], dark[token] = "#f4f4f5", "#18181b"
	}
	warnings := make([]api.BrandContrastWarning, brandID)
	for i := range warnings {
		warnings[i] = api.BrandContrastWarning{Mode: "light", Foreground: "ink-muted", Background: "surface", Ratio: 3, Minimum: 4.5}
	}
	return &api.BrandResponse{ID: brandID, Name: "Бренд " + strconv.FormatInt(brandID, 10), Appearance: "light", Theme: "custom",
		Palette: &api.BrandPaletteResponse{Mode: "advanced", Light: light, Dark: dark},
		Colors:  &api.BrandColors{Light: light, Dark: dark}, ClientCount: int(brandID), ContrastWarnings: warnings}, nil
}

// A custom brand's editor in Russian, drawn again after a save, says how many clients use the
// brand, how many of its pairs are below their minimum, and in the saved notice how many pairs
// fail, each in the form the count takes.
func TestRussian_ABrandsEditorCountsItsClientsAndFailingPairs(t *testing.T) {
	const wcag = " Текст и границы этих цветов не соответствуют контрасту WCAG 2.2 уровня AA."
	for _, tc := range []struct {
		count         int
		pairs, notice string
	}{
		{1, "1 пара ниже своего минимума.", "1 пара его цветов ниже минимального контраста."},
		{2, "2 пары ниже своего минимума.", "2 пары его цветов ниже минимального контраста."},
		{5, "5 пар ниже своего минимума.", "5 пар его цветов ниже минимального контраста."},
		{11, "11 пар ниже своего минимума.", "11 пар его цветов ниже минимального контраста."},
		{21, "21 пара ниже своего минимума.", "21 пара его цветов ниже минимального контраста."},
		{22, "22 пары ниже своего минимума.", "22 пары его цветов ниже минимального контраста."},
		{25, "25 пар ниже своего минимума.", "25 пар его цветов ниже минимального контраста."},
	} {
		t.Run(strconv.Itoa(tc.count), func(t *testing.T) {
			id := strconv.Itoa(tc.count)
			path := "/admin/settings/branding/" + id + "/edit"
			store := newRenderSessionStore(t)
			// The save's redirect leaves the saved flash for the brand's page, as HandleBrandPost does.
			saving := handlertest.Request(http.MethodPost, path)
			sess, err := store.Get(saving, builtin.AdminConsoleSessionName)
			require.NoError(t, err)
			sess.SetFlash(path, "savedSuccessfully", "true")
			saved := httptest.NewRecorder()
			require.NoError(t, store.Save(saving, saved, sess))

			req := handlertest.Request(http.MethodGet, path, handlertest.WithAccessToken(), handlertest.WithPathValue("brandId", id),
				handlertest.WithSettings(&api.PublicSettingsResponse{AppName: "Test"}), handlertest.WithLocale("ru-RU"))
			for _, cookie := range saved.Result().Cookies() {
				req.AddCookie(cookie)
			}
			w := httptest.NewRecorder()
			adminsettingshandlers.HandleBrandGet(render.New(web.TemplateFS(), web.StaticFS()), store, russianCustomBrand{}).ServeHTTP(w, req)
			require.Equal(t, http.StatusOK, w.Code)

			out := html.UnescapeString(w.Body.String())
			assert.Contains(t, out, `<p class="page-lead">Выберите его на вкладке «Настройки» client, чтобы отображать в нем страницы этого client. `+
				`Количество client с этим брендом: `+id+`.</p>`)
			assert.Contains(t, out, `id="paletteWarningsCount" role="status">`+tc.pairs+wcag+`</p>`)
			assert.Contains(t, out, `<p>Бренд сохранен. `+tc.notice+` <a class="text-link" href="#palette-warnings">Показать пары</a></p>`)
		})
	}
}
