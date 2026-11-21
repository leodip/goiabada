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

// A console page asked for in Polish, through ui_locales or the browser, is drawn in Polish (#665).
func TestPolish_AdminPageUsesQueryOrPolishHeader(t *testing.T) {
	for _, tc := range []struct{ target, accept string }{
		{"/admin/clients?ui_locales=pl", "en"},
		{"/admin/clients", "pl-PL"},
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
			assert.Contains(t, w.Body.String(), `<html lang="pl"`)
			assert.Contains(t, w.Body.String(), `data-catalog-lang="pl"`)
			assert.Contains(t, w.Body.String(), "Nowy client")
			assert.Contains(t, w.Body.String(), "Nie ma jeszcze clientów.")
		})
	}
}

func TestPolish_ConsoleRefusalIsRenderedOnItsForm(t *testing.T) {
	req := handlertest.Request(http.MethodPost, "/admin/resources/7/delete",
		handlertest.WithAccessToken(), handlertest.WithPathValue("resourceId", "7"),
		handlertest.WithSettings(&api.PublicSettingsResponse{AppName: "Test"}),
		handlertest.WithLocale("pl-PL"),
		handlertest.WithForm(url.Values{"resourceIdentifier": {"shipping"}}))
	w := httptest.NewRecorder()
	adminresourcehandlers.HandleDeletePost(render.New(web.TemplateFS(), web.StaticFS()), resourceToDelete{}, "https://console.example.test").ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `lang="pl"`)
	assert.Contains(t, html.UnescapeString(w.Body.String()), "To nie jest identyfikator tego zasobu. Wpisz go tak, jak pokazano powyżej.")
	assert.Contains(t, w.Body.String(), `aria-invalid="true"`)
}

// The account's sessions page in Polish: each instant day.month.year on a 24-hour clock, and how
// long ago it was in the form its count takes, one, few or many, at 1, 2, 5 and 22.
func TestPolish_TheSessionsPageDrawsDatesAndRelativeTimes(t *testing.T) {
	// Each offset sits half a unit clear of its boundary, so no phrase changes while the case runs.
	now := time.Now().UTC()
	var sessions []render.SessionInfo
	var cells []string
	for i, tc := range []struct {
		count         int
		started, last string
	}{
		{1, "1 godzinę temu", "1 minutę temu"},
		{2, "2 godziny temu", "2 minuty temu"},
		{5, "5 godzin temu", "5 minut temu"},
		{22, "22 godziny temu", "22 minuty temu"},
	} {
		started := now.Add(-time.Duration(tc.count)*time.Hour - 30*time.Minute)
		last := now.Add(-time.Duration(tc.count)*time.Minute - 30*time.Second)
		sessions = append(sessions, render.SessionInfo{UserSessionID: int64(i + 1), Started: &started, LastAccessed: &last})
		cells = append(cells,
			`">`+started.Format("02.01.2006 15:04")+`<span class="cell-secondary">`+tc.started+`</span></td>`,
			`">`+last.Format("02.01.2006 15:04")+`<span class="cell-secondary">`+tc.last+`</span></td>`)
	}

	out := renderMenuPageIn(t, "/account_user_sessions.html", map[string]interface{}{"sessions": sessions}, "pl", true)

	for _, cell := range cells {
		assert.Contains(t, out, cell)
	}
}

// The account's two-factor page in Polish says how many recovery codes are unused in the form the
// count takes, and that none are in a sentence of its own.
func TestPolish_TheRecoveryCodesSectionCountsTheUnusedCodes(t *testing.T) {
	for _, tc := range []struct {
		remaining int
		want      string
	}{
		{1, "1 z 10 twoich kodów odzyskiwania pozostaje nieużyty."},
		{2, "2 z 10 twoich kodów odzyskiwania pozostają nieużyte."},
		{4, "4 z 10 twoich kodów odzyskiwania pozostają nieużyte."},
		{5, "5 z 10 twoich kodów odzyskiwania pozostaje nieużytych."},
		{10, "10 z 10 twoich kodów odzyskiwania pozostaje nieużytych."},
		{0, "Nie masz żadnych nieużytych kodów odzyskiwania."},
	} {
		t.Run(strconv.Itoa(tc.remaining), func(t *testing.T) {
			out := renderMenuPageIn(t, "/account_otp.html", map[string]interface{}{
				"otpEnabled":             true,
				"recoveryCodesRemaining": tc.remaining,
			}, "pl", true)
			assert.Contains(t, out, tc.want)
		})
	}
}

// polishBrands is the auth server's brands as the brand list and a brand's deletion read them: a
// brand per count, failing that many contrast pairs and drawn for that many clients, and the
// default brand.
type polishBrands struct{}

var polishBrandCounts = []int{1, 2, 5, 22}

func (polishBrands) GetAllBrands(context.Context, string) ([]api.BrandResponse, error) {
	brands := []api.BrandResponse{{ID: 100, Name: "Domyślna", Appearance: "auto", Theme: "blueberry", IsDefault: true}}
	for _, count := range polishBrandCounts {
		brand, _ := polishBrands{}.GetBrandByID(context.Background(), "", int64(count))
		brands = append(brands, *brand)
	}
	return brands, nil
}

func (polishBrands) GetBrandByID(_ context.Context, _ string, brandID int64) (*api.BrandResponse, error) {
	warnings := make([]api.BrandContrastWarning, brandID)
	for i := range warnings {
		warnings[i] = api.BrandContrastWarning{Mode: "light", Foreground: "text", Background: "surface", Ratio: 3, Minimum: 4.5}
	}
	return &api.BrandResponse{ID: brandID, Name: "Marka " + strconv.FormatInt(brandID, 10), Appearance: "light",
		Theme: "plum", ClientCount: int(brandID), ContrastWarnings: warnings}, nil
}

func (polishBrands) DeleteBrand(context.Context, string, int64) error { return nil }

// The brand list in Polish marks each brand with how many of its pairs are below the contrast
// minimum, in the form the count takes.
func TestPolish_TheBrandListCountsTheFailingPairs(t *testing.T) {
	req := handlertest.Request(http.MethodGet, "/admin/settings/branding", handlertest.WithAccessToken(),
		handlertest.WithSettings(&api.PublicSettingsResponse{AppName: "Test"}), handlertest.WithLocale("pl-PL"))
	w := httptest.NewRecorder()
	adminsettingshandlers.HandleBrandingGet(render.New(web.TemplateFS(), web.StaticFS()), polishBrands{}).ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	out := w.Body.String()
	assert.Contains(t, out, `lang="pl"`)
	for _, want := range []string{
		"1 para poniżej minimalnego kontrastu",
		"2 pary poniżej minimalnego kontrastu",
		"5 par poniżej minimalnego kontrastu",
		"22 pary poniżej minimalnego kontrastu",
	} {
		assert.Contains(t, out, `<span class="tag tag-caution ml-1">`+want+`</span>`)
	}
}

// A brand's deletion in Polish says how many clients use it, in the form the count takes, and that
// they will move to the default brand.
func TestPolish_ABrandsDeletionCountsItsClients(t *testing.T) {
	for _, tc := range []struct {
		count int
		want  string
	}{
		{1, "Używa jej 1 client. Zostanie przeniesiony do marki domyślnej, Domyślna."},
		{2, "Używają jej 2 clienty. Zostaną przeniesione do marki domyślnej, Domyślna."},
		{5, "Używa jej 5 clientów. Zostaną przeniesione do marki domyślnej, Domyślna."},
		{22, "Używają jej 22 clienty. Zostaną przeniesione do marki domyślnej, Domyślna."},
	} {
		t.Run(strconv.Itoa(tc.count), func(t *testing.T) {
			id := strconv.Itoa(tc.count)
			req := handlertest.Request(http.MethodGet, "/admin/settings/branding/"+id+"/delete", handlertest.WithAccessToken(),
				handlertest.WithPathValue("brandId", id),
				handlertest.WithSettings(&api.PublicSettingsResponse{AppName: "Test"}), handlertest.WithLocale("pl-PL"))
			w := httptest.NewRecorder()
			adminsettingshandlers.HandleBrandDeleteGet(render.New(web.TemplateFS(), web.StaticFS()), polishBrands{}).ServeHTTP(w, req)
			require.Equal(t, http.StatusOK, w.Code)

			assert.Contains(t, html.UnescapeString(w.Body.String()), `<p class="page-lead">Marka zostanie usunięta. `+tc.want+`</p>`)
		})
	}
}

// polishCustomBrand is the auth server holding brand count on a stored custom palette, failing count
// contrast pairs and drawn for count clients, as a brand's editor reads it.
type polishCustomBrand struct{}

func (polishCustomBrand) GetBrandThemes(context.Context, string) ([]api.BrandThemeResponse, error) {
	return nil, nil
}

func (polishCustomBrand) GetBrandByID(_ context.Context, _ string, brandID int64) (*api.BrandResponse, error) {
	light, dark := map[string]string{}, map[string]string{}
	for _, token := range palette.Tokens() {
		light[token], dark[token] = "#f4f4f5", "#18181b"
	}
	warnings := make([]api.BrandContrastWarning, brandID)
	for i := range warnings {
		warnings[i] = api.BrandContrastWarning{Mode: "light", Foreground: "ink-muted", Background: "surface", Ratio: 3, Minimum: 4.5}
	}
	return &api.BrandResponse{ID: brandID, Name: "Marka " + strconv.FormatInt(brandID, 10), Appearance: "light", Theme: "custom",
		Palette: &api.BrandPaletteResponse{Mode: "advanced", Light: light, Dark: dark},
		Colors:  &api.BrandColors{Light: light, Dark: dark}, ClientCount: int(brandID), ContrastWarnings: warnings}, nil
}

// A custom brand's editor in Polish, drawn again after a save, says how many clients use the brand,
// how many of its pairs are below their minimum, and in the saved notice how many pairs fail, each
// in the form the count takes.
func TestPolish_ABrandsEditorCountsItsClientsAndFailingPairs(t *testing.T) {
	const wcag = " Tekst i krawędzie w tych kolorach nie spełniają wymogów kontrastu WCAG 2.2 na poziomie AA."
	for _, tc := range []struct {
		count                     int
		clients, warnings, notice string
	}{
		{1, "1 client używa tej marki.", "1 para jest poniżej swojego minimum." + wcag,
			"1 para jej kolorów jest poniżej minimalnego kontrastu."},
		{2, "2 clienty używają tej marki.", "2 pary są poniżej swojego minimum." + wcag,
			"2 pary jej kolorów są poniżej minimalnego kontrastu."},
		{5, "5 clientów używa tej marki.", "5 par jest poniżej swojego minimum." + wcag,
			"5 par jej kolorów jest poniżej minimalnego kontrastu."},
		{22, "22 clienty używają tej marki.", "22 pary są poniżej swojego minimum." + wcag,
			"22 pary jej kolorów są poniżej minimalnego kontrastu."},
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
				handlertest.WithSettings(&api.PublicSettingsResponse{AppName: "Test"}), handlertest.WithLocale("pl-PL"))
			for _, cookie := range saved.Result().Cookies() {
				req.AddCookie(cookie)
			}
			w := httptest.NewRecorder()
			adminsettingshandlers.HandleBrandGet(render.New(web.TemplateFS(), web.StaticFS()), store, polishCustomBrand{}).ServeHTTP(w, req)
			require.Equal(t, http.StatusOK, w.Code)

			out := html.UnescapeString(w.Body.String())
			assert.Contains(t, out, `<p class="page-lead">Wybierz ją na karcie Ustawienia clienta, aby wyświetlać w niej jego strony. `+tc.clients+`</p>`)
			assert.Contains(t, out, `id="paletteWarningsCount" role="status">`+tc.warnings+`</p>`)
			assert.Contains(t, out, `<p>Zapisano markę. `+tc.notice+` <a class="text-link" href="#palette-warnings">Pokaż pary</a></p>`)
		})
	}
}
