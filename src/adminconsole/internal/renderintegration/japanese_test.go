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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// japaneseCounts are the counts a Japanese counted phrase is read at: Japanese has one form, so 1,
// 2 and 11 read alike, each with a half-width space between the number and the Japanese after it.
var japaneseCounts = []int{1, 2, 11}

// A console page asked for in Japanese, through ui_locales or the browser, or listed after Chinese,
// is drawn in Japanese, client kept in Latin script with a space on each side (#662).
func TestJapanese_AdminPageUsesQueryOrJapaneseHeader(t *testing.T) {
	for _, tc := range []struct{ target, accept string }{
		{"/admin/clients?ui_locales=ja", "en"},
		{"/admin/clients", "ja-JP"},
		{"/admin/clients", "sv-SE,ja;q=0.8"},
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
			assert.Contains(t, w.Body.String(), `<html lang="ja"`)
			assert.Contains(t, w.Body.String(), `data-catalog-lang="ja"`)
			assert.Contains(t, w.Body.String(), "新しい client")
			assert.Contains(t, w.Body.String(), "client はまだありません。")
		})
	}
}

func TestJapanese_ConsoleRefusalIsRenderedOnItsForm(t *testing.T) {
	req := handlertest.Request(http.MethodPost, "/admin/resources/7/delete",
		handlertest.WithAccessToken(), handlertest.WithPathValue("resourceId", "7"),
		handlertest.WithSettings(&api.PublicSettingsResponse{AppName: "Test"}),
		handlertest.WithLocale("ja-JP"),
		handlertest.WithForm(url.Values{"resourceIdentifier": {"shipping"}}))
	w := httptest.NewRecorder()
	adminresourcehandlers.HandleDeletePost(render.New(web.TemplateFS(), web.StaticFS()), resourceToDelete{}, "https://console.example.test").ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `lang="ja"`)
	assert.Contains(t, html.UnescapeString(w.Body.String()), "このリソースの識別子と一致しません。上に表示されているとおりに入力してください。")
	assert.Contains(t, w.Body.String(), `aria-invalid="true"`)
}

// The account's sessions page in Japanese: each instant year/month/day on a 24-hour clock, and how
// long ago it was in Japanese's one form, at 1, 2 and 11.
func TestJapanese_TheSessionsPageDrawsDatesAndRelativeTimes(t *testing.T) {
	// Each offset sits half a unit clear of its boundary, so no phrase changes while the case runs.
	now := time.Now().UTC()
	var sessions []render.SessionInfo
	var cells []string
	for i, tc := range []struct {
		count         int
		started, last string
	}{
		{1, "1 日前", "1 分前"},
		{2, "2 日前", "2 分前"},
		{11, "11 日前", "11 分前"},
	} {
		started := now.Add(-time.Duration(tc.count)*24*time.Hour - 12*time.Hour)
		last := now.Add(-time.Duration(tc.count)*time.Minute - 30*time.Second)
		sessions = append(sessions, render.SessionInfo{UserSessionID: int64(i + 1), Started: &started, LastAccessed: &last})
		cells = append(cells,
			`">`+started.Format("2006/01/02 15:04")+`<span class="cell-secondary">`+tc.started+`</span></td>`,
			`">`+last.Format("2006/01/02 15:04")+`<span class="cell-secondary">`+tc.last+`</span></td>`)
	}

	out := renderMenuPageIn(t, "/account_user_sessions.html", map[string]interface{}{"sessions": sessions}, "ja", true)

	for _, cell := range cells {
		assert.Contains(t, out, cell)
	}
}

// The account's two-factor page in Japanese says how many recovery codes are unused, and that none
// are in a sentence of its own.
func TestJapanese_TheRecoveryCodesSectionCountsTheUnusedCodes(t *testing.T) {
	for _, tc := range []struct {
		remaining int
		want      string
	}{
		{1, "10 個のリカバリーコードのうち、1 個が未使用です。"},
		{2, "10 個のリカバリーコードのうち、2 個が未使用です。"},
		{10, "10 個のリカバリーコードのうち、10 個が未使用です。"},
		{0, "未使用のリカバリーコードがありません。認証アプリを紛失してもログインできるよう、新しいセットを取得してください。"},
	} {
		t.Run(strconv.Itoa(tc.remaining), func(t *testing.T) {
			out := renderMenuPageIn(t, "/account_otp.html", map[string]interface{}{
				"otpEnabled":             true,
				"recoveryCodesRemaining": tc.remaining,
			}, "ja", true)
			assert.Contains(t, out, tc.want)
		})
	}
}

// japaneseBrands is the auth server's brands as the brand list and a brand's deletion read them: a
// brand per count, failing that many contrast pairs and drawn for that many clients, and the
// default brand.
type japaneseBrands struct{}

func (japaneseBrands) GetAllBrands(context.Context, string) ([]api.BrandResponse, error) {
	brands := []api.BrandResponse{{ID: 100, Name: "標準", Appearance: "auto", Theme: "blueberry", IsDefault: true}}
	for _, count := range japaneseCounts {
		brand, _ := japaneseBrands{}.GetBrandByID(context.Background(), "", int64(count))
		brands = append(brands, *brand)
	}
	return brands, nil
}

func (japaneseBrands) GetBrandByID(_ context.Context, _ string, brandID int64) (*api.BrandResponse, error) {
	warnings := make([]api.BrandContrastWarning, brandID)
	for i := range warnings {
		warnings[i] = api.BrandContrastWarning{Mode: "light", Foreground: "text", Background: "surface", Ratio: 3, Minimum: 4.5}
	}
	return &api.BrandResponse{ID: brandID, Name: "ブランド " + strconv.FormatInt(brandID, 10), Appearance: "light",
		Theme: "plum", ClientCount: int(brandID), ContrastWarnings: warnings}, nil
}

func (japaneseBrands) DeleteBrand(context.Context, string, int64) error { return nil }

// The brand list in Japanese marks each brand with how many of its pairs are below the contrast
// minimum.
func TestJapanese_TheBrandListCountsTheFailingPairs(t *testing.T) {
	req := handlertest.Request(http.MethodGet, "/admin/settings/branding", handlertest.WithAccessToken(),
		handlertest.WithSettings(&api.PublicSettingsResponse{AppName: "Test"}), handlertest.WithLocale("ja-JP"))
	w := httptest.NewRecorder()
	adminsettingshandlers.HandleBrandingGet(render.New(web.TemplateFS(), web.StaticFS()), japaneseBrands{}).ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	out := w.Body.String()
	assert.Contains(t, out, `lang="ja"`)
	for _, want := range []string{
		"1 組がコントラストの最小値未満",
		"2 組がコントラストの最小値未満",
		"11 組がコントラストの最小値未満",
	} {
		assert.Contains(t, out, `<span class="tag tag-caution ml-1">`+want+`</span>`)
	}
}

// A brand's deletion in Japanese says how many clients use it, and that the default brand takes its
// place, in a sentence that names no plural, so it reads right for one client as for eleven.
func TestJapanese_ABrandsDeletionCountsItsClients(t *testing.T) {
	for _, count := range japaneseCounts {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			id := strconv.Itoa(count)
			req := handlertest.Request(http.MethodGet, "/admin/settings/branding/"+id+"/delete", handlertest.WithAccessToken(),
				handlertest.WithPathValue("brandId", id),
				handlertest.WithSettings(&api.PublicSettingsResponse{AppName: "Test"}), handlertest.WithLocale("ja-JP"))
			w := httptest.NewRecorder()
			adminsettingshandlers.HandleBrandDeleteGet(render.New(web.TemplateFS(), web.StaticFS()), japaneseBrands{}).ServeHTTP(w, req)
			require.Equal(t, http.StatusOK, w.Code)

			out := html.UnescapeString(w.Body.String())
			assert.Contains(t, out, `<p class="page-lead">このブランドは削除されます。`)
			assert.Contains(t, out, id+` 個の client がこのブランドを使用しています。削除後は、デフォルトのブランド「標準」が使用されます。</p>`)
			assert.NotContains(t, out, "これら", "no plural pronoun for a count that may be one")
		})
	}
}

// A custom brand's editor in Japanese, drawn again after a save, says how many clients use the
// brand, how many of its pairs are below their minimum, and in the saved notice how many pairs
// fail.
func TestJapanese_ABrandsEditorCountsItsClientsAndFailingPairs(t *testing.T) {
	const wcag = "これらの色で表示されるテキストと境界線は、WCAG 2.2 レベル AA のコントラストを満たしません。"
	for _, count := range japaneseCounts {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			id := strconv.Itoa(count)
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
				handlertest.WithSettings(&api.PublicSettingsResponse{AppName: "Test"}), handlertest.WithLocale("ja-JP"))
			for _, cookie := range saved.Result().Cookies() {
				req.AddCookie(cookie)
			}
			w := httptest.NewRecorder()
			adminsettingshandlers.HandleBrandGet(render.New(web.TemplateFS(), web.StaticFS()), store, russianCustomBrand{}).ServeHTTP(w, req)
			require.Equal(t, http.StatusOK, w.Code)

			out := html.UnescapeString(w.Body.String())
			assert.Contains(t, out, `<p class="page-lead">client の「設定」タブでこのブランドを選ぶと、その client のページがこのブランドで表示されます。`)
			assert.Contains(t, out, id+` 個の client がこのブランドを使用しています。</p>`)
			assert.Contains(t, out, `id="paletteWarningsCount" role="status">`+id+` 組が最小値を下回っています。`+wcag+`</p>`)
			assert.Regexp(t, `<p>ブランドを保存しました。\s*カラーの組み合わせのうち `+id+` 組がコントラストの最小値を下回っています。\s*`+
				`<a class="text-link" href="#palette-warnings">組み合わせを表示</a></p>`, out)
		})
	}
}

// The home page's cards are titled in Japanese, administration as 管理.
func TestJapanese_TheHomePageCards(t *testing.T) {
	out := renderPage(t, "/layouts/no_menu_layout.html", "/index.html", map[string]interface{}{
		"AuthServerBaseURL": "https://auth.example",
		"AccountLink":       "/account/profile",
		"AdminLink":         "/admin/clients",
	}, nil, "ja", true)
	assert.Contains(t, out, `<span class="link-row-title">管理</span>`)
	assert.Contains(t, out, `<span class="link-row-title">あなたのアカウント</span>`)
}
