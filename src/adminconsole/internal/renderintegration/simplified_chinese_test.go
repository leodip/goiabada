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

// chineseCounts are the counts a Chinese counted phrase is read at: Chinese has one form, so 1, 2
// and 11 read alike, each with the number joined to the Chinese after it.
var chineseCounts = []int{1, 2, 11}

// A console page asked for in Simplified Chinese, through ui_locales or the browser, or by what
// Chrome set to Chinese (Taiwan) sends, is drawn in Simplified Chinese, client kept in Latin script
// with a space between it and the Chinese beside it and none before the 。 after it. A request
// naming only Traditional Chinese reads English (#663 decisions 1, 3 and 4).
func TestSimplifiedChinese_AdminPageUsesQueryOrChineseHeader(t *testing.T) {
	for _, tc := range []struct {
		target, accept, lang, create, empty string
	}{
		{"/admin/clients?ui_locales=zh-Hans", "en", "zh-Hans", "新建 client", "尚无 client。"},
		{"/admin/clients?ui_locales=zh", "en", "zh-Hans", "新建 client", "尚无 client。"},
		{"/admin/clients?ui_locales=zh-CN", "en", "zh-Hans", "新建 client", "尚无 client。"},
		{"/admin/clients", "zh-CN", "zh-Hans", "新建 client", "尚无 client。"},
		{"/admin/clients", "zh-CN,zh;q=0.9,en;q=0.8", "zh-Hans", "新建 client", "尚无 client。"},
		{"/admin/clients", "zh-SG", "zh-Hans", "新建 client", "尚无 client。"},
		{"/admin/clients", "zh-Hans-HK", "zh-Hans", "新建 client", "尚无 client。"},
		{"/admin/clients", "zh-TW,zh;q=0.9", "zh-Hans", "新建 client", "尚无 client。"},
		{"/admin/clients", "zh-TW", "en", "New client", "No clients yet."},
		{"/admin/clients", "zh-HK", "en", "New client", "No clients yet."},
		{"/admin/clients", "zh-Hant", "en", "New client", "No clients yet."},
		{"/admin/clients", "zh-MY", "en", "New client", "No clients yet."},
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
			assert.Contains(t, w.Body.String(), `<html lang="`+tc.lang+`"`)
			assert.Contains(t, w.Body.String(), `data-catalog-lang="`+tc.lang+`"`)
			assert.Contains(t, w.Body.String(), tc.create)
			assert.Contains(t, w.Body.String(), tc.empty)
		})
	}
}

func TestSimplifiedChinese_ConsoleRefusalIsRenderedOnItsForm(t *testing.T) {
	req := handlertest.Request(http.MethodPost, "/admin/resources/7/delete",
		handlertest.WithAccessToken(), handlertest.WithPathValue("resourceId", "7"),
		handlertest.WithSettings(&api.PublicSettingsResponse{AppName: "Test"}),
		handlertest.WithLocale("zh-CN"),
		handlertest.WithForm(url.Values{"resourceIdentifier": {"shipping"}}))
	w := httptest.NewRecorder()
	adminresourcehandlers.HandleDeletePost(render.New(web.TemplateFS(), web.StaticFS()), resourceToDelete{}, "https://console.example.test").ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `lang="zh-Hans"`)
	assert.Contains(t, html.UnescapeString(w.Body.String()), "这不是此资源的标识符。请按上方所示输入。")
	assert.Contains(t, w.Body.String(), `aria-invalid="true"`)
}

// The account's sessions page in Simplified Chinese: each instant year-month-day on a 24-hour
// clock, and how long ago it was in Chinese's one form, the count joined, at 1, 2 and 11.
func TestSimplifiedChinese_TheSessionsPageDrawsDatesAndRelativeTimes(t *testing.T) {
	// Each offset sits half a unit clear of its boundary, so no phrase changes while the case runs.
	now := time.Now().UTC()
	var sessions []render.SessionInfo
	var cells []string
	for i, tc := range []struct {
		count         int
		started, last string
	}{
		{1, "1天前", "1分钟前"},
		{2, "2天前", "2分钟前"},
		{11, "11天前", "11分钟前"},
	} {
		started := now.Add(-time.Duration(tc.count)*24*time.Hour - 12*time.Hour)
		last := now.Add(-time.Duration(tc.count)*time.Minute - 30*time.Second)
		sessions = append(sessions, render.SessionInfo{UserSessionID: int64(i + 1), Started: &started, LastAccessed: &last})
		cells = append(cells,
			`">`+started.Format("2006-01-02 15:04")+`<span class="cell-secondary">`+tc.started+`</span></td>`,
			`">`+last.Format("2006-01-02 15:04")+`<span class="cell-secondary">`+tc.last+`</span></td>`)
	}

	out := renderMenuPageIn(t, "/account_user_sessions.html", map[string]interface{}{"sessions": sessions}, "zh-Hans", true)

	for _, cell := range cells {
		assert.Contains(t, out, cell)
	}
}

// The account's two-factor page in Simplified Chinese says how many recovery codes are unused, and
// that none are in a sentence of its own.
func TestSimplifiedChinese_TheRecoveryCodesSectionCountsTheUnusedCodes(t *testing.T) {
	for _, tc := range []struct {
		remaining int
		want      string
	}{
		{1, "您的10个恢复代码中有1个未使用。"},
		{2, "您的10个恢复代码中有2个未使用。"},
		{10, "您的10个恢复代码中有10个未使用。"},
		{0, "您没有未使用的恢复代码。请获取一组新代码，以便在丢失身份验证器应用时仍能登录。"},
	} {
		t.Run(strconv.Itoa(tc.remaining), func(t *testing.T) {
			out := renderMenuPageIn(t, "/account_otp.html", map[string]interface{}{
				"otpEnabled":             true,
				"recoveryCodesRemaining": tc.remaining,
			}, "zh-Hans", true)
			assert.Contains(t, out, tc.want)
		})
	}
}

// chineseBrands is the auth server's brands as the brand list and a brand's deletion read them: a
// brand per count, failing that many contrast pairs and drawn for that many clients, and the
// default brand.
type chineseBrands struct{}

func (chineseBrands) GetAllBrands(context.Context, string) ([]api.BrandResponse, error) {
	brands := []api.BrandResponse{{ID: 100, Name: "标准", Appearance: "auto", Theme: "blueberry", IsDefault: true}}
	for _, count := range chineseCounts {
		brand, _ := chineseBrands{}.GetBrandByID(context.Background(), "", int64(count))
		brands = append(brands, *brand)
	}
	return brands, nil
}

func (chineseBrands) GetBrandByID(_ context.Context, _ string, brandID int64) (*api.BrandResponse, error) {
	warnings := make([]api.BrandContrastWarning, brandID)
	for i := range warnings {
		warnings[i] = api.BrandContrastWarning{Mode: "light", Foreground: "text", Background: "surface", Ratio: 3, Minimum: 4.5}
	}
	return &api.BrandResponse{ID: brandID, Name: "品牌 " + strconv.FormatInt(brandID, 10), Appearance: "light",
		Theme: "plum", ClientCount: int(brandID), ContrastWarnings: warnings}, nil
}

func (chineseBrands) DeleteBrand(context.Context, string, int64) error { return nil }

// The brand list in Simplified Chinese marks each brand with how many of its pairs are below the
// contrast minimum.
func TestSimplifiedChinese_TheBrandListCountsTheFailingPairs(t *testing.T) {
	req := handlertest.Request(http.MethodGet, "/admin/settings/branding", handlertest.WithAccessToken(),
		handlertest.WithSettings(&api.PublicSettingsResponse{AppName: "Test"}), handlertest.WithLocale("zh-CN"))
	w := httptest.NewRecorder()
	adminsettingshandlers.HandleBrandingGet(render.New(web.TemplateFS(), web.StaticFS()), chineseBrands{}).ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	out := w.Body.String()
	assert.Contains(t, out, `lang="zh-Hans"`)
	for _, want := range []string{
		"1对颜色低于对比度最低要求",
		"2对颜色低于对比度最低要求",
		"11对颜色低于对比度最低要求",
	} {
		assert.Contains(t, out, `<span class="tag tag-caution ml-1">`+want+`</span>`)
	}
}

// A brand's deletion in Simplified Chinese says how many clients use it, and that the default brand,
// named in “”, takes its place, in a sentence with no plural pronoun, so it reads right for one
// client as for eleven.
func TestSimplifiedChinese_ABrandsDeletionCountsItsClients(t *testing.T) {
	for _, count := range chineseCounts {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			id := strconv.Itoa(count)
			req := handlertest.Request(http.MethodGet, "/admin/settings/branding/"+id+"/delete", handlertest.WithAccessToken(),
				handlertest.WithPathValue("brandId", id),
				handlertest.WithSettings(&api.PublicSettingsResponse{AppName: "Test"}), handlertest.WithLocale("zh-CN"))
			w := httptest.NewRecorder()
			adminsettingshandlers.HandleBrandDeleteGet(render.New(web.TemplateFS(), web.StaticFS()), chineseBrands{}).ServeHTTP(w, req)
			require.Equal(t, http.StatusOK, w.Code)

			out := html.UnescapeString(w.Body.String())
			assert.Contains(t, out, `<p class="page-lead">该品牌将被删除。`)
			assert.Contains(t, out, id+`个 client 使用它，删除后将改用默认品牌“标准”。</p>`)
			assert.NotContains(t, out, "它们", "no plural pronoun for a count that may be one")
		})
	}
}

// A custom brand's editor in Simplified Chinese, drawn again after a save, says how many clients use
// the brand, how many of its pairs are below their minimum, and in the saved notice how many pairs
// fail.
func TestSimplifiedChinese_ABrandsEditorCountsItsClientsAndFailingPairs(t *testing.T) {
	const wcag = "使用这些颜色绘制的文字和边界不符合 WCAG 2.2 AA 级对比度要求。"
	for _, count := range chineseCounts {
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
				handlertest.WithSettings(&api.PublicSettingsResponse{AppName: "Test"}), handlertest.WithLocale("zh-CN"))
			for _, cookie := range saved.Result().Cookies() {
				req.AddCookie(cookie)
			}
			w := httptest.NewRecorder()
			adminsettingshandlers.HandleBrandGet(render.New(web.TemplateFS(), web.StaticFS()), store, russianCustomBrand{}).ServeHTTP(w, req)
			require.Equal(t, http.StatusOK, w.Code)

			out := html.UnescapeString(w.Body.String())
			assert.Contains(t, out, `<p class="page-lead">在 client 的“设置”选项卡中选择它，即可使用它绘制该 client 的页面。`)
			assert.Contains(t, out, id+`个 client 使用此品牌。</p>`)
			assert.Contains(t, out, `id="paletteWarningsCount" role="status">`+id+`对颜色低于最低要求。`+wcag+`</p>`)
			assert.Regexp(t, `<p>品牌已保存。\s*该品牌有`+id+`对颜色低于对比度最低要求。\s*`+
				`<a class="text-link" href="#palette-warnings">查看这些颜色对</a></p>`, out)
		})
	}
}

// The home page's cards are titled in Simplified Chinese, administration as 管理.
func TestSimplifiedChinese_TheHomePageCards(t *testing.T) {
	out := renderPage(t, "/layouts/no_menu_layout.html", "/index.html", map[string]interface{}{
		"AuthServerBaseURL": "https://auth.example",
		"AccountLink":       "/account/profile",
		"AdminLink":         "/admin/clients",
	}, nil, "zh-Hans", true)
	assert.Contains(t, out, `<span class="link-row-title">管理</span>`)
	assert.Contains(t, out, `<span class="link-row-title">您的账户</span>`)
}
