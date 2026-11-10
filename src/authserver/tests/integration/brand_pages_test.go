package integration

import (
	"context"
	"database/sql"
	"io"
	"net/http"
	"strconv"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every auth server page is drawn in the default brand: both layouts and the form_post page carry
// its appearance as data-theme and link its stylesheet after main.css, and the stylesheet they link
// is the one the server answers as current, cacheable for a year (#810 decisions 3 and 7).

// makeDefaultBrand creates a brand with appearance and theme and makes it the default, and puts the
// default it replaced back, and deletes the brand, when the test ends. UpdateSettings never writes
// the pointer, so restoreSettings cannot put it back.
func makeDefaultBrand(t *testing.T, appearance record.BrandAppearance, theme string) *record.Brand {
	t.Helper()
	ctx := context.Background()

	brand := &record.Brand{Name: "Pages " + fake.LetterN(10), Appearance: appearance, Theme: theme}
	require.NoError(t, database.CreateBrand(ctx, nil, brand))

	var previous int64
	require.NoError(t, database.RunInTransaction(ctx, func(tx *sql.Tx) error {
		var err error
		previous, err = database.MakeBrandDefault(ctx, tx, brand.Id)
		return err
	}))

	t.Cleanup(func() {
		assert.NoError(t, database.RunInTransaction(ctx, func(tx *sql.Tx) error {
			if _, err := database.MakeBrandDefault(ctx, tx, previous); err != nil {
				return err
			}
			_, err := database.DeleteBrand(ctx, tx, brand.Id)
			return err
		}), "unable to put the default brand back")
	})
	return brand
}

// brandedPageHead is what a page's head says about its look.
type brandedPageHead struct {
	dataTheme    string
	hasDataTheme bool
	colorScheme  string
	stylesheets  []string
}

func readBrandedPageHead(t *testing.T, resp *http.Response) brandedPageHead {
	t.Helper()
	doc := parseHTMLResponse(t, resp)
	var head brandedPageHead
	head.dataTheme, head.hasDataTheme = doc.Find("html").Attr("data-theme")
	head.colorScheme, _ = doc.Find(`meta[name="color-scheme"]`).Attr("content")
	doc.Find(`link[rel="stylesheet"]`).Each(func(_ int, link *goquery.Selection) {
		href, _ := link.Attr("href")
		head.stylesheets = append(head.stylesheets, href)
	})
	return head
}

func TestPages_AreDrawnInTheDefaultBrand(t *testing.T) {
	brand := makeDefaultBrand(t, record.BrandAppearanceDark, "plum")
	client := newFormPostClient(t)
	base := appConfig.AuthServer.BaseURL

	for _, tc := range []struct {
		name       string
		load       func(t *testing.T, browser *http.Client) *http.Response
		wantStatus int
	}{
		{
			name: "the not-found page, on the layout without a client",
			load: func(t *testing.T, browser *http.Client) *http.Response {
				return loadPage(t, browser, base+"/no-such-page-"+fake.LetterN(8))
			},
			wantStatus: http.StatusNotFound,
		},
		{
			name: "the password page, on the sign-in layout",
			load: func(t *testing.T, browser *http.Client) *http.Response {
				params := formPostAuthorizeParams(client, "code", "", formPostHTTPSURI, "")
				resp := loadPage(t, browser, base+"/auth/authorize?"+params.Encode())
				location := assertRedirect(t, resp, "/auth/level1")
				_ = resp.Body.Close()
				resp = loadPage(t, browser, location)
				location = assertRedirect(t, resp, "/auth/pwd")
				_ = resp.Body.Close()
				return loadPage(t, browser, location)
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "the form_post page",
			load: func(t *testing.T, browser *http.Client) *http.Response {
				params := formPostAuthorizeParams(client, "code", "form_post", formPostHTTPSURI, "none")
				return loadPage(t, browser, base+"/auth/authorize?"+params.Encode())
			},
			wantStatus: http.StatusOK,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			browser := createHttpClient(t)
			resp := tc.load(t, browser)
			defer func() { _ = resp.Body.Close() }()

			require.Equal(t, tc.wantStatus, resp.StatusCode)
			head := readBrandedPageHead(t, resp)
			assert.Equal(t, "dark", head.dataTheme)
			assert.Equal(t, "dark", head.colorScheme)
			require.Len(t, head.stylesheets, 2, "main.css, then the brand's stylesheet")
			assert.Regexp(t, `^/static/main\.css\?v=[0-9a-f]{12}$`, head.stylesheets[0])
			assert.Regexp(t, `^/brand/`+strconv.FormatInt(brand.Id, 10)+`/stylesheet\.css\?v=[0-9a-f]{12}$`, head.stylesheets[1])

			// The link names the stylesheet as it is now: the server answers it with Plum's colors,
			// cacheable for a year.
			stylesheet, err := browser.Get(base + head.stylesheets[1])
			require.NoError(t, err)
			defer func() { _ = stylesheet.Body.Close() }()
			body, err := io.ReadAll(stylesheet.Body)
			require.NoError(t, err)
			assert.Equal(t, http.StatusOK, stylesheet.StatusCode)
			assert.Equal(t, "public, max-age=31536000, immutable", stylesheet.Header.Get("Cache-Control"))
			assert.Contains(t, string(body), "--color-brand: #7a3aa8;")
			assert.Contains(t, string(body), "--color-brand: #cda4f0;")
		})
	}
}

// An automatic brand writes no data-theme, so the device decides, and its stylesheet is still
// linked.
func TestPages_AnAutomaticDefaultBrandFollowsTheDevice(t *testing.T) {
	brand := makeDefaultBrand(t, record.BrandAppearanceAuto, "guava")

	resp := loadPage(t, createHttpClient(t), appConfig.AuthServer.BaseURL+"/no-such-page-"+fake.LetterN(8))
	defer func() { _ = resp.Body.Close() }()

	head := readBrandedPageHead(t, resp)
	assert.False(t, head.hasDataTheme, "got data-theme %q", head.dataTheme)
	assert.Equal(t, "light dark", head.colorScheme)
	require.Len(t, head.stylesheets, 2, "main.css, then the brand's stylesheet")
	assert.Regexp(t, `^/brand/`+strconv.FormatInt(brand.Id, 10)+`/stylesheet\.css\?v=[0-9a-f]{12}$`, head.stylesheets[1])
}
