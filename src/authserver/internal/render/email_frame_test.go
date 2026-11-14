package render

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/emailtemplate"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/web"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/logging/logtest"
)

// An email is drawn in the brand of the page it was sent from, as the sign-in card is, with every
// value written inline (#817 decisions 2, 4 and 6): the logo above the app name, a card in the
// brand's colors, corner shape and font family, and its links in the brand's color.

const emailBaseURL = "https://auth.example.com"

// systemUIFamily is main.css's --font-sans, the System UI family, as an email writes it: its names
// unquoted, which html/template's style filter requires.
const systemUIFamily = "-apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Helvetica Neue, Noto Sans, Arial, " +
	"sans-serif, Apple Color Emoji, Segoe UI Emoji, Segoe UI Symbol, Noto Color Emoji"

// emailColors are the colors an email draws its frame in: the area behind the card, the card and its
// border, the text, the app name and the links.
type emailColors struct {
	canvas, surface, line, ink, inkMuted, link string
}

// Plum's light and dark colors, and Blueberry's, as brandthemes' presets hold them.
var (
	plumLight      = emailColors{"#f6f4f7", "#ffffff", "#ddd7e1", "#201a26", "#5a5163", "#7a3aa8"}
	plumDark       = emailColors{"#120f15", "#1a161f", "#352e3d", "#e9e5ec", "#a9a0b2", "#cda4f0"}
	blueberryLight = emailColors{"#f4f5f7", "#ffffff", "#d8dce3", "#1a1f29", "#535c6c", "#2456c4"}
	blueberryDark  = emailColors{"#0f1217", "#171b22", "#2f3541", "#e6e8ec", "#a0a8b6", "#8ab4ff"}
	// sunnyLight is paletteBrand's light palette.
	sunnyLight = emailColors{"#fafaf7", "#ffffff", "#e1e1d9", "#1c1c18", "#5a5a4f", "#f5c400"}
)

// drawnEmail is what a rendered email says about its frame.
type drawnEmail struct {
	colorScheme   string
	colors        emailColors
	bodyColor     string
	tableCanvas   string
	cardBorder    string
	cardRadius    string
	fontFamily    string
	bodyFont      string
	logos         int
	logoSrc       string
	logoAlt       string
	logoHasAlt    bool
	logoWidth     string
	logoHeight    string
	name          string
	nameShown     bool
	linkColors    []string
	stylesheets   int
	styleElements int
}

// styleOf answers the declarations of an element's style attribute, by property.
func styleOf(selection *goquery.Selection) map[string]string {
	declarations := map[string]string{}
	style, _ := selection.Attr("style")
	for _, declaration := range strings.Split(style, ";") {
		property, value, ok := strings.Cut(declaration, ":")
		if !ok {
			continue
		}
		declarations[strings.TrimSpace(property)] = strings.TrimSpace(value)
	}
	return declarations
}

// readEmail reads the frame of a rendered email: the body is the area behind the card, the nested
// table the card, its cell the card's content, which holds the logo, the app name and the email's
// own body in main.
func readEmail(t *testing.T, html string) drawnEmail {
	t.Helper()
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	require.NoError(t, err)

	var email drawnEmail
	email.colorScheme, _ = doc.Find(`meta[name="color-scheme"]`).Attr("content")
	body := styleOf(doc.Find("body"))
	email.colors.canvas = body["background-color"]
	email.bodyColor = body["color"]
	email.bodyFont = body["font-family"]
	email.tableCanvas = styleOf(doc.Find("body > table"))["background-color"]

	card := doc.Find("body table table").First()
	cardStyle := styleOf(card)
	email.colors.surface = cardStyle["background-color"]
	email.cardBorder = cardStyle["border"]
	email.cardRadius = cardStyle["border-radius"]
	email.colors.line = strings.TrimPrefix(email.cardBorder, "1px solid ")

	cell := card.Find("td").First()
	cellStyle := styleOf(cell)
	email.colors.ink = cellStyle["color"]
	email.fontFamily = cellStyle["font-family"]

	images := doc.Find("img")
	email.logos = images.Length()
	email.logoSrc, _ = images.First().Attr("src")
	email.logoAlt, email.logoHasAlt = images.First().Attr("alt")
	email.logoWidth, _ = images.First().Attr("width")
	email.logoHeight, _ = images.First().Attr("height")

	name := cell.ChildrenFiltered("p")
	email.nameShown = name.Length() > 0
	email.name = strings.TrimSpace(name.Text())
	email.colors.inkMuted = styleOf(name)["color"]

	// A button is drawn in the brand's color with its label in the color drawn on it; the links
	// are the body's others.
	doc.Find("main a").Each(func(_ int, link *goquery.Selection) {
		if isEmailButton(link) {
			return
		}
		email.linkColors = append(email.linkColors, styleOf(link)["color"])
	})
	if len(email.linkColors) > 0 {
		email.colors.link = email.linkColors[0]
	}
	email.stylesheets = doc.Find("link").Length()
	email.styleElements = doc.Find("style").Length()
	return email
}

// renderBrandedEmail renders the password reset link, whose body holds a link, in ctx through a
// renderer whose base URL is emailBaseURL, and reads its frame.
func renderBrandedEmail(t *testing.T, ctx context.Context, brands *defaultBrandStub) drawnEmail {
	t.Helper()
	return readEmail(t, renderEmailHTML(t, ctx, New(web.TemplateFS(), web.StaticFS(), nilIfEmpty(brands)).WithBaseURL(emailBaseURL)))
}

// nilIfEmpty answers a nil reader for a nil stub, so a test can draw an email with no brands at all.
func nilIfEmpty(brands *defaultBrandStub) PageBrandReader {
	if brands == nil {
		return nil
	}
	return brands
}

func renderEmailHTML(t *testing.T, ctx context.Context, renderer *Renderer) string {
	t.Helper()
	ctx = reqctx.WithSettings(ctx, &record.Settings{AppName: "Acme Portal"})
	req := httptest.NewRequest(http.MethodPost, "/forgot-password", nil).WithContext(ctx)
	message, err := renderer.RenderEmail(req, emailtemplate.PasswordResetLink,
		emailtemplate.Values{Name: "Ana", Link: "https://auth.example.com/reset-password?code=abc", Expiry: 5 * time.Minute})
	require.NoError(t, err)
	return message.HTML
}

// themedBrand is the default brand of id 7 on theme, in appearance, with the seeded kit.
func themedBrand(appearance record.BrandAppearance, theme string) *record.Brand {
	brand := record.NewBrand("Shop", appearance, theme)
	brand.Id = 7
	return &brand
}

// An email is read in a client that drops style sheets and ignores the device's mode, so it is
// drawn in one palette, written inline: a dark brand's dark palette, and a light or automatic
// brand's light one. It declares that scheme, and nothing depends on a style sheet (decision 4).
func TestRender_AnEmailIsDrawnInThePaletteOfItsBrandsAppearance(t *testing.T) {
	for _, tc := range []struct {
		appearance record.BrandAppearance
		scheme     string
		colors     emailColors
	}{
		{record.BrandAppearanceLight, "light", plumLight},
		{record.BrandAppearanceAuto, "light", plumLight},
		{record.BrandAppearanceDark, "dark", plumDark},
	} {
		t.Run(string(tc.appearance), func(t *testing.T) {
			brands := &defaultBrandStub{brand: themedBrand(tc.appearance, "plum")}

			email := renderBrandedEmail(t, context.Background(), brands)

			assert.Equal(t, tc.scheme, email.colorScheme)
			assert.Equal(t, tc.colors, email.colors)
			assert.Equal(t, tc.colors.ink, email.bodyColor)
			assert.Equal(t, tc.colors.canvas, email.tableCanvas, "the table behind the card is the canvas too")
			assert.Equal(t, tc.colors.surface, email.colors.surface, "the card is the surface")
			assert.Equal(t, tc.colors.inkMuted, email.colors.inkMuted, "the app name is muted ink")
			assert.Equal(t, "1px solid "+tc.colors.line, email.cardBorder)
			assert.Equal(t, []string{tc.colors.link}, email.linkColors, "the body's link is in the brand's color")
			assert.Zero(t, email.stylesheets, "an email links no style sheet")
			assert.Zero(t, email.styleElements, "an email holds no style element")
			assert.Equal(t, 1, brands.reads)
		})
	}
}

// The card takes the brand's corner shape, as a panel's radius in pixels, and the text the brand's
// font family; an uploaded font, which an email cannot load, is drawn in the System UI family
// (decision 2).
func TestRender_AnEmailIsDrawnInItsBrandsCornersAndFont(t *testing.T) {
	for _, tc := range []struct {
		corners    record.BrandCorners
		font       record.BrandFont
		wantRadius string
		wantFamily string
	}{
		{record.BrandCornersRounded, record.BrandFontSystemUI, "12px", systemUIFamily},
		{record.BrandCornersSquare, record.BrandFontSerif, "0", "Charter, Bitstream Charter, Sitka Text, Cambria, serif"},
		{record.BrandCornersPill, record.BrandFontNeoGrotesque, "24px", "Inter, Roboto, Helvetica Neue, Arial Nova, Nimbus Sans, Arial, sans-serif"},
		{record.BrandCornersRounded, record.BrandFontUploaded, "12px", systemUIFamily},
	} {
		t.Run(string(tc.corners)+"/"+string(tc.font), func(t *testing.T) {
			brand := themedBrand(record.BrandAppearanceLight, "plum")
			brand.Corners = tc.corners
			brand.Font = tc.font
			brand.RegularFontAssetId = sql.NullInt64{Int64: 21, Valid: true}
			brands := &defaultBrandStub{brand: brand, assets: []record.BrandAsset{
				{Id: 21, Kind: record.BrandAssetKindFont, ContentType: "font/woff2", Fingerprint: "212121212121"},
			}}

			email := renderBrandedEmail(t, context.Background(), brands)

			assert.Equal(t, tc.wantRadius, email.cardRadius)
			assert.Equal(t, tc.wantFamily, email.fontFamily)
			assert.Equal(t, tc.wantFamily, email.bodyFont)
		})
	}
}

// The logo sits above the app name, linked by its absolute URL: the dark logo in a dark brand's
// email, the logo when it has none, and the logo in a light or automatic brand's. Its alt is the app
// name only while the name's text is hidden, as on a page, and a brand with no logo shows the name
// (decision 2).
func TestRender_AnEmailDrawsTheLogoAboveTheName(t *testing.T) {
	const logoURL = emailBaseURL + logoPath
	const darkLogoURL = emailBaseURL + darkLogoPath
	for _, tc := range []struct {
		name           string
		appearance     record.BrandAppearance
		logo, darkLogo bool
		hideAppName    bool
		wantLogo       string
		wantAlt        string
		wantName       bool
	}{
		{"no logo", record.BrandAppearanceLight, false, false, false, "", "", true},
		{"no logo, the switch on", record.BrandAppearanceLight, false, false, true, "", "", true},
		{"a logo beside the name", record.BrandAppearanceLight, true, false, false, logoURL, "", true},
		{"a logo in place of the name", record.BrandAppearanceLight, true, false, true, logoURL, "Acme Portal", false},
		{"a light brand's logo", record.BrandAppearanceLight, true, true, false, logoURL, "", true},
		{"an automatic brand's logo", record.BrandAppearanceAuto, true, true, false, logoURL, "", true},
		{"a dark brand's dark logo", record.BrandAppearanceDark, true, true, true, darkLogoURL, "Acme Portal", false},
		{"a dark brand with no dark logo", record.BrandAppearanceDark, true, false, false, logoURL, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			brands := &defaultBrandStub{brand: kitPageBrand(tc.appearance, tc.logo, tc.darkLogo, false, tc.hideAppName), assets: kitAssets}

			email := renderBrandedEmail(t, context.Background(), brands)

			if tc.wantLogo == "" {
				assert.Zero(t, email.logos)
			} else {
				assert.Equal(t, 1, email.logos)
				assert.Equal(t, tc.wantLogo, email.logoSrc)
				assert.True(t, email.logoHasAlt, "the logo carries an alt, empty or not")
				assert.Equal(t, tc.wantAlt, email.logoAlt)
				assert.Equal(t, "200", email.logoWidth, "a logo that fits is drawn at its own size")
				assert.Equal(t, "60", email.logoHeight)
			}
			assert.Equal(t, tc.wantName, email.nameShown)
			if tc.wantName {
				assert.Equal(t, "Acme Portal", email.name)
			}
		})
	}
}

// A logo is drawn at most 64 pixels tall and 424 wide, its proportions kept, so a client that ignores
// a style's bounds, as Outlook on Windows does, still draws it at the size a page does.
func TestRender_AnEmailDrawsALargeLogoScaledToFit(t *testing.T) {
	for _, tc := range []struct {
		width, height         int
		wantWidth, wantHeight string
	}{
		{512, 256, "128", "64"},
		{848, 64, "424", "32"},
		{512, 512, "64", "64"},
	} {
		brand := kitPageBrand(record.BrandAppearanceLight, true, false, false, false)
		brands := &defaultBrandStub{brand: brand, assets: []record.BrandAsset{
			{Id: 11, Kind: record.BrandAssetKindLogo, ContentType: "image/png", Fingerprint: "111111111111", Width: tc.width, Height: tc.height},
		}}

		email := renderBrandedEmail(t, context.Background(), brands)

		assert.Equal(t, tc.wantWidth, email.logoWidth)
		assert.Equal(t, tc.wantHeight, email.logoHeight)
	}
}

// An email is drawn in the brand of the page it was sent from: the brand of the client the page is
// drawn for, its own or the default (decision 1).
func TestRender_AnEmailIsDrawnInTheBrandOfItsPagesClient(t *testing.T) {
	brands := &defaultBrandStub{
		brand:   themedBrand(record.BrandAppearanceLight, "plum"),
		clients: map[string]*record.Brand{"app-1": paletteBrand(record.BrandAppearanceLight)},
	}

	named := reqctx.WithPageClient(context.Background(), &reqctx.PageClient{})
	reqctx.NamePageClient(named, "app-1")
	assert.Equal(t, sunnyLight, renderBrandedEmail(t, named, brands).colors)

	unnamed := reqctx.WithPageClient(context.Background(), &reqctx.PageClient{})
	assert.Equal(t, plumLight, renderBrandedEmail(t, unnamed, brands).colors)
}

// An email is in safe mode when its page is: while the operator's switch is on, and for the pages of
// a sign-in that asked for it. A custom palette is replaced by Blueberry's colors of the same
// appearance, and a built-in theme, the logo, the corners and the font are drawn as usual
// (decision 6).
func TestRender_AnEmailInSafeModeIsDrawnInBlueberryInPlaceOfACustomPalette(t *testing.T) {
	switchOn := reqctx.WithBrandSafeMode(context.Background())
	signIn := reqctx.WithPageClient(context.Background(), &reqctx.PageClient{})
	reqctx.NamePageClient(signIn, "app-1")
	reqctx.KeepPageSafeMode(signIn)

	custom := func(appearance record.BrandAppearance) *record.Brand {
		brand := paletteBrand(appearance)
		brand.Id = 7
		brand.Corners = record.BrandCornersPill
		brand.LogoAssetId = sql.NullInt64{Int64: 11, Valid: true}
		return brand
	}
	for _, tc := range []struct {
		name  string
		ctx   context.Context
		brand *record.Brand
		want  emailColors
	}{
		{"the switch, a light custom brand", switchOn, custom(record.BrandAppearanceLight), blueberryLight},
		{"the switch, a dark custom brand", switchOn, custom(record.BrandAppearanceDark), blueberryDark},
		{"a safe sign-in, a light custom brand", signIn, custom(record.BrandAppearanceLight), blueberryLight},
		{"the switch, a built-in theme", switchOn, themedBrand(record.BrandAppearanceLight, "plum"), plumLight},
		{"no safe mode, a light custom brand", context.Background(), custom(record.BrandAppearanceLight), sunnyLight},
	} {
		t.Run(tc.name, func(t *testing.T) {
			brands := &defaultBrandStub{brand: tc.brand, clients: map[string]*record.Brand{"app-1": tc.brand}, assets: kitAssets}

			email := renderBrandedEmail(t, tc.ctx, brands)

			assert.Equal(t, tc.want, email.colors)
			if tc.brand.Theme == record.BrandThemeCustom {
				assert.Equal(t, "24px", email.cardRadius, "the corners are drawn as usual")
				assert.Equal(t, emailBaseURL+logoPath, email.logoSrc, "the logo is drawn as usual")
			}
		})
	}
}

// An email is never refused over its look. One whose brand cannot be read, or drawn, is sent in
// Blueberry's light colors with the app name as text, rounded and in System UI, and the fault is
// logged; so is one on a deployment with no default brand, or rendered with no brands at all.
func TestRender_AnEmailWhoseBrandCannotBeReadIsDrawnUnbranded(t *testing.T) {
	unknown := kitPageBrand(record.BrandAppearanceDark, true, true, false, true)
	unknown.Theme = "kiwi"
	unknown.Corners = record.BrandCornersPill
	broken := paletteBrand(record.BrandAppearanceDark)
	broken.Palette.Dark = map[string]string{"canvas": "#000000"}
	client := reqctx.WithPageClient(context.Background(), &reqctx.PageClient{})
	reqctx.NamePageClient(client, "app-1")

	for _, tc := range []struct {
		name    string
		ctx     context.Context
		brands  *defaultBrandStub
		wantLog bool
	}{
		{"no brands", context.Background(), nil, false},
		{"no default brand", context.Background(), &defaultBrandStub{}, false},
		{"the default brand cannot be read", context.Background(), &defaultBrandStub{err: errs.New("database down")}, true},
		{"the client's brand cannot be read", client, &defaultBrandStub{clientErr: errs.New("database down")}, true},
		{"its assets cannot be read", context.Background(), &defaultBrandStub{brand: unknown, assetErr: errs.New("database down")}, true},
		{"an unknown theme", context.Background(), &defaultBrandStub{brand: unknown, assets: kitAssets}, true},
		{"a palette that cannot be drawn", context.Background(), &defaultBrandStub{brand: broken}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := logtest.CaptureSlog(t)

			email := renderBrandedEmail(t, tc.ctx, tc.brands)
			records := logs.Records()

			assert.Equal(t, "light", email.colorScheme)
			assert.Equal(t, blueberryLight, email.colors)
			assert.Equal(t, "12px", email.cardRadius)
			assert.Equal(t, systemUIFamily, email.fontFamily)
			assert.Zero(t, email.logos)
			assert.True(t, email.nameShown)
			assert.Equal(t, "Acme Portal", email.name)
			assert.Equal(t, tc.wantLog, len(records) > 0, "a fault is logged, and only a fault")
		})
	}
}

// A renderer given no base URL has no absolute URL to link a logo by, so its emails draw the app
// name as text in the logo's place.
func TestRender_AnEmailWithNoBaseURLDrawsTheNameInPlaceOfTheLogo(t *testing.T) {
	brands := &defaultBrandStub{brand: kitPageBrand(record.BrandAppearanceLight, true, false, false, true), assets: kitAssets}

	email := readEmail(t, renderEmailHTML(t, context.Background(), New(web.TemplateFS(), web.StaticFS(), brands)))

	assert.Zero(t, email.logos)
	assert.True(t, email.nameShown)
	assert.Equal(t, "Acme Portal", email.name)
}
