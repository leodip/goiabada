package render

import (
	"context"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"regexp"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/web"
	"github.com/leodip/goiabada/core/i18n"
)

// hexColor is a color as an email writes it: #rrggbb, never a variable or a name a client may not
// know.
var hexColor = regexp.MustCompile(`^#[0-9a-f]{6}$`)

// TestEmails_EveryBuiltInEmailIsDrawnInlineAlone holds every built-in email, in every language it is
// written in, to what an email client draws (#817): many clients drop a style sheet, a style element
// and a class, and none resolves a CSS variable, so an email links no style sheet, holds no style
// element and no class, and names no variable; its colors are written on the elements, the area
// behind the card, the card and each link of its body; and its logo is linked by an absolute URL,
// since an email has no page to resolve a relative one against. Each is drawn for a dark brand with
// a logo and a dark logo, and for a light brand with a logo, footer links and a support contact, so
// both of the frame's logos and its footer are held.
func TestEmails_EveryBuiltInEmailIsDrawnInlineAlone(t *testing.T) {
	bodies, err := fs.Glob(web.TemplateFS(), "emails/*.html")
	require.NoError(t, err)
	require.NotEmpty(t, bodies)

	dark := kitPageBrand(record.BrandAppearanceDark, true, true, false, false)
	dark.Theme, dark.Corners, dark.Font = "plum", record.BrandCornersPill, record.BrandFontSerif
	light := kitPageBrand(record.BrandAppearanceLight, true, false, false, true)
	light.FooterLinks = threeLinks
	light.SupportEmail, light.SupportURL, light.SupportPhone = "help@acme.example", "https://acme.example/support", "+442079460958"

	for _, body := range bodies {
		// email_x.html is English, email_x.<tag>.html is written in tag.
		name := strings.TrimSuffix(path.Base(body), ".html")
		base, lang, _ := strings.Cut(name, ".")
		if lang == "" {
			lang = "en"
		}
		for _, brand := range []*record.Brand{dark, light} {
			t.Run(name+"/"+string(brand.Appearance), func(t *testing.T) {
				ctx := reqctx.WithSettings(context.Background(), &record.Settings{AppName: "Acme Portal"})
				ctx = i18n.WithLocale(ctx, true, lang, "en")
				req := httptest.NewRequest(http.MethodPost, "/", nil).WithContext(ctx)
				brands := &defaultBrandStub{brand: brand, assets: kitAssets}
				buf, err := New(web.TemplateFS(), web.StaticFS(), brands).WithBaseURL(emailBaseURL).RenderTemplateToBuffer(req,
					"/layouts/email_layout.html", "/emails/"+base+".html", map[string]interface{}{
						"name": "Ana", "link": "https://auth.example.com/a-link", "verificationCode": "123456", "remaining": 3,
					})
				require.NoError(t, err)
				assertDrawnInlineAlone(t, buf.String())
				if len(brand.FooterLinks) > 0 && !strings.Contains(buf.String(), "<footer") {
					t.Error("an email of a brand with footer links draws its footer")
				}
			})
		}
	}
}

func assertDrawnInlineAlone(t *testing.T, html string) {
	t.Helper()
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	require.NoError(t, err)

	if doc.Find("link").Length() > 0 {
		t.Error("an email links nothing, no style sheet above all")
	}
	if doc.Find("style").Length() > 0 {
		t.Error("an email holds no style element")
	}
	if doc.Find("[class]").Length() > 0 {
		t.Error("an email names no class, which only a style sheet draws")
	}
	if strings.Contains(html, "var(") {
		t.Error("an email names no CSS variable")
	}

	// Every color is written inline, as #rrggbb: on the frame, which every email has, and on each
	// link an email's body holds.
	inlineColor := func(what string, selection *goquery.Selection, property string) {
		selection.Each(func(_ int, element *goquery.Selection) {
			if value := styleOf(element)[property]; !hexColor.MatchString(value) {
				t.Errorf("%s has %s %q, not an inline #rrggbb color", what, property, value)
			}
		})
	}
	if doc.Find("body table table td").Length() == 0 {
		t.Error("an email is drawn on a card, a table in the table behind it")
	}
	inlineColor("the area behind the card", doc.Find("body"), "background-color")
	inlineColor("the text", doc.Find("body"), "color")
	inlineColor("the card", doc.Find("body table table").First(), "background-color")
	inlineColor("the card's text", doc.Find("body table table td").First(), "color")
	inlineColor("a link", doc.Find("a"), "color")
	inlineColor("the footer's text", doc.Find("footer").Closest("td"), "color")
	if scheme, _ := doc.Find(`meta[name="color-scheme"]`).Attr("content"); scheme != "light" && scheme != "dark" {
		t.Errorf("an email declares the one scheme it is drawn in, not %q", scheme)
	}

	images := doc.Find("img")
	if images.Length() != 1 {
		t.Errorf("an email draws its brand's logo, %d images", images.Length())
	}
	images.Each(func(_ int, image *goquery.Selection) {
		src, _ := image.Attr("src")
		parsed, err := url.Parse(src)
		if err != nil || !parsed.IsAbs() || parsed.Host == "" || !strings.HasPrefix(src, emailBaseURL+"/") {
			t.Errorf("an image is linked by %q, not an absolute URL under the base URL", src)
		}
	})
}
