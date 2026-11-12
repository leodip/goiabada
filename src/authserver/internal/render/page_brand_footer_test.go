package render

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/web"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
)

// A card page draws its brand's footer links and support contact in a footer under the card (#814
// decisions 1 to 6), in both layouts the auth server's card pages are drawn in.

// footerBackground is a background image, as stored and read without its bytes.
var footerBackground = record.BrandAsset{Id: 14, Kind: record.BrandAssetKindBackground, ContentType: "image/webp",
	Fingerprint: "444444444444", Width: 1600, Height: 900}

// footerBrand is the default brand of id 7, on Blueberry, with links and the contact given.
func footerBrand(links record.BrandFooterLinks, email, url, phone string) *record.Brand {
	brand := record.NewBrand("Shop", record.BrandAppearanceAuto, "blueberry")
	brand.Id = 7
	brand.FooterLinks = links
	brand.SupportEmail = email
	brand.SupportURL = url
	brand.SupportPhone = phone
	return &brand
}

// threeLinks are a brand's three footer links, the first with a label for pt-BR and German.
var threeLinks = record.BrandFooterLinks{
	{URL: "https://acme.example/privacy", Label: "Privacy", Labels: map[string]string{"pt-BR": "Privacidade", "de": "Datenschutz"}},
	{URL: "https://status.acme.example/", Label: "Status"},
	{URL: "https://acme.example/", Label: "Acme"},
}

// renderFooterPage renders page in layout for a browser asking for acceptLanguage, drawn in the
// default brand brands reads.
func renderFooterPage(t *testing.T, layout, page, acceptLanguage string, brands *defaultBrandStub) *goquery.Document {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if acceptLanguage != "" {
		req.Header.Set("Accept-Language", acceptLanguage)
	}
	req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{AppName: "Acme Portal"}))
	req = req.WithContext(i18n.ResolveRequestLocale(req.Context(), req))
	buf, err := New(web.TemplateFS(), web.StaticFS(), brands).RenderTemplateToBuffer(req, layout, page, map[string]interface{}{})
	require.NoError(t, err)
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(buf.String()))
	require.NoError(t, err)
	return doc
}

// drawnLink is a link as a page draws it: its href, target and rel, an absent attribute as empty,
// its visible text, and the text it says to assistive technology alone.
type drawnLink struct {
	Href, Target, Rel, Text, SrOnly string
}

func readDrawnLink(link *goquery.Selection) drawnLink {
	var drawn drawnLink
	drawn.Href, _ = link.Attr("href")
	drawn.Target, _ = link.Attr("target")
	drawn.Rel, _ = link.Attr("rel")
	drawn.SrOnly = strings.TrimSpace(link.Find(".sr-only").Text())
	visible := link.Clone()
	visible.Find(".sr-only").Remove()
	drawn.Text = strings.TrimSpace(visible.Text())
	return drawn
}

// drawnFooter is what a page draws of its brand's footer: how many footers, whether one sits in main
// or straight after it, whether it is on a panel, its links in the list, and its contact line's text
// and links.
type drawnFooter struct {
	footers     int
	inMain      int
	afterMain   int
	panel       bool
	lists       int
	links       []drawnLink
	contacts    int
	contactText string
	contact     []drawnLink
}

func readFooter(doc *goquery.Document) drawnFooter {
	var drawn drawnFooter
	footer := doc.Find("footer")
	drawn.footers = footer.Length()
	drawn.inMain = doc.Find("main footer").Length()
	drawn.afterMain = doc.Find("main + footer").Length()
	drawn.panel = footer.HasClass("brand-footer-panel")
	drawn.lists = footer.Find("ul").Length()
	footer.Find("ul > li > a").Each(func(_ int, link *goquery.Selection) {
		drawn.links = append(drawn.links, readDrawnLink(link))
	})
	contact := footer.Find("p")
	drawn.contacts = contact.Length()
	visible := contact.Clone()
	visible.Find(".sr-only").Remove()
	drawn.contactText = strings.Join(strings.Fields(visible.Text()), " ")
	contact.Find("a").Each(func(_ int, link *goquery.Selection) {
		drawn.contact = append(drawn.contact, readDrawnLink(link))
	})
	return drawn
}

const newTabRel = "noopener noreferrer"

// A brand with three links and all three contact values draws them in the page's footer landmark,
// outside main and straight after it: the links in a list, in their order, each opening a new tab
// and saying so; then "Need help?" with the address as a mailto: link, the number as a tel: link
// and the URL under "Support page", which opens a new tab too (#814 decisions 1, 4, 5 and 6).
func TestRender_TheFooterDrawsTheLinksAndTheContactUnderTheCard(t *testing.T) {
	for _, layout := range cardLayouts {
		t.Run(layout.layout, func(t *testing.T) {
			brands := &defaultBrandStub{brand: footerBrand(threeLinks, "help@acme.example", "https://acme.example/support", "+442079460958")}

			footer := readFooter(renderFooterPage(t, layout.layout, layout.page, "en", brands))

			assert.Equal(t, 1, footer.footers)
			assert.Zero(t, footer.inMain, "the footer is its own landmark, outside main")
			assert.Equal(t, 1, footer.afterMain, "the footer sits straight after main, under the card")
			assert.False(t, footer.panel, "a brand with no background image draws no panel")
			assert.Equal(t, 1, footer.lists)
			assert.Equal(t, []drawnLink{
				{"https://acme.example/privacy", "_blank", newTabRel, "Privacy", "(opens in a new tab)"},
				{"https://status.acme.example/", "_blank", newTabRel, "Status", "(opens in a new tab)"},
				{"https://acme.example/", "_blank", newTabRel, "Acme", "(opens in a new tab)"},
			}, footer.links)
			assert.Equal(t, 1, footer.contacts)
			assert.Equal(t, "Need help? help@acme.example +442079460958 Support page", footer.contactText)
			assert.Equal(t, []drawnLink{
				{"mailto:help@acme.example", "", "", "help@acme.example", ""},
				{"tel:+442079460958", "", "", "+442079460958", ""},
				{"https://acme.example/support", "_blank", newTabRel, "Support page", "(opens in a new tab)"},
			}, footer.contact)
		})
	}
}

// Links alone draw the list and no "Need help?" line; a contact alone draws the line and no list,
// with a link for each value set and none for the others (#814 decisions 1 and 4).
func TestRender_TheFooterDrawsWhatTheBrandSets(t *testing.T) {
	for _, tc := range []struct {
		name        string
		brand       *record.Brand
		wantLinks   []drawnLink
		wantText    string
		wantContact []drawnLink
	}{
		{"links alone", footerBrand(threeLinks[1:2], "", "", ""),
			[]drawnLink{{"https://status.acme.example/", "_blank", newTabRel, "Status", "(opens in a new tab)"}}, "", nil},
		{"the address alone", footerBrand(nil, "help@acme.example", "", ""), nil,
			"Need help? help@acme.example", []drawnLink{{"mailto:help@acme.example", "", "", "help@acme.example", ""}}},
		{"the number alone", footerBrand(nil, "", "", "+14155550123"), nil,
			"Need help? +14155550123", []drawnLink{{"tel:+14155550123", "", "", "+14155550123", ""}}},
		{"the support page alone", footerBrand(nil, "", "https://help.acme.example/", ""), nil,
			"Need help? Support page", []drawnLink{{"https://help.acme.example/", "_blank", newTabRel, "Support page", "(opens in a new tab)"}}},
	} {
		for _, layout := range cardLayouts {
			t.Run(layout.layout+" "+tc.name, func(t *testing.T) {
				footer := readFooter(renderFooterPage(t, layout.layout, layout.page, "en", &defaultBrandStub{brand: tc.brand}))

				assert.Equal(t, 1, footer.footers)
				assert.Equal(t, tc.wantLinks, footer.links)
				if tc.wantLinks == nil {
					assert.Zero(t, footer.lists, "no links, no list")
				}
				if tc.wantText == "" {
					assert.Zero(t, footer.contacts, "no contact, no \"Need help?\" line")
				} else {
					assert.Equal(t, 1, footer.contacts)
				}
				assert.Equal(t, tc.wantText, footer.contactText)
				assert.Equal(t, tc.wantContact, footer.contact)
			})
		}
	}
}

// A brand with no links and no contact draws no footer at all, and nor does a brand that cannot be
// read: the page is drawn as before (#814 decision 6).
func TestRender_ABrandWithNoLinksAndNoContactDrawsNoFooter(t *testing.T) {
	for _, layout := range cardLayouts {
		t.Run(layout.layout+" an empty brand", func(t *testing.T) {
			doc := renderFooterPage(t, layout.layout, layout.page, "en", &defaultBrandStub{brand: footerBrand(nil, "", "", "")})

			assert.Zero(t, doc.Find("footer").Length())
			assert.Zero(t, doc.Find(".brand-footer").Length())
		})
		t.Run(layout.layout+" a brand that cannot be read", func(t *testing.T) {
			doc := renderFooterPage(t, layout.layout, layout.page, "en", &defaultBrandStub{err: errs.New("the database went away")})

			assert.Zero(t, doc.Find("footer").Length())
		})
	}
}

// A link is drawn with its label for the language the page is written in, the one its lang
// attribute names, and with its fallback label in a language it has none for; the built-in text is
// in that language too (#814 decisions 4 and 6).
func TestRender_TheFooterIsInThePagesLanguage(t *testing.T) {
	for _, tc := range []struct {
		acceptLanguage, wantLang string
		wantLabels               []string
		wantText, wantNotice     string
	}{
		{"pt-BR", "pt-BR", []string{"Privacidade", "Status", "Acme"}, "Precisa de ajuda? Página de suporte", "(abre em uma nova aba)"},
		{"de-AT", "de", []string{"Datenschutz", "Status", "Acme"}, "Brauchen Sie Hilfe? Supportseite", "(öffnet sich in einem neuen Tab)"},
		{"es", "es", []string{"Privacy", "Status", "Acme"}, "¿Necesitas ayuda? Página de soporte", "(se abre en una pestaña nueva)"},
		{"sv-SE", "en", []string{"Privacy", "Status", "Acme"}, "Need help? Support page", "(opens in a new tab)"},
	} {
		for _, layout := range cardLayouts {
			t.Run(layout.layout+" "+tc.acceptLanguage, func(t *testing.T) {
				brands := &defaultBrandStub{brand: footerBrand(threeLinks, "", "https://acme.example/support", "")}

				doc := renderFooterPage(t, layout.layout, layout.page, tc.acceptLanguage, brands)

				lang, _ := doc.Find("html").Attr("lang")
				require.Equal(t, tc.wantLang, lang)
				footer := readFooter(doc)
				var labels []string
				for _, link := range footer.links {
					labels = append(labels, link.Text)
					assert.Equal(t, tc.wantNotice, link.SrOnly)
				}
				assert.Equal(t, tc.wantLabels, labels)
				assert.Equal(t, tc.wantText, footer.contactText)
				require.Len(t, footer.contact, 1)
				assert.Equal(t, tc.wantNotice, footer.contact[0].SrOnly)
			})
		}
	}
}

// The footer is drawn on a panel exactly while its brand has a background image, at every fit
// (#814 decision 6).
func TestRender_TheFooterIsOnAPanelOverABackgroundImage(t *testing.T) {
	for _, fit := range []record.BrandBackgroundFit{record.BrandBackgroundFitCover, record.BrandBackgroundFitContain, record.BrandBackgroundFitTile} {
		for _, layout := range cardLayouts {
			t.Run(layout.layout+" "+string(fit), func(t *testing.T) {
				brand := footerBrand(threeLinks, "", "", "")
				brand.BackgroundFit = fit
				brand.BackgroundAssetId = sql.NullInt64{Int64: 14, Valid: true}
				brands := &defaultBrandStub{brand: brand, assets: []record.BrandAsset{footerBackground}}

				footer := readFooter(renderFooterPage(t, layout.layout, layout.page, "en", brands))

				assert.Equal(t, 1, footer.footers)
				assert.True(t, footer.panel)
			})
		}
	}
}

// The address is the "to" of its mailto: link, percent-encoded where RFC 6068 section 2 says it
// must be, a "%" among it, and shown as stored (#814 decision 1). A "%" followed by two hex digits
// is the case that matters: left as it is, a mail program would read "50%41off" as "50Aoff".
func TestRender_TheMailtoLinkEncodesTheAddress(t *testing.T) {
	for _, tc := range []struct{ address, wantHref string }{
		{"100%pure@acme.example", "mailto:100%25pure@acme.example"},
		{"50%41off@acme.example", "mailto:50%2541off@acme.example"},
	} {
		for _, layout := range cardLayouts {
			t.Run(layout.layout+" "+tc.address, func(t *testing.T) {
				brands := &defaultBrandStub{brand: footerBrand(nil, tc.address, "", "")}

				footer := readFooter(renderFooterPage(t, layout.layout, layout.page, "en", brands))

				assert.Equal(t, []drawnLink{{tc.wantHref, "", "", tc.address, ""}}, footer.contact)
			})
		}
	}
}

// Every value is drawn as text: a label and an address holding markup characters are escaped, and a
// stored URL that is not one a page may link, which no write stores, is not linked.
func TestRender_TheFooterEscapesEveryValue(t *testing.T) {
	links := record.BrandFooterLinks{
		{URL: "https://acme.example/terms?a=1&b=2", Label: `<b>Terms</b> & "more"`},
		{URL: "javascript:alert(1)", Label: "Script"},
	}
	for _, layout := range cardLayouts {
		t.Run(layout.layout, func(t *testing.T) {
			brands := &defaultBrandStub{brand: footerBrand(links, `<i>x</i>@acme.example`, "", "+1<script>")}

			doc := renderFooterPage(t, layout.layout, layout.page, "en", brands)

			assert.Zero(t, doc.Find("footer b, footer i, footer script").Length(), "markup is drawn as text")
			footer := readFooter(doc)
			require.Len(t, footer.links, 2)
			assert.Equal(t, `<b>Terms</b> & "more"`, footer.links[0].Text)
			assert.Equal(t, "https://acme.example/terms?a=1&b=2", footer.links[0].Href)
			assert.False(t, strings.HasPrefix(footer.links[1].Href, "javascript:"), "got %q", footer.links[1].Href)
			require.Len(t, footer.contact, 2)
			assert.Equal(t, `<i>x</i>@acme.example`, footer.contact[0].Text)
			assert.Equal(t, "+1<script>", footer.contact[1].Text)
		})
	}
}
