package render

import (
	"context"
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
	"github.com/leodip/goiabada/core/logging/logtest"
)

// An email draws its brand's footer links and support contact under the card, as a page draws them
// under its card, and nothing for a brand with neither (#817 decision 2).

// emailFooterLink is a footer link as an email draws it: its href, its text and its color.
type emailFooterLink struct {
	Href, Text, Color string
}

// drawnEmailFooter is what an email draws of its brand's footer: how many footers, how many sit in
// the card, its text's color, its links, and its contact line's text and links. The text is as a
// reader sees it, without what is hidden from assistive technology, which is decoration.
type drawnEmailFooter struct {
	footers     int
	inCard      int
	color       string
	links       []emailFooterLink
	contacts    int
	contactText string
	contact     []emailFooterLink
}

func readEmailFooterLink(link *goquery.Selection) emailFooterLink {
	href, _ := link.Attr("href")
	return emailFooterLink{Href: href, Text: strings.TrimSpace(link.Text()), Color: styleOf(link)["color"]}
}

// readEmailFooter reads the footer of a rendered email. Of its paragraphs, the one whose visible
// text is all links holds the brand's links, and the one with text of its own, "Need help?", is the
// contact line.
func readEmailFooter(t *testing.T, html string) drawnEmailFooter {
	t.Helper()
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	require.NoError(t, err)

	var drawn drawnEmailFooter
	footer := doc.Find("footer")
	drawn.footers = footer.Length()
	drawn.inCard = doc.Find("body table table").First().Find("footer").Length()
	drawn.color = styleOf(footer.Closest("td"))["color"]
	footer.Find("p").Each(func(_ int, paragraph *goquery.Selection) {
		visible := paragraph.Clone()
		visible.Find(`[aria-hidden="true"]`).Remove()
		own := visible.Clone()
		own.Find("a").Remove()
		var links []emailFooterLink
		paragraph.Find("a").Each(func(_ int, link *goquery.Selection) {
			links = append(links, readEmailFooterLink(link))
		})
		if strings.TrimSpace(own.Text()) == "" {
			drawn.links = append(drawn.links, links...)
			return
		}
		drawn.contacts++
		drawn.contactText = strings.Join(strings.Fields(visible.Text()), " ")
		drawn.contact = links
	})
	return drawn
}

// clientContext is a context whose pages are drawn for the client clientIdentifier.
func clientContext(clientIdentifier string) context.Context {
	ctx := reqctx.WithPageClient(context.Background(), &reqctx.PageClient{})
	reqctx.NamePageClient(ctx, clientIdentifier)
	return ctx
}

// renderFooterEmail renders the forgot-password email in ctx, drawn in the default brand brands
// reads.
func renderFooterEmail(t *testing.T, ctx context.Context, brands *defaultBrandStub) string {
	t.Helper()
	return renderEmailHTML(t, ctx, New(web.TemplateFS(), web.StaticFS(), nilIfEmpty(brands)).WithBaseURL(emailBaseURL))
}

// A brand with three links and all three contact values draws them in a footer under the card, not
// in it: the links in their order, each under its label, then "Need help?" with the address as a
// mailto: link, the number as a tel: link and the URL under "Support page". The text is the muted ink
// of the brand's appearance and each link the brand's color, written inline, as under a page's card,
// where the footer is drawn on the page's background too.
func TestRender_AnEmailDrawsItsBrandsFooterUnderTheCard(t *testing.T) {
	for _, tc := range []struct {
		name              string
		theme             string
		appearance        record.BrandAppearance
		wantInk, wantLink string
	}{
		{"blueberry, automatic", "blueberry", record.BrandAppearanceAuto, blueberryLight.inkMuted, blueberryLight.link},
		{"plum, dark", "plum", record.BrandAppearanceDark, plumDark.inkMuted, plumDark.link},
	} {
		t.Run(tc.name, func(t *testing.T) {
			brand := footerBrand(threeLinks, "help@acme.example", "https://acme.example/support", "+442079460958")
			brand.Theme, brand.Appearance = tc.theme, tc.appearance

			footer := readEmailFooter(t, renderFooterEmail(t, context.Background(), &defaultBrandStub{brand: brand}))

			assert.Equal(t, 1, footer.footers)
			assert.Zero(t, footer.inCard, "the footer is under the card, not in it")
			assert.Equal(t, tc.wantInk, footer.color, "the footer's text is the muted ink")
			assert.Equal(t, []emailFooterLink{
				{"https://acme.example/privacy", "Privacy", tc.wantLink},
				{"https://status.acme.example/", "Status", tc.wantLink},
				{"https://acme.example/", "Acme", tc.wantLink},
			}, footer.links)
			assert.Equal(t, 1, footer.contacts)
			assert.Equal(t, "Need help? help@acme.example +442079460958 Support page", footer.contactText)
			assert.Equal(t, []emailFooterLink{
				{"mailto:help@acme.example", "help@acme.example", tc.wantLink},
				{"tel:+442079460958", "+442079460958", tc.wantLink},
				{"https://acme.example/support", "Support page", tc.wantLink},
			}, footer.contact)
		})
	}
}

// Links alone draw the links and no "Need help?" line; a contact alone draws the line and no links,
// with a link for each value set and none for the others, as a page's footer does.
func TestRender_AnEmailsFooterDrawsWhatTheBrandSets(t *testing.T) {
	const link = "#2456c4"
	for _, tc := range []struct {
		name        string
		brand       *record.Brand
		wantLinks   []emailFooterLink
		wantText    string
		wantContact []emailFooterLink
	}{
		{"links alone", footerBrand(threeLinks[1:2], "", "", ""),
			[]emailFooterLink{{"https://status.acme.example/", "Status", link}}, "", nil},
		{"the address alone", footerBrand(nil, "help@acme.example", "", ""), nil,
			"Need help? help@acme.example", []emailFooterLink{{"mailto:help@acme.example", "help@acme.example", link}}},
		{"the number alone", footerBrand(nil, "", "", "+14155550123"), nil,
			"Need help? +14155550123", []emailFooterLink{{"tel:+14155550123", "+14155550123", link}}},
		{"the support page alone", footerBrand(nil, "", "https://help.acme.example/", ""), nil,
			"Need help? Support page", []emailFooterLink{{"https://help.acme.example/", "Support page", link}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			html := renderFooterEmail(t, context.Background(), &defaultBrandStub{brand: tc.brand})
			footer := readEmailFooter(t, html)

			assert.Equal(t, 1, footer.footers)
			assert.Equal(t, tc.wantLinks, footer.links)
			if tc.wantText == "" {
				assert.Zero(t, footer.contacts, "no contact, no \"Need help?\" line")
				assert.NotContains(t, html, "Need help?")
			} else {
				assert.Equal(t, 1, footer.contacts)
			}
			assert.Equal(t, tc.wantText, footer.contactText)
			assert.Equal(t, tc.wantContact, footer.contact)
		})
	}
}

// A brand with no links and no contact draws no footer, and nor does a brand that cannot be read,
// with no fallback to another brand's: here the client's brand has none, while the default has both.
func TestRender_AnEmailOfABrandWithNoLinksAndNoContactDrawsNoFooter(t *testing.T) {
	withBoth := footerBrand(threeLinks, "help@acme.example", "", "")
	for _, tc := range []struct {
		name   string
		ctx    context.Context
		brands *defaultBrandStub
	}{
		{"an empty brand", context.Background(), &defaultBrandStub{brand: footerBrand(nil, "", "", "")}},
		{"a client's empty brand", clientContext("app-1"),
			&defaultBrandStub{brand: withBoth, clients: map[string]*record.Brand{"app-1": footerBrand(nil, "", "", "")}}},
		{"a brand that cannot be read", context.Background(), &defaultBrandStub{err: errs.New("the database went away")}},
		{"a client's brand that cannot be read", clientContext("app-1"),
			&defaultBrandStub{brand: withBoth, clientErr: errs.New("the database went away")}},
		{"no brands", context.Background(), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logtest.CaptureSlog(t)

			html := renderFooterEmail(t, tc.ctx, tc.brands)

			assert.Zero(t, readEmailFooter(t, html).footers)
			assert.NotContains(t, html, "acme.example/privacy")
			assert.NotContains(t, html, "Need help?")
		})
	}
}

// Each link is drawn with its label for the language the email is written in, the one its lang
// attribute names, and with its fallback label in a language it has none for; "Need help?" and
// "Support page" are in that language too.
func TestRender_AnEmailsFooterIsInTheEmailsLanguage(t *testing.T) {
	for _, tc := range []struct {
		locale, wantLang string
		wantLabels       []string
		wantText         string
	}{
		{"pt-BR", "pt-BR", []string{"Privacidade", "Status", "Acme"}, "Precisa de ajuda? Página de suporte"},
		{"de-AT", "de", []string{"Datenschutz", "Status", "Acme"}, "Brauchen Sie Hilfe? Supportseite"},
		{"es", "es", []string{"Privacy", "Status", "Acme"}, "¿Necesitas ayuda? Página de soporte"},
		{"sv-SE", "en", []string{"Privacy", "Status", "Acme"}, "Need help? Support page"},
	} {
		t.Run(tc.locale, func(t *testing.T) {
			brands := &defaultBrandStub{brand: footerBrand(threeLinks, "", "https://acme.example/support", "")}
			ctx := i18n.WithLocale(context.Background(), true, tc.locale, "en")

			html := renderFooterEmail(t, ctx, brands)

			doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
			require.NoError(t, err)
			lang, _ := doc.Find("html").Attr("lang")
			require.Equal(t, tc.wantLang, lang)
			footer := readEmailFooter(t, html)
			var labels []string
			for _, link := range footer.links {
				labels = append(labels, link.Text)
			}
			assert.Equal(t, tc.wantLabels, labels)
			assert.Equal(t, tc.wantText, footer.contactText)
		})
	}
}

// The address is the "to" of its mailto: link, percent-encoded where RFC 6068 section 2 says it
// must be, and shown as stored; and every value is drawn as text: a label and an address holding
// markup characters are escaped, and a stored URL that is not one a page may link is not linked.
func TestRender_AnEmailsFooterEscapesEveryValue(t *testing.T) {
	links := record.BrandFooterLinks{
		{URL: "https://acme.example/terms?a=1&b=2", Label: `<b>Terms</b> & "more"`},
		{URL: "javascript:alert(1)", Label: "Script"},
	}
	brands := &defaultBrandStub{brand: footerBrand(links, "50%41off@acme.example", "", "+1<script>")}

	html := renderFooterEmail(t, context.Background(), brands)

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	require.NoError(t, err)
	assert.Zero(t, doc.Find("footer b, footer script").Length(), "markup is drawn as text")
	footer := readEmailFooter(t, html)
	require.Len(t, footer.links, 2)
	assert.Equal(t, "https://acme.example/terms?a=1&b=2", footer.links[0].Href)
	assert.Equal(t, `<b>Terms</b> & "more"`, footer.links[0].Text)
	assert.NotContains(t, footer.links[1].Href, "javascript:", "a URL a page may not link is not linked")
	require.Len(t, footer.contact, 2)
	assert.Equal(t, "mailto:50%2541off@acme.example", footer.contact[0].Href)
	assert.Equal(t, "50%41off@acme.example", footer.contact[0].Text)
	assert.Equal(t, "+1<script>", footer.contact[1].Text)
}
