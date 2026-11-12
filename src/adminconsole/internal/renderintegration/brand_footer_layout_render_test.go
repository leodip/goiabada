package renderintegration

import (
	"regexp"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The console draws its brand's footer links and support contact on its end-user pages (#814
// decisions 1 to 7). On a card page, home and each error page, the footer sits under the card. On
// an Account page it sits at the foot of the content. Either way it is the page's footer landmark,
// straight after main. An admin page draws none. Each link's label is the one for the language the
// page is written in, picked from the public settings' brand.

// footerLinks are a brand's three footer links as the public settings carry them, the first with a
// label for pt-BR and German.
var footerLinks = []api.BrandFooterLinkResponse{
	{Url: "https://acme.example/privacy", Label: "Privacy", Labels: map[string]string{"pt-BR": "Privacidade", "de": "Datenschutz"}},
	{Url: "https://status.acme.example/", Label: "Status", Labels: map[string]string{}},
	{Url: "https://acme.example/", Label: "Acme", Labels: map[string]string{}},
}

// footerBrand is kitBrand with links and the contact given.
func footerBrand(links []api.BrandFooterLinkResponse, email, url, phone string) *api.PublicBrandResponse {
	brand := kitBrand("auto")
	brand.FooterLinks = links
	brand.SupportEmail = email
	brand.SupportURL = url
	brand.SupportPhone = phone
	return brand
}

var (
	footerRe       = regexp.MustCompile(`(?s)<footer[ >].*?</footer>`)
	betweenTagsRe  = regexp.MustCompile(`>\s+<`)
	mainThenFooter = regexp.MustCompile(`(?s)</main>\s*<footer[ >]`)
)

// footersOf answers each footer a page draws, with the whitespace between its tags removed.
func footersOf(out string) []string {
	var footers []string
	for _, footer := range footerRe.FindAllString(out, -1) {
		footers = append(footers, betweenTagsRe.ReplaceAllString(footer, "><"))
	}
	return footers
}

// The footer's markup, written out here as a page must draw it: the links in a list, each opening
// a new tab and saying so to assistive technology; then "Need help?" with the address as a mailto:
// link, the number as a tel: link and the URL under "Support page".
const (
	threeLinksMarkup = `<ul class="auth-footer-links">` +
		`<li><a class="auth-footer-link" href="https://acme.example/privacy" target="_blank" rel="noopener noreferrer">Privacy<span class="sr-only"> (opens in a new tab)</span></a></li>` +
		`<li><a class="auth-footer-link" href="https://status.acme.example/" target="_blank" rel="noopener noreferrer">Status<span class="sr-only"> (opens in a new tab)</span></a></li>` +
		`<li><a class="auth-footer-link" href="https://acme.example/" target="_blank" rel="noopener noreferrer">Acme<span class="sr-only"> (opens in a new tab)</span></a></li>` +
		`</ul>`
	fullContactMarkup = `<p class="auth-footer-contact"><span>Need help?</span>` +
		`<a class="auth-footer-link" href="mailto:help@acme.example">help@acme.example</a>` +
		`<a class="auth-footer-link" href="tel:&#43;442079460958">&#43;442079460958</a>` +
		`<a class="auth-footer-link" href="https://acme.example/support" target="_blank" rel="noopener noreferrer">Support page<span class="sr-only"> (opens in a new tab)</span></a>` +
		`</p>`
)

// A card page draws the footer under its card, the page's footer landmark straight after main.
func TestRender_TheConsolesCardPagesDrawTheFooterUnderTheCard(t *testing.T) {
	brand := footerBrand(footerLinks, "help@acme.example", "https://acme.example/support", "+442079460958")
	for _, p := range []consolePage{homeConsolePage, errorConsolePage} {
		t.Run(p.name, func(t *testing.T) {
			out := renderConsolePage(t, p, brand)

			assert.Equal(t, []string{`<footer class="auth-footer">` + threeLinksMarkup + fullContactMarkup + `</footer>`}, footersOf(out))
			assert.Regexp(t, mainThenFooter, out, "the footer sits straight after main, outside it")
			assert.Regexp(t, `(?s)<div class="auth-page">\s*<main id="main" class="auth-main">`, out,
				"main and the footer share the page that draws the brand's background")
		})
	}
}

// An Account page draws the footer at the foot of its content, straight after main. It is never on a
// panel, as an Account page draws no background image (#814 decision 7).
func TestRender_TheConsolesAccountPagesDrawTheFooterAfterTheContent(t *testing.T) {
	brand := footerBrand(footerLinks, "help@acme.example", "https://acme.example/support", "+442079460958")
	brand.HasBackground = true

	out := renderConsolePage(t, accountConsolePage, brand)

	assert.Equal(t, []string{`<footer class="auth-footer app-footer">` + threeLinksMarkup + fullContactMarkup + `</footer>`}, footersOf(out))
	assert.Regexp(t, mainThenFooter, out, "the footer sits straight after main, outside it")
}

// An admin page draws no footer, whatever its brand holds.
func TestRender_TheConsolesAdminPagesDrawNoFooter(t *testing.T) {
	brand := footerBrand(footerLinks, "help@acme.example", "https://acme.example/support", "+442079460958")
	brand.HasBackground = true

	out := renderConsolePage(t, adminConsolePage, brand)

	assert.Empty(t, footersOf(out))
	assert.NotContains(t, out, "auth-footer")
}

// A card page's footer is on a panel exactly while its brand has a background image (#814 decision
// 6, D1).
func TestRender_TheConsolesCardFooterIsOnAPanelOverABackgroundImage(t *testing.T) {
	for _, hasBackground := range []bool{true, false} {
		for _, p := range []consolePage{homeConsolePage, errorConsolePage} {
			brand := footerBrand(footerLinks[1:2], "", "", "")
			brand.HasBackground = hasBackground

			footers := footersOf(renderConsolePage(t, p, brand))

			require.Len(t, footers, 1, p.name)
			if hasBackground {
				assert.True(t, strings.HasPrefix(footers[0], `<footer class="auth-footer auth-footer-panel">`), "%s: %s", p.name, footers[0])
			} else {
				assert.True(t, strings.HasPrefix(footers[0], `<footer class="auth-footer">`), "%s: %s", p.name, footers[0])
			}
		}
	}
}

// Links alone draw the list and no "Need help?" line; a contact alone draws the line and no list,
// with a link for each value set and none for the others (#814 decisions 1 and 4).
func TestRender_TheConsolesFooterDrawsWhatTheBrandSets(t *testing.T) {
	for _, tc := range []struct {
		name  string
		brand *api.PublicBrandResponse
		want  string
	}{
		{"links alone", footerBrand(footerLinks[1:2], "", "", ""), `<ul class="auth-footer-links">` +
			`<li><a class="auth-footer-link" href="https://status.acme.example/" target="_blank" rel="noopener noreferrer">Status<span class="sr-only"> (opens in a new tab)</span></a></li></ul>`},
		{"the address alone", footerBrand(nil, "help@acme.example", "", ""), `<p class="auth-footer-contact"><span>Need help?</span>` +
			`<a class="auth-footer-link" href="mailto:help@acme.example">help@acme.example</a></p>`},
		{"the number alone", footerBrand(nil, "", "", "+14155550123"), `<p class="auth-footer-contact"><span>Need help?</span>` +
			`<a class="auth-footer-link" href="tel:&#43;14155550123">&#43;14155550123</a></p>`},
		{"the support page alone", footerBrand(nil, "", "https://help.acme.example/", ""), `<p class="auth-footer-contact"><span>Need help?</span>` +
			`<a class="auth-footer-link" href="https://help.acme.example/" target="_blank" rel="noopener noreferrer">Support page<span class="sr-only"> (opens in a new tab)</span></a></p>`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, []string{`<footer class="auth-footer">` + tc.want + `</footer>`}, footersOf(renderConsolePage(t, homeConsolePage, tc.brand)))
			assert.Equal(t, []string{`<footer class="auth-footer app-footer">` + tc.want + `</footer>`}, footersOf(renderConsolePage(t, accountConsolePage, tc.brand)))
		})
	}
}

// A brand with no links and no contact draws no footer at all, and nor does a console with no brand:
// the page is drawn as before (#814 decision 6).
func TestRender_TheConsoleDrawsNoFooterForABrandWithNoLinksAndNoContact(t *testing.T) {
	for name, brand := range map[string]*api.PublicBrandResponse{
		"an empty brand":                    footerBrand([]api.BrandFooterLinkResponse{}, "", "", ""),
		"an empty brand over a background":  func() *api.PublicBrandResponse { b := footerBrand(nil, "", "", ""); b.HasBackground = true; return b }(),
		"no brand, as from an older server": nil,
	} {
		for _, p := range []consolePage{homeConsolePage, errorConsolePage, accountConsolePage} {
			out := renderConsolePage(t, p, brand)

			assert.Empty(t, footersOf(out), "%s on %s", name, p.name)
			assert.NotContains(t, out, "auth-footer", "%s on %s", name, p.name)
		}
	}
}

// A link is drawn with its label for the language the page is written in, the one its lang attribute
// names, and with its fallback label in a language it has none for; the built-in text is in that
// language too (#814 decisions 4 and 6, decision 9's shared rule).
func TestRender_TheConsolesFooterIsInThePagesLanguage(t *testing.T) {
	for _, tc := range []struct {
		lang, wantFirst, wantNotice, wantNeedHelp, wantSupport string
	}{
		{"pt-BR", "Privacidade", "(abre em uma nova aba)", "Precisa de ajuda?", "Página de suporte"},
		{"de", "Datenschutz", "(öffnet sich in einem neuen Tab)", "Brauchen Sie Hilfe?", "Supportseite"},
		{"es", "Privacy", "(se abre en una pestaña nueva)", "¿Necesitas ayuda?", "Página de soporte"},
		{"en", "Privacy", "(opens in a new tab)", "Need help?", "Support page"},
	} {
		for _, p := range []consolePage{homeConsolePage, accountConsolePage} {
			t.Run(p.name+" "+tc.lang, func(t *testing.T) {
				brand := footerBrand(footerLinks, "", "https://acme.example/support", "")
				settings := &api.PublicSettingsResponse{AppName: "Acme Portal", SMTPEnabled: true, Brand: brand}

				out := renderPageWith(t, p.path, p.layout, p.page, p.bind(), nil, tc.lang, settings)

				footers := footersOf(out)
				require.Len(t, footers, 1)
				notice := `<span class="sr-only"> ` + tc.wantNotice + `</span>`
				assert.Contains(t, footers[0], `rel="noopener noreferrer">`+tc.wantFirst+notice+`</a></li>`)
				assert.Contains(t, footers[0], `rel="noopener noreferrer">Status`+notice+`</a></li>`, "a link with no label for the language takes its fallback")
				assert.Contains(t, footers[0], `<span>`+tc.wantNeedHelp+`</span>`)
				assert.Contains(t, footers[0], `rel="noopener noreferrer">`+tc.wantSupport+notice+`</a></p>`)
			})
		}
	}
}

// The address is the "to" of its mailto: link, percent-encoded where RFC 6068 section 2 says it must
// be, a "%" among it, and shown as stored (#814 decision 1): left as it is, a mail program would read
// "50%41off" as "50Aoff".
func TestRender_TheConsolesMailtoLinkEncodesTheAddress(t *testing.T) {
	for _, tc := range []struct{ address, wantLink string }{
		{"100%pure@acme.example", `<a class="auth-footer-link" href="mailto:100%25pure@acme.example">100%pure@acme.example</a>`},
		{"50%41off@acme.example", `<a class="auth-footer-link" href="mailto:50%2541off@acme.example">50%41off@acme.example</a>`},
	} {
		footers := footersOf(renderConsolePage(t, homeConsolePage, footerBrand(nil, tc.address, "", "")))

		require.Len(t, footers, 1)
		assert.Contains(t, footers[0], tc.wantLink)
	}
}

// Every value is drawn as text: a label and an address holding markup characters are escaped, and a
// URL that is not one a page may link, which no write stores, is not linked.
func TestRender_TheConsolesFooterEscapesEveryValue(t *testing.T) {
	links := []api.BrandFooterLinkResponse{
		{Url: "https://acme.example/terms?a=1&b=2", Label: `<b>Terms</b> & "more"`},
		{Url: "javascript:alert(1)", Label: "Script"},
	}
	brand := footerBrand(links, `<i>x</i>@acme.example`, "", "+1<script>")

	footers := footersOf(renderConsolePage(t, homeConsolePage, brand))

	require.Len(t, footers, 1)
	assert.NotContains(t, footers[0], "<b>")
	assert.NotContains(t, footers[0], "<i>")
	assert.NotContains(t, footers[0], "<script>")
	assert.Contains(t, footers[0], `href="https://acme.example/terms?a=1&amp;b=2"`)
	assert.Contains(t, footers[0], `&lt;b&gt;Terms&lt;/b&gt; &amp; &#34;more&#34;`)
	assert.NotContains(t, footers[0], `href="javascript:`)
	assert.Contains(t, footers[0], `&lt;i&gt;x&lt;/i&gt;@acme.example</a>`)
	assert.Contains(t, footers[0], `&#43;1&lt;script&gt;</a>`)
}
