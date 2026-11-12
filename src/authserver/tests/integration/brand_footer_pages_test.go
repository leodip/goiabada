package integration

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The pages draw the default brand's footer links and support contact under the card, as stored on
// a real engine, and the public settings carry them (#814 decisions 1 to 6 and 9).

// pageFooterLink is a link a page's footer draws: its href, target and rel, its visible text and
// what it says to assistive technology alone.
type pageFooterLink struct {
	Href, Target, Rel, Text, SrOnly string
}

// pageFooter is what a page draws of its brand's footer: how many footer landmarks, whether one sits
// inside main or straight after it, the links in its list, and its contact line's text and links.
type pageFooter struct {
	footers, inMain, afterMain int
	links                      []pageFooterLink
	contactText                string
	contact                    []pageFooterLink
}

func readPageFooterLinks(links *goquery.Selection) []pageFooterLink {
	var drawn []pageFooterLink
	links.Each(func(_ int, link *goquery.Selection) {
		var l pageFooterLink
		l.Href, _ = link.Attr("href")
		l.Target, _ = link.Attr("target")
		l.Rel, _ = link.Attr("rel")
		l.SrOnly = strings.TrimSpace(link.Find(".sr-only").Text())
		visible := link.Clone()
		visible.Find(".sr-only").Remove()
		l.Text = strings.TrimSpace(visible.Text())
		drawn = append(drawn, l)
	})
	return drawn
}

func readPageFooter(t *testing.T, resp *http.Response) pageFooter {
	t.Helper()
	doc := parseHTMLResponse(t, resp)
	footer := doc.Find("footer")
	contact := footer.Find("p")
	visible := contact.Clone()
	visible.Find(".sr-only").Remove()
	return pageFooter{
		footers:     footer.Length(),
		inMain:      doc.Find("main footer").Length(),
		afterMain:   doc.Find("main + footer").Length(),
		links:       readPageFooterLinks(footer.Find("ul > li > a")),
		contactText: strings.Join(strings.Fields(visible.Text()), " "),
		contact:     readPageFooterLinks(contact.Find("a")),
	}
}

func TestPages_TheDefaultBrandsFooterIsDrawnUnderTheCard(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	_, created := keepDefaultBrand(t)
	// Three links, the first labelled in every built-in language, and all three contact values, the
	// address holding a "%".
	status, answer, _ := brandCall(t, accessToken, http.MethodPost, brandsPath, footerBrandBody(brandName("Footer pages")))
	require.Equal(t, http.StatusCreated, status, "%v", answer)
	id := int64(answer["brand"].(map[string]any)["id"].(float64))
	*created = append(*created, id)
	status, answer, _ = brandCall(t, accessToken, http.MethodPost, brandPath(id, "/make-default"), nil)
	require.Equal(t, http.StatusOK, status, "%v", answer)

	base := appConfig.AuthServer.BaseURL
	client := newFormPostClient(t)
	const rel = "noopener noreferrer"

	for _, tc := range []struct {
		name, language string
		load           func(t *testing.T, browser *http.Client) *http.Response
		wantLabels     []string
		wantText       string
		wantNotice     string
		wantSupport    string
	}{
		{"the password page", "en", func(t *testing.T, browser *http.Client) *http.Response {
			params := formPostAuthorizeParams(client, "code", "", formPostHTTPSURI, "")
			resp := loadPage(t, browser, base+"/auth/authorize?"+params.Encode())
			location := assertRedirect(t, resp, "/auth/level1")
			_ = resp.Body.Close()
			resp = loadPage(t, browser, location)
			location = assertRedirect(t, resp, "/auth/pwd")
			_ = resp.Body.Close()
			return loadPage(t, browser, location)
		}, []string{"Privacy notice", "Status", "Acme & Co"},
			"Need help? help+desk%2@acme.example +442079460958 Support page", "(opens in a new tab)", "Support page"},
		{"the not-found page, in German", "de", func(t *testing.T, browser *http.Client) *http.Response {
			return loadPage(t, browser, base+"/no-such-page-footer")
		}, []string{"Datenschutz", "Status", "Acme & Co"},
			"Brauchen Sie Hilfe? help+desk%2@acme.example +442079460958 Supportseite", "(öffnet sich in einem neuen Tab)", "Supportseite"},
		{"the form_post page", "en", func(t *testing.T, browser *http.Client) *http.Response {
			params := formPostAuthorizeParams(client, "code", "form_post", formPostHTTPSURI, "none")
			return loadPage(t, browser, base+"/auth/authorize?"+params.Encode())
		}, []string{"Privacy notice", "Status", "Acme & Co"},
			"Need help? help+desk%2@acme.example +442079460958 Support page", "(opens in a new tab)", "Support page"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := tc.load(t, browserAskingFor(t, tc.language))
			defer func() { _ = resp.Body.Close() }()

			footer := readPageFooter(t, resp)
			assert.Equal(t, 1, footer.footers)
			assert.Zero(t, footer.inMain, "the footer is its own landmark, outside main")
			assert.Equal(t, 1, footer.afterMain, "the footer sits straight under the card")
			assert.Equal(t, []pageFooterLink{
				{"https://acme.example/privacy", "_blank", rel, tc.wantLabels[0], tc.wantNotice},
				{"https://status.acme.example", "_blank", rel, tc.wantLabels[1], tc.wantNotice},
				{"https://acme.example", "_blank", rel, tc.wantLabels[2], tc.wantNotice},
			}, footer.links)
			assert.Equal(t, tc.wantText, footer.contactText)
			assert.Equal(t, []pageFooterLink{
				{"mailto:help+desk%252@acme.example", "", "", "help+desk%2@acme.example", ""},
				{"tel:+442079460958", "", "", "+442079460958", ""},
				{"https://help.acme.example/contact", "_blank", rel, tc.wantSupport, tc.wantNotice},
			}, footer.contact)
		})
	}

	// The public settings carry the same brand's links with every label, and its contact, for the
	// admin console's pages, whose own client has no brand of its own.
	browser := createHttpClient(t)
	status, settings, _ := getStylesheet(t, browser, base+"/api/public/settings")
	require.Equal(t, http.StatusOK, status)
	var published struct {
		Brand struct {
			FooterLinks []struct {
				Url    string            `json:"url"`
				Label  string            `json:"label"`
				Labels map[string]string `json:"labels"`
			} `json:"footerLinks"`
			SupportEmail string `json:"supportEmail"`
			SupportURL   string `json:"supportUrl"`
			SupportPhone string `json:"supportPhone"`
		} `json:"brand"`
	}
	require.NoError(t, json.Unmarshal([]byte(settings), &published))
	require.Len(t, published.Brand.FooterLinks, 3)
	assert.Equal(t, "https://acme.example/privacy", published.Brand.FooterLinks[0].Url)
	assert.Equal(t, "Privacy", published.Brand.FooterLinks[0].Label)
	assert.Equal(t, map[string]string{"en": "Privacy notice", "de": "Datenschutz", "es": "Privacidad",
		"fr": "Confidentialité", "it": "Riservatezza", "pt-BR": "Privacidade"}, published.Brand.FooterLinks[0].Labels)
	assert.Equal(t, map[string]string{}, published.Brand.FooterLinks[1].Labels)
	assert.Equal(t, "help+desk%2@acme.example", published.Brand.SupportEmail)
	assert.Equal(t, "https://help.acme.example/contact", published.Brand.SupportURL)
	assert.Equal(t, "+442079460958", published.Brand.SupportPhone)
}

// A default brand with no links and no contact draws no footer.
func TestPages_ABrandWithNoFooterDrawsNone(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	_, created := keepDefaultBrand(t)
	id := createBrandOverAPI(t, accessToken, created, brandName("No footer"), "auto", "guava")
	status, answer, _ := brandCall(t, accessToken, http.MethodPost, brandPath(id, "/make-default"), nil)
	require.Equal(t, http.StatusOK, status, "%v", answer)

	resp := loadPage(t, createHttpClient(t), appConfig.AuthServer.BaseURL+"/no-such-page-no-footer")
	defer func() { _ = resp.Body.Close() }()

	assert.Zero(t, readPageFooter(t, resp).footers)
}
