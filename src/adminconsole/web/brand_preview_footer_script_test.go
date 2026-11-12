package web

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// typeIn types value into the field with that id, as a person does, and restoreValue fills it as a
// browser restoring the form does, telling nothing.
func typeIn(id, value string) previewStep { return previewStep{Do: "type", Name: id, Value: value} }
func restoreValue(id, value string) previewStep {
	return previewStep{Do: "restoreValue", Name: id, Value: value}
}

// shownText is a contact value the sample shows.
func shownText(s string) *string { return &s }

// sampleLink is a footer link of the sample as the auth server's footer draws one, but as plain text:
// a list item holding one span in the footer link's look, with nothing in it that opens anything.
func sampleLink(text string) previewFooterLink {
	return previewFooterLink{Text: text, Element: "li>span.brand-footer-link"}
}

// noFooter is a sample's footer while the form holds no link and no contact: hidden, and empty.
var noFooter = previewFooter{Hidden: true, LinksHidden: true, Links: []previewFooterLink{}, ContactHidden: true, NeedHelp: "Need help?"}

// assertBothSamplesFooter holds the light and the dark sample to the same footer.
func assertBothSamplesFooter(t *testing.T, look previewLook, want previewFooter, msg string) {
	t.Helper()
	assert.Equal(t, want, look.Samples["light"].Footer, "light: %s", msg)
	assert.Equal(t, want, look.Samples["dark"].Footer, "dark: %s", msg)
}

// The sample draws the footer as each field is typed, before anything is saved (#814 decision 12):
// each row a link in the rows' order, an empty row none, each value trimmed as the form sends it; the
// "Need help?" line with the address and the number shown as themselves, the number without the
// separators the auth server stores it without, and the URL under "Support page". A form with no link
// and no contact draws no footer at all.
func TestBrandPreviewJS_TheSampleDrawsTheFooterAsItIsTyped(t *testing.T) {
	looks := runBrandPreview(t, previewPage{themeCards: bothCards, theme: "plum", appearance: "auto"},
		load(), lookAt(),
		typeIn("footerLinks-0-label", "  Privacy  "), lookAt(),
		typeIn("footerLinks-2-label", "Status"), typeIn("footerLinks-2-url", "https://status.example.test"), lookAt(),
		typeIn("footerLinks-1-label", "Terms"), lookAt(),
		typeIn("supportPhone", " +1 (555) 010-01.99 "), lookAt(),
		typeIn("supportEmail", " help@example.test "), typeIn("supportUrl", "https://help.example.test"), lookAt(),
		typeIn("footerLinks-0-label", ""), typeIn("footerLinks-1-label", "   "), lookAt(),
		typeIn("footerLinks-2-label", ""), lookAt(),
		typeIn("supportPhone", ""), typeIn("supportEmail", "  "), lookAt(),
		typeIn("supportUrl", ""), lookAt())

	want := []struct {
		footer previewFooter
		msg    string
	}{
		{noFooter, "nothing typed"},
		{previewFooter{LinksHidden: false, Links: []previewFooterLink{sampleLink("Privacy")}, ContactHidden: true, NeedHelp: "Need help?"},
			"a label typed, trimmed"},
		{previewFooter{Links: []previewFooterLink{sampleLink("Privacy"), sampleLink("Status")}, ContactHidden: true, NeedHelp: "Need help?"},
			"the third row: the second row is empty and draws nothing"},
		{previewFooter{Links: []previewFooterLink{sampleLink("Privacy"), sampleLink("Terms"), sampleLink("Status")}, ContactHidden: true, NeedHelp: "Need help?"},
			"the second row, in its place"},
		{previewFooter{Links: []previewFooterLink{sampleLink("Privacy"), sampleLink("Terms"), sampleLink("Status")},
			NeedHelp: "Need help?", Phone: shownText("+15550100199")},
			"a number typed with separators, shown as the auth server stores it"},
		{previewFooter{Links: []previewFooterLink{sampleLink("Privacy"), sampleLink("Terms"), sampleLink("Status")},
			NeedHelp: "Need help?", Email: shownText("help@example.test"), Phone: shownText("+15550100199"), URL: shownText("Support page")},
			"the whole contact"},
		{previewFooter{Links: []previewFooterLink{sampleLink("Status")},
			NeedHelp: "Need help?", Email: shownText("help@example.test"), Phone: shownText("+15550100199"), URL: shownText("Support page")},
			"two labels emptied, one of them blank"},
		{previewFooter{LinksHidden: true, Links: []previewFooterLink{},
			NeedHelp: "Need help?", Email: shownText("help@example.test"), Phone: shownText("+15550100199"), URL: shownText("Support page")},
			"no link left: the contact alone"},
		{previewFooter{LinksHidden: true, Links: []previewFooterLink{}, NeedHelp: "Need help?", URL: shownText("Support page")},
			"the support page alone"},
		{noFooter, "nothing left"},
	}
	require.Len(t, looks, len(want))
	for i, w := range want {
		assertBothSamplesFooter(t, looks[i], w.footer, w.msg)
		assert.Empty(t, looks[i].StyledElsewhere, "look %d: only the samples are styled", i)
	}
}

// Each contact value is drawn alone, with "Need help?" before it.
func TestBrandPreviewJS_TheSampleDrawsEachContactValueAlone(t *testing.T) {
	for _, tc := range []struct {
		field, value string
		want         previewFooter
	}{
		{"supportEmail", "a%b@example.test", previewFooter{LinksHidden: true, Links: []previewFooterLink{}, NeedHelp: "Need help?", Email: shownText("a%b@example.test")}},
		{"supportPhone", "+44 20 7946 0958", previewFooter{LinksHidden: true, Links: []previewFooterLink{}, NeedHelp: "Need help?", Phone: shownText("+442079460958")}},
		{"supportUrl", "https://help.example.test/a?b=c", previewFooter{LinksHidden: true, Links: []previewFooterLink{}, NeedHelp: "Need help?", URL: shownText("Support page")}},
	} {
		t.Run(tc.field, func(t *testing.T) {
			looks := runBrandPreview(t, previewPage{themeCards: bothCards, theme: "plum", appearance: "auto"},
				load(), typeIn(tc.field, tc.value), lookAt())
			assertBothSamplesFooter(t, looks[0], tc.want, tc.field)
		})
	}
}

// Each label is drawn in the language of the console page being viewed, the one its html element's
// lang attribute names, where the row has one, else its fallback label, by the rule the auth server's
// pages pick a label by (#814 decisions 9 and 12): a blank language label is none, and a language that
// is not built in takes the fallback.
func TestBrandPreviewJS_TheSampleDrawsEachLabelInThePagesLanguage(t *testing.T) {
	footer := map[string]string{
		"footerLinks-0-label": "Privacy", "footerLinks-0-labels-de": "Datenschutz", "footerLinks-0-labels-pt-BR": "Privacidade",
		"footerLinks-1-label": "Terms", "footerLinks-1-labels-de": "   ", "footerLinks-1-labels-en": "Terms of use",
		"footerLinks-2-labels-de": "Hilfe", "footerLinks-2-url": "https://help.example.test",
	}
	for _, tc := range []struct {
		lang string
		want []previewFooterLink
	}{
		{"de", []previewFooterLink{sampleLink("Datenschutz"), sampleLink("Terms"), sampleLink("Hilfe")}},
		{"pt-BR", []previewFooterLink{sampleLink("Privacidade"), sampleLink("Terms")}},
		{"en", []previewFooterLink{sampleLink("Privacy"), sampleLink("Terms of use")}},
		{"pt", []previewFooterLink{sampleLink("Privacy"), sampleLink("Terms")}},
		{"nl", []previewFooterLink{sampleLink("Privacy"), sampleLink("Terms")}},
	} {
		t.Run(tc.lang, func(t *testing.T) {
			looks := runBrandPreview(t, previewPage{themeCards: bothCards, theme: "plum", appearance: "auto", lang: tc.lang, footer: footer},
				load(), lookAt())
			assertBothSamplesFooter(t, looks[0], previewFooter{Links: tc.want, ContactHidden: true, NeedHelp: "Need help?"}, "on load, in "+tc.lang)
		})
	}

	// A language label typed is drawn at once, and emptied gives the fallback back.
	looks := runBrandPreview(t, previewPage{themeCards: bothCards, theme: "plum", appearance: "auto", lang: "fr", footer: footer},
		load(), typeIn("footerLinks-1-labels-fr", "Conditions"), lookAt(), typeIn("footerLinks-1-labels-fr", ""), lookAt())
	assertBothSamplesFooter(t, looks[0], previewFooter{Links: []previewFooterLink{sampleLink("Privacy"), sampleLink("Conditions")},
		ContactHidden: true, NeedHelp: "Need help?"}, "a French label typed")
	assertBothSamplesFooter(t, looks[1], previewFooter{Links: []previewFooterLink{sampleLink("Privacy"), sampleLink("Terms")},
		ContactHidden: true, NeedHelp: "Need help?"}, "the French label emptied")
}

// A value holding markup characters is drawn as text: the label and the address as typed, and no
// element made from them.
func TestBrandPreviewJS_TheSampleDrawsTheFootersValuesAsText(t *testing.T) {
	looks := runBrandPreview(t, previewPage{themeCards: bothCards, theme: "plum", appearance: "auto"},
		load(), typeIn("footerLinks-0-label", `<b>Bold</b> & "co"`), typeIn("supportEmail", `<i>x</i>@example.test`), lookAt())
	assertBothSamplesFooter(t, looks[0], previewFooter{Links: []previewFooterLink{sampleLink(`<b>Bold</b> & "co"`)},
		NeedHelp: "Need help?", Email: shownText(`<i>x</i>@example.test`)}, "markup drawn as text")
}

// The footer is on the panel while the brand has a background image, whatever its fit, and on the
// sample's background color without one (#814 decision 6).
func TestBrandPreviewJS_TheSamplesFooterIsOnThePanelOverABackground(t *testing.T) {
	footer := map[string]string{"footerLinks-0-label": "Privacy", "supportEmail": "help@example.test"}
	looks := runBrandPreview(t, previewPage{themeCards: bothCards, theme: "plum", appearance: "auto", backgroundFit: "cover", footer: footer},
		load(), lookAt(),
		upload("background", "24", testBackgroundURL), lookAt(),
		pick("backgroundFit", "tile"), lookAt(),
		remove("background"), lookAt())
	for i, panel := range []bool{false, true, true, false} {
		assertBothSamplesFooter(t, looks[i], previewFooter{Panel: panel, Links: []previewFooterLink{sampleLink("Privacy")},
			NeedHelp: "Need help?", Email: shownText("help@example.test")}, fmt.Sprintf("look %d", i))
	}

	// A stored background draws the panel on load.
	looks = runBrandPreview(t, previewPage{themeCards: bothCards, theme: "plum", appearance: "auto", footer: footer,
		slots: map[string]previewSlot{"background": {ID: "24", URL: testBackgroundURL}}},
		load(), lookAt())
	assert.True(t, looks[0].Samples["light"].Footer.Panel)
	assert.True(t, looks[0].Samples["dark"].Footer.Panel)
}

// A brand's stored footer is drawn on load, and the fields a browser restores, as on Back, on pageshow.
func TestBrandPreviewJS_PageshowDrawsTheRestoredFooter(t *testing.T) {
	looks := runBrandPreview(t, previewPage{themeCards: bothCards, theme: "plum", appearance: "auto",
		footer: map[string]string{"footerLinks-0-label": "Privacy", "footerLinks-0-url": "https://example.test/privacy"}},
		lookAt(), load(), lookAt(),
		restoreValue("footerLinks-1-label", "Status"), restoreValue("supportPhone", "+49 30 1234567"), lookAt(),
		previewStep{Do: "pageshow", Persisted: true}, lookAt())

	assertBothSamplesFooter(t, looks[0], noFooter, "nothing is drawn before the script runs")
	stored := previewFooter{Links: []previewFooterLink{sampleLink("Privacy")}, ContactHidden: true, NeedHelp: "Need help?"}
	assertBothSamplesFooter(t, looks[1], stored, "the stored footer, on load")
	assertBothSamplesFooter(t, looks[2], stored, "nothing is drawn before pageshow")
	assertBothSamplesFooter(t, looks[3], previewFooter{Links: []previewFooterLink{sampleLink("Privacy"), sampleLink("Status")},
		NeedHelp: "Need help?", Phone: shownText("+49301234567")}, "the restored fields")
}
