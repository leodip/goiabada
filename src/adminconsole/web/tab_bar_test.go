package web

import (
	"os"
	"testing"
)

// A tab bar whose tabs do not fit on one line wraps them into rows of pills, and a pill wider than
// the bar breaks its text inside itself rather than overflow the page (#902). The email template
// editor's language tabs carry each language's own name beside its English name, which no catalog
// can shorten, "português (Brasil) (Portuguese (Brazil))" ending at 308 px where a 320 px window
// with a classic scrollbar leaves 305. The underlined row stays one line of unbroken tabs, which
// shell.js measures to decide whether the bar wraps. ui.css is one file in both servers, so both
// copies and both generated stylesheets are held to it.
func TestUICSS_AWrappedTabBreaksItsText(t *testing.T) {
	for _, path := range []string{
		"tailwindcss/ui.css",
		"static/main.css",
		"../../authserver/web/tailwindcss/ui.css",
		"../../authserver/web/static/main.css",
	} {
		t.Run(path, func(t *testing.T) {
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			css := cssComment.ReplaceAllString(string(b), "")

			tab := cssRule(t, path, css, ".tab-item")
			if got := declarations(tab, "white-space"); len(got) != 1 || got[0] != "nowrap" {
				t.Errorf("%s: .tab-item's white-space is %q, want only nowrap, so the underlined row is measured unbroken", path, got)
			}

			pill := cssRule(t, path, css, ".tab-bar[data-wrapped] .tab-item")
			for _, want := range []struct{ property, value, why string }{
				{"max-width", "100%", "so no pill is wider than its bar"},
				{"white-space", "normal", "so a pill's text breaks between its words"},
				{"overflow-wrap", "anywhere", "so a word longer than the bar breaks too"},
			} {
				if got := declarations(pill, want.property); len(got) != 1 || got[0] != want.value {
					t.Errorf("%s: .tab-bar[data-wrapped] .tab-item's %s is %q, want only %s, %s", path, want.property, got, want.value, want.why)
				}
			}
		})
	}
}
