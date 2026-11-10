package web

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// A text link is underlined wherever it is drawn, a table's cells included. Without the underline a
// link in a table is told from the text beside it by its color alone, which is 2.52:1 on Blueberry
// in light and as low as 1.31:1 on Blackberry in dark, where WCAG 2.2 SC 1.4.1 Use of Color asks
// 3:1 (#810 decision 8). ui.css is one file in both servers, so both copies and both generated
// stylesheets are held to it.
func TestUICSS_TextLinksAreUnderlinedInTables(t *testing.T) {
	textLink := regexp.MustCompile(`\.text-link(?:[^-\w]|$)`)
	rule := regexp.MustCompile(`([^{}]+)\{([^{}]*)\}`)

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

			base := cssRule(t, path, css, ".text-link")
			if got := declarations(base, "text-decoration"); len(got) != 1 || got[0] != "underline" {
				t.Errorf("%s: .text-link's text-decoration is %q, want only underline", path, got)
			}

			for _, match := range rule.FindAllStringSubmatch(css, -1) {
				selector := strings.TrimSpace(match[1])
				if !textLink.MatchString(selector) {
					continue
				}
				for _, property := range []string{"text-decoration", "text-decoration-line"} {
					for _, value := range declarations(match[2], property) {
						if strings.Contains(value, "none") {
							t.Errorf("%s: %s sets %s: %s, which takes a text link's underline away", path, selector, property, value)
						}
					}
				}
			}
		})
	}
}
