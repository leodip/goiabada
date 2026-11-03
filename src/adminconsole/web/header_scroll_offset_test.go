package web

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// cssRule returns the declarations of the one rule whose selector is exactly selector, a rule with
// no rule nested inside it, wherever it sits in css: at the top or inside an @layer or @media.
func cssRule(t *testing.T, name, css, selector string) string {
	t.Helper()
	rule := regexp.MustCompile(`(?m)^[ \t]*` + regexp.QuoteMeta(selector) + `[ \t]*\{([^{}]*)\}`)
	matches := rule.FindAllStringSubmatch(css, -1)
	if len(matches) != 1 {
		t.Fatalf("%s: %d rules for %s, want exactly one", name, len(matches), selector)
	}
	return matches[0][1]
}

// declarations returns every value the declarations give property, in order.
func declarations(block, property string) []string {
	declaration := regexp.MustCompile(`(?m)(?:^|;)\s*` + regexp.QuoteMeta(property) + `\s*:\s*([^;]+);`)
	var values []string
	for _, match := range declaration.FindAllStringSubmatch(block, -1) {
		values = append(values, strings.TrimSpace(match[1]))
	}
	return values
}

// The console's header stays pinned to the top of the page while the page scrolls, so a field the
// keyboard moves the focus to could sit under it, focused and out of sight (WCAG 2.2 SC 2.4.11
// Focus Not Obscured (Minimum)). The page reserves the header's height, plus a 0.5rem gap that
// keeps the focus ring whole below it, as scroll-padding-top, which every scroll to an element
// honours: Tab and Shift+Tab, focus() and scrollIntoView, the skip link and in-page links. The
// header's height is one custom property, which the header and the offset both read, so the two
// cannot drift apart (#722 decision 1).
func TestUICSS_ScrollPaddingKeepsTheFocusClearOfTheHeader(t *testing.T) {
	served, err := fs.ReadFile(staticFS, "static/main.css")
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile("tailwindcss/ui.css")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range []struct{ name, css string }{
		{"tailwindcss/ui.css", string(source)},
		{"static/main.css", string(served)},
	} {
		t.Run(file.name, func(t *testing.T) {
			heights := regexp.MustCompile(`--app-header-height\s*:\s*([^;]+);`).FindAllStringSubmatch(file.css, -1)
			if len(heights) != 1 || strings.TrimSpace(heights[0][1]) != "4rem" {
				t.Errorf("%s: --app-header-height is declared %d times (%v), want once, as 4rem", file.name, len(heights), heights)
			}

			header := cssRule(t, file.name, file.css, ".app-header")
			if got := declarations(header, "min-height"); len(got) != 1 || got[0] != "var(--app-header-height)" {
				t.Errorf("%s: .app-header's min-height is %q, want only var(--app-header-height)", file.name, got)
			}

			page := cssRule(t, file.name, file.css, "html:has(.app-header)")
			if got := declarations(page, "scroll-padding-top"); len(got) != 1 || got[0] != "calc(var(--app-header-height) + 0.5rem)" {
				t.Errorf("%s: html:has(.app-header)'s scroll-padding-top is %q, want only calc(var(--app-header-height) + 0.5rem)", file.name, got)
			}
		})
	}
}

// The rule above matches a page only while it draws the header: every console page with the menu
// does, through menu_layout.html, and no auth server page does, so ui.css, one file in both servers,
// changes nothing there.
func TestAppHeader_DrawnByTheConsolesMenuLayoutAlone(t *testing.T) {
	layout, err := fs.ReadFile(templateFS, "template/layouts/menu_layout.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(layout), `<header class="app-header">`) {
		t.Error(`layouts/menu_layout.html draws no <header class="app-header">, so html:has(.app-header) reserves no room above a focused field`)
	}

	header := regexp.MustCompile(`class="[^"]*\bapp-header\b[^-]`)
	err = filepath.WalkDir("../../authserver/web/template", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(path) != ".html" {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if header.Match(b) {
			t.Errorf("%s draws .app-header, which would give an auth server page the console's scroll offset", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
