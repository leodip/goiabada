package web

import (
	"maps"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// On a phone, a list table stacks: each row becomes a card, and every cell but the first is
// preceded by its column's name and a colon. Chinese and Japanese write a full-width colon with no
// space after it ("外观：自动"), as their catalogs do, where every other language writes ": ". The
// label comes from the page's catalog, so the cell's own language picks the separator. The labels
// are drawn only while the table stacks, so both rules sit in the stacking media query. ui.css is
// one file in both servers, so both copies and both generated stylesheets are held to it.
func TestUICSS_ChineseAndJapaneseTableLabelsEndInAFullWidthColon(t *testing.T) {
	const stacking = "@media (max-width: 39.99rem) {"
	rule := regexp.MustCompile(`([^{}]*)\{([^{}]*)\}`)
	space := regexp.MustCompile(`\s+`)
	want := map[string]string{
		".data-table-stack td[data-label]::before":          `attr(data-label) ": "`,
		".data-table-stack td[data-label]:lang(ja)::before": `attr(data-label) "："`,
		".data-table-stack td[data-label]:lang(zh)::before": `attr(data-label) "："`,
	}

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

			if strings.Count(css, stacking) != 1 {
				t.Fatalf("%s: want one %q block, the stacked tables' media query", path, stacking)
			}
			start := strings.Index(css, stacking) + len(stacking)
			end, depth := start, 1
			for ; end < len(css) && depth > 0; end++ {
				switch css[end] {
				case '{':
					depth++
				case '}':
					depth--
				}
			}

			// Every rule that draws a cell's label, so a separator added by a rule of its own is
			// caught as well as a change to the two expected ones.
			got := map[string]string{}
			for _, match := range rule.FindAllStringSubmatchIndex(css, -1) {
				block := css[match[4]:match[5]]
				var content string
				for _, value := range declarations(block, "content") {
					if strings.HasPrefix(value, "attr(data-label)") {
						content = value
					}
				}
				if content == "" {
					continue
				}
				selectors := strings.TrimSpace(space.ReplaceAllString(css[match[2]:match[3]], " "))
				if match[0] < start || match[1] > end {
					t.Errorf("%s: %s draws a cell's label outside %q, so a table that does not stack would show it", path, selectors, stacking)
				}
				for _, selector := range strings.Split(selectors, ",") {
					got[strings.TrimSpace(selector)] = content
				}
			}
			if !maps.Equal(got, want) {
				t.Errorf("%s: the cell labels' rules are %q (selectors %q), want %q", path, got, slices.Sorted(maps.Keys(got)), want)
			}
		})
	}
}
