package web

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// A browser may break a Chinese line between any two characters, so at a phone width a button or
// a title can leave one character alone on its last line: "删除此账 / 户". On a label whose own
// language is Chinese, text-wrap: pretty moves a break only to keep a single character from
// standing alone ("删除此 / 账户") (#663 decision 7). It covers the short labels the Japanese rule
// covers: page titles and headings, buttons, tabs, field labels, menu entries and table headers.
// Paragraphs, hints and refusals break as they do today, and every other language is untouched,
// Japanese's own rule included. The rule sets the longhand, text-wrap-style: the text-wrap
// shorthand also resets the wrap mode, so a label another rule keeps on one line with
// white-space: nowrap, such as a table's remove button, would wrap ("移 / 除"). ui.css is one file
// in both servers, so both copies and both generated stylesheets are held to it.
func TestUICSS_ChineseLabelsDoNotEndInOneCharacterAlone(t *testing.T) {
	labels := shortLabels()
	rule := regexp.MustCompile(`([^{}]*)\{([^{}]*)\}`)
	chinese := regexp.MustCompile(`^:where\((.*)\):lang\(zh\)$`)
	space := regexp.MustCompile(`\s+`)

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

			// Every rule that wraps prettily, by the shorthand or its longhand, so a paragraph, a
			// hint or a refusal given the value by a rule of its own is caught as well as one
			// added to the labels' list, and so is the Japanese rule given it too.
			var pretty []string
			for _, match := range rule.FindAllStringSubmatch(css, -1) {
				shorthand := declarations(match[2], "text-wrap")
				longhand := declarations(match[2], "text-wrap-style")
				if !slices.Contains(shorthand, "pretty") && !slices.Contains(longhand, "pretty") {
					continue
				}
				selector := strings.TrimSpace(space.ReplaceAllString(match[1], " "))
				pretty = append(pretty, selector)
				if len(shorthand) != 0 {
					t.Errorf("%s: %s sets the text-wrap shorthand to %q, want text-wrap-style alone, so a label kept on one line by white-space: nowrap stays on one line", path, selector, shorthand)
				}
				if !slices.Equal(longhand, []string{"pretty"}) {
					t.Errorf("%s: %s sets text-wrap-style to %q, want only pretty", path, selector, longhand)
				}
				if others := declarations(match[2], "word-break"); len(others) != 0 {
					t.Errorf("%s: %s also sets word-break to %q, want the line breaks left as they are", path, selector, others)
				}
			}
			if len(pretty) != 1 {
				t.Fatalf("%s: %d rules set text-wrap: pretty (%q), want exactly one, the Chinese labels' rule", path, len(pretty), pretty)
			}

			scoped := chinese.FindStringSubmatch(pretty[0])
			if scoped == nil {
				t.Fatalf("%s: the text-wrap rule's selector is %q, want :where(<labels>):lang(zh), so only a label whose own language is Chinese wraps prettily", path, pretty[0])
			}
			var got []string
			for _, selector := range strings.Split(scoped[1], ",") {
				got = append(got, strings.TrimSpace(selector))
			}
			slices.Sort(got)
			if !slices.Equal(got, labels) {
				t.Errorf("%s: the Chinese labels' rule covers %q, want %q", path, got, labels)
			}
		})
	}
}
