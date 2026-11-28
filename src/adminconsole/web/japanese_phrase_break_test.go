package web

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// shortLabels returns, sorted, the selectors of the short labels a language's line-break rule
// covers: page titles and headings, buttons, tabs, field labels, menu entries and table headers.
func shortLabels() []string {
	labels := []string{
		// Page titles and headings.
		".page-title", ".panel-title", ".auth-title", ".auth-section-title", ".dialog-title",
		".brand-preview-title", ".nav-section",
		// Buttons and tabs.
		".button", ".tab-item",
		// Field labels.
		".field-label", ".choice-label", ".detail-list dt",
		// Menu entries.
		".nav-link", ".user-menu-link", ".link-row-title",
		// Table headers.
		".data-table th",
	}
	slices.Sort(labels)
	return labels
}

// A browser may break a Japanese line between any two characters, so a title or a label breaks in
// the middle of a word at a phone width: "管理者による二要素認証の無 / 効化". On a page whose
// language is Japanese, the short labels break between phrases instead (#662 decision 7): page
// titles and headings, buttons, tabs, field labels, menu entries and table headers. Paragraphs,
// hints and refusals break as they do today, since phrase breaking makes a long text ragged, and
// every other language is untouched. The rule asks for the language of the label itself, so a
// label marked as another language on a Japanese page, such as an email template's language tab,
// keeps its own. ui.css is one file in both servers, so both copies and both generated stylesheets
// are held to it.
func TestUICSS_JapaneseLabelsBreakBetweenPhrases(t *testing.T) {
	labels := shortLabels()
	rule := regexp.MustCompile(`([^{}]*)\{([^{}]*)\}`)
	japanese := regexp.MustCompile(`^:where\((.*)\):lang\(ja\)$`)
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

			// Every rule that breaks between phrases, so a paragraph, a hint or a refusal given the
			// value by a rule of its own is caught as well as one added to the labels' list.
			var breaking []string
			for _, match := range rule.FindAllStringSubmatch(css, -1) {
				values := declarations(match[2], "word-break")
				if !slices.Contains(values, "auto-phrase") {
					continue
				}
				selector := strings.TrimSpace(space.ReplaceAllString(match[1], " "))
				breaking = append(breaking, selector)
				if len(values) != 1 {
					t.Errorf("%s: %s sets word-break to %q, want only auto-phrase", path, selector, values)
				}
			}
			if len(breaking) != 1 {
				t.Fatalf("%s: %d rules break between phrases (%q), want exactly one, the Japanese labels' rule", path, len(breaking), breaking)
			}

			scoped := japanese.FindStringSubmatch(breaking[0])
			if scoped == nil {
				t.Fatalf("%s: the word-break rule's selector is %q, want :where(<labels>):lang(ja), so only a label whose own language is Japanese breaks between phrases", path, breaking[0])
			}
			var got []string
			for _, selector := range strings.Split(scoped[1], ",") {
				got = append(got, strings.TrimSpace(selector))
			}
			slices.Sort(got)
			if !slices.Equal(got, labels) {
				t.Errorf("%s: the Japanese labels' rule covers %q, want %q", path, got, labels)
			}
		})
	}
}
