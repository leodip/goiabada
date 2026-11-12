package web

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The brand's footer under the card (#814) and the paragraph of links at the foot of a card
// (auth_pwd.html, auth_otp.html and others) are two components with their own type size and
// spacing. Sharing a class let the later rule restyle the other's elements, so the paragraph keeps
// `auth-footer`, declared by its one rule, and the brand's footer is `brand-footer`.
func TestUICSS_CardFooterParagraphHasItsOwnRule(t *testing.T) {
	comment := regexp.MustCompile(`(?s)/\*.*?\*/`)
	prelude := regexp.MustCompile(`([^{};]+)\{`)
	cardFooter := regexp.MustCompile(`\.auth-footer([^-\w]|$)`)

	for _, path := range []string{uiCSS, consoleUICSS} {
		css, err := os.ReadFile(path)
		require.NoError(t, err)

		var rules []string
		for _, m := range prelude.FindAllStringSubmatch(comment.ReplaceAllString(string(css), ""), -1) {
			if selector := strings.TrimSpace(m[1]); cardFooter.MatchString(selector) {
				rules = append(rules, selector)
			}
		}
		assert.Equal(t, []string{".auth-footer"}, rules, path)
	}
}
