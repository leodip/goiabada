package mysqldb

import (
	"testing"
)

// TestQuoteIdentifier pins MySQL's half of the quoting the three server engines now share.
//
// MySQL was never broken the way PostgreSQL was, since an unquoted identifier is not folded
// here, so what these cases hold is the rest of the class: a name that needs quoting for some
// other reason, and a name that could end the quoting early (#293).
func TestQuoteIdentifier(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		{"lower case, what every existing deployment has", "goiabada", "`goiabada`"},
		{"mixed case survives, as it always did here", "Goiabada", "`Goiabada`"},
		{"a hyphen, a syntax error before quoting", "goiabada-prod", "`goiabada-prod`"},
		{"a space", "goiabada prod", "`goiabada prod`"},
		{"an embedded backtick is doubled, not passed through", "go`iabada", "`go``iabada`"},
		{"a trailing backtick cannot close the identifier early", "goiabada`", "`goiabada```"},
		{"empty, which the config default never produces but the function must not mangle", "", "``"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := quoteIdentifier(tc.in); got != tc.want {
				t.Errorf("quoteIdentifier(%q) = %s, want %s", tc.in, got, tc.want)
			}
		})
	}
}
