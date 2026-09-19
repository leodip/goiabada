package mssqldb

import (
	"testing"
)

// TestQuoteIdentifier and TestQuoteLiteral pin SQL Server's half of the quoting the three server
// engines now share.
//
// The create batch names the database twice, in two syntaxes: bracketed in CREATE DATABASE and
// as an nvarchar literal compared against sys.databases.name. It was already bracketed, so this
// engine was never broken the way PostgreSQL was; what these close is a name carrying `]`, which
// escaped the brackets, and one carrying `'`, which ended the literal early (#293).
func TestQuoteIdentifier(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		{"lower case, what every existing deployment has", "goiabada", "[goiabada]"},
		{"mixed case survives, as it always did here", "Goiabada", "[Goiabada]"},
		{"a hyphen, a syntax error before quoting", "goiabada-prod", "[goiabada-prod]"},
		{"a space", "goiabada prod", "[goiabada prod]"},
		{"a closing bracket is doubled, not passed through", "go]iabada", "[go]]iabada]"},
		{"a trailing closing bracket cannot end the identifier early", "goiabada]", "[goiabada]]]"},
		{"an opening bracket needs nothing, and must not get it", "go[iabada", "[go[iabada]"},
		{"empty, which the config default never produces but the function must not mangle", "", "[]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := quoteIdentifier(tc.in); got != tc.want {
				t.Errorf("quoteIdentifier(%q) = %s, want %s", tc.in, got, tc.want)
			}
		})
	}
}

func TestQuoteLiteral(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		{"lower case, what every existing deployment has", "goiabada", "'goiabada'"},
		{"mixed case is carried verbatim; the folding is the collation's, not the literal's", "Goiabada", "'Goiabada'"},
		{"a single quote is doubled, not passed through", "go'iabada", "'go''iabada'"},
		{"a trailing single quote cannot end the literal early", "goiabada'", "'goiabada'''"},
		{"empty, which the config default never produces but the function must not mangle", "", "''"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := quoteLiteral(tc.in); got != tc.want {
				t.Errorf("quoteLiteral(%q) = %s, want %s", tc.in, got, tc.want)
			}
		})
	}
}
