package data

import (
	"strconv"
	"testing"
)

// TestParseDialect is the whole parse table for GOIABADA_DB_TYPE. Every consumer of the dialect
// parses through ParseDialect, so this is the one place each input is pinned; the server's dispatch
// table and the test-database drop each carry one or two thin rows of their own (#438 decision 6).
func TestParseDialect(t *testing.T) {
	refusal := func(v string, n int) string {
		return "unsupported database type: " + v + " (string length " + strconv.Itoa(n) + "). supported types are: mysql, sqlite, postgres, mssql"
	}

	cases := []struct {
		in      string
		want    Dialect
		wantErr string
		why     string
	}{
		{in: "sqlite", want: SQLite, why: "the first of the four names"},
		{in: "mysql", want: MySQL, why: "the second of the four names"},
		{in: "postgres", want: Postgres, why: "the third of the four names"},
		{in: "mssql", want: MSSQL, why: "the fourth of the four names"},
		{in: `"mysql"`, want: MySQL, why: "surrounding double quotes are trimmed, because an environment variable often carries them"},
		{in: `'postgres'`, want: Postgres, why: "surrounding single quotes are trimmed too"},

		{in: `"mysql`, want: MySQL, why: "a chosen leniency: the trim is per side, so an unbalanced leading quote is accepted as the server always accepted it"},
		{in: `'mysql"`, want: MySQL, why: "a chosen leniency: the two quote kinds are one set, so mismatched quotes are accepted as the server always accepted them"},

		{in: "", wantErr: refusal("", 0), why: "a set-but-empty GOIABADA_DB_TYPE is refused, never read as the in-memory SQLite default"},
		{in: "wat", wantErr: refusal("wat", 3), why: "an unknown engine is refused"},
		{in: `"wat"`, wantErr: refusal("wat", 3), why: "the refusal prints the trimmed value and its length"},
		{in: "mysql ", wantErr: refusal("mysql ", 6), why: "whitespace is not trimmed: the length shows the invisible trailing space"},
		{in: " mysql", wantErr: refusal(" mysql", 6), why: "nor leading whitespace"},
		{in: "MySQL", wantErr: refusal("MySQL", 5), why: "case is not folded"},
	}

	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseDialect(tc.in)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("ParseDialect(%q) = %q, nil; want the refusal (%s)", tc.in, got, tc.why)
				}
				if err.Error() != tc.wantErr {
					t.Errorf("ParseDialect(%q) error\n got: %s\nwant: %s\n(%s)", tc.in, err.Error(), tc.wantErr, tc.why)
				}
				if got != "" {
					t.Errorf("ParseDialect(%q) = %q beside its refusal, want the zero Dialect (%s)", tc.in, got, tc.why)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseDialect(%q) refused: %v (%s)", tc.in, err, tc.why)
			}
			if got != tc.want {
				t.Errorf("ParseDialect(%q) = %q, want %q (%s)", tc.in, got, tc.want, tc.why)
			}
		})
	}
}
