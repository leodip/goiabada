package uuidtest

import (
	"errors"
	"testing"
)

// TestParse is the exhaustive table for the parser's leniency, and every row is
// a choice rather than an accident. The braced, urn:uuid: and 32-hex rows are
// the three spellings the third-party parser this package replaced accepted:
// they are here so that widening the parser back to them is a test failure
// rather than a quiet change (#278).
func TestParse(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr error
	}{
		{
			name: "canonical lowercase, returned unchanged",
			in:   "550e8400-e29b-41d4-a716-446655440000",
			want: "550e8400-e29b-41d4-a716-446655440000",
		},
		{
			name: "canonical uppercase, lowercased",
			in:   "550E8400-E29B-41D4-A716-446655440000",
			want: "550e8400-e29b-41d4-a716-446655440000",
		},
		{
			name:    "braced form, accepted by the retired parser, refused here",
			in:      "{550e8400-e29b-41d4-a716-446655440000}",
			wantErr: errWrongLength,
		},
		{
			name:    "urn:uuid: form, accepted by the retired parser, refused here",
			in:      "urn:uuid:550e8400-e29b-41d4-a716-446655440000",
			wantErr: errWrongLength,
		},
		{
			name:    "unhyphenated 32-hex form, accepted by the retired parser, refused here",
			in:      "550e8400e29b41d4a716446655440000",
			wantErr: errWrongLength,
		},
		{
			name:    "one character short",
			in:      "550e8400-e29b-41d4-a716-44665544000",
			wantErr: errWrongLength,
		},
		{
			name:    "one character long",
			in:      "550e8400-e29b-41d4-a716-4466554400000",
			wantErr: errWrongLength,
		},
		{
			name:    "non-hex character in the last position",
			in:      "550e8400-e29b-41d4-a716-44665544000g",
			wantErr: errNonHex,
		},
		{
			name:    "underscores where the hyphens belong",
			in:      "550e8400_e29b_41d4_a716_446655440000",
			wantErr: errHyphen,
		},
		// One row per separator position, because the row above cannot pin any single
		// one of them: with the check relaxed at index 8 alone, its underscore at 13
		// still raises errHyphen and the case passes over a parser that now accepts an
		// arbitrary character in the middle of a subject (#278).
		{
			name:    "an underscore at index 8 only",
			in:      "550e8400_e29b-41d4-a716-446655440000",
			wantErr: errHyphen,
		},
		{
			name:    "an underscore at index 13 only",
			in:      "550e8400-e29b_41d4-a716-446655440000",
			wantErr: errHyphen,
		},
		{
			name:    "an underscore at index 18 only",
			in:      "550e8400-e29b-41d4_a716-446655440000",
			wantErr: errHyphen,
		},
		{
			name:    "an underscore at index 23 only",
			in:      "550e8400-e29b-41d4-a716_446655440000",
			wantErr: errHyphen,
		},
		{
			name:    "empty",
			in:      "",
			wantErr: errWrongLength,
		},
		{
			name: "the nil UUID, which carries no version or variant",
			in:   "00000000-0000-0000-0000-000000000000",
			want: "00000000-0000-0000-0000-000000000000",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Parse(tc.in)

			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Parse(%q): got error %v, want %v", tc.in, err, tc.wantErr)
				}
				if got != "" {
					t.Fatalf("Parse(%q): refused but returned %q, want the empty string", tc.in, got)
				}
				return
			}

			if err != nil {
				t.Fatalf("Parse(%q): unexpected error: %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("Parse(%q): got %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
