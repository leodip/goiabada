package handlers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// The whole comparison table for the ceremony binding. The function is pure, so the table costs
// nothing and every caller then needs only one accept and one reject (#79 seam 3).
func TestCeremonyMatches(t *testing.T) {
	const stored = "aBcDeFgHiJkLmNoPqRsTuVwXyZ012345"

	testCases := []struct {
		name      string
		stored    string
		submitted string
		want      bool
	}{
		{
			name:      "Equal ids",
			stored:    stored,
			submitted: stored,
			want:      true,
		},
		{
			name:      "Different ids of the same length",
			stored:    stored,
			submitted: "543210ZyXwVuTsRqPoNmLkJiHgFeDcBa",
			want:      false,
		},
		{
			// The upgrade case. An auth context written before #79 carries no id, and matching
			// "" against "" would make it accept a form naming no ceremony at all.
			name:      "Empty stored id against an empty submission",
			stored:    "",
			submitted: "",
			want:      false,
		},
		{
			name:      "Empty stored id against a real submission",
			stored:    "",
			submitted: stored,
			want:      false,
		},
		{
			// What an absent form field looks like: r.PostFormValue answers "".
			name:      "Real stored id against an absent field",
			stored:    stored,
			submitted: "",
			want:      false,
		},
		{
			name:      "Near miss, one byte differs",
			stored:    stored,
			submitted: "aBcDeFgHiJkLmNoPqRsTuVwXyZ012346",
			want:      false,
		},
		{
			// A prefix must not match, which is the family of defect #79 is about: the
			// consent selection granted a scope because "consent1" was a prefix of
			// "consent10".
			name:      "Near miss, the submission is a prefix of the stored id",
			stored:    stored,
			submitted: stored[:len(stored)-1],
			want:      false,
		},
		{
			name:      "Near miss, the submission extends the stored id",
			stored:    stored,
			submitted: stored + "x",
			want:      false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ceremonyMatches(tc.stored, tc.submitted))
		})
	}
}
