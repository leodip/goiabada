package gender

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestGender_String owns the total String decision 16 of #385 settled. The in-range rows are the
// wire values the OIDC "gender" claim carries and a profile page re-renders, so they are pinned
// against literals rather than against the slice they come from. The out-of-range rows are the
// defect: probe/gender_string_test.go showed Gender(3) and Gender(-1) panicking on the index, and
// three of the four production sites that convert an int to a Gender do not range-check first.
func TestGender_String(t *testing.T) {
	testCases := []struct {
		name   string
		gender Gender
		want   string
	}{
		{"female is the zero value", GenderFemale, "female"},
		{"male", GenderMale, "male"},
		{"other, the top of the range", GenderOther, "other"},
		{"one past the range, which is what a profile form submitting gender=3 produces", Gender(3), ""},
		{"far past the range", Gender(99), ""},
		{"negative, which strconv.Atoi will happily produce from \"-1\"", Gender(-1), ""},
		{"far negative", Gender(-99), ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// No recover(): a panic here fails the test, which is the whole point of the
			// out-of-range rows.
			assert.Equal(t, tc.want, tc.gender.String())
		})
	}
}

// TestGender_StringAgreesWithIsGenderValid pins the two halves to each other. The empty string is
// what every production site writes for "no gender", so String answering it for exactly the
// integers IsGenderValid refuses is what lets a caller skip the guard without changing the outcome.
func TestGender_StringAgreesWithIsGenderValid(t *testing.T) {
	for i := -5; i <= 5; i++ {
		valid := IsGenderValid(i)
		rendered := Gender(i).String()
		if valid {
			assert.NotEmpty(t, rendered, "IsGenderValid(%d) is true, so String must name a gender", i)
		} else {
			assert.Empty(t, rendered, "IsGenderValid(%d) is false, so String must return the empty string", i)
		}
	}
}

// TestIsGenderValid covers the bound on its own, including the two edges the type's range has.
func TestIsGenderValid(t *testing.T) {
	testCases := []struct {
		name string
		in   int
		want bool
	}{
		{"the bottom of the range", 0, true},
		{"the middle", 1, true},
		{"the top of the range", 2, true},
		{"one past the top", 3, false},
		{"one below the bottom", -1, false},
		{"far outside", 1000, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, IsGenderValid(tc.in))
		})
	}
}
