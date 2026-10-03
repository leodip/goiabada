package apihandlers

import (
	"regexp"
	"testing"
)

// TestGenerateEmailVerificationCode_Format is seam 5: the shape both call sites now share.
//
// The format is the entropy. Three letters plus three digits was 24.1 bits, which falls to
// a flag-off deployment in about an hour of sustained guessing; four plus four is 32.1
// (#219). Asserted over many draws rather than one, because a generator that emitted the
// right shape only most of the time would pass a single sample.
func TestGenerateEmailVerificationCode_Format(t *testing.T) {
	const draws = 2000
	format := regexp.MustCompile(`^[A-Z]{4}[0-9]{4}$`)

	for i := 0; i < draws; i++ {
		if code := generateEmailVerificationCode(); !format.MatchString(code) {
			t.Fatalf("draw %d: %q does not match %s", i+1, code, format)
		}
	}
}

// TestGenerateEmailVerificationCode_Distribution is a coarse, non-flaky check that every
// letter and every digit is reachable and none dominates, in the style of
// TestGenerateRandomNumberString_Distribution. Tolerance is deliberately wide: what it
// guards against is a gross bias regression, not a statistical claim.
//
// It also catches the failure that would quietly halve the space: an alphabet carrying both
// cases. The comparison accepts a code in either case, so two distinct codes would verify
// each other.
func TestGenerateEmailVerificationCode_Distribution(t *testing.T) {
	const draws = 20000

	letters := map[byte]int{}
	digits := map[byte]int{}
	for i := 0; i < draws; i++ {
		code := generateEmailVerificationCode()
		for j := 0; j < 4; j++ {
			letters[code[j]]++
		}
		for j := 4; j < 8; j++ {
			digits[code[j]]++
		}
	}

	if len(letters) != 26 {
		t.Errorf("saw %d distinct letters over %d draws, want 26", len(letters), draws)
	}
	if len(digits) != 10 {
		t.Errorf("saw %d distinct digits over %d draws, want 10", len(digits), draws)
	}

	assertEven := func(name string, counts map[byte]int, alphabetSize int) {
		t.Helper()
		expected := draws * 4 / alphabetSize
		lo, hi := expected*70/100, expected*130/100
		for c, n := range counts {
			if n < lo || n > hi {
				t.Errorf("%s %q appeared %d times, outside [%d, %d]", name, c, n, lo, hi)
			}
		}
	}
	assertEven("letter", letters, 26)
	assertEven("digit", digits, 10)
}
