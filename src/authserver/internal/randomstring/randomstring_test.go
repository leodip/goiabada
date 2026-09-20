package randomstring

import (
	"strings"
	"testing"
)

const (
	letterAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digitAlphabet  = "0123456789"
)

func TestGenerators_LengthAndAlphabet(t *testing.T) {
	cases := []struct {
		name     string
		gen      func(int) string
		alphabet string
	}{
		{"Letters", Letters, letterAlphabet},
		{"Digits", Digits, digitAlphabet},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, length := range []int{1, 6, 32, 96} {
				s := c.gen(length)
				if len(s) != length {
					t.Fatalf("len(%s(%d)) = %d, want %d", c.name, length, len(s), length)
				}
				for i := 0; i < len(s); i++ {
					if !strings.ContainsRune(c.alphabet, rune(s[i])) {
						t.Fatalf("%s produced char %q not in its alphabet", c.name, s[i])
					}
				}
			}
			// Length 0 yields an empty string.
			if got := c.gen(0); got != "" {
				t.Errorf("%s(0) = %q, want \"\"", c.name, got)
			}
		})
	}
}

// TestLetters_LettersOnly locks the #84 intent: the letter generator must never emit digits (it
// feeds the alpha half of verification codes, with the numeric half coming from Digits).
func TestLetters_LettersOnly(t *testing.T) {
	s := Letters(500)
	if len(s) != 500 {
		t.Fatalf("len = %d, want 500", len(s))
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		isLetter := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		if !isLetter {
			t.Fatalf("Letters emitted non-letter %q", c)
		}
	}
}

// TestDigits_Distribution is a coarse, non-flaky sanity check that every digit appears and no
// digit dominates, guarding against a gross bias regression. Tolerance is deliberately wide.
func TestDigits_Distribution(t *testing.T) {
	const total = 200000
	s := Digits(total)
	if len(s) != total {
		t.Fatalf("len = %d, want %d", len(s), total)
	}

	var counts [10]int
	for i := 0; i < len(s); i++ {
		counts[s[i]-'0']++
	}

	expected := total / 10 // 20000
	lo, hi := expected*70/100, expected*130/100
	for d, c := range counts {
		if c < lo || c > hi {
			t.Errorf("digit %d appeared %d times, outside [%d, %d]", d, c, lo, hi)
		}
	}
}
