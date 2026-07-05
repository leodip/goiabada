package stringutil

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// errReader always fails, simulating a CSPRNG failure.
type errReader struct{}

func (errReader) Read(p []byte) (int, error) { return 0, errors.New("boom") }

// TestRandomStringFromReader_RejectionSampling is the direct proof for the
// modulo-bias fix (#85): bytes at or above the rejection limit are discarded
// rather than folded onto the low end of the alphabet.
func TestRandomStringFromReader_RejectionSampling(t *testing.T) {
	const digits = "0123456789" // n=10, limit = 256 - (256 % 10) = 250

	// 250 and 251 are >= limit and must be rejected; 5 then 7 are accepted.
	src := bytes.NewReader([]byte{250, 5, 251, 7})
	got, err := randomStringFromReader(src, 2, digits)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "57" {
		t.Errorf("rejection sampling: got %q, want %q", got, "57")
	}
}

// TestRandomStringFromReader_Mapping verifies accepted bytes map to the expected
// alphabet index via b % n, including the wrap at n.
func TestRandomStringFromReader_Mapping(t *testing.T) {
	const digits = "0123456789"

	// 0->'0', 9->'9', 10->'0' (10 % 10), 15->'5' (15 % 10).
	src := bytes.NewReader([]byte{0, 9, 10, 15})
	got, err := randomStringFromReader(src, 4, digits)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "0905" {
		t.Errorf("mapping: got %q, want %q", got, "0905")
	}
}

func TestRandomStringFromReader_ErrorPropagates(t *testing.T) {
	got, err := randomStringFromReader(errReader{}, 5, "0123456789")
	if err == nil {
		t.Error("expected error from failing reader, got nil")
	}
	if got != "" {
		t.Errorf("expected empty string on error, got %q", got)
	}
}

func TestRandomStringFromReader_NonPositiveLengthAndEmptyAlphabet(t *testing.T) {
	if got, err := randomStringFromReader(errReader{}, 0, "abc"); err != nil || got != "" {
		t.Errorf("length 0: got (%q, %v), want (\"\", nil) without touching the reader", got, err)
	}
	if got, err := randomStringFromReader(errReader{}, -1, "abc"); err != nil || got != "" {
		t.Errorf("negative length: got (%q, %v), want (\"\", nil)", got, err)
	}
	if got, err := randomStringFromReader(errReader{}, 5, ""); err != nil || got != "" {
		t.Errorf("empty alphabet: got (%q, %v), want (\"\", nil)", got, err)
	}
}

func TestGenerators_LengthAndAlphabet(t *testing.T) {
	const (
		securityAlphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_."
		letterAlphabet   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
		numberAlphabet   = "0123456789"
	)

	cases := []struct {
		name     string
		gen      func(int) string
		alphabet string
	}{
		{"GenerateSecurityRandomString", GenerateSecurityRandomString, securityAlphabet},
		{"GenerateRandomLetterString", GenerateRandomLetterString, letterAlphabet},
		{"GenerateRandomNumberString", GenerateRandomNumberString, numberAlphabet},
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

// TestGenerateRandomLetterString_LettersOnly locks the #84 intent: the letter
// generator must never emit digits (it feeds the alpha half of verification
// codes, with the numeric half coming from GenerateRandomNumberString).
func TestGenerateRandomLetterString_LettersOnly(t *testing.T) {
	s := GenerateRandomLetterString(500)
	if len(s) != 500 {
		t.Fatalf("len = %d, want 500", len(s))
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		isLetter := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		if !isLetter {
			t.Fatalf("GenerateRandomLetterString emitted non-letter %q", c)
		}
	}
}

// TestGenerateRandomNumberString_Distribution is a coarse, non-flaky sanity
// check that every digit appears and no digit dominates, guarding against a
// gross bias regression. Tolerance is deliberately wide.
func TestGenerateRandomNumberString_Distribution(t *testing.T) {
	const total = 200000
	s := GenerateRandomNumberString(total)
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
