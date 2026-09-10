package stringutil

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/exec"
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

// crashChildEnv marks the re-executed child of
// TestGenerateSecurityRandomString_CrashesIrrecoverablyOnReaderFailure. Only the
// child swaps crypto/rand.Reader, so the parent's binary -- and every other case
// in this package -- keeps the real source.
const crashChildEnv = "GOIABADA_STRINGUTIL_CRASH_CHILD"

// alwaysFailingReader is a CSPRNG that has stopped answering. errReader above is
// the same shape but is fed straight to randomStringFromReader; this one is
// installed as crypto/rand.Reader, which is the only way to reach the exported
// generators' source.
type alwaysFailingReader struct{}

func (alwaysFailingReader) Read([]byte) (int, error) {
	return 0, errors.New("stringutil_test: entropy source is unavailable")
}

// TestGenerateSecurityRandomString_CrashesIrrecoverablyOnReaderFailure pins the
// half of the exported generators' contract that no length or alphabet
// assertion can reach: on a CSPRNG failure the process dies, and no caller gets
// a string or a chance to invent one.
//
// It is the case #211 was missing. The wrapper this package shipped until then
// answered a failed draw with "", and every other case in this file passes
// against that version, so the ceremony ids and continuation ids it fed were
// guarded by hand at two call sites and nowhere else. Reverting
// randomStringFromAlphabet to io.ReadFull with an `if err != nil { return "" }`
// branch leaves the whole rest of this file green and fails only here.
//
// It runs in a re-executed child because the failure is a runtime fatal that no
// recover can catch, so it takes its process with it. The child needs no broken
// OS: crypto/rand.Read reads whatever crypto/rand.Reader holds and calls the
// fatal handler on any error from it.
func TestGenerateSecurityRandomString_CrashesIrrecoverablyOnReaderFailure(t *testing.T) {
	if os.Getenv(crashChildEnv) == "1" {
		rand.Reader = alwaysFailingReader{}
		defer func() {
			// Reached only if the draw failed in a catchable way, which is the
			// contract being violated. Exit 0 so the parent's assertion fails.
			if r := recover(); r != nil {
				fmt.Fprintf(os.Stderr, "GenerateSecurityRandomString panicked recoverably with %v\n", r)
				os.Exit(0)
			}
		}()
		got := GenerateSecurityRandomString(32)
		fmt.Fprintf(os.Stderr, "GenerateSecurityRandomString returned %q from a failing reader\n", got)
		os.Exit(0)
		return
	}

	cmd := exec.Command(os.Args[0],
		"-test.run=^TestGenerateSecurityRandomString_CrashesIrrecoverablyOnReaderFailure$")
	cmd.Env = append(os.Environ(), crashChildEnv+"=1")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	err := cmd.Run()
	if err == nil {
		t.Fatalf("child exited 0 with a failing CSPRNG, want a fatal crash; output:\n%s", out.String())
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("could not run the child: %v; output:\n%s", err, out.String())
	}
	const wantFatal = "crypto/rand: failed to read random data"
	if !strings.Contains(out.String(), wantFatal) {
		t.Fatalf("child died without %q, so it died of something other than the CSPRNG; output:\n%s",
			wantFatal, out.String())
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
