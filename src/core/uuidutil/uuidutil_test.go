package uuidutil

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

// draws is how many identifiers the format properties are checked over. One
// draw proves almost nothing here: the version nibble is fixed but the variant
// character is one of four, and a generator that got the masks wrong still
// produces a plausible-looking string most of the time.
const draws = 5000

const lowerHex = "0123456789abcdef"

// TestNew_CanonicalV4 owns the format table: everything a reader of New's
// output is entitled to assume. Removing either mask in New leaves this
// failing on the first few draws.
func TestNew_CanonicalV4(t *testing.T) {
	seen := make(map[string]struct{}, draws)
	for i := 0; i < draws; i++ {
		got := New()

		if len(got) != 36 {
			t.Fatalf("New(): %q is %d characters, want 36", got, len(got))
		}
		for _, pos := range []int{8, 13, 18, 23} {
			if got[pos] != '-' {
				t.Fatalf("New(): %q has %q at index %d, want a hyphen", got, got[pos], pos)
			}
		}
		if got[14] != '4' {
			t.Fatalf("New(): %q has version character %q, want %q (RFC 9562 section 4.2)",
				got, got[14], '4')
		}
		if !strings.ContainsRune("89ab", rune(got[19])) {
			t.Fatalf("New(): %q has variant character %q, want one of \"89ab\" (RFC 9562 section 4.1)",
				got, got[19])
		}
		for pos := 0; pos < len(got); pos++ {
			switch pos {
			case 8, 13, 18, 23:
				continue
			}
			if !strings.ContainsRune(lowerHex, rune(got[pos])) {
				t.Fatalf("New(): %q has %q at index %d, want a lowercase hex digit",
					got, got[pos], pos)
			}
		}

		parsed, err := Parse(got)
		if err != nil {
			t.Fatalf("Parse(New()): %q refused: %v", got, err)
		}
		if parsed != got {
			t.Fatalf("Parse(New()): %q came back as %q, want it unchanged", got, parsed)
		}

		if _, dup := seen[got]; dup {
			t.Fatalf("New(): %q drawn twice in %d draws", got, i+1)
		}
		seen[got] = struct{}{}
	}
}

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

// crashChildEnv marks the re-executed child of
// TestNew_CrashesIrrecoverablyOnReaderFailure. Only the child swaps
// crypto/rand.Reader, so the parent's binary -- and every other case in this
// package -- keeps the real source.
const crashChildEnv = "GOIABADA_UUIDUTIL_CRASH_CHILD"

// alwaysFailingReader is a CSPRNG that has stopped answering.
type alwaysFailingReader struct{}

func (alwaysFailingReader) Read([]byte) (int, error) {
	return 0, errors.New("uuidutil_test: entropy source is unavailable")
}

// TestNew_CrashesIrrecoverablyOnReaderFailure pins the half of New's contract
// that no format assertion can reach: on a CSPRNG failure the process dies, and
// no caller gets an identifier or a chance to invent one. Without it, a New
// rewritten to `if _, err := rand.Reader.Read(b[:]); err != nil { return "" }`
// passes every other case in this file while handing empty subjects and empty
// session identifiers to callers that cannot tell (#278).
//
// It runs in a re-executed child because the failure is a runtime fatal that no
// recover can catch, so it takes its process with it. The child needs no broken
// OS: crypto/rand.Read reads whatever crypto/rand.Reader holds and calls the
// fatal handler on any error from it.
func TestNew_CrashesIrrecoverablyOnReaderFailure(t *testing.T) {
	if os.Getenv(crashChildEnv) == "1" {
		rand.Reader = alwaysFailingReader{}
		defer func() {
			// Reached only if New panicked in a catchable way, which is the
			// contract being violated. Exit 0 so the parent's assertion fails.
			if r := recover(); r != nil {
				fmt.Fprintf(os.Stderr, "New() panicked recoverably with %v\n", r)
				os.Exit(0)
			}
		}()
		got := New()
		fmt.Fprintf(os.Stderr, "New() returned %q from a failing reader\n", got)
		os.Exit(0)
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestNew_CrashesIrrecoverablyOnReaderFailure$")
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
