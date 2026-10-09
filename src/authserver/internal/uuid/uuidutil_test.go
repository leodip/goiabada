package uuid

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/uuid/uuidtest"
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

		parsed, err := uuidtest.Parse(got)
		if err != nil {
			t.Fatalf("uuidtest.Parse(New()): %q refused: %v", got, err)
		}
		if parsed != got {
			t.Fatalf("uuidtest.Parse(New()): %q came back as %q, want it unchanged", got, parsed)
		}

		if _, dup := seen[got]; dup {
			t.Fatalf("New(): %q drawn twice in %d draws", got, i+1)
		}
		seen[got] = struct{}{}
	}
}

// crashChildEnv marks the re-executed child of
// TestNew_CrashesIrrecoverablyOnReaderFailure. Only the child swaps
// crypto/rand.Reader, so the parent's binary -- and every other case in this
// package -- keeps the real source.
const crashChildEnv = "GOIABADA_UUID_CRASH_CHILD"

// alwaysFailingReader is a CSPRNG that has stopped answering.
type alwaysFailingReader struct{}

func (alwaysFailingReader) Read([]byte) (int, error) {
	return 0, errors.New("uuid_test: entropy source is unavailable")
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
		callNewOverAFailingReader()
		// Reached only if New returned or panicked in a catchable way, either of
		// which violates the contract. Exit 0 so the parent's assertion fails.
		os.Exit(0)
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

// callNewOverAFailingReader is the crash child's body: New over a reader that
// always fails. It returns only when New returned or panicked recoverably, and
// says which on stderr.
func callNewOverAFailingReader() {
	rand.Reader = alwaysFailingReader{}
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "New() panicked recoverably with %v\n", r)
		}
	}()
	got := New()
	fmt.Fprintf(os.Stderr, "New() returned %q from a failing reader\n", got)
}
