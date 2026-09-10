package fake

import (
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/urlutil"
	"github.com/leodip/goiabada/core/uuidutil"
	"github.com/leodip/goiabada/core/validators"
)

// draws is how many times each property below is exercised. Every generator here
// is random, so a single draw proves almost nothing: the properties that matter
// (a password carrying all four classes, a bool taking both values) are the ones
// an unlucky implementation satisfies once in a while by accident.
const draws = 1000

func isFrom(s, alphabet string) bool {
	for _, r := range s {
		if !strings.ContainsRune(alphabet, r) {
			return false
		}
	}
	return true
}

func TestLetterN(t *testing.T) {
	for _, n := range []uint{1, 6, 8, 12, 43, 73, 129} {
		for i := 0; i < draws; i++ {
			got := LetterN(n)
			if uint(len(got)) != n {
				t.Fatalf("LetterN(%d): got %d characters, want %d", n, len(got), n)
			}
			if !isFrom(got, lowerChars+upperChars) {
				t.Fatalf("LetterN(%d): %q is not all letters", n, got)
			}
		}
	}
	for i := 0; i < draws; i++ {
		if got := LetterN(0); len(got) != 1 {
			t.Fatalf("LetterN(0): got %q, want one character", got)
		}
	}
}

func TestDigitN(t *testing.T) {
	for _, n := range []uint{1, 2, 3, 5, 10} {
		for i := 0; i < draws; i++ {
			got := DigitN(n)
			if uint(len(got)) != n {
				t.Fatalf("DigitN(%d): got %d characters, want %d", n, len(got), n)
			}
			if !isFrom(got, digitChars) {
				t.Fatalf("DigitN(%d): %q is not all digits", n, got)
			}
		}
	}
}

// TestMustDraw_PanicsOnShortResult pins the fail-closed contract LetterN and
// DigitN document, directly on the guard that carries it. It replaces a pair of
// cases that swapped crypto/rand.Reader for a failing reader and called through
// stringutil: since #211 that helper draws through crypto/rand.Read, which ends
// the process on a read error rather than returning "", so those cases would now
// take this whole test binary down instead of observing a panic.
//
// Calling mustDraw directly is what is left, and it is what the guard is for:
// nothing can produce a short draw today, and the panic is this package's own
// refusal to put a degraded value in a fixture (#272, #136).
func TestMustDraw_PanicsOnShortResult(t *testing.T) {
	func() {
		defer func() {
			if recover() == nil {
				t.Error(`mustDraw("ab", 3, "x"): want a panic on a short draw, got none`)
			}
		}()
		_ = mustDraw("ab", 3, "x")
	}()

	if got := mustDraw("abc", 3, "x"); got != "abc" {
		t.Errorf(`mustDraw("abc", 3, "x") = %q, want "abc"`, got)
	}
}

// TestPassword_AllClassesPresent is the pin for the guarantee Password documents:
// every draw carries a lowercase letter, an uppercase letter, a digit and a
// special character, at every length asked for. Removing the four per-class draws
// leaves this failing within a few dozen iterations at n = 8.
func TestPassword_AllClassesPresent(t *testing.T) {
	for _, n := range []int{4, 8, 32, 64} {
		for i := 0; i < draws; i++ {
			got := Password(n)
			if len(got) != n {
				t.Fatalf("Password(%d): got %d characters, want %d", n, len(got), n)
			}
			if !isFrom(got, passwordChars) {
				t.Fatalf("Password(%d): %q holds a character outside the alphabet", n, got)
			}
			for _, class := range []struct {
				name     string
				alphabet string
			}{
				{"lowercase", lowerChars},
				{"uppercase", upperChars},
				{"digit", digitChars},
				{"special", specialChars},
			} {
				if !strings.ContainsAny(got, class.alphabet) {
					t.Fatalf("Password(%d): %q has no %s character", n, got, class.name)
				}
			}
		}
	}
}

func TestPassword_PanicsBelowFour(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("Password(3): want a panic, got none")
		}
	}()
	_ = Password(3)
}

// TestEmail checks the address against the validator the handlers apply rather
// than against a regex copied here. ValidateEmailAddress reads no database, so a
// nil one is enough to construct the validator.
func TestEmail(t *testing.T) {
	val := validators.NewEmailValidator(nil)
	for i := 0; i < draws; i++ {
		got := Email()
		if len(got) != 24 {
			t.Fatalf("Email(): %q is %d characters, want 24", got, len(got))
		}
		if got != strings.ToLower(got) {
			t.Fatalf("Email(): %q is not lowercase", got)
		}
		if err := val.ValidateEmailAddress(got); err != nil {
			t.Fatalf("Email(): %q rejected by the validator: %v", got, err)
		}
	}
}

// TestURL holds the value to the predicate ValidateClientAndRedirectURI applies
// to a registered redirect URI, which is stricter than url.Parse: absolute, with
// a host, and no fragment.
func TestURL(t *testing.T) {
	for i := 0; i < draws; i++ {
		got := URL()
		u, err := url.Parse(got)
		if err != nil {
			t.Fatalf("URL(): %q does not parse: %v", got, err)
		}
		if !u.IsAbs() || u.Host == "" {
			t.Fatalf("URL(): %q is not absolute with a host", got)
		}
		if !urlutil.IsAbsoluteRedirectURI(got) {
			t.Fatalf("URL(): %q is not a usable redirect URI", got)
		}
	}
}

func TestUUID(t *testing.T) {
	for i := 0; i < draws; i++ {
		got := UUID()
		if _, err := uuidutil.Parse(got); err != nil {
			t.Fatalf("UUID(): %q does not parse: %v", got, err)
		}
	}
}

// TestUsername_Distinct is the #136 pin. Ten thousand draws with no repeat is not
// a probabilistic hope at 26^12; it fails immediately if the generated part is
// ever shortened to something a test database could collide on.
func TestUsername_Distinct(t *testing.T) {
	const usernameDraws = 10000
	seen := make(map[string]struct{}, usernameDraws)
	for i := 0; i < usernameDraws; i++ {
		got := Username()
		if len(got) != 16 {
			t.Fatalf("Username(): %q is %d characters, want 16", got, len(got))
		}
		if !strings.HasPrefix(got, "user") {
			t.Fatalf("Username(): %q does not start with \"user\"", got)
		}
		if !isFrom(got, lowerChars) {
			t.Fatalf("Username(): %q is not all lowercase letters", got)
		}
		if _, dup := seen[got]; dup {
			t.Fatalf("Username(): %q drawn twice in %d draws", got, usernameDraws)
		}
		seen[got] = struct{}{}
	}
}

func TestNames(t *testing.T) {
	for _, fn := range []struct {
		name string
		gen  func() string
	}{
		{"FirstName", FirstName},
		{"LastName", LastName},
		{"MiddleName", MiddleName},
	} {
		for i := 0; i < draws; i++ {
			got := fn.gen()
			if len(got) < 6 || len(got) > 8 {
				t.Fatalf("%s(): %q is %d characters, want 6 to 8", fn.name, got, len(got))
			}
			if !isFrom(got[:1], upperChars) {
				t.Fatalf("%s(): %q does not start uppercase", fn.name, got)
			}
			if !isFrom(got[1:], lowerChars) {
				t.Fatalf("%s(): %q is not lowercase after the first character", fn.name, got)
			}
		}
	}
}

func TestName(t *testing.T) {
	for i := 0; i < draws; i++ {
		got := Name()
		parts := strings.Split(got, " ")
		if len(parts) != 2 {
			t.Fatalf("Name(): %q is not two space-separated words", got)
		}
		for _, part := range parts {
			if len(part) < 6 || len(part) > 8 || !isFrom(part[:1], upperChars) {
				t.Fatalf("Name(): %q holds a malformed part %q", got, part)
			}
		}
	}
}

func TestIPv4Address(t *testing.T) {
	for i := 0; i < draws; i++ {
		got := IPv4Address()
		ip := net.ParseIP(got)
		if ip == nil {
			t.Fatalf("IPv4Address(): %q does not parse", got)
		}
		if ip.To4() == nil {
			t.Fatalf("IPv4Address(): %q is not a v4 address", got)
		}
	}
}

// TestBool_BothValues pins that Bool is a draw rather than a constant: an
// implementation returning one value always passes any single-draw assertion.
func TestBool_BothValues(t *testing.T) {
	var sawTrue, sawFalse bool
	for i := 0; i < draws; i++ {
		if Bool() {
			sawTrue = true
		} else {
			sawFalse = true
		}
	}
	if !sawTrue || !sawFalse {
		t.Fatalf("Bool(): over %d draws saw true=%v false=%v, want both", draws, sawTrue, sawFalse)
	}
}

func TestNumber(t *testing.T) {
	var sawMin, sawMax bool
	for i := 0; i < draws; i++ {
		got := Number(1, 3)
		if got < 1 || got > 3 {
			t.Fatalf("Number(1, 3): got %d, want 1 to 3", got)
		}
		if got == 1 {
			sawMin = true
		}
		if got == 3 {
			sawMax = true
		}
	}
	if !sawMin || !sawMax {
		t.Fatalf("Number(1, 3): over %d draws saw 1=%v 3=%v, want both ends", draws, sawMin, sawMax)
	}
	if got := Number(5, 5); got != 5 {
		t.Fatalf("Number(5, 5): got %d, want 5", got)
	}
}

func TestNumber_PanicsOnInvertedRange(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("Number(3, 1): want a panic, got none")
		}
	}()
	_ = Number(3, 1)
}

func TestDate(t *testing.T) {
	for i := 0; i < draws; i++ {
		got := Date()
		if got.Before(dateStart) || got.After(dateEnd) {
			t.Fatalf("Date(): %v is outside [%v, %v]", got, dateStart, dateEnd)
		}
		if got.Nanosecond() != 0 {
			t.Fatalf("Date(): %v carries a sub-second part", got)
		}
		if got.Location() != time.UTC {
			t.Fatalf("Date(): %v is in %v, want UTC", got, got.Location())
		}
	}
}

func TestSentence(t *testing.T) {
	for i := 0; i < draws; i++ {
		got := Sentence(5)
		words := strings.Split(got, " ")
		if len(words) != 5 {
			t.Fatalf("Sentence(5): %q has %d words, want 5", got, len(words))
		}
		for _, w := range words {
			if len(w) < 3 || len(w) > 8 {
				t.Fatalf("Sentence(5): %q holds a %d-character word %q, want 3 to 8", got, len(w), w)
			}
			if !isFrom(w, lowerChars) {
				t.Fatalf("Sentence(5): %q holds a non-lowercase word %q", got, w)
			}
		}
	}
}
