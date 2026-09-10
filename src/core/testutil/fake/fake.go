// Package fake supplies the random values the repository's tests write into
// fixtures: usernames, passwords, emails, redirect URIs, names, dates and plain
// letter runs. It exists only for _test.go files. Nothing a binary links reaches
// it, and no function here takes a *testing.T, so a call sits wherever a literal
// would: inside a composite literal, a table row, or an argument list.
//
// It replaces the third-party faker this repository used to depend on, retired
// in #272 because a test-only module in three go.mod files is a supply-chain
// cost with no production value. Two properties differ from that library on
// purpose, and both are why call sites can trust these values without checking
// them:
//
//   - Every value is drawn from crypto/rand, so nothing is reproducible from a
//     seed. A seed only replays a value if the whole package re-runs in source
//     order, because the draw count before the failing test selects the value;
//     `go test -run TestX` reproduces nothing. Test failures already print the
//     generated value they compared, which is the replay that gets used.
//   - Values are drawn from the full character space rather than from a small
//     word corpus, so two draws colliding is unreachable rather than merely
//     unlikely. That is what closes #136: a corpus of a few thousand surnames
//     collides inside a test database of a few thousand rows.
package fake

import (
	"crypto/rand"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/leodip/goiabada/core/stringutil"
	"github.com/leodip/goiabada/core/uuidutil"
)

const (
	lowerChars   = "abcdefghijklmnopqrstuvwxyz"
	upperChars   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digitChars   = "0123456789"
	specialChars = "@#$&?!-_*."
	// passwordChars is what the length beyond the four guaranteed characters is
	// drawn from. Keeping the four classes in one alphabet makes each remaining
	// position uniform over the whole space rather than over a rotation of it.
	passwordChars = lowerChars + upperChars + digitChars + specialChars
)

// intn returns a uniform value in [0, n) read from crypto/rand. Every draw in
// this package that is not a letter or a digit run goes through it, which is why
// the package holds no global source, no seed and no mutex: crypto/rand.Reader
// is safe for concurrent use and needs no initialisation.
//
// It panics on a CSPRNG failure rather than returning a zero. A fixture that
// silently degrades to a constant produces tests that pass while generating the
// same username every time, which is exactly the failure #136 describes.
func intn(n int) int {
	if n <= 0 {
		panic("fake: intn needs a positive bound")
	}
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		panic("fake: crypto/rand is unavailable: " + err.Error())
	}
	return int(v.Int64())
}

// mustDraw returns s unless it is short of the n characters that were asked
// for, which is how the stringutil helpers report a CSPRNG failure: they
// swallow the error and return "" to preserve a contract their production
// callers were written against. A fixture that degrades to a constant instead
// produces tests that pass while every username is the same string, which is
// exactly the collision #136 describes, so the draw fails closed here rather
// than propagating an invalid value into a fixture (#272).
//
// The alphabets are ASCII, so a byte count is a character count.
func mustDraw(s string, n uint, who string) string {
	if uint(len(s)) != n {
		panic("fake: " + who + " could not draw " + strconv.FormatUint(uint64(n), 10) +
			" characters: crypto/rand is unavailable")
	}
	return s
}

// LetterN returns n characters drawn from [A-Za-z]. n == 0 returns one
// character, matching what the call sites were written against.
//
// It panics on a CSPRNG failure, like intn. Removing the mustDraw guard breaks
// TestLetterN_PanicsOnEntropyFailure.
func LetterN(n uint) string {
	if n == 0 {
		n = 1
	}
	return mustDraw(stringutil.GenerateRandomLetterString(int(n)), n, "LetterN")
}

// DigitN returns n characters drawn from [0-9]. It stands in for the phone
// numbers, postcodes and street numbers the fixtures used to ask for by name:
// nothing parses those fields, only the column width constrains them, so a digit
// run of the right length is the whole requirement (#272).
//
// It panics on a CSPRNG failure, like intn. Removing the mustDraw guard breaks
// TestDigitN_PanicsOnEntropyFailure.
func DigitN(n uint) string {
	if n == 0 {
		n = 1
	}
	return mustDraw(stringutil.GenerateRandomNumberString(int(n)), n, "DigitN")
}

// Password returns an n-character password containing at least one lowercase
// letter, one uppercase letter, one digit and one of "@#$&?!-_*.".
//
// The guarantee is not decorative. Integration tests run under the seeded
// password policy "low", which requires none of those classes, so an unguaranteed
// draw passes today; raising a test to the "high" policy would then flake, and at
// eight characters roughly one draw in four lacks a special character. Four lines
// here are cheaper than a flake nobody can reproduce (#272). Removing them
// breaks TestPassword_AllClassesPresent.
//
// It panics below 4, which cannot be satisfied. The shortest length any call site
// asks for is 8.
func Password(n int) string {
	if n < 4 {
		panic("fake: Password needs at least 4 characters to carry all four classes")
	}

	out := make([]byte, 0, n)
	out = append(out, lowerChars[intn(len(lowerChars))])
	out = append(out, upperChars[intn(len(upperChars))])
	out = append(out, digitChars[intn(len(digitChars))])
	out = append(out, specialChars[intn(len(specialChars))])
	for len(out) < n {
		out = append(out, passwordChars[intn(len(passwordChars))])
	}

	// Fisher-Yates, so the four guaranteed characters do not always sit in the
	// first four positions.
	for i := len(out) - 1; i > 0; i-- {
		j := intn(i + 1)
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

// Email returns a 24-character address of the form "<12 lowercase letters>@example.com".
// It satisfies the address regex in EmailValidator.ValidateEmailAddress and sits
// well under the 60-character cap ValidateEmailUpdate applies.
func Email() string {
	return strings.ToLower(LetterN(12)) + "@example.com"
}

// URL returns an absolute https URI with a host and no fragment, which is what
// ValidateClientAndRedirectURI requires of a value registered as a client
// redirect URI and then presented at /auth/authorize.
func URL() string {
	return "https://" + strings.ToLower(LetterN(10)) + ".example.com/" + strings.ToLower(LetterN(6))
}

// UUID returns a random UUID string. It is the fixture-side name for the
// generator production uses, uuidutil.New, so a fixture and a real subject are
// drawn the same way and a test cannot pass on a value production could never
// have written (#278).
func UUID() string {
	return uuidutil.New()
}

// Username returns "user" followed by 12 lowercase letters: 16 characters, well
// inside the 32-character column.
//
// The length is the fix for #136. TestSearchUsersPaginated asserts that a freshly
// generated username matches exactly one row, over a LIKE across six columns of a
// table the server-backed engines never reset. Drawing from 26^12 rather than from
// a few thousand surnames takes the birthday expectation at a few thousand rows
// from around one collision to around 1e-15, and a 16-character lowercase run
// cannot appear inside an email or a name generated here either. Shortening it
// re-opens the flake; TestUsername_Distinct is what notices.
func Username() string {
	return "user" + strings.ToLower(LetterN(12))
}

// nameWord returns one capitalised run of 6 to 8 letters, which fits every
// varchar(64) name column in the schema.
func nameWord() string {
	return strings.ToUpper(LetterN(1)) + strings.ToLower(LetterN(uint(5+intn(3))))
}

// FirstName returns a capitalised 6-to-8-letter run.
func FirstName() string { return nameWord() }

// LastName returns a capitalised 6-to-8-letter run.
func LastName() string { return nameWord() }

// MiddleName returns a capitalised 6-to-8-letter run.
func MiddleName() string { return nameWord() }

// Name returns a first and last name joined by one space.
func Name() string { return FirstName() + " " + LastName() }

// IPv4Address returns a dotted-quad address. Fixtures store it as a session's
// device address; nothing routes to it.
func IPv4Address() string {
	octets := make([]string, 4)
	for i := range octets {
		octets[i] = strconv.Itoa(intn(256))
	}
	return strings.Join(octets, ".")
}

// Bool returns true or false with equal probability.
func Bool() bool {
	return intn(2) == 1
}

// Number returns a value in [min, max], inclusive at both ends. It panics when
// max is below min, which is a caller mistake rather than an empty range.
func Number(min, max int) int {
	if max < min {
		panic("fake: Number needs max >= min")
	}
	return min + intn(max-min+1)
}

var (
	dateStart = time.Date(1950, time.January, 1, 0, 0, 0, 0, time.UTC)
	dateEnd   = time.Date(2010, time.December, 31, 23, 59, 59, 0, time.UTC)
)

// Date returns a UTC instant between 1950-01-01 and 2010-12-31 with a zero
// sub-second part.
//
// Whole seconds are load-bearing: the same value is written to a MySQL datetime,
// a SQL Server datetime2 and a SQLite text column and then compared with what was
// stored, and the callers that do apply Truncate(time.Microsecond). A value with
// nanoseconds round-trips differently per engine and the comparison fails on one
// of the four (#272). The year range keeps every engine's minimum well behind it.
func Date() time.Time {
	span := int(dateEnd.Unix() - dateStart.Unix())
	return time.Unix(dateStart.Unix()+int64(intn(span+1)), 0).UTC()
}

// Sentence returns the given number of lowercase letter runs, each 3 to 8
// characters, joined by single spaces. It stands in for the prose the fixtures
// used to ask a corpus for, none of which is ever parsed.
func Sentence(words int) string {
	if words <= 0 {
		return ""
	}
	out := make([]string, words)
	for i := range out {
		out[i] = strings.ToLower(LetterN(uint(3 + intn(6))))
	}
	return strings.Join(out, " ")
}
