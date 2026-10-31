package otpcredential

import (
	"crypto/rand"
	"strings"
	"unicode"

	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/hashutil"
)

// Recovery codes (#257 decisions 1 and 2) come with the authenticator: Establish creates a set in
// the transaction that installs one, and RemoveTx deletes it in the transaction that removes one.
// They live here rather than in a package of their own because they share the authenticator's
// lifecycle and its transactions, which is what this package owns.
//
// A code is 24 characters of the Crockford base32 alphabet in lower case, which leaves out i, l, o
// and u, drawn from crypto/rand: 120 bits. It is shown in six groups of four,
// 7kq2-m9xh-4trw-b3np-j6vd-egac, and stored as the SHA-256 of its 24 characters, in hex. At 120
// bits NIST SP 800-63B-4 section 3.1.2.2 asks only that a look-up secret be stored hashed with an
// approved function, so checking one is one indexed lookup, with no salt and no password hash.

const (
	// RecoveryCodeSetSize is how many codes a set holds.
	RecoveryCodeSetSize = 10

	// recoveryCodeAlphabet is Crockford's base32 alphabet, lower case: 32 symbols, so each is
	// exactly 5 bits of a random byte.
	recoveryCodeAlphabet = "0123456789abcdefghjkmnpqrstvwxyz"
	recoveryCodeLength   = 24
	recoveryCodeGroup    = 4
)

// HashRecoveryCode is the stored form of a code as a person typed it: the SHA-256, in lowercase
// hex, of the code with spaces and hyphens taken out and letters lowered, so entry ignores case,
// spaces and hyphens (#257 decision 2). Anything else typed, a mistyped letter included, hashes to
// a value no set holds.
func HashRecoveryCode(code string) string {
	return hashutil.HashString(normalizeRecoveryCode(code))
}

// normalizeRecoveryCode drops every hyphen and every kind of space, a pasted tab or line break
// included, and lowers the rest.
func normalizeRecoveryCode(code string) string {
	return strings.Map(func(r rune) rune {
		if r == '-' || unicode.IsSpace(r) {
			return -1
		}
		return r
	}, strings.ToLower(code))
}

// newRecoveryCodes draws a set of codes, as shown, and their hashes, as stored, index for index.
func newRecoveryCodes() (codes []string, hashes []string, err error) {
	codes = make([]string, 0, RecoveryCodeSetSize)
	hashes = make([]string, 0, RecoveryCodeSetSize)
	seen := make(map[string]bool, RecoveryCodeSetSize)
	for len(codes) < RecoveryCodeSetSize {
		code, err := newRecoveryCode()
		if err != nil {
			return nil, nil, err
		}
		// A repeat at 120 bits is as good as impossible; drawing again keeps the set's ten codes
		// distinct, which the table's key on the pair requires, rather than leaving that to chance.
		if seen[code] {
			continue
		}
		seen[code] = true
		codes = append(codes, code)
		hashes = append(hashes, HashRecoveryCode(code))
	}
	return codes, hashes, nil
}

// newRecoveryCode draws one code from crypto/rand and formats it in groups.
func newRecoveryCode() (string, error) {
	random := make([]byte, recoveryCodeLength)
	if _, err := rand.Read(random); err != nil {
		return "", errs.Wrap(err, "unable to draw a recovery code")
	}

	var b strings.Builder
	b.Grow(recoveryCodeLength + recoveryCodeLength/recoveryCodeGroup - 1)
	for i, r := range random {
		if i > 0 && i%recoveryCodeGroup == 0 {
			b.WriteByte('-')
		}
		// 256 is a multiple of 32, so the low five bits of a uniform byte are uniform.
		b.WriteByte(recoveryCodeAlphabet[r&0x1f])
	}
	return b.String(), nil
}
