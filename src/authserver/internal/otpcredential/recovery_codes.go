package otpcredential

import (
	"context"
	"crypto/rand"
	"database/sql"
	"strings"
	"unicode"

	"github.com/leodip/goiabada/authserver/internal/record"
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

// RecoveryCodeOutcome is what checking a recovery code at sign-in concluded.
type RecoveryCodeOutcome int

const (
	// RecoveryCodeWrong is the zero value on purpose, as OutcomeWrong is: a result nobody filled
	// in refuses. A code no set of the user's holds, one of a replaced set included.
	RecoveryCodeWrong RecoveryCodeOutcome = iota
	// RecoveryCodeAccepted is a code of the user's set, unused until this call claimed it. It is
	// the only outcome a caller may treat as a verified second factor.
	RecoveryCodeAccepted
	// RecoveryCodeReplayed is a code of the user's current set that was already used. The
	// submitter is told what a wrong code gets; the caller audits it as a replay (#257 decisions 6
	// and 10).
	RecoveryCodeReplayed
)

// RecoveryCodeResult is the outcome and, on RecoveryCodeAccepted, how many of the set's codes are
// left unused after it, which the caller audits.
type RecoveryCodeResult struct {
	Outcome   RecoveryCodeOutcome
	Remaining int
}

// RecoveryCodeDatabase is what UseRecoveryCode reads and writes. data.Database satisfies it.
type RecoveryCodeDatabase interface {
	TryUseUserRecoveryCode(ctx context.Context, tx *sql.Tx, userId int64, codeHash string) (bool, error)
	UserRecoveryCodeExists(ctx context.Context, tx *sql.Tx, userId int64, codeHash string) (bool, error)
	CountUnusedUserRecoveryCodes(ctx context.Context, tx *sql.Tx, userId int64) (int, error)
}

// UseRecoveryCode checks a recovery code, as the user typed it, against user's set and claims it:
// one conditional write, so of two submissions of one code exactly one is accepted (#257 decision
// 3). A user with no authenticator has no codes, so their code is wrong before anything is read.
//
// It leaves the authenticator as it is, whatever the outcome (#257 decisions 4 and 6): the
// consecutive-failure count is not read, not advanced by a refusal and not cleared by an
// acceptance, so a recovery code still signs in while the authenticator is disabled, which is the
// self-service way out of the disable, and the authenticator stays disabled until it is rebound.
// At 120 bits a code needs no failure count of its own; the caller charges a refusal to the otp
// rate tier, the budget an authenticator code spends.
//
// A refused claim is looked up once more, to tell a used code of the current set, which the caller
// audits as a replay, from a wrong one. The submitter is told the same for both.
//
// The caller records the claim against the generation of the authenticator user was read with: the
// codes are deleted in the removal's transaction and the generation moves with it, so a code
// accepted from a set whose authenticator is removed meanwhile stands for nothing at
// /auth/completed (OTPClaim).
func UseRecoveryCode(ctx context.Context, db RecoveryCodeDatabase, user *record.User, code string) (RecoveryCodeResult, error) {
	if !user.OTPEnabled {
		return RecoveryCodeResult{Outcome: RecoveryCodeWrong}, nil
	}

	codeHash := HashRecoveryCode(code)
	used, err := db.TryUseUserRecoveryCode(ctx, nil, user.Id, codeHash)
	if err != nil {
		return RecoveryCodeResult{}, err
	}
	if !used {
		exists, lookupErr := db.UserRecoveryCodeExists(ctx, nil, user.Id, codeHash)
		if lookupErr != nil {
			return RecoveryCodeResult{}, lookupErr
		}
		if exists {
			return RecoveryCodeResult{Outcome: RecoveryCodeReplayed}, nil
		}
		return RecoveryCodeResult{Outcome: RecoveryCodeWrong}, nil
	}

	remaining, err := db.CountUnusedUserRecoveryCodes(ctx, nil, user.Id)
	if err != nil {
		return RecoveryCodeResult{}, err
	}
	return RecoveryCodeResult{Outcome: RecoveryCodeAccepted, Remaining: remaining}, nil
}

// IsBlankRecoveryCode reports whether code holds nothing once spaces and hyphens are taken out: a
// form submitted with no code, which is asked for one rather than refused.
func IsBlankRecoveryCode(code string) bool {
	return normalizeRecoveryCode(code) == ""
}
