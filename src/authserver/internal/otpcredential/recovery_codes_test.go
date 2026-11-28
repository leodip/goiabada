package otpcredential

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// recoveryCodeShape is a code as the user is shown it: 24 characters of the Crockford base32
// alphabet in lower case, which leaves out i, l, o and u, in six groups of four joined by hyphens
// (#257 decision 2).
var recoveryCodeShape = regexp.MustCompile(`^[0-9a-hjkmnp-tv-z]{4}(-[0-9a-hjkmnp-tv-z]{4}){5}$`)

// sha256Hex is the stored form of a code, worked out here from decision 2's definition rather than
// through the package: the SHA-256, in hex, of the code's 24 characters without the hyphens.
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// expectEstablishWrites stubs Establish's writes before the recovery codes, each succeeding.
func expectEstablishWrites(database *datamocks.Database, calls *[]string) {
	database.EXPECT().TryEstablishUserOTP(mock.Anything, otpTx, otpUserID, otpReadGeneration, mock.Anything).
		RunAndReturn(func(context.Context, *sql.Tx, int64, int64, []byte) (bool, error) {
			*calls = append(*calls, "establish")
			return true, nil
		}).Once()
	database.EXPECT().IncrementUserOTPConfigGeneration(mock.Anything, otpTx, otpUserID).
		RunAndReturn(func(context.Context, *sql.Tx, int64) (int64, error) {
			*calls = append(*calls, "increment")
			return 9, nil
		}).Once()
	database.EXPECT().ClearPendingOTPEnrollment(mock.Anything, otpTx, otpUserID).
		RunAndReturn(func(context.Context, *sql.Tx, int64) error {
			*calls = append(*calls, "clear")
			return nil
		}).Once()
	database.EXPECT().ClearUserOTPConsecutiveFailures(mock.Anything, otpTx, otpUserID).
		RunAndReturn(func(context.Context, *sql.Tx, int64) error {
			*calls = append(*calls, "clear-count")
			return nil
		}).Once()
}

// Every new authenticator comes with a set of ten recovery codes, created in the transaction that
// establishes it and returned to the caller to show once (#257 decision 1). What is stored is each
// code's SHA-256, never the code (decision 2).
func TestEstablish_CreatesASetOfRecoveryCodesInItsTransaction(t *testing.T) {
	database := datamocks.NewDatabase(t)
	user := enrollableUser()

	var calls []string
	datamocks.ExpectRunInTransaction(database, otpTx, func(edge string) { calls = append(calls, edge) })
	expectEstablishWrites(database, &calls)
	var stored []string
	database.EXPECT().ReplaceUserRecoveryCodes(mock.Anything, otpTx, otpUserID, mock.Anything).
		RunAndReturn(func(_ context.Context, _ *sql.Tx, _ int64, hashes []string) error {
			calls = append(calls, "recovery-codes")
			stored = hashes
			return nil
		}).Once()
	expectHeldRead(database, &calls)

	generation, codes, _, established, err := Establish(context.Background(), database, testDataCipher, user, otpSeed)

	require.NoError(t, err)
	assert.True(t, established)
	assert.EqualValues(t, 9, generation)
	assert.Equal(t, []string{"begin", "establish", "increment", "clear", "clear-count", "recovery-codes", "read", "commit"}, calls,
		"the set is created in the authenticator's own transaction, so no committed state has one without the other")

	require.Len(t, codes, 10, "a set is ten codes")
	require.Len(t, stored, 10, "and ten are stored")
	seen := map[string]bool{}
	for i, code := range codes {
		assert.Regexp(t, recoveryCodeShape, code, "code %d is shown in six groups of four", i)
		assert.False(t, seen[code], "code %d appears once in the set", i)
		seen[code] = true
		assert.Equal(t, sha256Hex(strings.ReplaceAll(code, "-", "")), stored[i],
			"what is stored for code %d is its SHA-256, and nothing of the code itself", i)
		assert.NotContains(t, stored[i], strings.ReplaceAll(code, "-", ""))
	}
}

// The codes are drawn afresh for every set: two authenticators never share one.
func TestEstablish_DrawsANewSetEachTime(t *testing.T) {
	all := map[string]bool{}
	for range 20 {
		database := datamocks.NewDatabase(t)
		var calls []string
		datamocks.ExpectRunInTransaction(database, otpTx)
		expectEstablishWrites(database, &calls)
		database.EXPECT().ReplaceUserRecoveryCodes(mock.Anything, otpTx, otpUserID, mock.Anything).Return(nil).Once()
		expectHeldRead(database, nil)

		_, codes, _, established, err := Establish(context.Background(), database, testDataCipher, enrollableUser(), otpSeed)
		require.NoError(t, err)
		require.True(t, established)
		for _, code := range codes {
			assert.False(t, all[code], "a code drawn twice: %s", code)
			all[code] = true
		}
	}
	assert.Len(t, all, 200)
}

// A set the database refuses fails the establish: the transaction rolls back, so there is no
// authenticator without its codes, and the caller gets no codes to show (#257 decision 1).
func TestEstablish_ARefusedSetEstablishesNothing(t *testing.T) {
	database := datamocks.NewDatabase(t)
	user := enrollableUser()
	writeErr := errors.New("insert refused")

	var calls []string
	stub := datamocks.ExpectRunInTransaction(database, otpTx)
	expectEstablishWrites(database, &calls)
	database.EXPECT().ReplaceUserRecoveryCodes(mock.Anything, otpTx, otpUserID, mock.Anything).Return(writeErr).Once()

	generation, codes, _, established, err := Establish(context.Background(), database, testDataCipher, user, otpSeed)

	require.ErrorIs(t, err, writeErr)
	require.ErrorIs(t, stub.BodyErr, writeErr, "the body hands the error to the helper, which rolls back")
	assert.False(t, established)
	assert.Zero(t, generation)
	assert.Nil(t, codes, "codes that were never stored must not be shown")
	assert.False(t, user.OTPEnabled)
}

// A commit the engine refuses: the codes were never stored, so none reach the caller.
func TestEstablish_ACommitFailureYieldsNoRecoveryCodes(t *testing.T) {
	database := datamocks.NewDatabase(t)
	commitErr := errors.New("commit refused")

	var calls []string
	datamocks.ExpectRunInTransactionThenFail(database, otpTx, commitErr)
	expectEstablishWrites(database, &calls)
	database.EXPECT().ReplaceUserRecoveryCodes(mock.Anything, otpTx, otpUserID, mock.Anything).Return(nil).Once()
	expectHeldRead(database, nil)

	_, codes, _, established, err := Establish(context.Background(), database, testDataCipher, enrollableUser(), otpSeed)

	require.ErrorIs(t, err, commitErr)
	assert.False(t, established)
	assert.Nil(t, codes)
}

// An establish whose compare-and-set matched nothing creates no set either: the authenticator it
// would belong to was never stored.
func TestEstablish_ALostCompareAndSetCreatesNoRecoveryCodes(t *testing.T) {
	database := datamocks.NewDatabase(t)

	datamocks.ExpectRunInTransaction(database, otpTx)
	database.EXPECT().TryEstablishUserOTP(mock.Anything, otpTx, otpUserID, otpReadGeneration, mock.Anything).
		Return(false, nil).Once()

	_, codes, _, established, err := Establish(context.Background(), database, testDataCipher, enrollableUser(), otpSeed)

	require.NoError(t, err)
	assert.False(t, established)
	assert.Nil(t, codes)
	database.AssertNotCalled(t, "ReplaceUserRecoveryCodes", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// Removing the authenticator deletes its recovery codes in the same transaction, which is what makes
// every path that removes one, the account page, the administrator's and the recover command's,
// clear them (#257 decision 3).
func TestRemove_DeletesTheRecoveryCodesInItsTransaction(t *testing.T) {
	database := datamocks.NewDatabase(t)
	user := enrolledUser(t)

	var calls []string
	datamocks.ExpectRunInTransaction(database, otpTx, func(edge string) { calls = append(calls, edge) })
	database.EXPECT().TryRemoveUserOTP(mock.Anything, otpTx, otpUserID, otpReadGeneration).
		RunAndReturn(func(context.Context, *sql.Tx, int64, int64) (bool, error) {
			calls = append(calls, "remove")
			return true, nil
		}).Once()
	database.EXPECT().ResetUserOTPStep(mock.Anything, otpTx, otpUserID).
		RunAndReturn(func(context.Context, *sql.Tx, int64) error {
			calls = append(calls, "reset")
			return nil
		}).Once()
	database.EXPECT().DeleteUserRecoveryCodes(mock.Anything, otpTx, otpUserID).
		RunAndReturn(func(context.Context, *sql.Tx, int64) error {
			calls = append(calls, "delete-codes")
			return nil
		}).Once()
	database.EXPECT().IncrementUserOTPConfigGeneration(mock.Anything, otpTx, otpUserID).
		RunAndReturn(func(context.Context, *sql.Tx, int64) (int64, error) {
			calls = append(calls, "increment")
			return 6, nil
		}).Once()
	database.EXPECT().LowerUserSessionsToPassword(mock.Anything, otpTx, otpUserID, "pwd").
		RunAndReturn(func(context.Context, *sql.Tx, int64, string) error {
			calls = append(calls, "lower")
			return nil
		}).Once()
	expectHeldRead(database, &calls)

	_, removed, err := Remove(context.Background(), database, user)

	require.NoError(t, err)
	assert.True(t, removed)
	assert.Equal(t, []string{"begin", "remove", "reset", "delete-codes", "increment", "lower", "read", "commit"}, calls)
}

// A deletion the engine refuses fails the removal: committed without it, the codes of an
// authenticator that is gone would still be there for the next one.
func TestRemoveTx_AFailedRecoveryCodeDeletionFailsTheRemoval(t *testing.T) {
	database := datamocks.NewDatabase(t)
	deleteErr := errors.New("delete refused")
	database.EXPECT().TryRemoveUserOTP(mock.Anything, otpTx, otpUserID, otpReadGeneration).Return(true, nil).Once()
	database.EXPECT().ResetUserOTPStep(mock.Anything, otpTx, otpUserID).Return(nil).Once()
	database.EXPECT().DeleteUserRecoveryCodes(mock.Anything, otpTx, otpUserID).Return(deleteErr).Once()

	removed, err := RemoveTx(context.Background(), database, otpTx, enrolledUser(t))

	require.ErrorIs(t, err, deleteErr)
	assert.False(t, removed)
	database.AssertNotCalled(t, "IncrementUserOTPConfigGeneration", mock.Anything, mock.Anything, mock.Anything)
}

// A code is looked up by its hash, and entry ignores case, spaces and hyphens, so every way a person
// may type or paste the code hashes to the same value (#257 decision 2). The expected value is the
// SHA-256 of the example code's 24 characters, worked out with sha256sum.
func TestHashRecoveryCode_IgnoresCaseSpacesAndHyphens(t *testing.T) {
	const want = "c6fc89366c85e65574ae4e7611c099de58437a2d479455bb7d15876a606c0472"

	for _, typed := range []string{
		"7kq2-m9xh-4trw-b3np-j6vd-egac",
		"7KQ2-M9XH-4TRW-B3NP-J6VD-EGAC",
		"7kq2m9xh4trwb3npj6vdegac",
		" 7kq2 m9xh 4trw b3np j6vd egac ",
		"7Kq2 - m9xH - 4trw-b3np-j6vd-egac\t",
	} {
		assert.Equal(t, want, HashRecoveryCode(typed), "%q", typed)
	}
	assert.NotEqual(t, want, HashRecoveryCode("7kq2-m9xh-4trw-b3np-j6vd-egab"), "another code is another hash")
}

// A recovery code typed in full-width, or with the digits of another script, is the code it spells
// (#662 decision 9): every decimal digit reads as its ASCII digit and a full-width Latin letter as
// its ordinary letter, before the hyphens and spaces are taken out as they always were. The
// expected value is the example code's hash above.
func TestHashRecoveryCode_ReadsFullWidthLettersAndTheDigitsOfAnyScript(t *testing.T) {
	const want = "c6fc89366c85e65574ae4e7611c099de58437a2d479455bb7d15876a606c0472"

	for _, typed := range []string{
		"7kq2-ｍ9xh-4trw-b3np-j6vd-egac",
		"７ｋｑ２-ｍ９ｘｈ-４ｔｒｗ-ｂ３ｎｐ-ｊ６ｖｄ-ｅｇａｃ",
		"７ＫＱ２-Ｍ９ＸＨ-４ＴＲＷ-Ｂ３ＮＰ-Ｊ６ＶＤ-ＥＧＡＣ",
		"٧kq٢-m٩xh-٤trw-b٣np-j٦vd-egac",
		"७kq२-m९xh-४trw-b३np-j६vd-egac",
		"　７ｋｑ２ ｍ９ｘｈ ４ｔｒｗ　ｂ３ｎｐ ｊ６ｖｄ ｅｇａｃ　",
	} {
		assert.Equal(t, want, HashRecoveryCode(typed), "%q", typed)
	}

	assert.NotEqual(t, want, HashRecoveryCode("７ｋｑ２-ｍ９ｘｈ-４ｔｒｗ-ｂ３ｎｐ-ｊ６ｖｄ-ｅｇａｂ"),
		"a wrong letter in full-width is another code")
}

// A hyphen between a code's groups may be typed as what a Japanese input method writes for the
// hyphen key, the full-width hyphen-minus in full-width mode and the long-vowel mark, full or half
// width, in kana mode, or as a dash or minus sign another keyboard or autocorrect writes; each is
// taken out as the hyphen is. The expected value is the example code's hash above.
func TestHashRecoveryCode_TakesOutEveryHyphenAPersonMayType(t *testing.T) {
	const want = "c6fc89366c85e65574ae4e7611c099de58437a2d479455bb7d15876a606c0472"

	for _, hyphen := range []string{
		"\uFF0D", // full-width hyphen-minus
		"\u30FC", // katakana-hiragana prolonged sound mark
		"\uFF70", // half-width katakana-hiragana prolonged sound mark
		"\u2010", // hyphen
		"\u2011", // non-breaking hyphen
		"\u2012", // figure dash
		"\u2013", // en dash
		"\u2014", // em dash
		"\u2015", // horizontal bar
		"\u2212", // minus sign
	} {
		typed := strings.Join([]string{"7kq2", "m9xh", "4trw", "b3np", "j6vd", "egac"}, hyphen)
		assert.Equal(t, want, HashRecoveryCode(typed), "%q", typed)
		assert.True(t, IsBlankRecoveryCode(hyphen+" "+hyphen), "%q alone is no code", hyphen)
	}
	assert.Equal(t, want, HashRecoveryCode("７ｋｑ２－ｍ９ｘｈ－４ｔｒｗ－ｂ３ｎｐ－ｊ６ｖｄ－ｅｇａｃ"),
		"a code typed wholly in full-width mode")
	assert.Equal(t, want, HashRecoveryCode("７ｋｑ２ーｍ９ｘｈー４ｔｒｗーｂ３ｎｐーｊ６ｖｄーｅｇａｃ"),
		"a code in full-width letters with its hyphens typed in kana mode")

	// Only hyphens are taken out: another mark between the groups, or a wrong letter beside a
	// full-width hyphen, is another code.
	assert.NotEqual(t, want, HashRecoveryCode("7kq2_m9xh_4trw_b3np_j6vd_egac"))
	assert.NotEqual(t, want, HashRecoveryCode("7kq2〜m9xh〜4trw〜b3np〜j6vd〜egac"), "the wave dash is not a hyphen")
	assert.NotEqual(t, want, HashRecoveryCode("７ｋｑ２－ｍ９ｘｈ－４ｔｒｗ－ｂ３ｎｐ－ｊ６ｖｄ－ｅｇａｂ"),
		"a wrong letter beside full-width hyphens is another code")
}
