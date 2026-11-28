package apihandlers

import (
	"database/sql"
	"net/http"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/otpcredential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Deleting the account reads an authenticator code and a recovery code typed in full-width, or
// with another script's digits, as the codes they spell (#662 decision 9).

func TestHandleAccountDeletionPost_DeletesWithAFullWidthAuthenticatorCode(t *testing.T) {
	f := newDeletionFixture(t)
	user := enrolledDeletionUser(t)
	f.expectCaller(user)
	f.expectEarlyCheck(false, 0)
	f.database.On("TryConsumeEnrolledUserOTPStep", mock.Anything, (*sql.Tx)(nil), deletionUserID, mock.Anything,
		user.OTPConfigGeneration).Return(true, nil).Once()
	stub := f.expectDeletionOpened(user)
	f.expectDeletionCompleted()

	rr := f.serve(deletionRequest(t, deletionSettings(), map[string]string{
		"password": deletionPassword, "otpCode": codeInScript(currentOTPCode(t), '０')}))

	f.assertDeleted(t, rr, stub)
	assert.Zero(t, f.credentials.failures)
}

func TestHandleAccountDeletionPost_DeletesWithAFullWidthRecoveryCode(t *testing.T) {
	// deletionRecoveryCode, abcd-efgh-jkmn-pqrs-tvwx-yz01, typed in full-width letters and with
	// Arabic-Indic digits.
	const typed = "ａｂｃｄ-ＥＦＧＨ-ｊｋｍｎ-ｐｑｒｓ-ｔｖｗｘ-ｙｚ٠١"

	f := newDeletionFixture(t)
	user := enrolledDeletionUser(t)
	f.expectCaller(user)
	f.expectEarlyCheck(false, 0)
	stub := f.expectDeletionOpened(user)
	f.database.On("TryUseUserRecoveryCode", mock.Anything, deletionTx, deletionUserID,
		otpcredential.HashRecoveryCode(deletionRecoveryCode)).Return(true, nil).Once()
	f.expectDeletionCompleted()

	rr := f.serve(deletionRequest(t, deletionSettings(), map[string]string{
		"password": deletionPassword, "recoveryCode": typed}))

	f.assertDeleted(t, rr, stub)
	assert.Zero(t, f.credentials.failures)
}

// A wrong code in full-width digits is a guess like any other: it advances the authenticator's
// failure count and spends the failure budget.
func TestHandleAccountDeletionPost_AWrongFullWidthCodeAdvancesTheFailureCount(t *testing.T) {
	f := newDeletionFixture(t)
	user := enrolledDeletionUser(t)
	f.expectCaller(user)
	f.expectEarlyCheck(false, 0)
	countTx := &sql.Tx{}
	datamocks.ExpectRunInTransaction(f.database, countTx)
	f.database.On("IncrementUserOTPConsecutiveFailures", mock.Anything, countTx, deletionUserID,
		user.OTPConfigGeneration).Return(false, nil).Once()

	rr := f.serve(deletionRequest(t, deletionSettings(), map[string]string{
		"password": deletionPassword, "otpCode": codeInScript(wrongButWellFormedCode(t), '０')}))

	require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
	assert.Equal(t, "INVALID_OTP_CODE", errorCodeOf(t, rr))
	assert.Equal(t, wrongCodeRefusal, descriptionOf(t, rr))
	assert.Equal(t, 1, f.credentials.failures)
	assert.Empty(t, f.jobs.jobs)
}
