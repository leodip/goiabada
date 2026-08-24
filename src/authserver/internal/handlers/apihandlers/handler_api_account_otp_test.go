package apihandlers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	mocks_audit "github.com/leodip/goiabada/authserver/internal/audit/mocks"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/otp"
	mocks_otp "github.com/leodip/goiabada/core/otp/mocks"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// This file did not exist before #111 stage 4, and §5 of the agreement had positively decided not to
// create it: the claim logic here was "identical to seam 5's", which owns it through a mock at the
// browser handler, and seam 4 observes this endpoint end to end. Stage 4's code review showed that
// reason had stopped being true, and it is worth recording why rather than quietly adding a file.
//
// Two branches here are specific to this handler and to no other. The response is JSON rather than a
// rerendered template, and the replay branch deliberately emits AuditOTPCodeReplayDetected *without*
// the AuditAuthFailedOtp that both browser sites emit beside it, because a wrong code at this endpoint
// has never audited anything and enabling OTP is not an authentication ceremony. Neither of those is
// reachable from seam 5, and no integration case can drive them either: a sequential second enable is
// intercepted by OTP_ALREADY_ENABLED before the claim is ever consulted, so making TryConsumeUserOTPStep
// return false end to end would need a coordinated concurrency hook. Regressing the replay branch to a
// distinct error code, dropping the replay event, or letting a claim error enable OTP anyway all left
// the whole four-engine suite green.
//
// The enable branch is covered from the claim onwards, which is the boundary the review found
// uncovered. The disable branch is covered only for decision 13's transaction shape, the call sequence
// no sequential caller can observe; that the marker is genuinely reset stays with
// TestAPIAccountOTPPut_Disable_ResetsConsumedStep, which asserts it end to end on four engines.

// otpTestSecret is a valid base32 TOTP secret, 32 chars of A-Z and 2-7. Nothing about the digits
// matters, only that totp and MatchStep agree on it.
const otpTestSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

// otpTestKeyURL is what the server actually stores for a pending enrollment: the whole otpauth://
// URL, not the bare seed, so a repeat GET can render a byte-identical QR image from it. Written out
// with algorithm, digits and period explicit, exactly as otp.Key.URL() serializes them, so
// otp.SecretFromKeyURL reads otpTestSecret back off it.
const otpTestKeyURL = "otpauth://totp/Goiabada:otp@example.com?algorithm=SHA1&digits=6&issuer=Goiabada&period=30&secret=" + otpTestSecret

// pendingEnrollment is the encrypted-and-timestamped pair the server writes when it issues an
// enrollment. issuedAt is passed in so a case can put the pair inside or outside
// otpEnrollmentLifetime.
func pendingEnrollment(t *testing.T, keyURL string, issuedAt time.Time) ([]byte, sql.NullTime) {
	t.Helper()
	ciphertext, err := encryption.EncryptData(keyURL)
	require.NoError(t, err)
	return ciphertext, sql.NullTime{Time: issuedAt, Valid: true}
}

// accountOTPEnableRequest builds an enable request carrying a code the handler will match, so every
// case below reaches the claim rather than stopping at the matcher.
//
// It sends no secretKey, and that is the contract rather than an omission: the server enrolls the
// seed it issued and refuses a request that names one (#247). accountOTPRawRequest below is what
// the cases about that refusal use.
func accountOTPEnableRequest(t *testing.T, subject, password, code string) *http.Request {
	t.Helper()
	return accountOTPRawRequest(t, subject, map[string]interface{}{
		"enabled":  true,
		"password": password,
		"otpCode":  code,
	})
}

// accountOTPRawRequest builds a PUT from an arbitrary body, so a case can send a field the request
// struct no longer models.
func accountOTPRawRequest(t *testing.T, subject string, fields map[string]interface{}) *http.Request {
	t.Helper()
	body, err := json.Marshal(fields)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/account/otp", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return setTokenContextWithClaims(req, map[string]interface{}{"sub": subject})
}

// currentOtpCode returns a code that matches otpTestSecret right now. The step it belongs to is
// deliberately not asserted against a computed value: decision 12's walk can report a step below the
// current one when a collision chain exists, and a period boundary can fall between this call and the
// handler's own time.Now(). Every case below captures the step the handler actually claimed and asserts
// the audit payload against that, which pins the payload without pinning the clock.
func currentOtpCode(t *testing.T) string {
	t.Helper()
	code, err := totp.GenerateCode(otpTestSecret, time.Now().UTC())
	require.NoError(t, err)
	return code
}

// otpTestUser is a user part way through an enrollment: the server has issued otpTestKeyURL to them
// and recorded it, which is the only state the enable branch can now succeed from. Without the
// pending pair every case here would stop at OTP_ENROLLMENT_NOT_PENDING before reaching the claim.
func otpTestUser(t *testing.T, password string) *models.User {
	t.Helper()
	hash, err := hashutil.HashPassword(password)
	require.NoError(t, err)
	ciphertext, issuedAt := pendingEnrollment(t, otpTestKeyURL, time.Now().UTC())
	// OTPEnabled false: the OTP_ALREADY_ENABLED check above the claim is what makes this the only
	// state the enable branch is ever reached in, which is why requireOTPEnabled is passed false.
	return &models.User{
		Id: 77, Enabled: true, PasswordHash: hash, OTPEnabled: false,
		OtpEnrollmentSecretEncrypted: ciphertext,
		OtpEnrollmentIssuedAt:        issuedAt,
	}
}

// TestHandleAPIAccountOTPPut_Enable_ReplayIsRefused is the one that matters. A refused claim must draw
// the identical body a wrong code draws, must record the replay, and must not enable OTP.
func TestHandleAPIAccountOTPPut_Enable_ReplayIsRefused(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	const subject = "the-subject"
	const password = "P4ss!word"
	user := otpTestUser(t, password)

	database.On("GetUserBySubject", (*sql.Tx)(nil), subject).Return(user, nil).Once()

	// The step is captured rather than predicted, per currentOtpCode's note. false is the replay
	// answer: the compare-and-set matched no row because this step is already recorded.
	var claimedStep int64
	database.On("TryConsumeUserOTPStep", (*sql.Tx)(nil), user.Id, mock.Anything, false).
		Run(func(args mock.Arguments) {
			claimedStep = args.Get(2).(int64)
		}).
		Return(false, nil).Once()

	// Registering only this event is itself the assertion that AuditAuthFailedOtp is not emitted: the
	// mock fails an unexpected Log call, so adding the browser sites' failure event here would break
	// this test. That asymmetry is deliberate and decision 5 permits it, since there is no existing
	// failure event at this endpoint for the replay event to be emitted "alongside".
	var payload map[string]interface{}
	auditLogger.On("Log", constants.AuditOTPCodeReplayDetected, mock.Anything).
		Run(func(args mock.Arguments) {
			payload = args.Get(1).(map[string]interface{})
		}).Return().Once()

	rr := httptest.NewRecorder()
	HandleAPIAccountOTPPut(database, auditLogger, unlimitedCredentials{}).
		ServeHTTP(rr, accountOTPEnableRequest(t, subject, password, currentOtpCode(t)))

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Equal(t, "INVALID_OTP_CODE", errorCodeOf(t, rr))
	assert.Equal(t, wrongCodeDescription(t), descriptionOf(t, rr),
		"a replay must be indistinguishable from a wrong code to the caller")

	require.NotZero(t, claimedStep, "the handler must have matched a step before claiming it")
	assert.Equal(t, user.Id, payload["userId"])
	assert.Equal(t, claimedStep, payload["step"],
		"the replay event carries the step that was replayed, so an operator can see which code it was")

	// No enable write. UpdateUser is not registered on the mock, so reaching it would fail the test as
	// an unexpected call; asserting it explicitly says that is the point rather than an accident.
	database.AssertNotCalled(t, "UpdateUser", mock.Anything, mock.Anything)
	assert.False(t, user.OTPEnabled)
}

// TestHandleAPIAccountOTPPut_Enable_ClaimErrorIs500 pins fail-closed. A database fault must not be
// collapsed into either answer: refusing valid codes is bad and accepting replays is worse.
func TestHandleAPIAccountOTPPut_Enable_ClaimErrorIs500(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	const subject = "the-subject"
	const password = "P4ss!word"
	user := otpTestUser(t, password)

	database.On("GetUserBySubject", (*sql.Tx)(nil), subject).Return(user, nil).Once()
	database.On("TryConsumeUserOTPStep", (*sql.Tx)(nil), user.Id, mock.Anything, false).
		Return(false, errors.New("the database is unwell")).Once()

	rr := httptest.NewRecorder()
	HandleAPIAccountOTPPut(database, auditLogger, unlimitedCredentials{}).
		ServeHTTP(rr, accountOTPEnableRequest(t, subject, password, currentOtpCode(t)))

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Equal(t, "INTERNAL_SERVER_ERROR", errorCodeOf(t, rr))

	// Nothing enabled and nothing audited. An error must not read as a successful enrollment, and it
	// must not read as a replay either: the event names an attack and a fault is not one.
	database.AssertNotCalled(t, "UpdateUser", mock.Anything, mock.Anything)
	assert.False(t, user.OTPEnabled)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything)
}

// TestHandleAPIAccountOTPPut_Enable_WrongCodeDoesNotClaim is the control that makes the two cases above
// attributable. A code that does not match must stop at the matcher, so the claim is never reached and
// nothing is audited.
func TestHandleAPIAccountOTPPut_Enable_WrongCodeDoesNotClaim(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	const subject = "the-subject"
	const password = "P4ss!word"
	user := otpTestUser(t, password)

	database.On("GetUserBySubject", (*sql.Tx)(nil), subject).Return(user, nil).Once()

	rr := httptest.NewRecorder()
	HandleAPIAccountOTPPut(database, auditLogger, unlimitedCredentials{}).
		ServeHTTP(rr, accountOTPEnableRequest(t, subject, password, wrongButWellFormedCode(t)))

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Equal(t, "INVALID_OTP_CODE", errorCodeOf(t, rr))
	database.AssertNotCalled(t, "TryConsumeUserOTPStep",
		mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything)
}

// TestHandleAPIAccountOTPPut_Enable_CommitsBothWritesAtomically is the enable half of #242
// decision 2, and the counterpart of the disable case below. Establishing the authenticator and
// advancing the OTP configuration generation have to land as one commit.
//
// The alternative rejected there was a separate increment whose error is merely surfaced, and the
// window it leaves is the exact state the re-prompt exists to prevent: otp_enabled on with the
// counter unmoved, so every existing session's snapshot still matches and they all keep obtaining
// tokens stamped acr: urn:goiabada:level2_optional with amr: ["pwd"] for a user who now has an
// authenticator. The caller cannot recover from it either, since a retry is refused with
// OTP_ALREADY_ENABLED and the only way out is to disable and enroll again.
//
// The call shape is what distinguishes this from a sequential pair of writes, which is why it is
// asserted through a mock: end to end, a caller observes the same final row either way.
func TestHandleAPIAccountOTPPut_Enable_CommitsBothWritesAtomically(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	const subject = "the-subject"
	const password = "P4ss!word"
	user := otpTestUser(t, password)

	database.On("GetUserBySubject", (*sql.Tx)(nil), subject).Return(user, nil).Once()
	database.On("TryConsumeUserOTPStep", (*sql.Tx)(nil), user.Id, mock.Anything, false).
		Return(true, nil).Once()

	var calls []string
	database.On("BeginTransaction").Return(otpDisableTx, nil).
		Run(func(mock.Arguments) { calls = append(calls, "begin") }).Once()
	database.On("UpdateUser", otpDisableTx, user).Return(nil).
		Run(func(mock.Arguments) { calls = append(calls, "update") }).Once()
	database.On("IncrementUserOtpConfigGeneration", otpDisableTx, user.Id).Return(int64(1), nil).
		Run(func(mock.Arguments) { calls = append(calls, "increment") }).Once()
	database.On("ClearPendingOTPEnrollment", otpDisableTx, user.Id).Return(nil).
		Run(func(mock.Arguments) { calls = append(calls, "clear") }).Once()
	database.On("CommitTransaction", otpDisableTx).Return(nil).
		Run(func(mock.Arguments) { calls = append(calls, "commit") }).Once()
	database.On("RollbackTransaction", otpDisableTx).Return(nil).Once()

	database.On("GetUserById", (*sql.Tx)(nil), user.Id).Return(user, nil).Once()
	auditLogger.On("Log", constants.AuditEnabledOTP, mock.Anything).Return().Once()

	rr := httptest.NewRecorder()
	HandleAPIAccountOTPPut(database, auditLogger, unlimitedCredentials{}).
		ServeHTTP(rr, accountOTPEnableRequest(t, subject, password, currentOtpCode(t)))

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, []string{"begin", "update", "increment", "clear", "commit"}, calls,
		"the enable write, the counter advance and the pending-enrolment clear belong inside one "+
			"transaction, commit last. The clear is handed otpDisableTx rather than nil: committed "+
			"on its own it would discard the pending seed even when the enable rolls back, and the "+
			"caller would be left with a QR code the server no longer recognises (#247)")
	assert.True(t, user.OTPEnabled)

	// Part 1.3. The handler used to read the caller's own sid claim and flag that one session,
	// so a token with no sid, which this request carries, reached no session at all. The counter
	// above covers every session of this user, and it fires whether or not a sid is present.
	database.AssertNotCalled(t, "GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything)
	database.AssertNotCalled(t, "UpdateUserSession", mock.Anything, mock.Anything)
}

// TestHandleAPIAccountOTPPut_Enable_CounterFailureRollsBack is the other half: the enable write
// lands and the counter advance fails. Committing here is exactly the state above, so the whole
// enrollment goes back and the caller retries cleanly. The TOTP code is spent either way, which is
// not new: #111 claims the step before the enable write precisely so a failed enable cannot leave
// OTP switched on, and the user types the next code.
func TestHandleAPIAccountOTPPut_Enable_CounterFailureRollsBack(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	const subject = "the-subject"
	const password = "P4ss!word"
	user := otpTestUser(t, password)

	database.On("GetUserBySubject", (*sql.Tx)(nil), subject).Return(user, nil).Once()
	database.On("TryConsumeUserOTPStep", (*sql.Tx)(nil), user.Id, mock.Anything, false).
		Return(true, nil).Once()

	database.On("BeginTransaction").Return(otpDisableTx, nil).Once()
	database.On("UpdateUser", otpDisableTx, user).Return(nil).Once()
	database.On("IncrementUserOtpConfigGeneration", otpDisableTx, user.Id).
		Return(int64(0), errors.New("the database is unwell")).Once()
	database.On("RollbackTransaction", otpDisableTx).Return(nil).Once()

	rr := httptest.NewRecorder()
	HandleAPIAccountOTPPut(database, auditLogger, unlimitedCredentials{}).
		ServeHTTP(rr, accountOTPEnableRequest(t, subject, password, currentOtpCode(t)))

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Equal(t, "INTERNAL_SERVER_ERROR", errorCodeOf(t, rr))
	// Neither is registered on the mock, so reaching either would already fail the test. Saying so
	// explicitly is the point: nothing commits, and an enable that did not happen is not audited
	// as one.
	database.AssertNotCalled(t, "CommitTransaction", mock.Anything)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything)
}

// otpDisableTx is an opaque non-nil transaction, the counterpart of this package's apiRevokeTx. The
// two disable cases below register every write against this exact handle, so a write that slipped
// back to the pool would arrive carrying a nil tx and fail as an unexpected call. That is the
// assertion; nothing about *sql.Tx itself is exercised.
var otpDisableTx = &sql.Tx{}

// accountOTPDisableRequest carries no sid claim. That used to matter, because the handler read the
// claim to flag one session; it no longer does, and the counter advance below fires for every
// caller whether or not a sid is present, which is part 1.3 of #242 pinned at this tier.
func accountOTPDisableRequest(t *testing.T, subject, password string) *http.Request {
	t.Helper()
	body, err := json.Marshal(map[string]interface{}{
		"enabled":  false,
		"password": password,
	})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/account/otp", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return setTokenContextWithClaims(req, map[string]interface{}{"sub": subject})
}

// TestHandleAPIAccountOTPPut_Disable_CommitsBothWritesAtomically pins #111 decision 13. Clearing
// otp_enabled and resetting the consumed-step marker have to land as one commit: committed separately,
// the row spends a moment reading otp_enabled = false with the old marker standing, and an enrollment
// landing in that moment claims a step that this reset then erases, leaving a consumed code claimable
// again. The hazard is the gap between two commits, not an uncommitted read, which no supported engine
// permits.
//
// The four-engine integration cases (TestAPIAccountOTPPut_Disable_ResetsConsumedStep and its admin
// sibling) prove the reset happens; they cannot see whether it shares a transaction with the write
// above it, because a sequential caller observes the same end state either way. Only the call shape
// distinguishes them, which is why this is asserted through a mock and why the order is asserted too:
// both writes inside, commit last.
func TestHandleAPIAccountOTPPut_Disable_CommitsBothWritesAtomically(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	const subject = "the-subject"
	const password = "P4ss!word"
	user := otpTestUser(t, password)
	user.OTPEnabled = true

	database.On("GetUserBySubject", (*sql.Tx)(nil), subject).Return(user, nil).Once()

	var calls []string
	database.On("BeginTransaction").Return(otpDisableTx, nil).
		Run(func(mock.Arguments) { calls = append(calls, "begin") }).Once()
	database.On("UpdateUser", otpDisableTx, user).Return(nil).
		Run(func(mock.Arguments) { calls = append(calls, "update") }).Once()
	database.On("ResetUserOTPStep", otpDisableTx, user.Id).Return(nil).
		Run(func(mock.Arguments) { calls = append(calls, "reset") }).Once()
	// The counter that tells every session of this user they owe a second factor again, inside the
	// same transaction for the reason #242 decision 2 gives: a removal that commits without the
	// counter moving leaves every live session asserting amr ["pwd","otp"] for an authenticator
	// that is gone.
	database.On("IncrementUserOtpConfigGeneration", otpDisableTx, user.Id).Return(int64(1), nil).
		Run(func(mock.Arguments) { calls = append(calls, "increment") }).Once()
	database.On("CommitTransaction", otpDisableTx).Return(nil).
		Run(func(mock.Arguments) { calls = append(calls, "commit") }).Once()
	// Deferred, so it runs after the commit and is a no-op there. Registered rather than asserted:
	// its absence would mean a failing write left the transaction open.
	database.On("RollbackTransaction", otpDisableTx).Return(nil).Once()

	database.On("GetUserById", (*sql.Tx)(nil), user.Id).Return(user, nil).Once()
	auditLogger.On("Log", constants.AuditDisabledOTP, mock.Anything).Return().Once()

	rr := httptest.NewRecorder()
	HandleAPIAccountOTPPut(database, auditLogger, unlimitedCredentials{}).
		ServeHTTP(rr, accountOTPDisableRequest(t, subject, password))

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, []string{"begin", "update", "reset", "increment", "commit"}, calls,
		"all three writes belong inside one transaction, otp_enabled first per #111 decision 10, "+
			"the counter advance last before the commit per #242 decision 2")
	assert.False(t, user.OTPEnabled)
	assert.Empty(t, user.OTPSecretEncrypted, "the authenticator's secret goes with it")
}

// TestHandleAPIAccountOTPPut_Disable_ResetFailureRollsBack is the other half of the transaction: a
// failing reset must take the otp_enabled write down with it rather than leaving the authenticator
// half-removed. Committing here would strand the row at otp_enabled = false with a live marker, which
// is a lockout on re-enrollment until the marker's step passes.
func TestHandleAPIAccountOTPPut_Disable_ResetFailureRollsBack(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	const subject = "the-subject"
	const password = "P4ss!word"
	user := otpTestUser(t, password)
	user.OTPEnabled = true

	database.On("GetUserBySubject", (*sql.Tx)(nil), subject).Return(user, nil).Once()
	database.On("BeginTransaction").Return(otpDisableTx, nil).Once()
	database.On("UpdateUser", otpDisableTx, user).Return(nil).Once()
	database.On("ResetUserOTPStep", otpDisableTx, user.Id).
		Return(errors.New("the database is unwell")).Once()
	database.On("RollbackTransaction", otpDisableTx).Return(nil).Once()

	rr := httptest.NewRecorder()
	HandleAPIAccountOTPPut(database, auditLogger, unlimitedCredentials{}).
		ServeHTTP(rr, accountOTPDisableRequest(t, subject, password))

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Equal(t, "INTERNAL_SERVER_ERROR", errorCodeOf(t, rr))
	// Neither is registered on the mock, so reaching either would already fail the test. Saying so
	// explicitly is the point rather than an accident: nothing commits, and a disable that did not
	// happen is not audited as one.
	database.AssertNotCalled(t, "CommitTransaction", mock.Anything)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything)
}

// wrongButWellFormedCode is six digits that pass the handler's shape checks and do not match the secret,
// so the matcher is what refuses them. Derived by walking away from the real code rather than hardcoded,
// because a fixed literal is the real code roughly once in a million runs.
func wrongButWellFormedCode(t *testing.T) string {
	t.Helper()
	real := currentOtpCode(t)
	for _, candidate := range []string{"000000", "111111", "222222"} {
		if candidate != real {
			if _, matched := otp.MatchStep(candidate, otpTestSecret, time.Now().UTC()); !matched {
				return candidate
			}
		}
	}
	t.Fatal("could not find a six-digit code that the secret refuses")
	return ""
}

// wrongCodeDescription is the description the handler writes for a code that did not match, read out of
// the handler itself by driving that branch. The replay branch has to write this same string, and
// comparing against a copy of the literal would pass with both copies wrong.
func wrongCodeDescription(t *testing.T) string {
	t.Helper()
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	const subject = "oracle-subject"
	const password = "P4ss!word"
	user := otpTestUser(t, password)
	database.On("GetUserBySubject", (*sql.Tx)(nil), subject).Return(user, nil).Once()

	rr := httptest.NewRecorder()
	HandleAPIAccountOTPPut(database, auditLogger, unlimitedCredentials{}).
		ServeHTTP(rr, accountOTPEnableRequest(t, subject, password, wrongButWellFormedCode(t)))
	require.Equal(t, http.StatusBadRequest, rr.Code)
	return descriptionOf(t, rr)
}

// decodeErrorBody reads writeJSONError's envelope, which is flat: error_code and error_description.
func decodeErrorBody(t *testing.T, rr *httptest.ResponseRecorder) api.ErrorResponse {
	t.Helper()
	var body api.ErrorResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body),
		"expected an error envelope, got %s", rr.Body.String())
	return body
}

func errorCodeOf(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	return decodeErrorBody(t, rr).ErrorCode
}

func descriptionOf(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	return decodeErrorBody(t, rr).ErrorDescription
}

// -----------------------------------------------------------------------------
// The enrollment contract (#247)
//
// Everything below is about one property: the server enrolls the seed it issued and no other, and
// it can only do that if the issuing step is a write and the confirming step reads it back. The
// cases come in two halves, the GET that issues and the PUT that consumes.
//
// Handler unit tests are where the compare-and-set losing, the pending value expiring and a
// caller-supplied secretKey can each be driven exactly. Seam G covers the same contract end to end
// over HTTP, where those three states are hard to arrange and easy to arrange wrongly.

// enrollmentGetRequest builds a GET carrying a validated token for the given subject, with the
// settings the handler reads out of the request context.
func enrollmentGetRequest(subject string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/account/otp/enrollment", nil)
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeySettings,
		&models.Settings{AppName: "Goiabada"}))
	return setTokenContextWithClaims(req, map[string]interface{}{"sub": subject})
}

func decodeEnrollment(t *testing.T, rr *httptest.ResponseRecorder) api.AccountOTPEnrollmentResponse {
	t.Helper()
	var resp api.AccountOTPEnrollmentResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp),
		"expected an enrollment response, got %s", rr.Body.String())
	return resp
}

// A live pending enrollment is answered as it stands, and nothing is minted. This is goal 7: a
// reload of the enrollment page must not replace the seed behind a QR code the user has already
// scanned, which is what every call did before (#242 part 3, still live on this surface).
//
// The generator mock is constructed and never given an expectation, so calling it fails the test.
// That is the assertion: mockery's NewOtpSecretGenerator(t) registers a cleanup that refuses an
// unexpected call.
func TestHandleAPIAccountOTPEnrollmentGet_LivePendingIsReturnedUnchanged(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	generator := mocks_otp.NewOtpSecretGenerator(t)

	const subject = "enrolling-subject"
	user := otpTestUser(t, "P4ss!word")
	database.On("GetUserBySubject", (*sql.Tx)(nil), subject).Return(user, nil).Once()

	rr := httptest.NewRecorder()
	HandleAPIAccountOTPEnrollmentGet(database, generator).ServeHTTP(rr, enrollmentGetRequest(subject))

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	resp := decodeEnrollment(t, rr)
	assert.Equal(t, otpTestSecret, resp.SecretKey,
		"a second call must answer with the seed already issued, not a new one")

	expectedImage, err := otp.RenderQRCodeImage(otpTestKeyURL)
	require.NoError(t, err)
	assert.Equal(t, expectedImage, resp.Base64Image,
		"and with the same QR image, since it is rendered from the same stored URL")

	database.AssertNotCalled(t, "TryInstallPendingOTPEnrollment",
		mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// A pending enrollment older than otpEnrollmentLifetime is not honoured: it is replaced. Without
// decision 12's expiry an abandoned seed would sit on the user row with nothing to sweep it.
func TestHandleAPIAccountOTPEnrollmentGet_ExpiredPendingIsReplaced(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	generator := mocks_otp.NewOtpSecretGenerator(t)

	const subject = "enrolling-subject"
	user := otpTestUser(t, "P4ss!word")
	user.OtpEnrollmentSecretEncrypted, user.OtpEnrollmentIssuedAt =
		pendingEnrollment(t, otpTestKeyURL, time.Now().UTC().Add(-otpEnrollmentLifetime-time.Minute))
	database.On("GetUserBySubject", (*sql.Tx)(nil), subject).Return(user, nil).Once()

	freshKeyURL, err := (&otp.OTPSecretGenerator{}).GenerateOTPSecret("otp@example.com", "Goiabada")
	require.NoError(t, err)
	generator.On("GenerateOTPSecret", user.Email, "Goiabada").Return(freshKeyURL, nil).Once()

	// The staleBefore the handler passes must be far enough back to leave the expired value
	// replaceable and no further, so it is captured and checked rather than waved through.
	var staleBefore time.Time
	database.On("TryInstallPendingOTPEnrollment", (*sql.Tx)(nil), user.Id,
		mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			staleBefore = args.Get(4).(time.Time)
		}).
		Return(true, nil).Once()

	rr := httptest.NewRecorder()
	HandleAPIAccountOTPEnrollmentGet(database, generator).ServeHTTP(rr, enrollmentGetRequest(subject))

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	freshSecret, err := otp.SecretFromKeyURL(freshKeyURL)
	require.NoError(t, err)
	assert.Equal(t, freshSecret, decodeEnrollment(t, rr).SecretKey)
	assert.NotEqual(t, otpTestSecret, decodeEnrollment(t, rr).SecretKey)

	assert.WithinDuration(t, time.Now().UTC().Add(-otpEnrollmentLifetime), staleBefore, time.Minute,
		"the expiry line the writer is given must be the lifetime behind now")
}

// Losing the compare-and-set answers with the winner's seed rather than the one this call minted.
// Two concurrent enrollment calls must agree on one QR code: handing out the unstored one would
// give the user a code the PUT can never accept.
func TestHandleAPIAccountOTPEnrollmentGet_LostRaceAnswersWithTheStoredSeed(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	generator := mocks_otp.NewOtpSecretGenerator(t)

	const subject = "enrolling-subject"
	loser := otpTestUser(t, "P4ss!word")
	loser.OtpEnrollmentSecretEncrypted, loser.OtpEnrollmentIssuedAt = nil, sql.NullTime{}
	database.On("GetUserBySubject", (*sql.Tx)(nil), subject).Return(loser, nil).Once()

	mintedKeyURL, err := (&otp.OTPSecretGenerator{}).GenerateOTPSecret("otp@example.com", "Goiabada")
	require.NoError(t, err)
	generator.On("GenerateOTPSecret", loser.Email, "Goiabada").Return(mintedKeyURL, nil).Once()

	database.On("TryInstallPendingOTPEnrollment", (*sql.Tx)(nil), loser.Id,
		mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Once()

	// The row as the winner left it.
	winner := otpTestUser(t, "P4ss!word")
	database.On("GetUserById", (*sql.Tx)(nil), loser.Id).Return(winner, nil).Once()

	rr := httptest.NewRecorder()
	HandleAPIAccountOTPEnrollmentGet(database, generator).ServeHTTP(rr, enrollmentGetRequest(subject))

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	mintedSecret, err := otp.SecretFromKeyURL(mintedKeyURL)
	require.NoError(t, err)
	resp := decodeEnrollment(t, rr)
	assert.Equal(t, otpTestSecret, resp.SecretKey, "the stored seed is the one the caller must get")
	assert.NotEqual(t, mintedSecret, resp.SecretKey, "never the seed this call failed to store")
}

// A caller that lost the race to a user who has finished enrolling gets the ordinary refusal, not a
// 500 and not a seed. Enrollment is over for them.
func TestHandleAPIAccountOTPEnrollmentGet_LostRaceToACompletedEnrollment(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	generator := mocks_otp.NewOtpSecretGenerator(t)

	const subject = "enrolling-subject"
	user := otpTestUser(t, "P4ss!word")
	user.OtpEnrollmentSecretEncrypted, user.OtpEnrollmentIssuedAt = nil, sql.NullTime{}
	database.On("GetUserBySubject", (*sql.Tx)(nil), subject).Return(user, nil).Once()

	keyURL, err := (&otp.OTPSecretGenerator{}).GenerateOTPSecret("otp@example.com", "Goiabada")
	require.NoError(t, err)
	generator.On("GenerateOTPSecret", user.Email, "Goiabada").Return(keyURL, nil).Once()
	database.On("TryInstallPendingOTPEnrollment", (*sql.Tx)(nil), user.Id,
		mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Once()

	enrolled := otpTestUser(t, "P4ss!word")
	enrolled.OTPEnabled = true
	enrolled.OtpEnrollmentSecretEncrypted, enrolled.OtpEnrollmentIssuedAt = nil, sql.NullTime{}
	database.On("GetUserById", (*sql.Tx)(nil), user.Id).Return(enrolled, nil).Once()

	rr := httptest.NewRecorder()
	HandleAPIAccountOTPEnrollmentGet(database, generator).ServeHTTP(rr, enrollmentGetRequest(subject))

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Equal(t, "OTP_ALREADY_ENABLED", errorCodeOf(t, rr))
}

// A request still carrying secretKey is refused, and refused loudly. Decision 13 chose the break:
// nothing sets DisallowUnknownFields, so dropping the field alone would have changed which secret
// was enrolled without telling the integrator anything.
//
// The table is the point. The refusal is on the field's presence, so a null and a number must
// refuse exactly as a string does, and it runs before the password check so an upgrading caller
// sees the reason rather than an authentication failure.
func TestHandleAPIAccountOTPPut_SecretKeyIsRefused(t *testing.T) {
	testCases := []struct {
		name  string
		value interface{}
	}{
		{name: "a secret", value: otpTestSecret},
		{name: "an empty string", value: ""},
		{name: "null", value: nil},
		{name: "a number", value: 12345},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// No expectations on either mock: the refusal must land before the user is
			// loaded, so any database call fails this test.
			database := mocks_data.NewDatabase(t)
			auditLogger := mocks_audit.NewAuditLogger(t)

			req := accountOTPRawRequest(t, "the-subject", map[string]interface{}{
				"enabled":   true,
				"password":  "P4ss!word",
				"otpCode":   currentOtpCode(t),
				"secretKey": tc.value,
			})

			rr := httptest.NewRecorder()
			HandleAPIAccountOTPPut(database, auditLogger, unlimitedCredentials{}).ServeHTTP(rr, req)

			assert.Equal(t, http.StatusBadRequest, rr.Code)
			assert.Equal(t, "SECRET_KEY_NOT_ACCEPTED", errorCodeOf(t, rr))
			assert.Contains(t, descriptionOf(t, rr), "/api/v1/account/otp/enrollment",
				"the refusal must say where the enrollment now comes from")
		})
	}
}

// A disable request carrying secretKey is refused too. The rule is about the shape of the request,
// not about the branch it would have taken.
func TestHandleAPIAccountOTPPut_SecretKeyIsRefusedOnDisableToo(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	req := accountOTPRawRequest(t, "the-subject", map[string]interface{}{
		"enabled":   false,
		"password":  "P4ss!word",
		"secretKey": otpTestSecret,
	})

	rr := httptest.NewRecorder()
	HandleAPIAccountOTPPut(database, auditLogger, unlimitedCredentials{}).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Equal(t, "SECRET_KEY_NOT_ACCEPTED", errorCodeOf(t, rr))
}

// countingCredentials is unlimitedCredentials that remembers. The stub above answers silently,
// which is right for the cases that only need the limiter not to refuse; this one is for the case
// that has to assert the budget was never spent at all.
type countingCredentials struct{ failures int }

func (c *countingCredentials) RecordCredentialFailure(*http.Request) { c.failures++ }

// TestHandleAPIAccountOTPPut_OversizedBodyIsRefused pins maxOTPRequestBodyBytes.
//
// This handler is the one API JSON endpoint that reads its request body WHOLE, with io.ReadAll,
// because the body is parsed twice: once as a raw object to see whether the caller sent a
// secretKey field at all, and once into the request struct. Every other JSON handler streams
// through a decoder, and the three upload handlers already cap their reads. Buffering is what
// makes the cap load-bearing, so the cap needs a test that fails without it (#247).
//
// THE PADDING IS VALID JSON, AND THAT IS THE WHOLE DESIGN OF THIS CASE. A malformed oversized body
// answers 400 INVALID_REQUEST_BODY whether the cap is there or not, from the json.Unmarshal below
// it, so it would pass with MaxBytesReader deleted and pin nothing. With well-formed JSON the two
// outcomes separate: capped, io.ReadAll fails and the handler answers 400 having touched nothing;
// uncapped, it parses cleanly and runs on to load the user, which the expectation-free mocks turn
// into a failure. Verified by mutation, replacing the read with a bare io.ReadAll(r.Body).
//
// No secretKey either, for the same reason: that refusal also answers 400 and would mask this one.
func TestHandleAPIAccountOTPPut_OversizedBodyIsRefused(t *testing.T) {
	// Expectation-free: an oversized body must be refused before the user is loaded, so any
	// database or audit call is a failure, and the limiter is asked afterwards.
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)
	limiter := &countingCredentials{}

	req := accountOTPRawRequest(t, "the-subject", map[string]interface{}{
		"enabled":  true,
		"password": "P4ss!word",
		"otpCode":  currentOtpCode(t),
		// An unknown field, so it is ignored rather than rejected on its name: nothing here
		// sets DisallowUnknownFields. Its only job is to put the body over the cap.
		"padding": strings.Repeat("A", maxOTPRequestBodyBytes),
	})
	assert.Greater(t, req.ContentLength, int64(maxOTPRequestBodyBytes),
		"the body must actually exceed the cap, or this case proves nothing")

	rr := httptest.NewRecorder()
	HandleAPIAccountOTPPut(database, auditLogger, limiter).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Equal(t, "INVALID_REQUEST_BODY", errorCodeOf(t, rr))

	// The shared credential budget is not spent by a request that never reached a password
	// check. An oversized body would otherwise be a way to exhaust the account's own limiter.
	assert.Zero(t, limiter.failures,
		"refusing an oversized body must not spend the credential budget")
}

// No live pending enrollment refuses the enable, and refuses it before any code is checked. Both
// rows are the same refusal deliberately: an expired enrollment is no enrollment.
//
// This is also what makes a partially migrated or rolled back deployment fail closed. With nothing
// to read back, enrolling stops working rather than falling back to trusting the wire again.
func TestHandleAPIAccountOTPPut_Enable_RefusedWithoutALivePendingEnrollment(t *testing.T) {
	testCases := []struct {
		name    string
		prepare func(*testing.T, *models.User)
	}{
		{
			name: "none was ever issued",
			prepare: func(t *testing.T, u *models.User) {
				u.OtpEnrollmentSecretEncrypted, u.OtpEnrollmentIssuedAt = nil, sql.NullTime{}
			},
		},
		{
			name: "the one issued has expired",
			prepare: func(t *testing.T, u *models.User) {
				u.OtpEnrollmentSecretEncrypted, u.OtpEnrollmentIssuedAt = pendingEnrollment(
					t, otpTestKeyURL, time.Now().UTC().Add(-otpEnrollmentLifetime-time.Second))
			},
		},
		{
			name: "ciphertext with no issue time, which no writer produces",
			prepare: func(t *testing.T, u *models.User) {
				u.OtpEnrollmentIssuedAt = sql.NullTime{}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			database := mocks_data.NewDatabase(t)
			auditLogger := mocks_audit.NewAuditLogger(t)

			const subject = "the-subject"
			const password = "P4ss!word"
			user := otpTestUser(t, password)
			tc.prepare(t, user)
			database.On("GetUserBySubject", (*sql.Tx)(nil), subject).Return(user, nil).Once()

			rr := httptest.NewRecorder()
			HandleAPIAccountOTPPut(database, auditLogger, unlimitedCredentials{}).
				ServeHTTP(rr, accountOTPEnableRequest(t, subject, password, currentOtpCode(t)))

			assert.Equal(t, http.StatusBadRequest, rr.Code)
			assert.Equal(t, "OTP_ENROLLMENT_NOT_PENDING", errorCodeOf(t, rr))

			// Nothing was claimed and nothing was written. A refusal that still spent the
			// user's time step would burn a code they could otherwise retry with.
			database.AssertNotCalled(t, "TryConsumeUserOTPStep",
				mock.Anything, mock.Anything, mock.Anything, mock.Anything)
			assert.False(t, user.OTPEnabled)
		})
	}
}

// The seed that gets stored is the one the server issued. This is the defect in one assertion: the
// handler used to match the code against the secret the request carried and then store that same
// value, so it enrolled whatever it was handed.
//
// The code submitted here is generated from otpTestSecret, which is the pending seed, so a handler
// still reading a caller-supplied secret would find none and could not reach the claim at all.
// What the case pins is the other half: the value that reaches the row.
func TestHandleAPIAccountOTPPut_Enable_StoresTheIssuedSeed(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	const subject = "the-subject"
	const password = "P4ss!word"
	user := otpTestUser(t, password)
	database.On("GetUserBySubject", (*sql.Tx)(nil), subject).Return(user, nil).Once()
	database.On("TryConsumeUserOTPStep", (*sql.Tx)(nil), user.Id, mock.Anything, false).
		Return(true, nil).Once()

	tx := &sql.Tx{}
	database.On("BeginTransaction").Return(tx, nil).Once()
	database.On("RollbackTransaction", tx).Return(nil).Once()
	database.On("UpdateUser", tx, user).Return(nil).Once()
	database.On("IncrementUserOtpConfigGeneration", tx, user.Id).Return(int64(4), nil).Once()
	// The clear rides in the enable's own transaction, so no committed state has OTP on with a
	// live seed still installed behind it.
	database.On("ClearPendingOTPEnrollment", tx, user.Id).Return(nil).Once()
	database.On("CommitTransaction", tx).Return(nil).Once()
	database.On("GetUserById", (*sql.Tx)(nil), user.Id).Return(user, nil).Once()
	auditLogger.On("Log", constants.AuditEnabledOTP, mock.Anything).Return().Once()

	rr := httptest.NewRecorder()
	HandleAPIAccountOTPPut(database, auditLogger, unlimitedCredentials{}).
		ServeHTTP(rr, accountOTPEnableRequest(t, subject, password, currentOtpCode(t)))

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.True(t, user.OTPEnabled)

	stored, err := user.GetOTPSecret()
	require.NoError(t, err)
	assert.Equal(t, otpTestSecret, stored,
		"the enrolled authenticator must be the one the server issued and recorded")
}

// A blank code is refused by name. OTP_CODE_AND_SECRET_REQUIRED became OTP_CODE_REQUIRED when the
// secret left the request, and a renamed error code is a published contract change that nothing
// else in the suite observes.
func TestHandleAPIAccountOTPPut_Enable_BlankCodeIsRefusedByName(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	const subject = "the-subject"
	const password = "P4ss!word"
	user := otpTestUser(t, password)
	database.On("GetUserBySubject", (*sql.Tx)(nil), subject).Return(user, nil).Once()

	rr := httptest.NewRecorder()
	HandleAPIAccountOTPPut(database, auditLogger, unlimitedCredentials{}).
		ServeHTTP(rr, accountOTPEnableRequest(t, subject, password, "   "))

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Equal(t, "OTP_CODE_REQUIRED", errorCodeOf(t, rr))
}
