package apihandlers

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The account API's enable holds a code to six ASCII digits before it compares it, and that check
// now reads the digits of any script as ASCII ones first (#662 decision 9). It trims nothing, as
// before, so a space around the code is refused by the check, with the check's own refusal.

const (
	codeShapeRefusal = "The code is 6 digits. Enter the one your authenticator app shows."
	wrongCodeRefusal = "That code isn't right. Codes change every 30 seconds, so enter the one your app shows now."
)

// codeInScript writes an ASCII code in the digits of the script whose zero is zero.
func codeInScript(code string, zero rune) string {
	out := make([]rune, 0, len(code))
	for _, c := range code {
		if c >= '0' && c <= '9' {
			c = zero + (c - '0')
		}
		out = append(out, c)
	}
	return string(out)
}

func TestHandleAccountOTPPut_Enable_ReadsTheDigitsOfAnyScript(t *testing.T) {
	for _, tc := range []struct {
		name string
		code func(ascii string) string
	}{
		{"full-width digits", func(c string) string { return codeInScript(c, '０') }},
		{"Arabic-Indic digits", func(c string) string { return codeInScript(c, '٠') }},
		{"Devanagari digits", func(c string) string { return codeInScript(c, '०') }},
		{"a mix of scripts in one code", func(c string) string {
			return c[:2] + codeInScript(c[2:4], '０') + codeInScript(c[4:5], '٠') + codeInScript(c[5:], '०')
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)

			const subject = "the-subject"
			const password = "P4ss!word"
			user := otpTestUser(t, password)
			database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), subject).Return(user, nil).Once()
			database.On("TryConsumeUserOTPStep", mock.Anything, (*sql.Tx)(nil), user.ID, mock.Anything).
				Return(true, nil).Once()
			tx := &sql.Tx{}
			datamocks.ExpectRunInTransaction(database, tx)
			database.On("TryEstablishUserOTP", mock.Anything, tx, user.ID, user.OTPConfigGeneration, mock.Anything).
				Return(true, nil).Once()
			database.On("IncrementUserOTPConfigGeneration", mock.Anything, tx, user.ID).Return(int64(4), nil).Once()
			database.On("ClearPendingOTPEnrollment", mock.Anything, tx, user.ID).Return(nil).Once()
			database.On("ClearUserOTPConsecutiveFailures", mock.Anything, tx, user.ID).Return(nil).Once()
			database.On("GetUserByIDForUpdate", mock.Anything, tx, user.ID).Return(user, nil).Once()
			database.On("ReplaceUserRecoveryCodes", mock.Anything, tx, user.ID, mock.Anything).Return(nil).Once()
			database.On("GetUserByID", mock.Anything, (*sql.Tx)(nil), user.ID).Return(user, nil).Once()
			auditLogger.On("Log", mock.Anything, audit.EventEnabledOTP, mock.Anything).Return().Once()
			auditLogger.On("Log", mock.Anything, audit.EventRecoveryCodesCreated, mock.Anything).Return().Once()

			rr := httptest.NewRecorder()
			HandleAccountOTPPut(database, auditLogger, unlimitedCredentials{}, testDataCipher, heldNotifier(t, &heldJobs{})).
				ServeHTTP(rr, accountOTPEnableRequest(t, subject, password, tc.code(currentOTPCode(t))))

			require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
			assert.True(t, user.OTPEnabled)
		})
	}
}

func TestHandleAccountOTPPut_Enable_RefusesWhatItRefusedInAnyScript(t *testing.T) {
	for _, tc := range []struct {
		name        string
		code        func(t *testing.T) string
		description string
	}{
		{"a wrong code in full-width digits, refused by the comparison",
			func(t *testing.T) string { return codeInScript(wrongButWellFormedCode(t), '０') }, wrongCodeRefusal},
		{"five full-width digits",
			func(t *testing.T) string { return codeInScript(currentOTPCode(t)[:5], '０') }, codeShapeRefusal},
		{"seven full-width digits",
			func(t *testing.T) string { return codeInScript(currentOTPCode(t)+"0", '０') }, codeShapeRefusal},
		{"a space inside a full-width code", func(t *testing.T) string {
			c := currentOTPCode(t)
			return codeInScript(c[:3]+" "+c[3:], '０')
		}, codeShapeRefusal},
		{"a space around an ASCII code, as before",
			func(t *testing.T) string { return " " + currentOTPCode(t) }, codeShapeRefusal},
		{"a space around a full-width code",
			func(t *testing.T) string { return codeInScript(currentOTPCode(t), '０') + " " }, codeShapeRefusal},
		{"an ideographic space around a full-width code",
			func(t *testing.T) string { return "　" + codeInScript(currentOTPCode(t), '０') }, codeShapeRefusal},
		{"full-width letters are no digits",
			func(*testing.T) string { return "ＡＢＣＤＥＦ" }, codeShapeRefusal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)

			const subject = "the-subject"
			const password = "P4ss!word"
			user := otpTestUser(t, password)
			database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), subject).Return(user, nil).Once()

			rr := httptest.NewRecorder()
			HandleAccountOTPPut(database, auditLogger, unlimitedCredentials{}, testDataCipher, heldNotifier(t, &heldJobs{})).
				ServeHTTP(rr, accountOTPEnableRequest(t, subject, password, tc.code(t)))

			assert.Equal(t, http.StatusBadRequest, rr.Code)
			assert.Equal(t, "INVALID_OTP_CODE", errorCodeOf(t, rr))
			assert.Equal(t, tc.description, descriptionOf(t, rr))
			assert.False(t, user.OTPEnabled)
			database.AssertNotCalled(t, "TryConsumeUserOTPStep",
				mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		})
	}
}
