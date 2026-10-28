package authflow

import (
	"context"
	"database/sql"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The sign-in form's password operation, held to one password comparison per submission against
// the hash that branch should compare, so a refusal takes as long whether or not the address has an
// account and whether or not its user has set a password (#681 decision 2). Its handler tests reach
// the operation only through its constructor and cannot see the comparisons.

// passwordComparison is one call to the operation's password verifier.
type passwordComparison struct {
	hashedPassword string
	password       string
}

// passwordVerifierRecorder stands in for the operation's password verifier: it records every
// comparison and answers what the test chose.
type passwordVerifierRecorder struct {
	answer bool
	calls  []passwordComparison
}

func (r *passwordVerifierRecorder) verify(hashedPassword string, password string) bool {
	r.calls = append(r.calls, passwordComparison{hashedPassword: hashedPassword, password: password})
	return r.answer
}

// fakePasswordSubmissionDatabase answers the one lookup with the account it holds, or with none.
type fakePasswordSubmissionDatabase struct {
	user    *record.User
	lookups []string
}

func (f *fakePasswordSubmissionDatabase) GetUserByEmail(_ context.Context, _ *sql.Tx, email string) (*record.User, error) {
	f.lookups = append(f.lookups, email)
	return f.user, nil
}

// fakePasswordSubmissionBrowser counts the rate-limiter charges and records the browser-session
// writes, which a refusal must not make.
type fakePasswordSubmissionBrowser struct {
	credentialFailures int
	rotations          int
	saves              []*ceremony.AuthContext
}

func (f *fakePasswordSubmissionBrowser) RecordCredentialFailure() {
	f.credentialFailures++
}

func (f *fakePasswordSubmissionBrowser) RegenerateSession(string, int64) error {
	f.rotations++
	return nil
}

func (f *fakePasswordSubmissionBrowser) SaveAuthContext(authContext *ceremony.AuthContext) error {
	f.saves = append(f.saves, authContext)
	return nil
}

// auditEntry is one event the operation audited.
type auditEntry struct {
	event   string
	details map[string]interface{}
}

// fakeAuditLogger records every event it is given.
type fakeAuditLogger struct {
	entries []auditEntry
}

func (f *fakeAuditLogger) Log(_ context.Context, auditEvent string, details map[string]interface{}) {
	f.entries = append(f.entries, auditEntry{event: auditEvent, details: details})
}

func TestPasswordSubmission_Refusals(t *testing.T) {
	tests := []struct {
		name string
		// user is the account the address names, nil for none.
		user *record.User
		// email is the address as the handler normalized it.
		email    string
		password string
		// verifierAnswer is what the recorder answers. The dummy branches have it answer "match",
		// so only ignoring the dummy comparison's result refuses them.
		verifierAnswer bool
		wantComparison passwordComparison
		wantAudit      auditEntry
	}{
		{
			name:           "missing account",
			user:           nil,
			email:          "test@example.com",
			password:       "a-guessed-password",
			verifierAnswer: true,
			wantComparison: passwordComparison{hashedPassword: testDummyHash, password: "a-guessed-password"},
			wantAudit: auditEntry{event: audit.EventAuthFailedPwd, details: map[string]interface{}{
				// SHA-256 of "test@example.com", computed outside this code. No account is named,
				// because none matched.
				"email_digest": "973dfe463ec85785f5f95af5ba3906eedb2d931c24e69824a89ea65dba4e813b",
			}},
		},
		{
			// An account an administrator created with the setup email keeps an empty hash until its
			// user sets a password, and bcrypt refuses an empty hash without doing any work
			// (#681 decision 3).
			name:           "account with no password",
			user:           &record.User{Id: 31, Email: "alice@example.com", PasswordHash: "", Enabled: true},
			email:          "alice@example.com",
			password:       "a-guessed-password",
			verifierAnswer: true,
			wantComparison: passwordComparison{hashedPassword: testDummyHash, password: "a-guessed-password"},
			wantAudit: auditEntry{event: audit.EventAuthFailedPwd, details: map[string]interface{}{
				// SHA-256 of "alice@example.com", computed outside this code.
				"email_digest": "ff8d9819fc0e12bf0d24892e45987e249a28dce836a85cad60e28eaaa8c6d976",
				"user_id":      int64(31),
			}},
		},
		{
			name: "wrong password",
			user: &record.User{Id: 31, Email: "alice@example.com",
				PasswordHash: "$2a$10$abcdefghijklmnopqrstuuVkFBHFf8f6TBkO6PkS5Lg2Y4LZHn8a2", Enabled: true},
			email:          "alice@example.com",
			password:       "a-wrong-password",
			verifierAnswer: false,
			wantComparison: passwordComparison{
				hashedPassword: "$2a$10$abcdefghijklmnopqrstuuVkFBHFf8f6TBkO6PkS5Lg2Y4LZHn8a2",
				password:       "a-wrong-password",
			},
			wantAudit: auditEntry{event: audit.EventAuthFailedPwd, details: map[string]interface{}{
				"email_digest": "ff8d9819fc0e12bf0d24892e45987e249a28dce836a85cad60e28eaaa8c6d976",
				"user_id":      int64(31),
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			database := &fakePasswordSubmissionDatabase{user: tt.user}
			auditLogger := &fakeAuditLogger{}
			browser := &fakePasswordSubmissionBrowser{}
			recorder := &passwordVerifierRecorder{answer: tt.verifierAnswer}

			operation := NewPasswordSubmission(database, auditLogger)
			operation.verifyPassword = recorder.verify

			authContext := &ceremony.AuthContext{
				AuthState:  ceremony.AuthStateLevel1Password,
				CeremonyId: "ceremony-id",
				ClientId:   "test-client",
			}

			result, err := operation.Run(context.Background(), browser, authContext, tt.email, tt.password)

			require.NoError(t, err)
			assert.Equal(t, PasswordSubmissionResult{Answer: PasswordRefused}, result)
			assert.Equal(t, []string{tt.email}, database.lookups)
			require.Len(t, recorder.calls, 1)
			assert.Equal(t, tt.wantComparison.hashedPassword, recorder.calls[0].hashedPassword)
			assert.Equal(t, tt.wantComparison.password, recorder.calls[0].password)
			assert.Equal(t, 1, browser.credentialFailures)
			require.Len(t, auditLogger.entries, 1)
			assert.Equal(t, tt.wantAudit.event, auditLogger.entries[0].event)
			assert.Equal(t, tt.wantAudit.details, auditLogger.entries[0].details)
			assert.Zero(t, browser.rotations)
			assert.Empty(t, browser.saves)
			assert.Equal(t, ceremony.AuthStateLevel1Password, authContext.AuthState)
			assert.Zero(t, authContext.UserId)
		})
	}
}

// TestPasswordSubmission_AcceptedWithTheConstructorsVerifier runs the right password through the
// verifier the constructor sets, which is what shows production compares with the real check.
func TestPasswordSubmission_AcceptedWithTheConstructorsVerifier(t *testing.T) {
	passwordHash, err := passwordhash.Hash("the-right-password")
	require.NoError(t, err)

	database := &fakePasswordSubmissionDatabase{
		user: &record.User{Id: 31, Email: "alice@example.com", PasswordHash: passwordHash, Enabled: true, Locale: "pt-BR"},
	}
	auditLogger := &fakeAuditLogger{}
	browser := &fakePasswordSubmissionBrowser{}
	authContext := &ceremony.AuthContext{
		AuthState:  ceremony.AuthStateLevel1Password,
		CeremonyId: "ceremony-id",
		ClientId:   "test-client",
	}

	result, err := NewPasswordSubmission(database, auditLogger).
		Run(context.Background(), browser, authContext, "alice@example.com", "the-right-password")

	require.NoError(t, err)
	assert.Equal(t, PasswordSubmissionResult{
		Answer:     PasswordAccepted,
		UserLocale: "pt-BR",
		NextStep:   "/auth/level1completed",
	}, result)
	assert.Zero(t, browser.credentialFailures)
	require.Len(t, auditLogger.entries, 1)
	assert.Equal(t, audit.EventAuthSuccessPwd, auditLogger.entries[0].event)
	assert.Equal(t, map[string]interface{}{"user_id": int64(31)}, auditLogger.entries[0].details)
	assert.Equal(t, 1, browser.rotations)
	assert.Equal(t, []*ceremony.AuthContext{authContext}, browser.saves)
}
