package authflow

import (
	"context"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The one operation that records "a password was proven" on a sign-in, for the password page and
// for registration and activation carrying on the sign-in that started them (#622 decision 9). The
// rotation and the state change live in it alone, so each caller gets them in the same order.

// proofBrowser records the browser-session writes in the order they were made, and fails the one a
// test names.
type proofBrowser struct {
	steps     []string
	rotatedId string
	rotatedTo int64
	saved     *ceremony.AuthContext
	rotateErr error
	saveErr   error
}

func (b *proofBrowser) RegenerateSession(ceremonyId string, userId int64) error {
	b.steps = append(b.steps, "rotate")
	b.rotatedId, b.rotatedTo = ceremonyId, userId
	return b.rotateErr
}

func (b *proofBrowser) SaveAuthContext(authContext *ceremony.AuthContext) error {
	b.steps = append(b.steps, "save")
	saved := *authContext
	b.saved = &saved
	return b.saveErr
}

func TestPasswordProof_RecordsThePasswordRotatesAndThenSaves(t *testing.T) {
	auditLogger := &fakeAuditLogger{}
	browser := &proofBrowser{}
	authContext := &ceremony.AuthContext{
		AuthState:  ceremony.AuthStateLevel1Password,
		CeremonyId: "the-sign-in",
		ClientId:   "shop",
	}
	user := &record.User{Id: 57, Email: "new@example.com", Enabled: true, AuthStateGeneration: 3, OtpConfigGeneration: 2}

	before := time.Now().UTC()
	result := NewPasswordProof(auditLogger).Record(context.Background(), browser, authContext, user)

	assert.Equal(t, PasswordProofResult{NextStep: "/auth/level1completed"}, result)
	assert.Equal(t, []string{"rotate", "save"}, browser.steps, "the identifier is rotated before the save")
	assert.Equal(t, "the-sign-in", browser.rotatedId)
	assert.Equal(t, int64(57), browser.rotatedTo, "the rotation keeps the ceremonies of the user who proved it")

	require.NotNil(t, browser.saved)
	assert.Equal(t, ceremony.AuthStateLevel1PasswordCompleted, browser.saved.AuthState)
	assert.Equal(t, int64(57), browser.saved.UserId)
	assert.True(t, browser.saved.Level1AuthCompleted)
	assert.Equal(t, int64(3), browser.saved.AuthStateGeneration)
	require.NotNil(t, browser.saved.OtpConfigGeneration)
	assert.Equal(t, int64(2), *browser.saved.OtpConfigGeneration)
	assert.Equal(t, "pwd", browser.saved.AuthMethods)
	require.NotNil(t, browser.saved.PasswordVerifiedAt)
	assert.False(t, browser.saved.PasswordVerifiedAt.Before(before.Truncate(time.Second)))

	require.Len(t, auditLogger.entries, 1)
	assert.Equal(t, audit.EventAuthSuccessPwd, auditLogger.entries[0].event)
	assert.Equal(t, map[string]interface{}{"user_id": int64(57)}, auditLogger.entries[0].details)
}

func TestPasswordProof_AFailedRotationIsNeverFollowedByTheSave(t *testing.T) {
	browser := &proofBrowser{rotateErr: errs.WithStack(ceremony.ErrCeremonyReplaced)}
	authContext := &ceremony.AuthContext{AuthState: ceremony.AuthStateLevel1Password, CeremonyId: "the-sign-in"}

	result := NewPasswordProof(&fakeAuditLogger{}).Record(context.Background(), browser, authContext,
		&record.User{Id: 57, Enabled: true})

	require.ErrorIs(t, result.SaveErr, ceremony.ErrCeremonyReplaced)
	assert.Equal(t, []string{"rotate"}, browser.steps)
}

func TestPasswordProof_AFailedSaveIsAnswered(t *testing.T) {
	browser := &proofBrowser{saveErr: errs.WithStack(ceremony.ErrCeremonyReplaced)}
	authContext := &ceremony.AuthContext{AuthState: ceremony.AuthStateLevel1Password, CeremonyId: "the-sign-in"}

	result := NewPasswordProof(&fakeAuditLogger{}).Record(context.Background(), browser, authContext,
		&record.User{Id: 57, Enabled: true})

	require.ErrorIs(t, result.SaveErr, ceremony.ErrCeremonyReplaced)
	assert.Equal(t, []string{"rotate", "save"}, browser.steps)
}
