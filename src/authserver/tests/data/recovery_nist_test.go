package datatests

import (
	"context"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/recovery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// storeNistPolicy writes the nist policy and the app name Goiabada to settings row 1 and reads
// them back, and puts the row back as it was when the test ends: the tier's settings row is
// shared by every test, so what this one stores must not outlive it.
func storeNistPolicy(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	snapshot, err := database.GetSettingsById(ctx, nil, 1)
	require.NoError(t, err)
	require.NotNil(t, snapshot)
	t.Cleanup(func() {
		require.NoError(t, database.UpdateSettings(context.Background(), nil, snapshot))
	})

	changed := *snapshot
	changed.PasswordPolicy = record.PasswordPolicyNist
	changed.AppName = "Goiabada"
	require.NoError(t, database.UpdateSettings(ctx, nil, &changed))

	stored, err := database.GetSettingsById(ctx, nil, 1)
	require.NoError(t, err)
	assert.Equal(t, 4, int(stored.PasswordPolicy), "nist is stored as 4")
	assert.Equal(t, "nist", stored.PasswordPolicy.String())
	assert.Equal(t, "Goiabada", stored.AppName)
}

// `recover --password-stdin` holds the password to a stored nist policy with the words of the
// user it loads, its email and username, and the app name of the stored settings, and a refusal
// writes nothing (#550 decision 6).
func TestRecovery_HoldsThePasswordToAStoredNistPolicy(t *testing.T) {
	ctx := context.Background()
	f := seedRecoveryFixture(t)
	require.NotEmpty(t, f.user.Username)
	storeNistPolicy(t)

	for name, tc := range map[string]struct {
		password string
		reason   string
	}{
		"a listed password":          {"PasswordPassword", "This password is one attackers try first."},
		"the user's email padded":    {f.user.Email + "2026!!!!!!!!!!!", "This password is too close to the account's"},
		"the user's username padded": {f.user.Username + f.user.Username + "2026!!!!!!!!!!!", "This password is too close to the account's"},
		"the app name padded":        {"goiabada2026!!!!!", "This password is too close to the account's"},
	} {
		t.Run(name, func(t *testing.T) {
			recorder := &recoveryAuditRecorder{}
			_, err := recovery.Run(ctx, database, recorder, recovery.Request{
				Email: f.user.Email, Password: tc.password,
			})

			var refusal *recovery.RefusedError
			require.ErrorAs(t, err, &refusal)
			assert.Contains(t, refusal.Reason, "the password is refused by the stored password policy: "+tc.reason)
			assert.Empty(t, recorder.events)
			after, err := database.GetUserById(ctx, nil, f.user.Id)
			require.NoError(t, err)
			assert.Equal(t, f.user.PasswordHash, after.PasswordHash, "a refused password is not set")
			assert.Equal(t, f.user.AuthStateGeneration, after.AuthStateGeneration)
		})
	}
}
