package datatests

import (
	"context"
	"database/sql"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/recovery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// nistSettingsReader answers the stored settings row with the nist policy and the app name
// Goiabada, and passes every other call through: the tier's settings row is shared by every test,
// so the policy is put on the one read the recovery makes rather than written to the row.
type nistSettingsReader struct {
	data.Database
}

func (d nistSettingsReader) GetSettingsById(ctx context.Context, tx *sql.Tx, id int64) (*record.Settings, error) {
	settings, err := d.Database.GetSettingsById(ctx, tx, id)
	if settings != nil {
		settings.PasswordPolicy = record.PasswordPolicyNist
		settings.AppName = "Goiabada"
	}
	return settings, err
}

// `recover --password-stdin` holds the password to a stored nist policy with the words of the
// user it loads, its email and username, and the app name of the stored settings, and a refusal
// writes nothing (#550 decision 6).
func TestRecovery_HoldsThePasswordToAStoredNistPolicy(t *testing.T) {
	ctx := context.Background()
	f := seedRecoveryFixture(t)
	require.NotEmpty(t, f.user.Username)

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
			_, err := recovery.Run(ctx, nistSettingsReader{database}, recorder, recovery.Request{
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
