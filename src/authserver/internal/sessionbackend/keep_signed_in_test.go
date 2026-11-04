package sessionbackend

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/internal/sessionkeys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The Keep users signed in after the browser closes rule, as the auth server's store asks it about a
// signed-in browser session (#743 decisions 2 and 5): Always keeps every session signed in, Never
// none, and Let each user choose only a session whose recorded answer is ticked, a session with no
// answer counting as unticked.
func TestKeepSignedIn_FollowsTheSettingAndUnderLetEachUserChooseTheRecordedAnswer(t *testing.T) {
	signedIn := func(answer ...bool) map[string]any {
		values := map[string]any{sessionkeys.SessionIdentifier: "a-user-session"}
		if len(answer) > 0 {
			values[sessionkeys.KeepSignedIn] = answer[0]
		}
		return values
	}

	for name, test := range map[string]struct {
		mode   record.KeepSignedIn
		values map[string]any
		want   bool
	}{
		"Always, no answer":                {mode: "always", values: signedIn(), want: true},
		"Always, an unticked answer":       {mode: "always", values: signedIn(false), want: true},
		"Never, no answer":                 {mode: "never", values: signedIn(), want: false},
		"Never, a ticked answer":           {mode: "never", values: signedIn(true), want: false},
		"Let each user choose, ticked":     {mode: "ask", values: signedIn(true), want: true},
		"Let each user choose, unticked":   {mode: "ask", values: signedIn(false), want: false},
		"Let each user choose, no answer":  {mode: "ask", values: signedIn(), want: false},
		"Let each user choose, not a bool": {mode: "ask", values: map[string]any{sessionkeys.KeepSignedIn: "true"}, want: false},
		"a mode the server does not know":  {mode: "sometimes", values: signedIn(true), want: false},
		"no mode at all, a ticked answer":  {mode: "", values: signedIn(true), want: false},
		"Let each user choose, nil answer": {mode: "ask", values: map[string]any{sessionkeys.KeepSignedIn: nil}, want: false},
		"Let each user choose, no values":  {mode: "ask", values: map[string]any{}, want: false},
		"Let each user choose, nil values": {mode: "ask", values: nil, want: false},
		"Always, nil values":               {mode: "always", values: nil, want: true},
	} {
		t.Run(name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			ctx := reqctx.WithSettings(context.Background(), &record.Settings{KeepSignedIn: test.mode})

			keep, err := NewKeepSignedIn(database)(ctx, test.values)

			require.NoError(t, err)
			assert.Equal(t, test.want, keep)
			database.AssertNotCalled(t, "GetSettingsById", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// With no settings on the request the rule reads the settings row, as the backend's lifetimes do,
// and a read that fails is an error rather than a guess.
func TestKeepSignedIn_ReadsTheSettingsRowWithoutARequestValue(t *testing.T) {
	t.Run("the row's mode decides", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.EXPECT().GetSettingsById(mock.Anything, (*sql.Tx)(nil), int64(1)).
			Return(&record.Settings{KeepSignedIn: record.KeepSignedInNever}, nil)

		keep, err := NewKeepSignedIn(database)(context.Background(),
			map[string]any{sessionkeys.SessionIdentifier: "a-user-session", sessionkeys.KeepSignedIn: true})

		require.NoError(t, err)
		assert.False(t, keep)
	})

	t.Run("a failed read is an error", func(t *testing.T) {
		cause := errors.New("settings failed")
		database := datamocks.NewDatabase(t)
		database.EXPECT().GetSettingsById(mock.Anything, (*sql.Tx)(nil), int64(1)).Return(nil, cause)

		_, err := NewKeepSignedIn(database)(context.Background(), map[string]any{})

		require.ErrorIs(t, err, cause)
	})

	t.Run("a missing row is an error", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.EXPECT().GetSettingsById(mock.Anything, (*sql.Tx)(nil), int64(1)).Return(nil, nil)

		_, err := NewKeepSignedIn(database)(context.Background(), map[string]any{})

		require.Error(t, err)
	})
}
