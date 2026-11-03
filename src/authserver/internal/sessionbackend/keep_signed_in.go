package sessionbackend

import (
	"context"
	"database/sql"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/sessionkeys"
	"github.com/leodip/goiabada/core/sessionstore"
)

// KeepSignedInDatabase is what the auth server's Keep users signed in rule reads: the settings row,
// when the request carries no settings of its own.
type KeepSignedInDatabase interface {
	GetSettingsById(ctx context.Context, tx *sql.Tx, settingsId int64) (*record.Settings, error)
}

// NewKeepSignedIn is the rule the auth server's session store asks, per write, whether a signed-in
// browser session's cookie outlives the browser (#743 decisions 2 and 5), from the Keep users
// signed in after the browser closes setting in force for the request:
//
//   - Always: it does.
//   - Never: it does not.
//   - Let each user choose: only when the session recorded a ticked Keep me signed in box. A
//     session with no answer, one signed in under another mode or before the setting existed,
//     counts as unticked, since nobody consented to a cookie that outlives the browser.
//
// A mode this server does not know keeps no one signed in, the same direction. The settings are
// the request's, as the backend's lifetimes are, so the setting applies from the next cookie write
// a browser session gets.
func NewKeepSignedIn(database KeepSignedInDatabase) sessionstore.KeepSignedIn {
	return func(ctx context.Context, values map[string]any) (bool, error) {
		settings, err := settingsFor(ctx, database)
		if err != nil {
			return false, err
		}

		switch settings.KeepSignedIn {
		case record.KeepSignedInAlways:
			return true, nil
		case record.KeepSignedInAsk:
			ticked, _ := values[sessionkeys.KeepSignedIn].(bool)
			return ticked, nil
		default:
			return false, nil
		}
	}
}
