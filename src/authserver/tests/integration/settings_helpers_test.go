package integration

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The settings row (settings.id = 1) is one row every test on this server shares. The server reads
// it on every request, so a value a test leaves there is the value every later test runs against:
// before #433 the general settings tests left global PKCE off and the issuer rewritten for the
// rest of the tier, and a test that assumed the seeded session lifetime failed or passed depending
// on which files had run first. So a test that changes the row, through the admin API or directly,
// calls restoreSettings or changeSettings before its first change, and TestMain refuses a run that
// ends with the row different from how it began.

// restoreSettings reads the settings row and registers a cleanup that writes it back when the test
// ends, however it ends, and answers a copy the test may change and write. Call it before the first
// change, and in the parent of any subtests that change the row, since a cleanup runs once its test
// and every subtest of it are done. Cleanups run last-registered first, so a test that calls it
// twice ends with the row it found at the first call.
//
// last_cleanup_at is left as the cleanup finds it: the background worker claims its runs through
// that column (Database.TryClaimCleanupRun), so it is the server's, not the test's, to write.
func restoreSettings(t *testing.T) *models.Settings {
	t.Helper()

	found, err := database.GetSettingsById(context.Background(), nil, 1)
	require.NoError(t, err)
	require.NotNil(t, found)

	snapshot := *found
	snapshot.SMTPPasswordEncrypted = bytes.Clone(found.SMTPPasswordEncrypted)

	t.Cleanup(func() {
		current, err := database.GetSettingsById(context.Background(), nil, 1)
		if !assert.NoError(t, err, "unable to read the settings row to restore it") || current == nil {
			return
		}
		restored := snapshot
		restored.LastCleanupAt = current.LastCleanupAt
		assert.NoError(t, database.UpdateSettings(context.Background(), nil, &restored),
			"unable to restore the settings row")
	})

	return found
}

// changeSettings is restoreSettings followed by one direct write: edit changes the copy, the copy
// is written, and the row as written is answered.
func changeSettings(t *testing.T, edit func(settings *models.Settings)) *models.Settings {
	t.Helper()

	settings := restoreSettings(t)
	edit(settings)
	require.NoError(t, database.UpdateSettings(context.Background(), nil, settings))
	return settings
}

// settingsColumnsNoTestOwns are the fields settingsChanges skips: the key, the two timestamps the
// seeder and UpdateSettings write, the column the background worker claims its runs through, and
// the legacy key column UpdateSettings never writes (it is dont-update).
var settingsColumnsNoTestOwns = map[string]bool{
	"Id":                     true,
	"CreatedAt":              true,
	"UpdatedAt":              true,
	"LastCleanupAt":          true,
	"AESEncryptionKeyLegacy": true,
}

// settingsChanges answers one line per field that differs between two reads of the settings row,
// skipping settingsColumnsNoTestOwns. It walks the struct rather than naming fields, so a column
// added later is compared without anyone remembering to list it here. A byte slice is compared by
// content, since a driver may read an empty blob back as nil, and is not printed, since the one
// there is the encrypted SMTP password.
func settingsChanges(before, after *models.Settings) []string {
	beforeValue, afterValue := reflect.ValueOf(*before), reflect.ValueOf(*after)
	fields := beforeValue.Type()

	var changes []string
	for i := range fields.NumField() {
		name := fields.Field(i).Name
		if settingsColumnsNoTestOwns[name] {
			continue
		}
		was, is := beforeValue.Field(i).Interface(), afterValue.Field(i).Interface()
		if wasBytes, ok := was.([]byte); ok {
			if !bytes.Equal(wasBytes, is.([]byte)) {
				changes = append(changes, name+" changed")
			}
			continue
		}
		if !reflect.DeepEqual(was, is) {
			changes = append(changes, fmt.Sprintf("%s was %v, is %v", name, was, is))
		}
	}
	return changes
}
