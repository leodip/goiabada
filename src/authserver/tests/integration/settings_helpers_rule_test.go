package integration

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// populatedSettings answers a row with every field set, so a test that changes one field changes
// it away from something rather than from a zero value.
func populatedSettings() models.Settings {
	stamp := sql.NullTime{Time: time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC), Valid: true}
	return models.Settings{
		Id:                                      1,
		CreatedAt:                               stamp,
		UpdatedAt:                               stamp,
		AppName:                                 "Goiabada",
		Issuer:                                  "https://auth.example.org",
		UITheme:                                 "dark",
		PasswordPolicy:                          models.PasswordPolicyMedium,
		SelfRegistrationEnabled:                 true,
		TokenExpirationInSeconds:                300,
		RefreshTokenOfflineIdleTimeoutInSeconds: 2592000,
		RefreshTokenOfflineMaxLifetimeInSeconds: 31536000,
		UserSessionIdleTimeoutInSeconds:         7200,
		UserSessionMaxLifetimeInSeconds:         86400,
		IncludeOpenIDConnectClaimsInIdToken:     true,
		AESEncryptionKeyLegacy:                  []byte{},
		SMTPHost:                                "mailpit",
		SMTPPort:                                1025,
		SMTPUsername:                            "user",
		SMTPPasswordEncrypted:                   []byte{0x01, 0x02, 0x03},
		SMTPFromName:                            "Goiabada",
		SMTPFromEmail:                           "noreply@goiabada.dev",
		SMTPEncryption:                          "none",
		SMTPEnabled:                             true,
		PKCERequired:                            true,
		AuditLogsInConsoleEnabled:               true,
		AuditLogsInDatabaseEnabled:              true,
		AuditLogRetentionDays:                   180,
		LastCleanupAt:                           stamp,
	}
}

// changeField sets field to a value other than the one it holds, and fails the test for a kind it
// has no way to change, so a column of a new kind cannot slip past TestSettingsChanges_NamesEveryOtherField.
func changeField(t *testing.T, name string, field reflect.Value) {
	t.Helper()

	switch field.Kind() {
	case reflect.String:
		field.SetString(field.String() + "-changed")
	case reflect.Int, reflect.Int64:
		field.SetInt(field.Int() + 1)
	case reflect.Bool:
		field.SetBool(!field.Bool())
	case reflect.Slice:
		field.SetBytes(append([]byte{0xff}, field.Bytes()...))
	case reflect.Struct:
		if nullTime, ok := field.Interface().(sql.NullTime); ok {
			field.Set(reflect.ValueOf(sql.NullTime{Time: nullTime.Time.Add(time.Hour), Valid: true}))
			return
		}
		t.Fatalf("no way to change %s, a %s", name, field.Type())
	default:
		t.Fatalf("no way to change %s, a %s", name, field.Type())
	}
}

func TestSettingsChanges_IdenticalRowsHaveNone(t *testing.T) {
	before, after := populatedSettings(), populatedSettings()
	assert.Empty(t, settingsChanges(&before, &after))
}

// Every field but the five no test owns is compared: changing any one of them alone is reported,
// once, under its own name. The loop is over the struct, so a column added later is covered here
// without being listed.
func TestSettingsChanges_NamesEveryOtherField(t *testing.T) {
	fields := reflect.TypeOf(models.Settings{})
	compared := 0
	for i := range fields.NumField() {
		name := fields.Field(i).Name
		if settingsColumnsNoTestOwns[name] {
			continue
		}
		compared++
		t.Run(name, func(t *testing.T) {
			before, after := populatedSettings(), populatedSettings()
			changeField(t, name, reflect.ValueOf(&after).Elem().Field(i))

			changes := settingsChanges(&before, &after)
			require.Len(t, changes, 1)
			assert.True(t, strings.HasPrefix(changes[0], name+" "), "the change is named %q: %q", name, changes[0])
		})
	}
	assert.Equal(t, fields.NumField()-len(settingsColumnsNoTestOwns), compared)
}

// The five no test owns are skipped, each of them a real field of the row, so a misspelt entry
// cannot turn into a comparison of a column the server writes.
func TestSettingsChanges_SkipsTheColumnsNoTestOwns(t *testing.T) {
	assert.Len(t, settingsColumnsNoTestOwns, 5)
	for name := range settingsColumnsNoTestOwns {
		t.Run(name, func(t *testing.T) {
			before, after := populatedSettings(), populatedSettings()
			field := reflect.ValueOf(&after).Elem().FieldByName(name)
			require.True(t, field.IsValid(), "%s is not a field of models.Settings", name)
			changeField(t, name, field)

			assert.Empty(t, settingsChanges(&before, &after))
		})
	}
}

// A driver may read an empty blob back as nil, so the two are the same stored value.
func TestSettingsChanges_AnEmptyBlobEqualsANilOne(t *testing.T) {
	before, after := populatedSettings(), populatedSettings()
	before.SMTPPasswordEncrypted = []byte{}
	after.SMTPPasswordEncrypted = nil

	assert.Empty(t, settingsChanges(&before, &after))
}

// The one blob compared is the encrypted SMTP password, so a change to it is named and not printed.
func TestSettingsChanges_DoesNotPrintABlob(t *testing.T) {
	before, after := populatedSettings(), populatedSettings()
	after.SMTPPasswordEncrypted = []byte("ciphertext")

	assert.Equal(t, []string{"SMTPPasswordEncrypted changed"}, settingsChanges(&before, &after))
}

func TestSettingsChanges_PrintsBothValuesOfAnyOtherField(t *testing.T) {
	before, after := populatedSettings(), populatedSettings()
	after.UserSessionMaxLifetimeInSeconds = 7200

	assert.Equal(t, []string{"UserSessionMaxLifetimeInSeconds was 86400, is 7200"}, settingsChanges(&before, &after))
}

// readSettingsRow reads the row as the server now sees it.
func readSettingsRow(t *testing.T) *models.Settings {
	t.Helper()

	settings, err := database.GetSettingsById(context.Background(), nil, 1)
	require.NoError(t, err)
	require.NotNil(t, settings)
	return settings
}

// A subtest changes the row both ways a test does, through the admin API and directly, and the row
// is back once the subtest ends. The general PUT is the one that used to leave global PKCE off.
func TestRestoreSettings_PutsTheRowBackWhenTheTestEnds(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	before := readSettingsRow(t)

	t.Run("changes the row", func(t *testing.T) {
		restoreSettings(t)

		resp := makeAPIRequest(t, "PUT", appConfig.AuthServer.BaseURL+"/api/v1/admin/settings/general",
			accessToken, api.UpdateSettingsGeneralRequest{
				AppName:        "Restore probe",
				Issuer:         "https://restore.example.org",
				PasswordPolicy: "high",
			})
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		changed := readSettingsRow(t)
		changed.UserSessionIdleTimeoutInSeconds = 60
		changed.UserSessionMaxLifetimeInSeconds = 120
		changed.SMTPPasswordEncrypted = []byte("ciphertext")
		require.NoError(t, database.UpdateSettings(context.Background(), nil, changed))

		assert.NotEmpty(t, settingsChanges(before, readSettingsRow(t)), "the subtest changed nothing to restore")
		assert.False(t, readSettingsRow(t).PKCERequired)
	})

	assert.Empty(t, settingsChanges(before, readSettingsRow(t)))
}

func TestChangeSettings_WritesTheEditAndRestoresIt(t *testing.T) {
	before := readSettingsRow(t)

	t.Run("changes the row", func(t *testing.T) {
		written := changeSettings(t, func(settings *models.Settings) {
			settings.DynamicClientRegistrationEnabled = !before.DynamicClientRegistrationEnabled
		})

		assert.Equal(t, !before.DynamicClientRegistrationEnabled, written.DynamicClientRegistrationEnabled)
		assert.Equal(t, []string{fmt.Sprintf("DynamicClientRegistrationEnabled was %v, is %v",
			before.DynamicClientRegistrationEnabled, !before.DynamicClientRegistrationEnabled)},
			settingsChanges(before, readSettingsRow(t)))
	})

	assert.Empty(t, settingsChanges(before, readSettingsRow(t)))
}

// Cleanups run last-registered first, so two calls in one test end with the row the first found.
func TestChangeSettings_TwoCallsEndWithTheRowTheFirstFound(t *testing.T) {
	before := readSettingsRow(t)

	t.Run("changes the row twice", func(t *testing.T) {
		changeSettings(t, func(settings *models.Settings) { settings.TokenExpirationInSeconds = 61 })
		changeSettings(t, func(settings *models.Settings) { settings.TokenExpirationInSeconds = 62 })
		assert.Equal(t, 62, readSettingsRow(t).TokenExpirationInSeconds)
	})

	assert.Empty(t, settingsChanges(before, readSettingsRow(t)))
}

// A claim the background worker makes while a test holds the row survives that test's restore:
// last_cleanup_at is the worker's schedule, and writing the snapshot's value back would move it.
func TestRestoreSettings_KeepsACleanupClaimMadeMeanwhile(t *testing.T) {
	original := readSettingsRow(t).LastCleanupAt
	t.Cleanup(func() {
		current, err := database.GetSettingsById(context.Background(), nil, 1)
		if assert.NoError(t, err) {
			current.LastCleanupAt = original
			assert.NoError(t, database.UpdateSettings(context.Background(), nil, current))
		}
	})

	claimedAt := time.Now().UTC().Truncate(time.Second)
	t.Run("the worker claims a run", func(t *testing.T) {
		restoreSettings(t)

		claimed, err := database.TryClaimCleanupRun(context.Background(), nil, claimedAt, claimedAt.Add(time.Minute))
		require.NoError(t, err)
		require.True(t, claimed)
	})

	after := readSettingsRow(t).LastCleanupAt
	require.True(t, after.Valid)
	assert.WithinDuration(t, claimedAt, after.Time, time.Second)
}
