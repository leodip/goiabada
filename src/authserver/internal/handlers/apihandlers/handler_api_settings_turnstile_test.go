package apihandlers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/encryption"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/internal/turnstile"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Cloudflare's published test keys (#642's Testing section): a site key and a secret key that pass
// any token, and a second site key.
const (
	turnstileTestSiteKey      = "1x00000000000000000000AA"
	turnstileOtherSiteKey     = "2x00000000000000000000AB"
	turnstileTestSecretKey    = "1x0000000000000000000000000000000AA"
	turnstileStoredSecretKey  = "stored-turnstile-secret"
	turnstileEnteredSecretKey = "entered-turnstile-secret"
)

// turnstileSaveSettings is the settings row a Turnstile save starts from: the challenge on or off,
// with turnstileTestSiteKey, and turnstileStoredSecretKey sealed under the test cipher when
// withSecret is set.
func turnstileSaveSettings(t *testing.T, enabled, withSecret bool) *record.Settings {
	t.Helper()
	settings := &record.Settings{ID: 1, TurnstileEnabled: enabled, TurnstileSiteKey: turnstileTestSiteKey}
	if withSecret {
		ciphertext, err := testDataCipher.Encrypt(turnstileStoredSecretKey)
		require.NoError(t, err)
		settings.TurnstileSecretKeyEncrypted = ciphertext
	}
	return settings
}

// turnstileSaveBody is a Turnstile save of enabled and siteKey, carrying extra beside them; a secret
// key, or its removal, is sent only when extra names it.
func turnstileSaveBody(t *testing.T, enabled bool, siteKey string, extra map[string]interface{}) string {
	t.Helper()
	body := map[string]interface{}{"turnstileEnabled": enabled, "turnstileSiteKey": siteKey}
	for key, value := range extra {
		body[key] = value
	}
	encoded, err := json.Marshal(body)
	require.NoError(t, err)
	return string(encoded)
}

// turnstileSave is what one Turnstile save did: its answer, the row it wrote or nil, and the details
// of the event it recorded or nil.
type turnstileSave struct {
	rr      *httptest.ResponseRecorder
	written *record.Settings
	audited map[string]interface{}
}

// fakeSecretKeyChecker stands in for Cloudflare's check of a secret key: it answers every check with
// answer, and records each secret key it was asked about.
type fakeSecretKeyChecker struct {
	answer  turnstile.SecretKeyCheck
	checked []string
}

func (f *fakeSecretKeyChecker) CheckSecretKey(_ context.Context, secretKey string) turnstile.SecretKeyCheck {
	f.checked = append(f.checked, secretKey)
	return f.answer
}

// acceptingSecretKeyChecker is a check Cloudflare accepts every secret key in.
func acceptingSecretKeyChecker() *fakeSecretKeyChecker {
	return &fakeSecretKeyChecker{answer: turnstile.SecretKeyAccepted}
}

// serveTurnstileSave runs PUT /api/v1/admin/settings/turnstile as a manage-settings caller, starting
// from settings, with every secret key Cloudflare is asked about accepted. A refused save is held to
// writing nothing and recording nothing.
func serveTurnstileSave(t *testing.T, settings *record.Settings, body string) turnstileSave {
	t.Helper()
	return serveTurnstileSaveCheckedBy(t, settings, body, acceptingSecretKeyChecker())
}

// serveTurnstileSaveCheckedBy is serveTurnstileSave with checker answering for Cloudflare.
func serveTurnstileSaveCheckedBy(t *testing.T, settings *record.Settings, body string, checker *fakeSecretKeyChecker) turnstileSave {
	t.Helper()
	return serveTurnstileSaveUnder(t, testDataCipher, settings, nil, body, checker)
}

// serveTurnstileSaveUnder is serveTurnstileSaveCheckedBy by a server holding dataCipher, whose save
// reads locked under its row lock, or the row the request loaded when locked is nil.
func serveTurnstileSaveUnder(t *testing.T, dataCipher *encryption.DataCipher, settings, locked *record.Settings,
	body string, checker *fakeSecretKeyChecker) turnstileSave {
	t.Helper()
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	var result turnstileSave
	if locked == nil {
		allowSettingsSave(database)
	} else {
		database.EXPECT().RunInTransaction(mock.Anything, mock.Anything).
			RunAndReturn(func(_ context.Context, fn func(tx *sql.Tx) error) error { return fn(settingsSaveTx) }).Maybe()
		database.EXPECT().AcquireSettingsRow(mock.Anything, settingsSaveTx, mock.Anything).Return(nil).Maybe()
		database.EXPECT().GetSettingsByID(mock.Anything, settingsSaveTx, mock.Anything).
			RunAndReturn(func(context.Context, *sql.Tx, int64) (*record.Settings, error) {
				stored := *locked
				stored.TurnstileSecretKeyEncrypted = bytes.Clone(locked.TurnstileSecretKeyEncrypted)
				return &stored, nil
			}).Maybe()
	}
	database.On("UpdateSettings", mock.Anything, settingsSaveTx, mock.AnythingOfType("*record.Settings")).
		Run(func(args mock.Arguments) {
			saved := *args.Get(2).(*record.Settings)
			saved.TurnstileSecretKeyEncrypted = bytes.Clone(saved.TurnstileSecretKeyEncrypted)
			result.written = &saved
		}).Return(nil).Maybe()
	auditLogger.On("Log", mock.Anything, audit.EventUpdatedTurnstileSettings, mock.Anything).
		Run(func(args mock.Arguments) { result.audited = args.Get(2).(map[string]interface{}) }).Return().Maybe()

	r := httptest.NewRequest(http.MethodPut, "/api/v1/admin/settings/turnstile", strings.NewReader(body))
	r = r.WithContext(reqctx.WithSettings(r.Context(), settings))
	r = setTokenContextWithClaims(r, map[string]interface{}{"scope": "authserver:manage-settings", "sub": grantCaller})
	result.rr = httptest.NewRecorder()
	HandleSettingsTurnstilePut(database, auditLogger, dataCipher, checker).ServeHTTP(result.rr, r)

	if result.rr.Code != http.StatusOK {
		database.AssertNotCalled(t, "UpdateSettings", mock.Anything, mock.Anything, mock.Anything)
		auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
	}
	return result
}

// turnstileAnswer reads a Turnstile answer, every field of it required, and refuses an answer that
// carries a secret key in any form.
func turnstileAnswer(t *testing.T, rr *httptest.ResponseRecorder) (enabled bool, siteKey string, hasSecretKey bool) {
	t.Helper()
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.ElementsMatch(t, []string{"turnstileEnabled", "turnstileSiteKey", "hasTurnstileSecretKey"}, turnstileAnswerKeys(body),
		"the answer carries the three fields and nothing else")
	assert.NotContains(t, rr.Body.String(), turnstileStoredSecretKey)
	assert.NotContains(t, rr.Body.String(), turnstileEnteredSecretKey)
	enabled, _ = body["turnstileEnabled"].(bool)
	siteKey, _ = body["turnstileSiteKey"].(string)
	hasSecretKey, _ = body["hasTurnstileSecretKey"].(bool)
	return enabled, siteKey, hasSecretKey
}

func turnstileAnswerKeys(body map[string]interface{}) []string {
	keys := make([]string, 0, len(body))
	for key := range body {
		keys = append(keys, key)
	}
	return keys
}

// decryptedSecretKey is the plaintext of the secret key a save wrote.
func decryptedSecretKey(t *testing.T, written *record.Settings) string {
	t.Helper()
	require.NotEmpty(t, written.TurnstileSecretKeyEncrypted, "a secret key is written")
	plaintext, err := testDataCipher.Decrypt(written.TurnstileSecretKeyEncrypted)
	require.NoError(t, err)
	return plaintext
}

// The GET answers the switch, the site key and whether a secret key is stored, and never the secret
// key, sealed or not (#642 decision 11).
func TestHandleSettingsTurnstileGet_AnswersWhetherASecretKeyIsStoredAndNeverTheKey(t *testing.T) {
	for _, withSecret := range []bool{true, false} {
		settings := turnstileSaveSettings(t, true, withSecret)
		r := httptest.NewRequest(http.MethodGet, "/api/v1/admin/settings/turnstile", nil)
		r = r.WithContext(reqctx.WithSettings(r.Context(), settings))
		rr := httptest.NewRecorder()

		HandleSettingsTurnstileGet().ServeHTTP(rr, r)

		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		enabled, siteKey, hasSecretKey := turnstileAnswer(t, rr)
		assert.True(t, enabled)
		assert.Equal(t, turnstileTestSiteKey, siteKey)
		assert.Equal(t, withSecret, hasSecretKey)
		if withSecret {
			assert.NotContains(t, rr.Body.String(), string(settings.TurnstileSecretKeyEncrypted))
		}
	}
}

// Turning the challenge on with a site key and a secret key stores the three, the secret key sealed
// under the data key, and records the values the save replaced and wrote, the secret key only as
// whether one is stored.
func TestHandleSettingsTurnstilePut_TurningTheChallengeOnStoresTheKeys(t *testing.T) {
	settings := &record.Settings{ID: 1}

	save := serveTurnstileSave(t, settings, turnstileSaveBody(t, true, turnstileTestSiteKey,
		map[string]interface{}{"turnstileSecretKey": turnstileTestSecretKey}))

	require.Equal(t, http.StatusOK, save.rr.Code, save.rr.Body.String())
	require.NotNil(t, save.written)
	assert.True(t, save.written.TurnstileEnabled)
	assert.Equal(t, turnstileTestSiteKey, save.written.TurnstileSiteKey)
	assert.Equal(t, turnstileTestSecretKey, decryptedSecretKey(t, save.written))
	assert.NotContains(t, string(save.written.TurnstileSecretKeyEncrypted), turnstileTestSecretKey, "sealed, not stored as typed")

	enabled, siteKey, hasSecretKey := turnstileAnswer(t, save.rr)
	assert.True(t, enabled)
	assert.Equal(t, turnstileTestSiteKey, siteKey)
	assert.True(t, hasSecretKey)
	assert.NotContains(t, save.rr.Body.String(), turnstileTestSecretKey)

	assert.Equal(t, map[string]interface{}{
		"logged_in_user": grantCaller,
		"old": map[string]interface{}{
			"turnstile_enabled":        false,
			"turnstile_site_key":       "",
			"has_turnstile_secret_key": false,
		},
		"new": map[string]interface{}{
			"turnstile_enabled":        true,
			"turnstile_site_key":       turnstileTestSiteKey,
			"has_turnstile_secret_key": true,
		},
	}, save.audited)
}

// An absent or empty secret key keeps the stored one: the API never answers it, so a client sending
// the form back as it read it has nothing to put there. That holds turning the challenge on, keeping
// it on, and turning it off. The secret key kept is sealed anew, so the row's bytes change while the
// secret key does not (#492 decision 10).
func TestHandleSettingsTurnstilePut_AnAbsentOrEmptySecretKeyKeepsTheStoredOne(t *testing.T) {
	cases := []struct {
		name            string
		storedEnabled   bool
		enabled         bool
		extra           map[string]interface{}
		wantSavedSwitch bool
	}{
		{name: "secret key absent, challenge kept on", storedEnabled: true, enabled: true},
		{name: "secret key empty, challenge kept on", storedEnabled: true, enabled: true,
			extra: map[string]interface{}{"turnstileSecretKey": "", "clearTurnstileSecretKey": false}},
		{name: "challenge turned on with the stored secret key", storedEnabled: false, enabled: true},
		{name: "challenge turned off", storedEnabled: true, enabled: false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			settings := turnstileSaveSettings(t, c.storedEnabled, true)
			stored := bytes.Clone(settings.TurnstileSecretKeyEncrypted)

			save := serveTurnstileSave(t, settings, turnstileSaveBody(t, c.enabled, turnstileTestSiteKey, c.extra))

			require.Equal(t, http.StatusOK, save.rr.Code, save.rr.Body.String())
			require.NotNil(t, save.written)
			assert.Equal(t, c.enabled, save.written.TurnstileEnabled)
			assert.Equal(t, turnstileTestSiteKey, save.written.TurnstileSiteKey, "the site key is kept")
			assertKeptSecretKeySealedAnew(t, testDataCipher, stored, save.written.TurnstileSecretKeyEncrypted)
			_, _, hasSecretKey := turnstileAnswer(t, save.rr)
			assert.True(t, hasSecretKey)
		})
	}
}

// assertKeptSecretKeySealedAnew holds written to turnstileStoredSecretKey sealed anew: other bytes
// than the stored ones, which opener opens to the stored secret key.
func assertKeptSecretKeySealedAnew(t *testing.T, opener *encryption.DataCipher, stored, written []byte) {
	t.Helper()
	assert.NotEqual(t, stored, written, "the kept secret key is sealed anew, not written back as read")
	plaintext, err := opener.Decrypt(written)
	require.NoError(t, err)
	assert.Equal(t, turnstileStoredSecretKey, plaintext)
}

// A kept secret key is sealed again under the server's current data key before the save writes it.
// It is the secret key the request's site key check read, sealed under the previous key, and a
// re-encryption committed during the save, while Cloudflare was asked about the key, moved the row
// to the current key: writing back what the request read would undo that. It is still the checked
// row's secret key, even when another widget's site key and secret key were saved meanwhile (#492
// decision 10). That holds turning the challenge on, keeping it on, and turning it off.
func TestHandleSettingsTurnstilePut_AKeptSecretKeyIsSealedAgainUnderTheCurrentKey(t *testing.T) {
	switches := []struct {
		name          string
		storedEnabled bool
		enabled       bool
	}{
		{name: "challenge kept on", storedEnabled: true, enabled: true},
		{name: "challenge turned on", storedEnabled: false, enabled: true},
		{name: "challenge turned off", storedEnabled: true, enabled: false},
	}
	meanwhile := []struct {
		name            string
		lockedSiteKey   string
		lockedSecretKey string
	}{
		{name: "the row re-encrypted meanwhile", lockedSiteKey: turnstileTestSiteKey, lockedSecretKey: turnstileStoredSecretKey},
		{name: "another widget saved meanwhile", lockedSiteKey: turnstileOtherSiteKey, lockedSecretKey: "another-widget-secret"},
	}
	for _, sw := range switches {
		for _, m := range meanwhile {
			t.Run(sw.name+", "+m.name, func(t *testing.T) {
				settings := turnstileSaveSettings(t, sw.storedEnabled, true) // sealed under the previous key
				locked := *settings
				locked.TurnstileSiteKey = m.lockedSiteKey
				resealed, err := currentKeyOnlyCipher.Encrypt(m.lockedSecretKey)
				require.NoError(t, err)
				locked.TurnstileSecretKeyEncrypted = resealed

				save := serveTurnstileSaveUnder(t, rotatingDataCipher, settings, &locked,
					turnstileSaveBody(t, sw.enabled, turnstileTestSiteKey, nil), acceptingSecretKeyChecker())

				require.Equal(t, http.StatusOK, save.rr.Code, save.rr.Body.String())
				require.NotNil(t, save.written)
				assert.Equal(t, sw.enabled, save.written.TurnstileEnabled)
				assert.Equal(t, turnstileTestSiteKey, save.written.TurnstileSiteKey)
				assertKeptSecretKeySealedAnew(t, currentKeyOnlyCipher, settings.TurnstileSecretKeyEncrypted,
					save.written.TurnstileSecretKeyEncrypted)
			})
		}
	}
}

// A kept secret key neither data key opens cannot be sealed again: when the row still holds it,
// keeping the challenge on, or turning it off, writes it back as stored, byte for byte, and names it
// in a Warn record, so a challenge can still be turned off (#492 decision 10). Turning the challenge
// on with it still answers 500, as Cloudflare cannot be asked about it.
func TestHandleSettingsTurnstilePut_AKeptSecretKeyNeitherKeyOpensIsWrittenBackAsStored(t *testing.T) {
	strangerCipher, err := encryption.NewDataCipher([]byte("ffffffffffffffffffffffffffffffff"))
	require.NoError(t, err)
	unreadable, err := strangerCipher.Encrypt(turnstileStoredSecretKey)
	require.NoError(t, err)

	for _, enabled := range []bool{true, false} {
		t.Run(fmt.Sprintf("challenge on: %v", enabled), func(t *testing.T) {
			settings := turnstileSaveSettings(t, true, false)
			settings.TurnstileSecretKeyEncrypted = bytes.Clone(unreadable)
			capture := logtest.CaptureSlog(t)

			save := serveTurnstileSaveUnder(t, rotatingDataCipher, settings, nil,
				turnstileSaveBody(t, enabled, turnstileTestSiteKey, nil), acceptingSecretKeyChecker())

			require.Equal(t, http.StatusOK, save.rr.Code, save.rr.Body.String())
			require.NotNil(t, save.written)
			assert.Equal(t, enabled, save.written.TurnstileEnabled)
			assert.Equal(t, unreadable, save.written.TurnstileSecretKeyEncrypted, "the stored ciphertext, byte for byte")
			records := capture.Records()
			require.Len(t, records, 1)
			assert.Equal(t, slog.LevelWarn, records[0].Level)
			assert.Equal(t, "the stored secret the request read opens under neither data encryption key, so the save checks the row under its lock",
				records[0].Message)
			assert.Equal(t, "turnstile_secret_key", records[0].Attrs["secret"])
		})
	}

	t.Run("challenge turned on", func(t *testing.T) {
		settings := turnstileSaveSettings(t, false, false)
		settings.TurnstileSecretKeyEncrypted = bytes.Clone(unreadable)
		checker := acceptingSecretKeyChecker()

		save := serveTurnstileSaveUnder(t, rotatingDataCipher, settings, nil,
			turnstileSaveBody(t, true, turnstileTestSiteKey, nil), checker)

		assert.Equal(t, http.StatusInternalServerError, save.rr.Code, save.rr.Body.String())
		assert.Nil(t, save.written)
		assert.Empty(t, checker.checked)
	})
}

// A kept secret key neither data key opens is never written over other bytes the row holds when the
// save locks it, as for the SMTP password (#492 decisions 4 and 10): the row's secret key is kept
// when it was entered for the site key this save writes, a secret key removed meanwhile stays
// removed, unless this save keeps the challenge on, which needs one, and another widget's secret key
// is not paired with this save's site key. Turning the challenge off still goes through whenever the
// row's secret key can be kept.
func TestHandleSettingsTurnstilePut_AKeptSecretKeyNeitherKeyOpensNeverOverwritesTheRowAsLocked(t *testing.T) {
	strangerCipher, err := encryption.NewDataCipher([]byte("ffffffffffffffffffffffffffffffff"))
	require.NoError(t, err)
	unreadable, err := strangerCipher.Encrypt(turnstileStoredSecretKey)
	require.NoError(t, err)
	repaired, err := currentKeyOnlyCipher.Encrypt(turnstileStoredSecretKey)
	require.NoError(t, err)
	another, err := currentKeyOnlyCipher.Encrypt("another-widget-secret")
	require.NoError(t, err)

	cases := []struct {
		name          string
		enabled       bool
		lockedSiteKey string
		lockedSecret  []byte
		wantSecret    []byte
		refusedWith   string
	}{
		{name: "challenge kept on, the secret key repaired meanwhile", enabled: true,
			lockedSiteKey: turnstileTestSiteKey, lockedSecret: repaired, wantSecret: repaired},
		{name: "challenge turned off, the secret key repaired meanwhile", enabled: false,
			lockedSiteKey: turnstileTestSiteKey, lockedSecret: repaired, wantSecret: repaired},
		{name: "challenge turned off, the secret key removed meanwhile", enabled: false,
			lockedSiteKey: turnstileTestSiteKey},
		{name: "challenge kept on, the secret key removed meanwhile", enabled: true,
			lockedSiteKey: turnstileTestSiteKey, refusedWith: "handler.settings_turnstile.secret_key_required"},
		{name: "challenge kept on, another widget saved meanwhile", enabled: true,
			lockedSiteKey: turnstileOtherSiteKey, lockedSecret: another, refusedWith: "handler.settings_turnstile.site_key_changed"},
		{name: "challenge turned off, another widget saved meanwhile", enabled: false,
			lockedSiteKey: turnstileOtherSiteKey, lockedSecret: another, refusedWith: "handler.settings_turnstile.site_key_changed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			settings := turnstileSaveSettings(t, true, false)
			settings.TurnstileSecretKeyEncrypted = bytes.Clone(unreadable)
			locked := *settings
			locked.TurnstileSiteKey = c.lockedSiteKey
			locked.TurnstileSecretKeyEncrypted = bytes.Clone(c.lockedSecret)

			save := serveTurnstileSaveUnder(t, rotatingDataCipher, settings, &locked,
				turnstileSaveBody(t, c.enabled, turnstileTestSiteKey, nil), acceptingSecretKeyChecker())

			if c.refusedWith != "" {
				assert.Equal(t, http.StatusBadRequest, save.rr.Code, save.rr.Body.String())
				code, _ := decodeErrorEnvelope(t, save.rr)
				assert.Equal(t, c.refusedWith, code)
				assert.Nil(t, save.written, "nothing is written")
				return
			}
			require.Equal(t, http.StatusOK, save.rr.Code, save.rr.Body.String())
			require.NotNil(t, save.written)
			assert.Equal(t, c.enabled, save.written.TurnstileEnabled)
			assert.Equal(t, c.wantSecret, save.written.TurnstileSecretKeyEncrypted, "the row's secret key, as locked")
			assert.NotEqual(t, unreadable, save.written.TurnstileSecretKeyEncrypted, "the request's stale bytes are not written")
		})
	}
}

// A save keeping a secret key neither data key opens, read with the challenge on, checks no secret
// key with Cloudflare. When another save turned the challenge off meanwhile, it would turn the
// challenge on with the row's secret key unchecked, and a key Cloudflare rejects lets every form
// through: it is refused, and the secret key is checked once it is entered again. Turning the
// challenge off, or keeping it off, still saves.
func TestHandleSettingsTurnstilePut_ASaveKeepingAnUnreadableSecretKeyNeverTurnsTheChallengeOnUnchecked(t *testing.T) {
	strangerCipher, err := encryption.NewDataCipher([]byte("ffffffffffffffffffffffffffffffff"))
	require.NoError(t, err)
	unreadable, err := strangerCipher.Encrypt(turnstileStoredSecretKey)
	require.NoError(t, err)
	replaced, err := currentKeyOnlyCipher.Encrypt(turnstileEnteredSecretKey)
	require.NoError(t, err)

	for _, lockedSecret := range []struct {
		name  string
		bytes []byte
	}{
		{name: "the same secret key", bytes: unreadable},
		{name: "a secret key entered meanwhile", bytes: replaced},
	} {
		lockedOff := func() *record.Settings {
			locked := turnstileSaveSettings(t, false, false)
			locked.TurnstileSecretKeyEncrypted = bytes.Clone(lockedSecret.bytes)
			return locked
		}
		read := turnstileSaveSettings(t, true, false)
		read.TurnstileSecretKeyEncrypted = bytes.Clone(unreadable)

		t.Run("challenge kept on, turned off meanwhile, "+lockedSecret.name, func(t *testing.T) {
			checker := acceptingSecretKeyChecker()
			save := serveTurnstileSaveUnder(t, rotatingDataCipher, read, lockedOff(),
				turnstileSaveBody(t, true, turnstileTestSiteKey, nil), checker)

			assert.Equal(t, http.StatusBadRequest, save.rr.Code, save.rr.Body.String())
			code, _ := decodeErrorEnvelope(t, save.rr)
			assert.Equal(t, "handler.settings_turnstile.secret_key_required", code)
			assert.Nil(t, save.written, "the challenge is not turned on")
			assert.Empty(t, checker.checked)
		})

		t.Run("challenge kept off, turned off meanwhile, "+lockedSecret.name, func(t *testing.T) {
			save := serveTurnstileSaveUnder(t, rotatingDataCipher, read, lockedOff(),
				turnstileSaveBody(t, false, turnstileTestSiteKey, nil), acceptingSecretKeyChecker())

			require.Equal(t, http.StatusOK, save.rr.Code, save.rr.Body.String())
			require.NotNil(t, save.written)
			assert.False(t, save.written.TurnstileEnabled)
			assert.Equal(t, lockedSecret.bytes, save.written.TurnstileSecretKeyEncrypted, "the row's secret key, as locked")
		})
	}

	t.Run("the secret key entered again is checked before the challenge is turned on", func(t *testing.T) {
		read := turnstileSaveSettings(t, false, false)
		read.TurnstileSecretKeyEncrypted = bytes.Clone(unreadable)
		checker := acceptingSecretKeyChecker()

		save := serveTurnstileSaveUnder(t, rotatingDataCipher, read, nil,
			turnstileSaveBody(t, true, turnstileTestSiteKey, map[string]interface{}{"turnstileSecretKey": turnstileEnteredSecretKey}),
			checker)

		require.Equal(t, http.StatusOK, save.rr.Code, save.rr.Body.String())
		assert.Equal(t, []string{turnstileEnteredSecretKey}, checker.checked)
		require.NotNil(t, save.written)
		assert.True(t, save.written.TurnstileEnabled)
	})
}

// A save keeping the stored secret key, read with the challenge on, checks no secret key with
// Cloudflare either. When another save turned the challenge off meanwhile, whether or not it entered
// another secret key, this save would turn the challenge back on with a secret key it never
// checked: it is refused, and writes nothing. With the challenge still on under the lock, or kept
// off, it saves as before, still without asking Cloudflare.
func TestHandleSettingsTurnstilePut_ASaveKeepingTheStoredSecretKeyNeverTurnsTheChallengeOnUnchecked(t *testing.T) {
	replaced, err := testDataCipher.Encrypt(turnstileEnteredSecretKey)
	require.NoError(t, err)

	for _, lockedSecret := range []struct {
		name    string
		replace bool
	}{
		{name: "the same secret key"},
		{name: "a secret key entered meanwhile", replace: true},
	} {
		locked := func(enabled bool) *record.Settings {
			row := turnstileSaveSettings(t, enabled, true)
			if lockedSecret.replace {
				row.TurnstileSecretKeyEncrypted = bytes.Clone(replaced)
			}
			return row
		}

		t.Run("challenge kept on, turned off meanwhile, "+lockedSecret.name, func(t *testing.T) {
			checker := acceptingSecretKeyChecker()
			save := serveTurnstileSaveUnder(t, testDataCipher, turnstileSaveSettings(t, true, true), locked(false),
				turnstileSaveBody(t, true, turnstileTestSiteKey, nil), checker)

			assert.Equal(t, http.StatusBadRequest, save.rr.Code, save.rr.Body.String())
			code, _ := decodeErrorEnvelope(t, save.rr)
			assert.Equal(t, "handler.settings_turnstile.secret_key_required", code)
			assert.Nil(t, save.written, "the challenge is not turned on")
			assert.Empty(t, checker.checked)
		})

		t.Run("challenge kept on, still on, "+lockedSecret.name, func(t *testing.T) {
			checker := acceptingSecretKeyChecker()
			save := serveTurnstileSaveUnder(t, testDataCipher, turnstileSaveSettings(t, true, true), locked(true),
				turnstileSaveBody(t, true, turnstileTestSiteKey, nil), checker)

			require.Equal(t, http.StatusOK, save.rr.Code, save.rr.Body.String())
			require.NotNil(t, save.written)
			assert.True(t, save.written.TurnstileEnabled)
			assert.Equal(t, turnstileStoredSecretKey, decryptedSecretKey(t, save.written), "the key the request read")
			assert.Empty(t, checker.checked)
		})

		t.Run("challenge kept off, turned off meanwhile, "+lockedSecret.name, func(t *testing.T) {
			save := serveTurnstileSaveUnder(t, testDataCipher, turnstileSaveSettings(t, true, true), locked(false),
				turnstileSaveBody(t, false, turnstileTestSiteKey, nil), acceptingSecretKeyChecker())

			require.Equal(t, http.StatusOK, save.rr.Code, save.rr.Body.String())
			require.NotNil(t, save.written)
			assert.False(t, save.written.TurnstileEnabled)
		})
	}
}

// A non-empty secret key replaces the stored one, whether or not one was stored and whether or not
// the challenge is on.
func TestHandleSettingsTurnstilePut_ANewSecretKeyReplacesTheStoredOne(t *testing.T) {
	for _, withSecret := range []bool{true, false} {
		for _, enabled := range []bool{true, false} {
			settings := turnstileSaveSettings(t, false, withSecret)

			save := serveTurnstileSave(t, settings, turnstileSaveBody(t, enabled, turnstileTestSiteKey,
				map[string]interface{}{"turnstileSecretKey": turnstileEnteredSecretKey}))

			require.Equal(t, http.StatusOK, save.rr.Code, save.rr.Body.String())
			require.NotNil(t, save.written)
			assert.Equal(t, turnstileEnteredSecretKey, decryptedSecretKey(t, save.written),
				"stored %v, enabled %v", withSecret, enabled)
		}
	}
}

// clearTurnstileSecretKey removes the stored secret key while the challenge is off, the site key
// changing or not, and with nothing stored it is a save like any other.
func TestHandleSettingsTurnstilePut_ClearingTheSecretKeyWithTheChallengeOffRemovesIt(t *testing.T) {
	for _, withSecret := range []bool{true, false} {
		for _, siteKey := range []string{turnstileTestSiteKey, turnstileOtherSiteKey} {
			settings := turnstileSaveSettings(t, true, withSecret)

			save := serveTurnstileSave(t, settings, turnstileSaveBody(t, false, siteKey,
				map[string]interface{}{"clearTurnstileSecretKey": true}))

			require.Equal(t, http.StatusOK, save.rr.Code, save.rr.Body.String())
			require.NotNil(t, save.written)
			assert.False(t, save.written.TurnstileEnabled)
			assert.Empty(t, save.written.TurnstileSecretKeyEncrypted)
			assert.Equal(t, siteKey, save.written.TurnstileSiteKey)
			_, _, hasSecretKey := turnstileAnswer(t, save.rr)
			assert.False(t, hasSecretKey)
		}
	}
}

// A changed site key with a new secret key saves: the two come from one widget, and both arrived.
func TestHandleSettingsTurnstilePut_AChangedSiteKeyWithItsSecretKeySaves(t *testing.T) {
	settings := turnstileSaveSettings(t, true, true)

	save := serveTurnstileSave(t, settings, turnstileSaveBody(t, true, turnstileOtherSiteKey,
		map[string]interface{}{"turnstileSecretKey": turnstileEnteredSecretKey}))

	require.Equal(t, http.StatusOK, save.rr.Code, save.rr.Body.String())
	require.NotNil(t, save.written)
	assert.Equal(t, turnstileOtherSiteKey, save.written.TurnstileSiteKey)
	assert.Equal(t, turnstileEnteredSecretKey, decryptedSecretKey(t, save.written))
}

// The site key is stored with surrounding space trimmed, and compared with the stored one so: the
// same key pasted with a trailing space is not a change of key.
func TestHandleSettingsTurnstilePut_TheSiteKeyIsTrimmed(t *testing.T) {
	settings := turnstileSaveSettings(t, true, true)
	stored := bytes.Clone(settings.TurnstileSecretKeyEncrypted)

	save := serveTurnstileSave(t, settings, turnstileSaveBody(t, true, "  "+turnstileTestSiteKey+" \t", nil))

	require.Equal(t, http.StatusOK, save.rr.Code, save.rr.Body.String())
	require.NotNil(t, save.written)
	assert.Equal(t, turnstileTestSiteKey, save.written.TurnstileSiteKey)
	assertKeptSecretKeySealedAnew(t, testDataCipher, stored, save.written.TurnstileSecretKeyEncrypted)
}

// Each refusal of #642 decision 11 that needs no call to Cloudflare answers 400 with its catalog key
// and English sentence, and writes and records nothing.
func TestHandleSettingsTurnstilePut_RefusalsWriteNothing(t *testing.T) {
	long := strings.Repeat("k", 129)
	cases := []struct {
		name            string
		storedEnabled   bool
		storedSecret    bool
		body            func(t *testing.T) string
		wantCode        string
		wantDescription string
	}{
		{
			name: "turning the challenge on without a site key", storedSecret: true,
			body:     func(t *testing.T) string { return turnstileSaveBody(t, true, "  ", nil) },
			wantCode: "handler.settings_turnstile.site_key_required", wantDescription: "Enter the site key to turn the Turnstile challenge on.",
		},
		{
			name:     "turning the challenge on without a secret key, none stored",
			body:     func(t *testing.T) string { return turnstileSaveBody(t, true, turnstileTestSiteKey, nil) },
			wantCode: "handler.settings_turnstile.secret_key_required", wantDescription: "Enter the secret key to turn the Turnstile challenge on.",
		},
		{
			name: "a secret key of spaces only, none stored",
			body: func(t *testing.T) string {
				return turnstileSaveBody(t, true, turnstileTestSiteKey, map[string]interface{}{"turnstileSecretKey": "   "})
			},
			wantCode: "handler.settings_turnstile.secret_key_required", wantDescription: "Enter the secret key to turn the Turnstile challenge on.",
		},
		{
			name: "clearing the secret key while the challenge stays on", storedEnabled: true, storedSecret: true,
			body: func(t *testing.T) string {
				return turnstileSaveBody(t, true, turnstileTestSiteKey, map[string]interface{}{"clearTurnstileSecretKey": true})
			},
			wantCode:        "handler.settings_turnstile.secret_key_clear_while_enabled",
			wantDescription: "The secret key can't be removed while the Turnstile challenge is on.",
		},
		{
			name: "clearing the secret key while turning the challenge on", storedSecret: true,
			body: func(t *testing.T) string {
				return turnstileSaveBody(t, true, turnstileTestSiteKey, map[string]interface{}{"clearTurnstileSecretKey": true})
			},
			wantCode:        "handler.settings_turnstile.secret_key_clear_while_enabled",
			wantDescription: "The secret key can't be removed while the Turnstile challenge is on.",
		},
		{
			name: "a changed site key without the secret key, challenge on", storedEnabled: true, storedSecret: true,
			body:     func(t *testing.T) string { return turnstileSaveBody(t, true, turnstileOtherSiteKey, nil) },
			wantCode: "handler.settings_turnstile.site_key_changed", wantDescription: "The site key has changed: enter the secret key again, or remove it.",
		},
		{
			name: "a changed site key without the secret key, challenge off", storedSecret: true,
			body:     func(t *testing.T) string { return turnstileSaveBody(t, false, turnstileOtherSiteKey, nil) },
			wantCode: "handler.settings_turnstile.site_key_changed", wantDescription: "The site key has changed: enter the secret key again, or remove it.",
		},
		{
			name: "an emptied site key without removing the secret key", storedSecret: true,
			body:     func(t *testing.T) string { return turnstileSaveBody(t, false, "", nil) },
			wantCode: "handler.settings_turnstile.site_key_changed", wantDescription: "The site key has changed: enter the secret key again, or remove it.",
		},
		{
			name: "a new secret key together with its removal", storedSecret: true,
			body: func(t *testing.T) string {
				return turnstileSaveBody(t, false, turnstileTestSiteKey,
					map[string]interface{}{"turnstileSecretKey": turnstileEnteredSecretKey, "clearTurnstileSecretKey": true})
			},
			wantCode:        "handler.settings_turnstile.secret_key_and_clear",
			wantDescription: "Send either a new secret key or clearTurnstileSecretKey, not both.",
		},
		{
			name: "a site key longer than 128 characters",
			body: func(t *testing.T) string {
				return turnstileSaveBody(t, false, long, map[string]interface{}{"turnstileSecretKey": turnstileEnteredSecretKey})
			},
			wantCode: "handler.settings_turnstile.site_key_too_long", wantDescription: "The site key can't be longer than 128 characters.",
		},
		{
			name: "a secret key longer than 128 characters",
			body: func(t *testing.T) string {
				return turnstileSaveBody(t, false, turnstileTestSiteKey, map[string]interface{}{"turnstileSecretKey": long})
			},
			wantCode: "handler.settings_turnstile.secret_key_too_long", wantDescription: "The secret key can't be longer than 128 characters.",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			save := serveTurnstileSave(t, turnstileSaveSettings(t, c.storedEnabled, c.storedSecret), c.body(t))

			assert.Equal(t, http.StatusBadRequest, save.rr.Code, save.rr.Body.String())
			code, description := decodeErrorEnvelope(t, save.rr)
			assert.Equal(t, c.wantCode, code)
			assert.Equal(t, c.wantDescription, description)
			assert.Nil(t, save.written)
			assert.Nil(t, save.audited)
		})
	}
}

// The bounds are inclusive: a site key and a secret key of 128 characters each save.
func TestHandleSettingsTurnstilePut_KeysOf128CharactersSave(t *testing.T) {
	siteKey, secretKey := strings.Repeat("s", 128), strings.Repeat("k", 128)

	save := serveTurnstileSave(t, &record.Settings{ID: 1}, turnstileSaveBody(t, true, siteKey,
		map[string]interface{}{"turnstileSecretKey": secretKey}))

	require.Equal(t, http.StatusOK, save.rr.Code, save.rr.Body.String())
	require.NotNil(t, save.written)
	assert.Equal(t, siteKey, save.written.TurnstileSiteKey)
	assert.Equal(t, secretKey, decryptedSecretKey(t, save.written))
}

// A body that will not parse is an integrator's mistake, answered in English with nothing written.
func TestHandleSettingsTurnstilePut_ABodyThatWillNotParseIsRefused(t *testing.T) {
	save := serveTurnstileSave(t, &record.Settings{ID: 1}, `{"turnstileEnabled": "yes"`)

	assert.Equal(t, http.StatusBadRequest, save.rr.Code)
	code, _ := decodeErrorEnvelope(t, save.rr)
	assert.Equal(t, "INVALID_REQUEST_BODY", code)
	assert.Nil(t, save.written)
}

// A save that stores a new secret key, or turns the challenge on, asks Cloudflare about the secret key
// it leaves stored: the one entered, or the one already stored (#642 decision 11). Cloudflare's
// acceptance lets the save go on.
func TestHandleSettingsTurnstilePut_ANewSecretKeyOrTurningTheChallengeOnChecksTheSecretKey(t *testing.T) {
	cases := []struct {
		name          string
		storedEnabled bool
		storedSecret  bool
		body          func(t *testing.T) string
		wantChecked   string
	}{
		{
			name: "a new secret key, challenge off",
			body: func(t *testing.T) string {
				return turnstileSaveBody(t, false, turnstileTestSiteKey, map[string]interface{}{"turnstileSecretKey": turnstileEnteredSecretKey})
			},
			wantChecked: turnstileEnteredSecretKey,
		},
		{
			name: "a new secret key, challenge kept on", storedEnabled: true, storedSecret: true,
			body: func(t *testing.T) string {
				return turnstileSaveBody(t, true, turnstileTestSiteKey, map[string]interface{}{"turnstileSecretKey": turnstileEnteredSecretKey})
			},
			wantChecked: turnstileEnteredSecretKey,
		},
		{
			name: "a new secret key, pasted with space around it", storedSecret: true,
			body: func(t *testing.T) string {
				return turnstileSaveBody(t, false, turnstileTestSiteKey, map[string]interface{}{"turnstileSecretKey": " " + turnstileEnteredSecretKey + "\t"})
			},
			wantChecked: turnstileEnteredSecretKey,
		},
		{
			name: "turning the challenge on with a new secret key", storedSecret: true,
			body: func(t *testing.T) string {
				return turnstileSaveBody(t, true, turnstileTestSiteKey, map[string]interface{}{"turnstileSecretKey": turnstileEnteredSecretKey})
			},
			wantChecked: turnstileEnteredSecretKey,
		},
		{
			name: "turning the challenge on with the stored secret key", storedSecret: true,
			body:        func(t *testing.T) string { return turnstileSaveBody(t, true, turnstileTestSiteKey, nil) },
			wantChecked: turnstileStoredSecretKey,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			checker := acceptingSecretKeyChecker()

			save := serveTurnstileSaveCheckedBy(t, turnstileSaveSettings(t, c.storedEnabled, c.storedSecret), c.body(t), checker)

			require.Equal(t, http.StatusOK, save.rr.Code, save.rr.Body.String())
			assert.Equal(t, []string{c.wantChecked}, checker.checked, "Cloudflare is asked once, about the secret key left stored")
			require.NotNil(t, save.written)
			assert.Equal(t, c.wantChecked, decryptedSecretKey(t, save.written))
		})
	}
}

// Turning the challenge off, removing the secret key, and a save that keeps the challenge on with the
// stored secret key never ask Cloudflare: none of them puts a secret key in use that was not.
func TestHandleSettingsTurnstilePut_SavesThatPutNoSecretKeyInUseNeverCallCloudflare(t *testing.T) {
	cases := []struct {
		name          string
		storedEnabled bool
		body          func(t *testing.T) string
		wantSecret    bool
	}{
		{
			name: "turning the challenge off", storedEnabled: true,
			body:       func(t *testing.T) string { return turnstileSaveBody(t, false, turnstileTestSiteKey, nil) },
			wantSecret: true,
		},
		{
			name: "turning the challenge off and removing the secret key", storedEnabled: true,
			body: func(t *testing.T) string {
				return turnstileSaveBody(t, false, turnstileTestSiteKey, map[string]interface{}{"clearTurnstileSecretKey": true})
			},
		},
		{
			name: "removing the secret key, challenge off",
			body: func(t *testing.T) string {
				return turnstileSaveBody(t, false, turnstileOtherSiteKey, map[string]interface{}{"clearTurnstileSecretKey": true})
			},
		},
		{
			name: "keeping the challenge on with the stored secret key", storedEnabled: true,
			body:       func(t *testing.T) string { return turnstileSaveBody(t, true, turnstileTestSiteKey, nil) },
			wantSecret: true,
		},
		{
			name:       "keeping the challenge off with the stored secret key",
			body:       func(t *testing.T) string { return turnstileSaveBody(t, false, turnstileTestSiteKey, nil) },
			wantSecret: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Cloudflare would reject every secret key: a call would refuse the save.
			checker := &fakeSecretKeyChecker{answer: turnstile.SecretKeyRejected}

			save := serveTurnstileSaveCheckedBy(t, turnstileSaveSettings(t, c.storedEnabled, true), c.body(t), checker)

			require.Equal(t, http.StatusOK, save.rr.Code, save.rr.Body.String())
			assert.Empty(t, checker.checked, "Cloudflare is not called")
			require.NotNil(t, save.written)
			assert.Equal(t, c.wantSecret, len(save.written.TurnstileSecretKeyEncrypted) > 0)
		})
	}
}

// A secret key Cloudflare rejects, or one that cannot be checked with it, refuses the save, which
// writes and records nothing: a new secret key, or turning the challenge on with the stored one.
func TestHandleSettingsTurnstilePut_ASecretKeyCloudflareDoesNotAcceptRefusesTheSave(t *testing.T) {
	answers := []struct {
		answer          turnstile.SecretKeyCheck
		wantCode        string
		wantDescription string
	}{
		{turnstile.SecretKeyRejected, "handler.settings_turnstile.secret_key_rejected",
			"Cloudflare doesn't accept the secret key. Copy it again from the widget in the Cloudflare dashboard."},
		{turnstile.SecretKeyUnchecked, "handler.settings_turnstile.secret_key_unchecked",
			"The secret key couldn't be checked with Cloudflare. Try again in a moment."},
	}
	saves := []struct {
		name          string
		storedEnabled bool
		storedSecret  bool
		body          func(t *testing.T) string
	}{
		{
			name: "a new secret key, challenge off",
			body: func(t *testing.T) string {
				return turnstileSaveBody(t, false, turnstileTestSiteKey, map[string]interface{}{"turnstileSecretKey": turnstileEnteredSecretKey})
			},
		},
		{
			name: "a new secret key, challenge on", storedEnabled: true, storedSecret: true,
			body: func(t *testing.T) string {
				return turnstileSaveBody(t, true, turnstileTestSiteKey, map[string]interface{}{"turnstileSecretKey": turnstileEnteredSecretKey})
			},
		},
		{
			name: "turning the challenge on with the stored secret key", storedSecret: true,
			body: func(t *testing.T) string { return turnstileSaveBody(t, true, turnstileTestSiteKey, nil) },
		},
	}
	for _, a := range answers {
		for _, c := range saves {
			t.Run(string(a.answer)+", "+c.name, func(t *testing.T) {
				checker := &fakeSecretKeyChecker{answer: a.answer}

				save := serveTurnstileSaveCheckedBy(t, turnstileSaveSettings(t, c.storedEnabled, c.storedSecret), c.body(t), checker)

				assert.Equal(t, http.StatusBadRequest, save.rr.Code, save.rr.Body.String())
				code, description := decodeErrorEnvelope(t, save.rr)
				assert.Equal(t, a.wantCode, code)
				assert.Equal(t, a.wantDescription, description)
				assert.Len(t, checker.checked, 1)
				assert.Nil(t, save.written)
				assert.Nil(t, save.audited)
			})
		}
	}
}

// A save another refusal answers is refused without asking Cloudflare.
func TestHandleSettingsTurnstilePut_ARefusedSaveDoesNotCallCloudflare(t *testing.T) {
	checker := acceptingSecretKeyChecker()

	save := serveTurnstileSaveCheckedBy(t, turnstileSaveSettings(t, true, true), turnstileSaveBody(t, true, turnstileOtherSiteKey,
		map[string]interface{}{"turnstileSecretKey": turnstileEnteredSecretKey, "clearTurnstileSecretKey": true}), checker)

	assert.Equal(t, http.StatusBadRequest, save.rr.Code, save.rr.Body.String())
	assert.Empty(t, checker.checked)
}
