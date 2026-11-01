package apihandlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
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
	settings := &record.Settings{Id: 1, TurnstileEnabled: enabled, TurnstileSiteKey: turnstileTestSiteKey}
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

// serveTurnstileSave runs PUT /api/v1/admin/settings/turnstile as a manage-settings caller, starting
// from settings. A refused save is held to writing nothing and recording nothing.
func serveTurnstileSave(t *testing.T, settings *record.Settings, body string) turnstileSave {
	t.Helper()
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	var result turnstileSave
	allowSettingsSave(database)
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
	HandleSettingsTurnstilePut(database, auditLogger, testDataCipher).ServeHTTP(result.rr, r)

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
	settings := &record.Settings{Id: 1}

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

// An absent or empty secret key keeps the stored one, byte for byte: the API never answers it, so a
// client sending the form back as it read it has nothing to put there. That holds turning the
// challenge on, keeping it on, and turning it off.
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
			assert.Equal(t, stored, save.written.TurnstileSecretKeyEncrypted, "the stored ciphertext, byte for byte")
			_, _, hasSecretKey := turnstileAnswer(t, save.rr)
			assert.True(t, hasSecretKey)
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
	assert.Equal(t, stored, save.written.TurnstileSecretKeyEncrypted)
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

	save := serveTurnstileSave(t, &record.Settings{Id: 1}, turnstileSaveBody(t, true, siteKey,
		map[string]interface{}{"turnstileSecretKey": secretKey}))

	require.Equal(t, http.StatusOK, save.rr.Code, save.rr.Body.String())
	require.NotNil(t, save.written)
	assert.Equal(t, siteKey, save.written.TurnstileSiteKey)
	assert.Equal(t, secretKey, decryptedSecretKey(t, save.written))
}

// A body that will not parse is an integrator's mistake, answered in English with nothing written.
func TestHandleSettingsTurnstilePut_ABodyThatWillNotParseIsRefused(t *testing.T) {
	save := serveTurnstileSave(t, &record.Settings{Id: 1}, `{"turnstileEnabled": "yes"`)

	assert.Equal(t, http.StatusBadRequest, save.rr.Code)
	code, _ := decodeErrorEnvelope(t, save.rr)
	assert.Equal(t, "INVALID_REQUEST_BODY", code)
	assert.Nil(t, save.written)
}
