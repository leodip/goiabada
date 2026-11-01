package integration

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Cloudflare's published Turnstile test keys (#642's Testing section). The secret keys are real
// ones Cloudflare's siteverify accepts, so these saves stay valid once a save checks the secret key
// with Cloudflare: the first passes any token, the second fails every token.
const (
	turnstilePassingSiteKey   = "1x00000000000000000000AA"
	turnstileBlockingSiteKey  = "2x00000000000000000000AB"
	turnstilePassingSecretKey = "1x0000000000000000000000000000000AA"
	turnstileFailingSecretKey = "2x0000000000000000000000000000000AA"
)

const turnstileSettingsPath = "/api/v1/admin/settings/turnstile"

// turnstileSettingsAnswer reads a GET or a successful PUT, asserting the answer carries exactly the
// three fields of #642 decision 11 and nothing of the secret key.
func turnstileSettingsAnswer(t *testing.T, resp *http.Response) api.SettingsTurnstileResponse {
	t.Helper()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var fields map[string]any
	require.NoError(t, json.Unmarshal(raw, &fields))
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	assert.ElementsMatch(t, []string{"turnstileEnabled", "turnstileSiteKey", "hasTurnstileSecretKey"}, names)
	assert.NotContains(t, string(raw), turnstilePassingSecretKey)
	assert.NotContains(t, string(raw), turnstileFailingSecretKey)

	var body api.SettingsTurnstileResponse
	require.NoError(t, json.Unmarshal(raw, &body))
	return body
}

// putTurnstile saves body as accessToken and answers the response and its request id.
func putTurnstile(t *testing.T, accessToken string, body any) (*http.Response, string) {
	t.Helper()
	resp, requestId := sendAdmin(t, accessToken, http.MethodPut, turnstileSettingsPath, body)
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp, requestId
}

// storedTurnstile is the settings row as stored.
func storedTurnstile(t *testing.T) *record.Settings {
	t.Helper()
	settings, err := database.GetSettingsById(context.Background(), nil, 1)
	require.NoError(t, err)
	require.NotNil(t, settings)
	return settings
}

// A fresh installation has the challenge off with no keys, and the GET answers so.
func TestAPISettingsTurnstileGet_AnswersTheStoredSettings(t *testing.T) {
	restoreSettings(t)
	accessToken, _ := createAdminClientWithToken(t)

	resp, _ := sendAdmin(t, accessToken, http.MethodGet, turnstileSettingsPath, nil)
	defer func() { _ = resp.Body.Close() }()
	body := turnstileSettingsAnswer(t, resp)
	stored := storedTurnstile(t)
	assert.Equal(t, stored.TurnstileEnabled, body.TurnstileEnabled)
	assert.Equal(t, stored.TurnstileSiteKey, body.TurnstileSiteKey)
	assert.Equal(t, len(stored.TurnstileSecretKeyEncrypted) > 0, body.HasTurnstileSecretKey)

	sealed, err := dataCipher.Encrypt(turnstilePassingSecretKey)
	require.NoError(t, err)
	changeSettings(t, func(settings *record.Settings) {
		settings.TurnstileEnabled = true
		settings.TurnstileSiteKey = turnstilePassingSiteKey
		settings.TurnstileSecretKeyEncrypted = sealed
	})
	resp2, _ := sendAdmin(t, accessToken, http.MethodGet, turnstileSettingsPath, nil)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, api.SettingsTurnstileResponse{
		TurnstileEnabled:      true,
		TurnstileSiteKey:      turnstilePassingSiteKey,
		HasTurnstileSecretKey: true,
	}, turnstileSettingsAnswer(t, resp2))
}

// The secret key is write-only: stored sealed under the data key, kept by a save that omits it or
// sends it empty, replaced by a new one, and removed only by clearTurnstileSecretKey, with the
// challenge off (#642 decision 11).
func TestAPISettingsTurnstilePut_TheSecretKeyLifecycle(t *testing.T) {
	restoreSettings(t)
	accessToken, _ := createAdminClientWithToken(t)

	// Turned on with both keys.
	resp, _ := putTurnstile(t, accessToken, api.UpdateSettingsTurnstileRequest{
		TurnstileEnabled:   true,
		TurnstileSiteKey:   turnstilePassingSiteKey,
		TurnstileSecretKey: turnstilePassingSecretKey,
	})
	assert.Equal(t, api.SettingsTurnstileResponse{
		TurnstileEnabled: true, TurnstileSiteKey: turnstilePassingSiteKey, HasTurnstileSecretKey: true,
	}, turnstileSettingsAnswer(t, resp))
	stored := storedTurnstile(t)
	assert.True(t, stored.TurnstileEnabled)
	assert.Equal(t, turnstilePassingSiteKey, stored.TurnstileSiteKey)
	set := stored.TurnstileSecretKeyEncrypted
	assert.NotContains(t, string(set), turnstilePassingSecretKey, "the secret key is stored sealed")
	plaintext, err := dataCipher.Decrypt(set)
	require.NoError(t, err)
	assert.Equal(t, turnstilePassingSecretKey, plaintext)

	// Kept by a save that omits it, and by one that sends it empty.
	resp, _ = putTurnstile(t, accessToken, map[string]any{"turnstileEnabled": true, "turnstileSiteKey": turnstilePassingSiteKey})
	assert.True(t, turnstileSettingsAnswer(t, resp).HasTurnstileSecretKey)
	assert.Equal(t, set, storedTurnstile(t).TurnstileSecretKeyEncrypted, "an omitted secret key keeps the stored ciphertext")
	resp, _ = putTurnstile(t, accessToken, api.UpdateSettingsTurnstileRequest{TurnstileEnabled: true, TurnstileSiteKey: turnstilePassingSiteKey})
	assert.True(t, turnstileSettingsAnswer(t, resp).HasTurnstileSecretKey)
	assert.Equal(t, set, storedTurnstile(t).TurnstileSecretKeyEncrypted, "an empty secret key keeps the stored ciphertext")

	// Replaced by a new one.
	resp, _ = putTurnstile(t, accessToken, api.UpdateSettingsTurnstileRequest{
		TurnstileEnabled: true, TurnstileSiteKey: turnstilePassingSiteKey, TurnstileSecretKey: turnstileFailingSecretKey,
	})
	assert.True(t, turnstileSettingsAnswer(t, resp).HasTurnstileSecretKey)
	plaintext, err = dataCipher.Decrypt(storedTurnstile(t).TurnstileSecretKeyEncrypted)
	require.NoError(t, err)
	assert.Equal(t, turnstileFailingSecretKey, plaintext)

	// Turned off, the keys stay.
	resp, _ = putTurnstile(t, accessToken, api.UpdateSettingsTurnstileRequest{TurnstileSiteKey: turnstilePassingSiteKey})
	assert.Equal(t, api.SettingsTurnstileResponse{
		TurnstileEnabled: false, TurnstileSiteKey: turnstilePassingSiteKey, HasTurnstileSecretKey: true,
	}, turnstileSettingsAnswer(t, resp))
	assert.False(t, storedTurnstile(t).TurnstileEnabled)

	// Removed, with the challenge off.
	resp, _ = putTurnstile(t, accessToken, api.UpdateSettingsTurnstileRequest{
		TurnstileSiteKey: turnstilePassingSiteKey, ClearTurnstileSecretKey: true,
	})
	assert.False(t, turnstileSettingsAnswer(t, resp).HasTurnstileSecretKey)
	assert.Empty(t, storedTurnstile(t).TurnstileSecretKeyEncrypted)
}

// Each refusal of #642 decision 11 that needs no call to Cloudflare answers 400 with its catalog key
// and writes nothing.
func TestAPISettingsTurnstilePut_RefusalsWriteNothing(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	sealed, err := dataCipher.Encrypt(turnstilePassingSecretKey)
	require.NoError(t, err)

	cases := []struct {
		name            string
		stored          func(settings *record.Settings)
		body            any
		wantCode        string
		wantDescription string
	}{
		{
			name:            "turning the challenge on without a site key",
			stored:          func(settings *record.Settings) { settings.TurnstileSecretKeyEncrypted = sealed },
			body:            api.UpdateSettingsTurnstileRequest{TurnstileEnabled: true},
			wantCode:        "handler.settings_turnstile.site_key_required",
			wantDescription: "Enter the site key to turn the Turnstile challenge on.",
		},
		{
			name:            "turning the challenge on without a secret key",
			stored:          func(*record.Settings) {},
			body:            api.UpdateSettingsTurnstileRequest{TurnstileEnabled: true, TurnstileSiteKey: turnstilePassingSiteKey},
			wantCode:        "handler.settings_turnstile.secret_key_required",
			wantDescription: "Enter the secret key to turn the Turnstile challenge on.",
		},
		{
			name: "clearing the secret key while the challenge is on",
			stored: func(settings *record.Settings) {
				settings.TurnstileEnabled = true
				settings.TurnstileSecretKeyEncrypted = sealed
			},
			body: api.UpdateSettingsTurnstileRequest{
				TurnstileEnabled: true, TurnstileSiteKey: turnstilePassingSiteKey, ClearTurnstileSecretKey: true,
			},
			wantCode:        "handler.settings_turnstile.secret_key_clear_while_enabled",
			wantDescription: "The secret key can't be removed while the Turnstile challenge is on.",
		},
		{
			name: "changing the site key without the secret key",
			stored: func(settings *record.Settings) {
				settings.TurnstileEnabled = true
				settings.TurnstileSecretKeyEncrypted = sealed
			},
			body:            api.UpdateSettingsTurnstileRequest{TurnstileEnabled: true, TurnstileSiteKey: turnstileBlockingSiteKey},
			wantCode:        "handler.settings_turnstile.site_key_changed",
			wantDescription: "The site key has changed: enter the secret key again, or remove it.",
		},
		{
			name:   "a new secret key together with its removal",
			stored: func(settings *record.Settings) { settings.TurnstileSecretKeyEncrypted = sealed },
			body: api.UpdateSettingsTurnstileRequest{
				TurnstileSiteKey: turnstilePassingSiteKey, TurnstileSecretKey: turnstileFailingSecretKey, ClearTurnstileSecretKey: true,
			},
			wantCode:        "handler.settings_turnstile.secret_key_and_clear",
			wantDescription: "Send either a new secret key or clearTurnstileSecretKey, not both.",
		},
		{
			name:            "a site key longer than 128 characters",
			stored:          func(*record.Settings) {},
			body:            api.UpdateSettingsTurnstileRequest{TurnstileSiteKey: strings.Repeat("s", 129), TurnstileSecretKey: turnstilePassingSecretKey},
			wantCode:        "handler.settings_turnstile.site_key_too_long",
			wantDescription: "The site key can't be longer than 128 characters.",
		},
		{
			name:            "a secret key longer than 128 characters",
			stored:          func(*record.Settings) {},
			body:            api.UpdateSettingsTurnstileRequest{TurnstileSiteKey: turnstilePassingSiteKey, TurnstileSecretKey: strings.Repeat("k", 129)},
			wantCode:        "handler.settings_turnstile.secret_key_too_long",
			wantDescription: "The secret key can't be longer than 128 characters.",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := changeSettings(t, func(settings *record.Settings) {
				settings.TurnstileEnabled = false
				settings.TurnstileSiteKey = turnstilePassingSiteKey
				settings.TurnstileSecretKeyEncrypted = nil
				c.stored(settings)
			})

			resp, _ := putTurnstile(t, accessToken, c.body)

			require.Equal(t, http.StatusBadRequest, resp.StatusCode)
			var errBody api.ErrorResponse
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&errBody))
			assert.Equal(t, c.wantCode, errBody.ErrorCode)
			assert.Equal(t, c.wantDescription, errBody.ErrorDescription)
			after := storedTurnstile(t)
			assert.Equal(t, before.TurnstileEnabled, after.TurnstileEnabled, "the switch is unchanged")
			assert.Equal(t, before.TurnstileSiteKey, after.TurnstileSiteKey, "the site key is unchanged")
			assert.Equal(t, string(before.TurnstileSecretKeyEncrypted), string(after.TurnstileSecretKeyEncrypted),
				"the secret key is unchanged")
		})
	}
}

// updated_turnstile_settings records who saved, and the switch, the site key and whether a secret key
// is stored before and after the save; never the secret key (#642 decision 11).
func TestAPISettingsTurnstilePut_TheEventRecordsTheSaveWithoutTheSecretKey(t *testing.T) {
	requireDatabaseAuditLogs(t)
	changeSettings(t, func(settings *record.Settings) {
		settings.TurnstileEnabled = false
		settings.TurnstileSiteKey = ""
		settings.TurnstileSecretKeyEncrypted = nil
	})
	accessToken, adminClient := createAdminClientWithToken(t)

	resp, requestId := putTurnstile(t, accessToken, api.UpdateSettingsTurnstileRequest{
		TurnstileEnabled: true, TurnstileSiteKey: turnstilePassingSiteKey, TurnstileSecretKey: turnstilePassingSecretKey,
	})
	turnstileSettingsAnswer(t, resp)

	rows := auditRows(t, accessToken, "updated_turnstile_settings", requestId)
	assert.Equal(t, []map[string]any{{
		"logged_in_user": adminClient.ClientIdentifier,
		"old": map[string]any{
			"turnstile_enabled":        false,
			"turnstile_site_key":       "",
			"has_turnstile_secret_key": false,
		},
		"new": map[string]any{
			"turnstile_enabled":        true,
			"turnstile_site_key":       turnstilePassingSiteKey,
			"has_turnstile_secret_key": true,
		},
	}}, rows)

	logs, listResp := getAuditLogs(t, accessToken, "requestId="+requestId)
	defer func() { _ = listResp.Body.Close() }()
	for _, entry := range logs.AuditLogs {
		assert.NotContains(t, entry.Details, turnstilePassingSecretKey, "no event of the save carries the secret key")
	}
}

// The route takes the scopes the other settings routes take: authserver:manage-settings saves, as
// authserver:manage does, authserver:admin-read reads and is refused a save, and no token is a 401.
func TestAPISettingsTurnstile_TakesTheSettingsScopes(t *testing.T) {
	restoreSettings(t)
	manageSettingsToken, _ := createClientWithGranularScope(t, builtin.ManageSettingsPermissionIdentifier)
	adminReadToken, _ := createClientWithGranularScope(t, builtin.AdminReadPermissionIdentifier)

	resp, _ := putTurnstile(t, manageSettingsToken, api.UpdateSettingsTurnstileRequest{
		TurnstileEnabled: true, TurnstileSiteKey: turnstilePassingSiteKey, TurnstileSecretKey: turnstilePassingSecretKey,
	})
	assert.True(t, turnstileSettingsAnswer(t, resp).TurnstileEnabled, "authserver:manage-settings turns the challenge on")

	read, _ := sendAdmin(t, adminReadToken, http.MethodGet, turnstileSettingsPath, nil)
	defer func() { _ = read.Body.Close() }()
	assert.True(t, turnstileSettingsAnswer(t, read).TurnstileEnabled)

	refused, _ := putTurnstile(t, adminReadToken, api.UpdateSettingsTurnstileRequest{TurnstileSiteKey: turnstilePassingSiteKey})
	assert.Equal(t, http.StatusForbidden, refused.StatusCode)
	assert.True(t, storedTurnstile(t).TurnstileEnabled, "the refused save wrote nothing")

	for _, method := range []string{http.MethodGet, http.MethodPut} {
		req, err := http.NewRequest(method, appConfig.AuthServer.BaseURL+turnstileSettingsPath, nil)
		require.NoError(t, err)
		noToken, err := createHttpClient(t).Do(req)
		require.NoError(t, err)
		_ = noToken.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, noToken.StatusCode, method)
	}
}
