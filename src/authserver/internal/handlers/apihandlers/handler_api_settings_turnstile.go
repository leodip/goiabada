package apihandlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/internal/turnstile"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/inputvalidation"
)

// The bounds of the Turnstile keys, in characters. Cloudflare's keys are a few dozen ASCII
// characters; the site key's bound is its column's width.
const (
	turnstileSiteKeyMaxLength   = 128
	turnstileSecretKeyMaxLength = 128
)

// HandleSettingsTurnstileGet - GET /api/v1/admin/settings/turnstile
func HandleSettingsTurnstileGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		settings, ok := reqctx.SettingsFrom(r.Context())
		if !ok {
			writeInternalServerError(w, r, reqctx.ErrNoSettings)
			return
		}

		writeJSON(w, r, http.StatusOK, settingsTurnstileResponse(settings))
	}
}

// settingsTurnstileDatabase is what the Turnstile settings endpoint needs: the settings save.
type settingsTurnstileDatabase interface {
	settingsSaveDatabase
}

// turnstileSecretKeyChecker asks Cloudflare whether it knows a secret key. *turnstile.Verifier
// satisfies it.
type turnstileSecretKeyChecker interface {
	CheckSecretKey(ctx context.Context, secretKey string) turnstile.SecretKeyCheck
}

// HandleSettingsTurnstilePut - PUT /api/v1/admin/settings/turnstile
//
// It saves the Cloudflare Turnstile challenge's switch, site key and secret key (#642 decision 11).
// The secret key is write-only, as the SMTP password is: an absent or empty one keeps what is
// stored, a new one replaces it, and only clearTurnstileSecretKey removes it. A save is refused
// when it would turn the challenge on without both keys, remove the secret key while the challenge
// is on, or change the site key without the secret key entered again, since the two come from one
// widget. It is refused too when it stores a new secret key, or turns the challenge on, and
// Cloudflare rejects the secret key, or the key cannot be checked with it because Cloudflare cannot be
// reached or gives no usable answer. Turning the challenge off keeps the keys.
func HandleSettingsTurnstilePut(
	database settingsTurnstileDatabase,
	auditLogger AuditLogger,
	dataCipher *encryption.DataCipher,
	secretKeyChecker turnstileSecretKeyChecker,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		currentSettings, ok := reqctx.SettingsFrom(r.Context())
		if !ok {
			writeInternalServerError(w, r, reqctx.ErrNoSettings)
			return
		}

		var req api.UpdateSettingsTurnstileRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}

		// Both keys are pasted from Cloudflare's dashboard, and neither holds a space, so space
		// around either is the paste's. A secret key of spaces alone is no secret key: it keeps the
		// stored one.
		siteKey := strings.TrimSpace(req.TurnstileSiteKey)
		secretKey := strings.TrimSpace(req.TurnstileSecretKey)

		if inputvalidation.TextLength(siteKey) > turnstileSiteKeyMaxLength {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeSettingsTurnstileSiteKeyTooLong,
				map[string]any{"max": turnstileSiteKeyMaxLength}))
			return
		}
		if inputvalidation.TextLength(secretKey) > turnstileSecretKeyMaxLength {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeSettingsTurnstileSecretKeyTooLong,
				map[string]any{"max": turnstileSecretKeyMaxLength}))
			return
		}
		if secretKey != "" && req.ClearTurnstileSecretKey {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeSettingsTurnstileSecretKeyAndClear, nil))
			return
		}

		storedSecretKey := len(currentSettings.TurnstileSecretKeyEncrypted) > 0
		if req.TurnstileEnabled {
			if siteKey == "" {
				writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeSettingsTurnstileSiteKeyRequired, nil))
				return
			}
			// With the challenge on, every form submission is verified with the secret key, so it
			// cannot be removed: the challenge is turned off first.
			if req.ClearTurnstileSecretKey {
				writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeSettingsTurnstileSecretKeyClearWhileEnabled, nil))
				return
			}
			if secretKey == "" && !storedSecretKey {
				writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeSettingsTurnstileSecretKeyRequired, nil))
				return
			}
		}

		// A stored secret key belongs to the widget its site key names: a new site key needs that
		// widget's secret key, or the removal of the stored one, or every form would be verified
		// with another widget's secret key. The keys are compared trimmed, as stored.
		if storedSecretKey && secretKey == "" && !req.ClearTurnstileSecretKey &&
			siteKey != strings.TrimSpace(currentSettings.TurnstileSiteKey) {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeSettingsTurnstileSiteKeyChanged, nil))
			return
		}

		// A save that puts a secret key in use asks Cloudflare about it first, outside the save's
		// transaction: a new secret key, or the stored one when the challenge is turned on. Turning the
		// challenge off and removing the secret key put none in use, and never call Cloudflare
		// (#642 decision 11). A key Cloudflare rejects would let every form through as misconfigured;
		// one that cannot be checked, Cloudflare unreachable or its answer unusable, is refused too,
		// to be saved once it can be.
		checkedSecretKey := secretKey
		if checkedSecretKey == "" && req.TurnstileEnabled && !currentSettings.TurnstileEnabled {
			stored, decryptErr := dataCipher.Decrypt(currentSettings.TurnstileSecretKeyEncrypted)
			if decryptErr != nil {
				writeInternalServerError(w, r, decryptErr)
				return
			}
			checkedSecretKey = stored
		}
		if checkedSecretKey != "" {
			switch secretKeyChecker.CheckSecretKey(r.Context(), checkedSecretKey) {
			case turnstile.SecretKeyAccepted:
			case turnstile.SecretKeyRejected:
				writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeSettingsTurnstileSecretKeyRejected, nil))
				return
			default:
				writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeSettingsTurnstileSecretKeyUnchecked, nil))
				return
			}
		}

		// The secret key written is decided here, against the row the site key check above read: a
		// kept secret key is that row's, the one the check found entered for this site key. Keeping
		// the one the save reads under its lock instead could pair this save's site key with another
		// widget's secret key, saved meanwhile, as the email save's password rule explains.
		secretKeyEncrypted := currentSettings.TurnstileSecretKeyEncrypted
		switch {
		case req.ClearTurnstileSecretKey:
			secretKeyEncrypted = nil
		case secretKey != "":
			encrypted, encryptErr := dataCipher.Encrypt(secretKey)
			if encryptErr != nil {
				writeInternalServerError(w, r, encryptErr)
				return
			}
			secretKeyEncrypted = encrypted
		}

		var oldVals map[string]interface{}
		saved, err := saveSettingsSection(r.Context(), database, currentSettings.Id, func(stored *record.Settings) {
			oldVals = turnstileSettingsAuditValues(stored)
			stored.TurnstileEnabled = req.TurnstileEnabled
			stored.TurnstileSiteKey = siteKey
			stored.TurnstileSecretKeyEncrypted = secretKeyEncrypted
		})
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		auditLogger.Log(r.Context(), audit.EventUpdatedTurnstileSettings, map[string]interface{}{
			"logged_in_user": callerSubject(r),
			"old":            oldVals,
			"new":            turnstileSettingsAuditValues(saved),
		})

		writeJSON(w, r, http.StatusOK, settingsTurnstileResponse(saved))
	}
}

// settingsTurnstileResponse is the Turnstile settings as the API answers them, the secret key only
// as whether one is stored.
func settingsTurnstileResponse(settings *record.Settings) api.SettingsTurnstileResponse {
	return api.SettingsTurnstileResponse{
		TurnstileEnabled:      settings.TurnstileEnabled,
		TurnstileSiteKey:      settings.TurnstileSiteKey,
		HasTurnstileSecretKey: len(settings.TurnstileSecretKeyEncrypted) > 0,
	}
}

// turnstileSettingsAuditValues is what updated_turnstile_settings records of one side of a save: the
// switch, the site key, which is public, and whether a secret key is stored, never the secret key.
func turnstileSettingsAuditValues(settings *record.Settings) map[string]interface{} {
	return map[string]interface{}{
		"turnstile_enabled":        settings.TurnstileEnabled,
		"turnstile_site_key":       settings.TurnstileSiteKey,
		"has_turnstile_secret_key": len(settings.TurnstileSecretKeyEncrypted) > 0,
	}
}
