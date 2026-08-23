package apihandlers

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/authserver/internal/handlers"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/pkg/errors"
)

// HandleAPISettingsKeysGet - GET /api/v1/admin/settings/keys
func HandleAPISettingsKeysGet(
	httpHelper handlers.HttpHelper,
	database data.Database,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		allSigningKeys, err := database.GetAllSigningKeys(nil)
		if err != nil {
			writeJSONError(w, "Failed to get signing keys", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}

		// Map keys
		mapped := make([]api.SettingsSigningKeyResponse, 0, len(allSigningKeys))
		for _, k := range allSigningKeys {
			var createdAt *time.Time
			if k.CreatedAt.Valid {
				t := k.CreatedAt.Time
				createdAt = &t
			}
			mapped = append(mapped, api.SettingsSigningKeyResponse{
				Id:               k.Id,
				CreatedAt:        createdAt,
				State:            k.State,
				KeyIdentifier:    k.KeyIdentifier,
				Type:             k.Type,
				Algorithm:        k.Algorithm,
				PublicKeyASN1DER: base64.StdEncoding.EncodeToString(k.PublicKeyASN1_DER),
				PublicKeyPEM:     string(k.PublicKeyPEM),
				PublicKeyJWK:     string(k.PublicKeyJWK),
			})
		}

		// Order: next, current, then all previous
		ordered := make([]api.SettingsSigningKeyResponse, 0, len(mapped))
		for _, v := range mapped {
			if v.State == enums.KeyStateNext.String() {
				ordered = append(ordered, v)
				break
			}
		}
		for _, v := range mapped {
			if v.State == enums.KeyStateCurrent.String() {
				ordered = append(ordered, v)
				break
			}
		}
		for _, v := range mapped {
			if v.State == enums.KeyStatePrevious.String() {
				ordered = append(ordered, v)
			}
		}

		resp := api.GetSettingsKeysResponse{Keys: ordered}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		httpHelper.EncodeJson(w, r, resp)
	}
}

// HandleAPISettingsKeysRotatePost - POST /api/v1/admin/settings/keys/rotate
//
// The transition itself lives in oauth.SigningKeyRotator, which takes it as one transaction.
// This used to be five unsynchronised writes here, and the delete of the previous key ran
// before the check that a next key even existed, so a rotation that was about to be refused
// had already destroyed the key still signing live tokens (#251).
func HandleAPISettingsKeysRotatePost(
	authHelper handlers.AuthHelper,
	database data.Database,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {

	rotator := oauth.NewSigningKeyRotator(database)

	return func(w http.ResponseWriter, r *http.Request) {
		err := rotator.Rotate()

		switch {
		case err == nil:
			// Audited here and only here, so the log carries exactly one entry per rotation
			// that actually happened.
			auditLogger.Log(constants.AuditRotatedKeys, map[string]interface{}{
				"loggedInUser": authHelper.GetLoggedInSubject(r),
			})

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(api.SuccessResponse{Success: true})

		case errors.Is(err, oauth.ErrRotationInProgress):
			// 409 rather than 200: this call rotated nothing. Reporting success would have the
			// admin console announce one rotation twice, and would invite a caller to believe
			// it holds a key it never created. Retrying is wrong for the same reason, which is
			// what the REST API page now says.
			writeJSONError(w, "Another key rotation is in progress", "ROTATION_IN_PROGRESS",
				http.StatusConflict)

		case errors.Is(err, oauth.ErrKeySetIncomplete):
			writeJSONError(w, "Expected current and next keys to exist", "KEY_SET_INCOMPLETE",
				http.StatusInternalServerError)

		default:
			writeJSONError(w, "Failed to rotate signing keys", "INTERNAL_ERROR",
				http.StatusInternalServerError)
		}
	}
}

// HandleAPISettingsKeyDelete - DELETE /api/v1/admin/settings/keys/{id}
func HandleAPISettingsKeyDelete(
	authHelper handlers.AuthHelper,
	database data.Database,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idStr := chi.URLParam(r, "id")
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil || id <= 0 {
			writeJSONError(w, "Invalid key ID", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		kp, err := database.GetKeyPairById(nil, id)
		if err != nil {
			writeJSONError(w, "Failed to load key", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}
		if kp == nil {
			writeJSONError(w, "Key not found", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		keyState, err := enums.KeyStateFromString(kp.State)
		if err != nil {
			writeJSONError(w, "Invalid key state", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}
		if keyState != enums.KeyStatePrevious {
			writeJSONError(w, "Only a previous key can be revoked", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		if err := database.DeleteKeyPair(nil, kp.Id); err != nil {
			writeJSONError(w, "Failed to delete key", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}

		auditLogger.Log(constants.AuditRevokedKey, map[string]interface{}{
			"loggedInUser": authHelper.GetLoggedInSubject(r),
			"keyId":        kp.KeyIdentifier,
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(api.SuccessResponse{Success: true})
	}
}
