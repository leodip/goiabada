package apihandlers

import (
    "crypto/x509"
    "encoding/base64"
    "encoding/json"
    "encoding/pem"
    "net/http"
    "strconv"
    "time"

    "github.com/go-chi/chi/v5"
    "github.com/google/uuid"
    "github.com/leodip/goiabada/authserver/internal/handlers"
    "github.com/leodip/goiabada/core/api"
    "github.com/leodip/goiabada/core/constants"
    "github.com/leodip/goiabada/core/data"
    "github.com/leodip/goiabada/core/enums"
    "github.com/leodip/goiabada/core/models"
    "github.com/leodip/goiabada/core/rsautil"
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
        for _, v := range mapped { if v.State == enums.KeyStateNext.String() { ordered = append(ordered, v); break } }
        for _, v := range mapped { if v.State == enums.KeyStateCurrent.String() { ordered = append(ordered, v); break } }
        for _, v := range mapped { if v.State == enums.KeyStatePrevious.String() { ordered = append(ordered, v) } }

        resp := api.GetSettingsKeysResponse{ Keys: ordered }
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)
        httpHelper.EncodeJson(w, r, resp)
    }
}

// HandleAPISettingsKeysRotatePost - POST /api/v1/admin/settings/keys/rotate
func HandleAPISettingsKeysRotatePost(
    httpHelper handlers.HttpHelper,
    authHelper handlers.AuthHelper,
    database data.Database,
    auditLogger handlers.AuditLogger,
) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        allSigningKeys, err := database.GetAllSigningKeys(nil)
        if err != nil {
            writeJSONError(w, "Failed to get signing keys", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }

        var currentKey *models.KeyPair
        var nextKey *models.KeyPair
        var previousKey *models.KeyPair
        for i := range allSigningKeys {
            kp := &allSigningKeys[i]
            keyState, err := enums.KeyStateFromString(kp.State)
            if err != nil {
                writeJSONError(w, "Invalid key state", "INTERNAL_ERROR", http.StatusInternalServerError)
                return
            }
            switch keyState {
            case enums.KeyStateCurrent:
                currentKey = kp
            case enums.KeyStateNext:
                nextKey = kp
            case enums.KeyStatePrevious:
                previousKey = kp
            }
        }

        // Delete existing previous key, if any
        if previousKey != nil {
            if err := database.DeleteKeyPair(nil, previousKey.Id); err != nil {
                writeJSONError(w, "Failed to delete previous key", "INTERNAL_ERROR", http.StatusInternalServerError)
                return
            }
        }

        if currentKey == nil || nextKey == nil {
            writeJSONError(w, "Expected current and next keys to exist", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }

        // current -> previous
        currentKey.State = enums.KeyStatePrevious.String()
        if err := database.UpdateKeyPair(nil, currentKey); err != nil {
            writeJSONError(w, "Failed to update current key", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }

        // next -> current
        nextKey.State = enums.KeyStateCurrent.String()
        if err := database.UpdateKeyPair(nil, nextKey); err != nil {
            writeJSONError(w, "Failed to update next key", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }

        // create new next key (RSA 4096, RS256), same as today
        privateKey, err := rsautil.GeneratePrivateKey(4096)
        if err != nil {
            writeJSONError(w, "Unable to generate a private key", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }
        privateKeyPEM := rsautil.EncodePrivateKeyToPEM(privateKey)

        publicKeyASN1Der, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
        if err != nil {
            writeJSONError(w, "Unable to marshal public key to PKIX", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }
        publicKeyPEM := pem.EncodeToMemory(&pem.Block{ Type: "RSA PUBLIC KEY", Bytes: publicKeyASN1Der })

        kid := uuid.New().String()
        publicKeyJWK, err := rsautil.MarshalRSAPublicKeyToJWK(&privateKey.PublicKey, kid)
        if err != nil {
            writeJSONError(w, "Failed to marshal JWK", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }

        keyPair := &models.KeyPair{
            State:             enums.KeyStateNext.String(),
            KeyIdentifier:     kid,
            Type:              "RSA",
            Algorithm:         "RS256",
            PrivateKeyPEM:     privateKeyPEM,
            PublicKeyPEM:      publicKeyPEM,
            PublicKeyASN1_DER: publicKeyASN1Der,
            PublicKeyJWK:      publicKeyJWK,
        }
        if err := database.CreateKeyPair(nil, keyPair); err != nil {
            writeJSONError(w, "Failed to create new key", "INTERNAL_ERROR", http.StatusInternalServerError)
            return
        }

        auditLogger.Log(constants.AuditRotatedKeys, map[string]interface{}{
            "loggedInUser": authHelper.GetLoggedInSubject(r),
        })

        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)
        json.NewEncoder(w).Encode(api.SuccessResponse{ Success: true })
    }
}

// HandleAPISettingsKeyDelete - DELETE /api/v1/admin/settings/keys/{id}
func HandleAPISettingsKeyDelete(
    httpHelper handlers.HttpHelper,
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
        json.NewEncoder(w).Encode(api.SuccessResponse{ Success: true })
    }
}
