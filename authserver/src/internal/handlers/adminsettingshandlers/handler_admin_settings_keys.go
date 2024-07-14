package adminsettingshandlers

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/data"
	"github.com/leodip/goiabada/internal/enums"
	"github.com/leodip/goiabada/internal/handlers"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/leodip/goiabada/internal/models"
	"github.com/pkg/errors"
)

func HandleAdminSettingsKeysGet(
	httpHelper handlers.HttpHelper,
	database data.Database,
) http.HandlerFunc {

	type keyInfo struct {
		Id               int64
		CreatedAt        string
		State            string
		KeyIdentifier    string
		Type             string
		Algorithm        string
		PublicKeyASN1DER string
		PublicKeyPEM     string
		PublicKeyJWK     string
	}

	return func(w http.ResponseWriter, r *http.Request) {

		allSigningKeys, err := database.GetAllSigningKeys(nil)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		keys := make([]keyInfo, 0, len(allSigningKeys))
		for _, signingKey := range allSigningKeys {

			keyState, err := enums.KeyStateFromString(signingKey.State)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			ki := keyInfo{
				Id:            signingKey.Id,
				CreatedAt:     signingKey.CreatedAt.Time.Format("02 Jan 2006 15:04:05 MST"),
				State:         keyState.String(),
				KeyIdentifier: signingKey.KeyIdentifier,
				Type:          signingKey.Type,
				Algorithm:     signingKey.Algorithm,
			}

			ki.PublicKeyASN1DER = base64.StdEncoding.EncodeToString(signingKey.PublicKeyASN1_DER)
			ki.PublicKeyPEM = string(signingKey.PublicKeyPEM)
			ki.PublicKeyJWK = string(signingKey.PublicKeyJWK)

			keys = append(keys, ki)
		}

		orderedKeys := make([]keyInfo, 0, len(keys))
		for _, ki := range keys {
			if ki.State == enums.KeyStateNext.String() {
				orderedKeys = append(orderedKeys, ki)
				break
			}
		}
		for _, ki := range keys {
			if ki.State == enums.KeyStateCurrent.String() {
				orderedKeys = append(orderedKeys, ki)
				break
			}
		}
		for _, ki := range keys {
			if ki.State == enums.KeyStatePrevious.String() {
				orderedKeys = append(orderedKeys, ki)
			}
		}

		bind := map[string]interface{}{
			"keys":      orderedKeys,
			"csrfField": csrf.TemplateField(r),
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_settings_keys.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminSettingsKeysRotatePost(
	httpHelper handlers.HttpHelper,
	authHelper handlers.AuthHelper,
	database data.Database,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		allSigningKeys, err := database.GetAllSigningKeys(nil)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		var currentKey *models.KeyPair
		var nextKey *models.KeyPair
		var previousKey *models.KeyPair
		for i, signingKey := range allSigningKeys {
			keyState, err := enums.KeyStateFromString(signingKey.State)
			if err != nil {
				httpHelper.JsonError(w, r, err)
				return
			}
			switch keyState {
			case enums.KeyStateCurrent:
				currentKey = &allSigningKeys[i]
			case enums.KeyStateNext:
				nextKey = &allSigningKeys[i]
			case enums.KeyStatePrevious:
				previousKey = &allSigningKeys[i]
			}
		}

		if previousKey != nil {
			err = database.DeleteKeyPair(nil, previousKey.Id)
			if err != nil {
				httpHelper.JsonError(w, r, err)
				return
			}
		}

		if currentKey == nil {
			httpHelper.JsonError(w, r, errors.WithStack(fmt.Errorf("no current key found")))
			return
		}

		if nextKey == nil {
			httpHelper.JsonError(w, r, errors.WithStack(fmt.Errorf("no next key found")))
			return
		}

		// current key becomes previous
		currentKey.State = enums.KeyStatePrevious.String()
		err = database.UpdateKeyPair(nil, currentKey)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		// next key becomes current
		nextKey.State = enums.KeyStateCurrent.String()
		err = database.UpdateKeyPair(nil, nextKey)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		// create a new next key
		privateKey, err := lib.GeneratePrivateKey(4096)
		if err != nil {
			httpHelper.JsonError(w, r, errors.Wrap(err, "unable to generate a private key"))
			return
		}
		privateKeyPEM := lib.EncodePrivateKeyToPEM(privateKey)

		publickeyasn1Der, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		if err != nil {
			httpHelper.JsonError(w, r, errors.Wrap(err, "unable to marshal public key to PKIX"))
			return
		}

		publicKeyPEM := pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PUBLIC KEY",
				Bytes: publickeyasn1Der,
			},
		)

		kid := uuid.New().String()
		publicKeyJWK, err := lib.MarshalRSAPublicKeyToJWK(&privateKey.PublicKey, kid)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		keyPair := &models.KeyPair{
			State:             enums.KeyStateNext.String(),
			KeyIdentifier:     kid,
			Type:              "RSA",
			Algorithm:         "RS256",
			PrivateKeyPEM:     privateKeyPEM,
			PublicKeyPEM:      publicKeyPEM,
			PublicKeyASN1_DER: publickeyasn1Der,
			PublicKeyJWK:      publicKeyJWK,
		}
		err = database.CreateKeyPair(nil, keyPair)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		lib.LogAudit(constants.AuditRotatedKeys, map[string]interface{}{
			"loggedInUser": authHelper.GetLoggedInSubject(r),
		})

		result := struct {
			Success bool
		}{
			Success: true,
		}
		httpHelper.EncodeJson(w, r, result)
	}
}

func HandleAdminSettingsKeysRevokePost(
	httpHelper handlers.HttpHelper,
	authHelper handlers.AuthHelper,
	database data.Database,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		var data map[string]interface{}
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&data); err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		id, ok := data["id"].(float64)
		if !ok {
			httpHelper.JsonError(w, r, errors.WithStack(fmt.Errorf("unable to cast id to float64")))
			return
		}

		allSigningKeys, err := database.GetAllSigningKeys(nil)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		var previousKey *models.KeyPair
		for i, signingKey := range allSigningKeys {
			keyState, err := enums.KeyStateFromString(signingKey.State)
			if err != nil {
				httpHelper.JsonError(w, r, err)
				return
			}
			if keyState == enums.KeyStatePrevious && signingKey.Id == int64(id) {
				previousKey = &allSigningKeys[i]
			}
		}

		if previousKey == nil {
			httpHelper.JsonError(w, r, errors.WithStack(fmt.Errorf("no previous key found")))
			return
		}

		err = database.DeleteKeyPair(nil, previousKey.Id)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		lib.LogAudit(constants.AuditRevokedKey, map[string]interface{}{
			"loggedInUser": authHelper.GetLoggedInSubject(r),
			"keyId":        previousKey.KeyIdentifier,
		})

		result := struct {
			Success bool
		}{
			Success: true,
		}
		httpHelper.EncodeJson(w, r, result)
	}
}
