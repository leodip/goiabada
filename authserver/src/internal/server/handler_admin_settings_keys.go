package server

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/enums"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/pkg/errors"
)

func (s *Server) handleAdminSettingsKeysGet() http.HandlerFunc {

	type keyInfo struct {
		Id               uint
		CreatedAt        time.Time
		State            string
		KeyIdentifier    string
		Type             string
		Algorithm        string
		PublicKeyASN1DER string
		PublicKeyPEM     string
		PublicKeyJWK     string
	}

	return func(w http.ResponseWriter, r *http.Request) {

		allSigningKeys, err := s.database.GetAllSigningKeys()
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		keys := make([]keyInfo, 0, len(allSigningKeys))
		for _, signingKey := range allSigningKeys {

			keyState, err := enums.KeyStateFromString(signingKey.State)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}

			ki := keyInfo{
				Id:            signingKey.Id,
				CreatedAt:     signingKey.CreatedAt,
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

		sess, err := s.sessionStore.Get(r, common.SessionName)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		savedSuccessfully := sess.Flashes("savedSuccessfully")
		err = sess.Save(r, w)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		bind := map[string]interface{}{
			"keys":              orderedKeys,
			"savedSuccessfully": len(savedSuccessfully) > 0,
			"csrfField":         csrf.TemplateField(r),
		}

		err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_settings_keys.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAdminSettingsKeysRotatePost() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		allSigningKeys, err := s.database.GetAllSigningKeys()
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		var currentKey *entities.KeyPair
		var nextKey *entities.KeyPair
		var previousKey *entities.KeyPair
		for i, signingKey := range allSigningKeys {
			keyState, err := enums.KeyStateFromString(signingKey.State)
			if err != nil {
				s.jsonError(w, r, err)
				return
			}
			if keyState == enums.KeyStateCurrent {
				currentKey = &allSigningKeys[i]
			} else if keyState == enums.KeyStateNext {
				nextKey = &allSigningKeys[i]
			} else if keyState == enums.KeyStatePrevious {
				previousKey = &allSigningKeys[i]
			}
		}

		if previousKey != nil {
			err = s.database.DeleteKeyPair(previousKey.Id)
			if err != nil {
				s.jsonError(w, r, err)
				return
			}
		}

		if currentKey == nil {
			s.jsonError(w, r, fmt.Errorf("no current key found"))
			return
		}

		if nextKey == nil {
			s.jsonError(w, r, fmt.Errorf("no next key found"))
			return
		}

		// current key becomes previous
		currentKey.State = enums.KeyStatePrevious.String()
		_, err = s.database.UpdateKeyPair(currentKey)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		// next key becomes current
		nextKey.State = enums.KeyStateCurrent.String()
		_, err = s.database.UpdateKeyPair(nextKey)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		// create a new next key
		privateKey, err := lib.GeneratePrivateKey(4096)
		if err != nil {
			s.jsonError(w, r, errors.Wrap(err, "unable to generate a private key"))
			return
		}
		privateKeyPEM := lib.EncodePrivateKeyToPEM(privateKey)

		publicKeyASN1_DER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		if err != nil {
			s.jsonError(w, r, errors.Wrap(err, "unable to marshal public key to PKIX"))
			return
		}

		publicKeyPEM := pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PUBLIC KEY",
				Bytes: publicKeyASN1_DER,
			},
		)

		kid := uuid.New().String()
		publicKeyJWK, err := lib.MarshalRSAPublicKeyToJWK(&privateKey.PublicKey, kid)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		keyPair := &entities.KeyPair{
			State:             enums.KeyStateNext.String(),
			KeyIdentifier:     kid,
			Type:              "RSA",
			Algorithm:         "RS256",
			PrivateKeyPEM:     privateKeyPEM,
			PublicKeyPEM:      publicKeyPEM,
			PublicKeyASN1_DER: publicKeyASN1_DER,
			PublicKeyJWK:      publicKeyJWK,
		}
		_, err = s.database.CreateKeyPair(keyPair)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		result := struct {
			Success bool
		}{
			Success: true,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}

func (s *Server) handleAdminSettingsKeysRevokePost() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		var data map[string]interface{}
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&data); err != nil {
			s.jsonError(w, r, err)
			return
		}

		id, ok := data["id"].(float64)
		if !ok {
			s.jsonError(w, r, fmt.Errorf("unable to cast id to float64"))
			return
		}

		allSigningKeys, err := s.database.GetAllSigningKeys()
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		var previousKey *entities.KeyPair
		for i, signingKey := range allSigningKeys {
			keyState, err := enums.KeyStateFromString(signingKey.State)
			if err != nil {
				s.jsonError(w, r, err)
				return
			}
			if keyState == enums.KeyStatePrevious && signingKey.Id == uint(id) {
				previousKey = &allSigningKeys[i]
			}
		}

		if previousKey == nil {
			s.jsonError(w, r, fmt.Errorf("no previous key found"))
			return
		}

		err = s.database.DeleteKeyPair(previousKey.Id)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		result := struct {
			Success bool
		}{
			Success: true,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}
