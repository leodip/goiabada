package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/leodip/goiabada/internal/data"
	"github.com/leodip/goiabada/internal/enums"
	"github.com/leodip/goiabada/internal/models"
)

func HandleCertsGet(
	httpHelper HttpHelper,
	database data.Database,
) http.HandlerFunc {

	type jwk struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Kty string `json:"kty"`
		Use string `json:"use"`
		N   string `json:"n"`
		E   string `json:"e"`
	}

	type jwks struct {
		Keys []jwk `json:"keys"`
	}

	return func(w http.ResponseWriter, r *http.Request) {

		allSigningKeys, err := database.GetAllSigningKeys(nil)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		result := jwks{}

		var nextKey *models.KeyPair
		var currentKey *models.KeyPair
		var previousKey *models.KeyPair

		for idx, signingKey := range allSigningKeys {

			keyState, err := enums.KeyStateFromString(signingKey.State)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			switch keyState {
			case enums.KeyStateNext:
				nextKey = &allSigningKeys[idx]
			case enums.KeyStateCurrent:
				currentKey = &allSigningKeys[idx]
			case enums.KeyStatePrevious:
				previousKey = &allSigningKeys[idx]
			}
		}

		if nextKey != nil {
			var publicKeyJwk jwk
			err := json.Unmarshal(nextKey.PublicKeyJWK, &publicKeyJwk)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
			result.Keys = append(result.Keys, publicKeyJwk)
		}

		if currentKey != nil {
			var publicKeyJwk jwk
			err := json.Unmarshal(currentKey.PublicKeyJWK, &publicKeyJwk)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
			result.Keys = append(result.Keys, publicKeyJwk)
		}

		if previousKey != nil {
			var publicKeyJwk jwk
			err := json.Unmarshal(previousKey.PublicKeyJWK, &publicKeyJwk)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
			result.Keys = append(result.Keys, publicKeyJwk)
		}

		httpHelper.EncodeJson(w, r, result)
	}
}
