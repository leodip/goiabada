package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/oauth"
)

func HandleCertsGet(
	httpHelper HttpHelper,
	database data.Database,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		allSigningKeys, err := database.GetAllSigningKeys(nil)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		result := oauth.Jwks{}

		var nextKey *models.KeyPair
		var currentKey *models.KeyPair
		var previousKey *models.KeyPair

		for idx, signingKey := range allSigningKeys {

			keyState, err := models.KeyStateFromString(signingKey.State)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			switch keyState {
			case models.KeyStateNext:
				nextKey = &allSigningKeys[idx]
			case models.KeyStateCurrent:
				currentKey = &allSigningKeys[idx]
			case models.KeyStatePrevious:
				previousKey = &allSigningKeys[idx]
			}
		}

		if nextKey != nil {
			var publicKeyJwk oauth.Jwk
			err := json.Unmarshal(nextKey.PublicKeyJWK, &publicKeyJwk)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
			result.Keys = append(result.Keys, publicKeyJwk)
		}

		if currentKey != nil {
			var publicKeyJwk oauth.Jwk
			err := json.Unmarshal(currentKey.PublicKeyJWK, &publicKeyJwk)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
			result.Keys = append(result.Keys, publicKeyJwk)
		}

		if previousKey != nil {
			var publicKeyJwk oauth.Jwk
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
