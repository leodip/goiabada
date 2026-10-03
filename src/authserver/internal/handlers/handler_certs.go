package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/oauth"
)

// certsDatabase is what the JWKS endpoint needs: the signing keys it publishes.
type certsDatabase interface {
	GetAllSigningKeys(ctx context.Context, tx *sql.Tx) ([]record.KeyPair, error)
}

func HandleCertsGet(
	jsonWriter JSONWriter,
	database certsDatabase,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		allSigningKeys, err := database.GetAllSigningKeys(r.Context(), nil)
		if err != nil {
			jsonWriter.JSONError(w, r, err)
			return
		}

		result := oauth.Jwks{}

		var nextKey *record.KeyPair
		var currentKey *record.KeyPair
		var previousKey *record.KeyPair

		for idx, signingKey := range allSigningKeys {

			keyState, err := record.KeyStateFromString(signingKey.State)
			if err != nil {
				jsonWriter.JSONError(w, r, err)
				return
			}

			switch keyState {
			case record.KeyStateNext:
				nextKey = &allSigningKeys[idx]
			case record.KeyStateCurrent:
				currentKey = &allSigningKeys[idx]
			case record.KeyStatePrevious:
				previousKey = &allSigningKeys[idx]
			}
		}

		if nextKey != nil {
			var publicKeyJwk oauth.Jwk
			err := json.Unmarshal(nextKey.PublicKeyJWK, &publicKeyJwk)
			if err != nil {
				jsonWriter.JSONError(w, r, err)
				return
			}
			result.Keys = append(result.Keys, publicKeyJwk)
		}

		if currentKey != nil {
			var publicKeyJwk oauth.Jwk
			err := json.Unmarshal(currentKey.PublicKeyJWK, &publicKeyJwk)
			if err != nil {
				jsonWriter.JSONError(w, r, err)
				return
			}
			result.Keys = append(result.Keys, publicKeyJwk)
		}

		if previousKey != nil {
			var publicKeyJwk oauth.Jwk
			err := json.Unmarshal(previousKey.PublicKeyJWK, &publicKeyJwk)
			if err != nil {
				jsonWriter.JSONError(w, r, err)
				return
			}
			result.Keys = append(result.Keys, publicKeyJwk)
		}

		jsonWriter.EncodeJSON(w, r, result)
	}
}
