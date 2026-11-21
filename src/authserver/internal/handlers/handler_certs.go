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

		// RFC 7517 section 5: the set MUST have a keys member whose value is an array, so a set with
		// no keys is [] and never null (#714).
		result := oauth.JWKS{Keys: []oauth.JWK{}}

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
			var publicKeyJWK oauth.JWK
			err := json.Unmarshal(nextKey.PublicKeyJWK, &publicKeyJWK)
			if err != nil {
				jsonWriter.JSONError(w, r, err)
				return
			}
			result.Keys = append(result.Keys, publicKeyJWK)
		}

		if currentKey != nil {
			var publicKeyJWK oauth.JWK
			err := json.Unmarshal(currentKey.PublicKeyJWK, &publicKeyJWK)
			if err != nil {
				jsonWriter.JSONError(w, r, err)
				return
			}
			result.Keys = append(result.Keys, publicKeyJWK)
		}

		if previousKey != nil {
			var publicKeyJWK oauth.JWK
			err := json.Unmarshal(previousKey.PublicKeyJWK, &publicKeyJWK)
			if err != nil {
				jsonWriter.JSONError(w, r, err)
				return
			}
			result.Keys = append(result.Keys, publicKeyJWK)
		}

		setMetadataCacheLifetime(w)
		jsonWriter.EncodeJSON(w, r, result)
	}
}
