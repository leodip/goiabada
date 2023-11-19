package server

import (
	"encoding/json"
	"net/http"

	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/enums"
)

func (s *Server) handleCertsGet() http.HandlerFunc {

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

		allSigningKeys, err := s.database.GetAllSigningKeys()
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		result := jwks{}

		var nextKey *entities.KeyPair
		var currentKey *entities.KeyPair
		var previousKey *entities.KeyPair

		for idx, signingKey := range allSigningKeys {

			keyState, err := enums.KeyStateFromString(signingKey.State)
			if err != nil {
				s.internalServerError(w, r, err)
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
				s.internalServerError(w, r, err)
				return
			}
			result.Keys = append(result.Keys, publicKeyJwk)
		}

		if currentKey != nil {
			var publicKeyJwk jwk
			err := json.Unmarshal(currentKey.PublicKeyJWK, &publicKeyJwk)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}
			result.Keys = append(result.Keys, publicKeyJwk)
		}

		if previousKey != nil {
			var publicKeyJwk jwk
			err := json.Unmarshal(previousKey.PublicKeyJWK, &publicKeyJwk)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}
			result.Keys = append(result.Keys, publicKeyJwk)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}
