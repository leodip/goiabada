package server

import (
	"encoding/json"
	"net/http"

	core_validators "github.com/leodip/goiabada/internal/core/validators"
	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleTokenPost(tokenIssuer tokenIssuer, tokenValidator tokenValidator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		input := core_validators.ValidateTokenRequestInput{
			GrantType:    r.FormValue("grant_type"),
			Code:         r.FormValue("code"),
			RedirectURI:  r.FormValue("redirect_uri"),
			CodeVerifier: r.FormValue("code_verifier"),
			ClientId:     r.FormValue("client_id"),
			ClientSecret: r.FormValue("client_secret"),
			Scope:        r.FormValue("scope"),
			RefreshToken: r.FormValue("refresh_token"),
		}

		tokenRequestResult, err := tokenValidator.ValidateTokenRequest(r.Context(), &input)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		keyPair, err := s.database.GetCurrentSigningKey()
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		if input.GrantType == "authorization_code" {

			tokenResp, err := tokenIssuer.GenerateTokenForAuthCode(r.Context(),
				tokenRequestResult.CodeEntity, keyPair, lib.GetBaseUrl())
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}
			tokenRequestResult.CodeEntity.Used = true
			_, err = s.database.SaveCode(tokenRequestResult.CodeEntity)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(tokenResp)

		} else if input.GrantType == "client_credentials" {

			tokenResp, err := tokenIssuer.GenerateTokenForClientCred(r.Context(), tokenRequestResult.Client, tokenRequestResult.Scope, keyPair)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(tokenResp)

		} else if input.GrantType == "refresh_token" {
			refreshToken := tokenRequestResult.RefreshToken
			if refreshToken.Used {
				s.jsonError(w, r, customerrors.NewValidationError("invalid_grant", "Refresh token has already been used."))
				return
			} else {
				refreshToken.Used = true
				_, err = s.database.SaveRefreshToken(refreshToken)
				if err != nil {
					s.internalServerError(w, r, err)
					return
				}
			}

			tokenResp, err := tokenIssuer.GenerateTokenForRefresh(r.Context(),
				tokenRequestResult.CodeEntity, input.Scope, keyPair, lib.GetBaseUrl())
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(tokenResp)
		} else {
			s.jsonError(w, r, customerrors.NewValidationError("unsupported_grant_type", "Unsupported grant_type."))
			return
		}
	}
}
