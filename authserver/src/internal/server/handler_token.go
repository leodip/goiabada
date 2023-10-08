package server

import (
	"encoding/json"
	"net/http"

	core_token "github.com/leodip/goiabada/internal/core/token"
	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleTokenPost(tokenIssuer tokenIssuer, tokenValidator tokenValidator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		input := core_token.ValidateTokenRequestInput{
			GrantType:    r.FormValue("grant_type"),
			Code:         r.FormValue("code"),
			RedirectUri:  r.FormValue("redirect_uri"),
			CodeVerifier: r.FormValue("code_verifier"),
			ClientId:     r.FormValue("client_id"),
			ClientSecret: r.FormValue("client_secret"),
		}

		tokenRequestResult, err := tokenValidator.ValidateTokenRequest(r.Context(), &input)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		keyPair, err := s.database.GetSigningKey()
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
			_, err = s.database.UpdateCode(tokenRequestResult.CodeEntity)
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

		} else {
			s.jsonError(w, r, customerrors.NewValidationError("unsupported_grant_type", "Unsupported grant_type."))
			return
		}
	}
}
