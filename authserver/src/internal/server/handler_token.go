package server

import (
	"encoding/json"
	"net/http"

	core_token "github.com/leodip/goiabada/internal/core/token"
	core_validators "github.com/leodip/goiabada/internal/core/validators"
	"github.com/leodip/goiabada/internal/customerrors"
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

		validateTokenRequestResult, err := tokenValidator.ValidateTokenRequest(r.Context(), &input)
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

			tokenResp, err := tokenIssuer.GenerateTokenResponseForAuthCode(r.Context(),
				&core_token.GenerateTokenResponseForAuthCodeInput{
					Code: validateTokenRequestResult.CodeEntity,
				})
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}
			validateTokenRequestResult.CodeEntity.Used = true
			_, err = s.database.SaveCode(validateTokenRequestResult.CodeEntity)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Pragma", "no-cache")
			json.NewEncoder(w).Encode(tokenResp)

		} else if input.GrantType == "client_credentials" {

			tokenResp, err := tokenIssuer.GenerateTokenResponseForClientCred(r.Context(), validateTokenRequestResult.Client, validateTokenRequestResult.Scope, keyPair)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Pragma", "no-cache")
			json.NewEncoder(w).Encode(tokenResp)

		} else if input.GrantType == "refresh_token" {
			refreshToken := validateTokenRequestResult.RefreshToken
			if refreshToken.Revoked {
				s.jsonError(w, r, customerrors.NewValidationError("invalid_grant", "This refresh token has been revoked."))
				return
			} else {
				refreshToken.Revoked = true
				_, err = s.database.SaveRefreshToken(refreshToken)
				if err != nil {
					s.internalServerError(w, r, err)
					return
				}
			}

			input := &core_token.GenerateTokenForRefreshInput{
				Code:             validateTokenRequestResult.CodeEntity,
				ScopeRequested:   input.Scope,
				RefreshToken:     validateTokenRequestResult.RefreshToken,
				RefreshTokenInfo: validateTokenRequestResult.RefreshTokenInfo,
			}

			tokenResp, err := tokenIssuer.GenerateTokenResponseForRefresh(r.Context(), input)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Pragma", "no-cache")
			json.NewEncoder(w).Encode(tokenResp)
		} else {
			s.jsonError(w, r, customerrors.NewValidationError("unsupported_grant_type", "Unsupported grant_type."))
			return
		}
	}
}
