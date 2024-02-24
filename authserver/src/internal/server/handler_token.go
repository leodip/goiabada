package server

import (
	"encoding/json"
	"net/http"

	"github.com/leodip/goiabada/internal/constants"
	core_token "github.com/leodip/goiabada/internal/core/token"
	core_validators "github.com/leodip/goiabada/internal/core/validators"
	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleTokenPost(tokenIssuer tokenIssuer, tokenValidator tokenValidator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		r.ParseForm()
		input := core_validators.ValidateTokenRequestInput{
			GrantType:    r.PostForm.Get("grant_type"),
			Code:         r.PostForm.Get("code"),
			RedirectURI:  r.PostForm.Get("redirect_uri"),
			CodeVerifier: r.PostForm.Get("code_verifier"),
			ClientId:     r.PostForm.Get("client_id"),
			ClientSecret: r.PostForm.Get("client_secret"),
			Scope:        r.PostForm.Get("scope"),
			RefreshToken: r.PostForm.Get("refresh_token"),
		}

		validateTokenRequestResult, err := tokenValidator.ValidateTokenRequest(r.Context(), &input)
		if err != nil {
			s.jsonError(w, r, err)
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
			err = s.database.UpdateCode(nil, validateTokenRequestResult.CodeEntity)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}

			lib.LogAudit(constants.AuditTokenIssuedAuthorizationCodeResponse, map[string]interface{}{
				"codeId": validateTokenRequestResult.CodeEntity.Id,
			})

			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Pragma", "no-cache")
			json.NewEncoder(w).Encode(tokenResp)
			return

		} else if input.GrantType == "client_credentials" {

			tokenResp, err := tokenIssuer.GenerateTokenResponseForClientCred(r.Context(),
				validateTokenRequestResult.Client, validateTokenRequestResult.Scope)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}

			lib.LogAudit(constants.AuditTokenIssuedClientCredentialsResponse, map[string]interface{}{
				"clientId": validateTokenRequestResult.Client.Id,
			})

			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Pragma", "no-cache")
			json.NewEncoder(w).Encode(tokenResp)
			return

		} else if input.GrantType == "refresh_token" {
			refreshToken := validateTokenRequestResult.RefreshToken
			if refreshToken.Revoked {
				s.jsonError(w, r, customerrors.NewValidationError("invalid_grant", "This refresh token has been revoked."))
				return
			} else {
				refreshToken.Revoked = true
				err = s.database.UpdateRefreshToken(nil, refreshToken)
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

			// bump user session
			if len(refreshToken.SessionIdentifier) > 0 {
				_, err := s.bumpUserSession(w, r, refreshToken.SessionIdentifier, refreshToken.Code.ClientId)
				if err != nil {
					s.internalServerError(w, r, err)
					return
				}
			}

			lib.LogAudit(constants.AuditTokenIssuedRefreshTokenResponse, map[string]interface{}{
				"codeId":          validateTokenRequestResult.CodeEntity.Id,
				"refreshTokenJti": validateTokenRequestResult.RefreshToken.RefreshTokenJti,
			})

			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Pragma", "no-cache")
			json.NewEncoder(w).Encode(tokenResp)
			return
		} else {
			s.jsonError(w, r, customerrors.NewValidationError("unsupported_grant_type", "Unsupported grant_type."))
			return
		}
	}
}
