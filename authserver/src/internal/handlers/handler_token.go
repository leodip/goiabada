package handlers

import (
	"net/http"

	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/data"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/leodip/goiabada/internal/security"
	"github.com/leodip/goiabada/internal/validators"
)

func HandleTokenPost(
	httpHelper HttpHelper,
	userSessionManager UserSessionManager,
	database data.Database,
	tokenIssuer TokenIssuer,
	tokenValidator TokenValidator,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}
		input := validators.ValidateTokenRequestInput{
			GrantType:    r.PostForm.Get("grant_type"),
			Code:         r.PostForm.Get("code"),
			RedirectURI:  r.PostForm.Get("redirect_uri"),
			CodeVerifier: r.PostForm.Get("code_verifier"),
			ClientId:     r.PostForm.Get("client_id"),
			ClientSecret: r.PostForm.Get("client_secret"),
			Scope:        r.PostForm.Get("scope"),
			RefreshToken: r.PostForm.Get("refresh_token"),
		}

		validateResult, err := tokenValidator.ValidateTokenRequest(r.Context(), &input)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		switch input.GrantType {
		case "authorization_code":
			tokenResp, err := tokenIssuer.GenerateTokenResponseForAuthCode(r.Context(), validateResult.CodeEntity)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
			validateResult.CodeEntity.Used = true
			err = database.UpdateCode(nil, validateResult.CodeEntity)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			lib.LogAudit(constants.AuditTokenIssuedAuthorizationCodeResponse, map[string]interface{}{
				"codeId": validateResult.CodeEntity.Id,
			})

			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Pragma", "no-cache")
			httpHelper.EncodeJson(w, r, tokenResp)
			return

		case "client_credentials":
			tokenResp, err := tokenIssuer.GenerateTokenResponseForClientCred(r.Context(), validateResult.Client, validateResult.Scope)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			lib.LogAudit(constants.AuditTokenIssuedClientCredentialsResponse, map[string]interface{}{
				"clientId": validateResult.Client.Id,
			})

			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Pragma", "no-cache")
			httpHelper.EncodeJson(w, r, tokenResp)
			return

		case "refresh_token":
			refreshToken := validateResult.RefreshToken
			if refreshToken.Revoked {
				httpHelper.JsonError(w, r, customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
					"This refresh token has been revoked.", http.StatusBadRequest))
				return
			}
			refreshToken.Revoked = true
			err = database.UpdateRefreshToken(nil, refreshToken)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			input := &security.GenerateTokenForRefreshInput{
				Code:             validateResult.CodeEntity,
				ScopeRequested:   input.Scope,
				RefreshToken:     validateResult.RefreshToken,
				RefreshTokenInfo: validateResult.RefreshTokenInfo,
			}

			tokenResp, err := tokenIssuer.GenerateTokenResponseForRefresh(r.Context(), input)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			// bump user session
			if len(refreshToken.SessionIdentifier) > 0 {
				_, err := userSessionManager.BumpUserSession(r, refreshToken.SessionIdentifier, refreshToken.Code.ClientId)
				if err != nil {
					httpHelper.InternalServerError(w, r, err)
					return
				}
			}

			lib.LogAudit(constants.AuditTokenIssuedRefreshTokenResponse, map[string]interface{}{
				"codeId":          validateResult.CodeEntity.Id,
				"refreshTokenJti": validateResult.RefreshToken.RefreshTokenJti,
			})

			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Pragma", "no-cache")
			httpHelper.EncodeJson(w, r, tokenResp)
			return

		default:
			httpHelper.JsonError(w, r, customerrors.NewErrorDetailWithHttpStatusCode("unsupported_grant_type",
				"Unsupported grant_type.", http.StatusBadRequest))
			return
		}
	}
}
