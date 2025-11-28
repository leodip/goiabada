package handlers

import (
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/validators"
)

func HandleTokenPost(
	httpHelper HttpHelper,
	userSessionManager UserSessionManager,
	database data.Database,
	tokenIssuer TokenIssuer,
	tokenValidator TokenValidator,
	auditLogger AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		// Extract client credentials - supports both client_secret_basic and client_secret_post
		clientId, clientSecret, err := extractClientCredentials(r)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		input := validators.ValidateTokenRequestInput{
			GrantType:    r.PostForm.Get("grant_type"),
			Code:         r.PostForm.Get("code"),
			RedirectURI:  r.PostForm.Get("redirect_uri"),
			CodeVerifier: r.PostForm.Get("code_verifier"),
			ClientId:     clientId,
			ClientSecret: clientSecret,
			Scope:        r.PostForm.Get("scope"),
			RefreshToken: r.PostForm.Get("refresh_token"),
			// ROPC parameters (RFC 6749 Section 4.3)
			Username: r.PostForm.Get("username"),
			Password: r.PostForm.Get("password"),
		}

		validateResult, err := tokenValidator.ValidateTokenRequest(r.Context(), &input)
		if err != nil {
			// Check if user is disabled and log audit event
			if errDetail, ok := err.(*customerrors.ErrorDetail); ok && errDetail.IsError(customerrors.ErrUserDisabled) {
				auditLogger.Log(constants.AuditUserDisabled, map[string]interface{}{
					"clientId": input.ClientId,
				})
			}
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

			auditLogger.Log(constants.AuditTokenIssuedAuthorizationCodeResponse, map[string]interface{}{
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

			auditLogger.Log(constants.AuditTokenIssuedClientCredentialsResponse, map[string]interface{}{
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

			var tokenResp *oauth.TokenResponse

			// Check if this is an ROPC refresh token (no CodeEntity) or auth code flow token
			if validateResult.CodeEntity == nil {
				// ROPC refresh token - use dedicated ROPC refresh flow
				ropcInput := &oauth.GenerateTokenForRefreshROPCInput{
					RefreshToken:     validateResult.RefreshToken,
					ScopeRequested:   input.Scope,
					RefreshTokenInfo: validateResult.RefreshTokenInfo,
				}

				tokenResp, err = tokenIssuer.GenerateTokenResponseForRefreshROPC(r.Context(), ropcInput)
				if err != nil {
					httpHelper.InternalServerError(w, r, err)
					return
				}

				auditLogger.Log(constants.AuditTokenIssuedRefreshTokenResponse, map[string]interface{}{
					"userId":          validateResult.RefreshToken.UserId.Int64,
					"clientId":        validateResult.RefreshToken.ClientId.Int64,
					"refreshTokenJti": validateResult.RefreshToken.RefreshTokenJti,
					"flow":            "ropc",
				})
			} else {
				// Auth code flow refresh token
				refreshInput := &oauth.GenerateTokenForRefreshInput{
					Code:             validateResult.CodeEntity,
					ScopeRequested:   input.Scope,
					RefreshToken:     validateResult.RefreshToken,
					RefreshTokenInfo: validateResult.RefreshTokenInfo,
				}

				tokenResp, err = tokenIssuer.GenerateTokenResponseForRefresh(r.Context(), refreshInput)
				if err != nil {
					httpHelper.InternalServerError(w, r, err)
					return
				}

				// bump user session (only for auth code flow - ROPC doesn't use sessions)
				if len(refreshToken.SessionIdentifier) > 0 {
					userSession, err := userSessionManager.BumpUserSession(r, refreshToken.SessionIdentifier, refreshToken.Code.ClientId)
					if err != nil {
						httpHelper.InternalServerError(w, r, err)
						return
					}

					auditLogger.Log(constants.AuditBumpedUserSession, map[string]interface{}{
						"userId":   userSession.UserId,
						"clientId": refreshToken.Code.ClientId,
					})
				}

				auditLogger.Log(constants.AuditTokenIssuedRefreshTokenResponse, map[string]interface{}{
					"codeId":          validateResult.CodeEntity.Id,
					"refreshTokenJti": validateResult.RefreshToken.RefreshTokenJti,
					"flow":            "auth_code",
				})
			}

			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Pragma", "no-cache")
			httpHelper.EncodeJson(w, r, tokenResp)
			return

		case "password":
			// RFC 6749 Section 4.3 - Resource Owner Password Credentials Grant
			// SECURITY NOTE: ROPC is deprecated in OAuth 2.1 due to credential exposure risks.

			// Get session identifier for normal refresh tokens (if available)
			sessionIdentifier := ""
			if r.Context().Value(constants.ContextKeySessionIdentifier) != nil {
				sessionIdentifier = r.Context().Value(constants.ContextKeySessionIdentifier).(string)
			}

			ropcInput := &oauth.ROPCGrantInput{
				Client:            validateResult.Client,
				User:              validateResult.User,
				Scope:             validateResult.Scope,
				SessionIdentifier: sessionIdentifier,
			}

			tokenResp, err := tokenIssuer.GenerateTokenResponseForROPC(r.Context(), ropcInput)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			auditLogger.Log(constants.AuditTokenIssuedROPCResponse, map[string]interface{}{
				"userId":   validateResult.User.Id,
				"clientId": validateResult.Client.Id,
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

// extractClientCredentials extracts client_id and client_secret from the request.
// It supports both client_secret_basic (Authorization header) and client_secret_post (form body).
// Per RFC 6749 clients MUST NOT use more than one authentication method per request.
func extractClientCredentials(r *http.Request) (clientId, clientSecret string, err error) {
	// Check for Basic auth in Authorization header
	basicClientId, basicClientSecret, hasBasicAuth := parseBasicAuth(r.Header.Get("Authorization"))

	// Get credentials from POST body
	postClientId := r.PostForm.Get("client_id")
	postClientSecret := r.PostForm.Get("client_secret")
	hasPostAuth := postClientSecret != ""

	// RFC 6749 clients MUST NOT use more than one authentication method
	if hasBasicAuth && hasPostAuth {
		return "", "", customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
			"Client authentication failed: multiple authentication methods provided. "+
				"Use either HTTP Basic authentication OR client_secret in the request body, but not both.",
			http.StatusBadRequest)
	}

	// Use Basic auth if present
	if hasBasicAuth {
		return basicClientId, basicClientSecret, nil
	}

	// Fall back to POST body credentials
	return postClientId, postClientSecret, nil
}

// parseBasicAuth parses an HTTP Basic Authentication header value.
// It returns the client_id, client_secret, and whether Basic auth was present.
func parseBasicAuth(authHeader string) (clientId, clientSecret string, ok bool) {
	if authHeader == "" {
		return "", "", false
	}

	// Must start with "Basic "
	const prefix = "Basic "
	if !strings.HasPrefix(authHeader, prefix) {
		return "", "", false
	}

	// Decode base64
	encoded := authHeader[len(prefix):]
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", "", false
	}

	// Split on first colon (password may contain colons)
	credentials := string(decoded)
	colonIdx := strings.Index(credentials, ":")
	if colonIdx < 0 {
		return "", "", false
	}

	return credentials[:colonIdx], credentials[colonIdx+1:], true
}
