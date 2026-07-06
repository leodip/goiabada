package handlers

import (
	"encoding/base64"
	"log/slog"
	"net/http"
	"strings"

	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/models"
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
		clientId, clientSecret, usedBasicAuth, err := extractClientCredentials(r)
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
			Username:      r.PostForm.Get("username"),
			Password:      r.PostForm.Get("password"),
			UsedBasicAuth: usedBasicAuth,
		}

		validateResult, err := tokenValidator.ValidateTokenRequest(r.Context(), &input)
		if err != nil {
			// RFC 6749 §4.1.2: when an authorization code is reused by an
			// authenticated requester, the server MUST deny the request and
			// SHOULD revoke all tokens previously issued from that code.
			// The validator returns AuthCodeReusedError only after the request
			// has authenticated against the used code (client_id, redirect_uri,
			// client_secret/PKCE), so revocation here cannot be triggered by
			// an unauthenticated attacker.
			if reused, ok := err.(*customerrors.AuthCodeReusedError); ok {
				if revokeErr := revokeAndAuditAuthCodeReuse(database, auditLogger, reused.Code); revokeErr != nil {
					httpHelper.InternalServerError(w, r, revokeErr)
					return
				}
				httpHelper.JsonError(w, r, reused.Detail)
				return
			}
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
			// Atomically claim the code (compare-and-set on `used`) BEFORE issuing
			// any tokens. Redemption spans a read in the validator and this mark, so
			// a plain read-then-unconditional-update leaves a window where two
			// concurrent requests both observe used=false and both mint tokens.
			// MarkCodeAsUsed returns true only for the request that flips the flag,
			// which is the single winner allowed to proceed (#77).
			//
			// A failed mint after a successful claim consumes the code (the client
			// must re-authenticate): acceptable, since codes are one-time and 60s
			// lived, and it is the price of never issuing two token sets from one code.
			claimed, err := database.MarkCodeAsUsed(nil, validateResult.CodeEntity.Id)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
			if !claimed {
				// Lost the race: another request concurrently redeemed this same code
				// and won the atomic claim above. Reject this duplicate WITHOUT running
				// the session-wide reuse cascade. The winner is a legitimate in-flight
				// redemption (a concurrent duplicate still had to carry the correct
				// PKCE verifier), and tearing the session down here would fight the
				// winner's in-progress token minting on the same rows.
				//
				// This does not weaken reuse protection: a genuine *later* replay of an
				// already-used code is still detected and fully revoked by the
				// sequential-reuse path in the validator above (#77).
				slog.Debug("authorization_code: lost the concurrent claim race, rejecting duplicate redemption",
					"codeId", validateResult.CodeEntity.Id)
				httpHelper.JsonError(w, r, customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
					"Code is invalid.", http.StatusBadRequest))
				return
			}

			tokenResp, err := tokenIssuer.GenerateTokenResponseForAuthCode(r.Context(), validateResult.CodeEntity)
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
				// For refresh token requests, we're not doing step-up authentication,
				// so we pass empty strings for authMethods and acrLevel to preserve
				// the session's existing values.
				if len(refreshToken.SessionIdentifier) > 0 {
					userSession, err := userSessionManager.BumpUserSession(r, refreshToken.SessionIdentifier,
						refreshToken.Code.ClientId, "", "")
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

// revokeAndAuditAuthCodeReuse runs the RFC 6749 §10.5 response to a reused
// authorization code: it revokes the associated token family/session and, only
// on a successful revoke, emits the reuse audit event (so the audit reflects
// real revoked JTIs). It is shared by the validator-driven sequential-reuse
// path and the concurrent double-spend guard in the authorization_code grant
// (#77). On a nil return the caller is responsible for writing the client-facing
// invalid_grant response; on a non-nil error the caller must surface a 500.
func revokeAndAuditAuthCodeReuse(database data.Database, auditLogger AuditLogger, code *models.Code) error {
	revokedJtis, err := revokeOnAuthCodeReuse(database, code)
	if err != nil {
		return err
	}
	if code != nil {
		auditLogger.Log(constants.AuditAuthCodeReuseDetected, map[string]interface{}{
			"clientId":                code.ClientId,
			"userId":                  code.UserId,
			"codeId":                  code.Id,
			"sessionIdentifier":       code.SessionIdentifier,
			"revokedRefreshTokenJtis": revokedJtis,
		})
	}
	return nil
}

// revokeOnAuthCodeReuse revokes refresh tokens linked to the replayed code's
// session and deletes the user session. All writes happen inside a single
// transaction so any failure rolls the entire revocation back rather than
// leaving partial state. The replay response itself must NOT look successful
// when revocation fails, so callers should surface a 500 to the client.
func revokeOnAuthCodeReuse(database data.Database, code *models.Code) ([]string, error) {
	if code == nil {
		return nil, nil
	}

	tx, err := database.BeginTransaction()
	if err != nil {
		return nil, err
	}
	defer database.RollbackTransaction(tx) //nolint:errcheck

	var refreshTokens []*models.RefreshToken
	if code.SessionIdentifier != "" {
		refreshTokens, err = database.GetRefreshTokensBySessionIdentifier(tx, code.SessionIdentifier)
	} else {
		// Defensive fallback: auth-code-flow codes always carry a session
		// identifier today, but if a future change ever produces a
		// session-less auth code, fall back to revoking only the refresh
		// tokens directly linked to this code so reuse still has teeth.
		slog.Warn("auth code reuse on a code without a session identifier, falling back to code-id-scoped revocation",
			"codeId", code.Id)
		refreshTokens, err = database.GetRefreshTokensByCodeId(tx, code.Id)
	}
	if err != nil {
		return nil, err
	}

	revokedJtis := make([]string, 0, len(refreshTokens))
	for _, rt := range refreshTokens {
		if rt.Revoked {
			continue
		}
		rt.Revoked = true
		if err := database.UpdateRefreshToken(tx, rt); err != nil {
			return nil, err
		}
		revokedJtis = append(revokedJtis, rt.RefreshTokenJti)
	}

	// Tear down the session only when we actually revoked tokens issued from the
	// replayed code. If there were none to revoke, there is nothing to contain, and
	// deleting the session would disrupt an unrelated/in-flight session. This is
	// what makes concurrent redemption safe: a losing racer's cascade finds no
	// committed tokens yet (revokedJtis is empty) and so leaves the winner's live
	// session intact, instead of tearing it down out from under the winner's
	// in-progress mint (which read that session for its refresh-token lifetime). (#77)
	if code.SessionIdentifier != "" && len(revokedJtis) > 0 {
		session, err := database.GetUserSessionBySessionIdentifier(tx, code.SessionIdentifier)
		if err != nil {
			return nil, err
		}
		if session != nil {
			if err := database.DeleteUserSession(tx, session.Id); err != nil {
				return nil, err
			}
		}
	}

	if err := database.CommitTransaction(tx); err != nil {
		return nil, err
	}
	return revokedJtis, nil
}

// extractClientCredentials extracts client_id and client_secret from the request.
// It supports both client_secret_basic (Authorization header) and client_secret_post (form body).
// Per RFC 6749 clients MUST NOT use more than one authentication method per request.
// Returns usedBasicAuth=true if the client used HTTP Basic Authentication.
func extractClientCredentials(r *http.Request) (clientId, clientSecret string, usedBasicAuth bool, err error) {
	// Check for Basic auth in Authorization header
	basicClientId, basicClientSecret, hasBasicAuth := parseBasicAuth(r.Header.Get("Authorization"))

	// Get credentials from POST body
	postClientId := r.PostForm.Get("client_id")
	postClientSecret := r.PostForm.Get("client_secret")
	hasPostAuth := postClientSecret != ""

	// RFC 6749 clients MUST NOT use more than one authentication method
	if hasBasicAuth && hasPostAuth {
		return "", "", false, customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
			"Client authentication failed: multiple authentication methods provided. "+
				"Use either HTTP Basic authentication OR client_secret in the request body, but not both.",
			http.StatusBadRequest)
	}

	// Use Basic auth if present
	if hasBasicAuth {
		return basicClientId, basicClientSecret, true, nil
	}

	// Fall back to POST body credentials
	return postClientId, postClientSecret, false, nil
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
