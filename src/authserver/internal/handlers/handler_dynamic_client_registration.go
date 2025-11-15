package handlers

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/stringutil"
)

// HandleDynamicClientRegistrationPost implements RFC 7591 §3 Client Registration Endpoint
func HandleDynamicClientRegistrationPost(
	httpHelper HttpHelper,
	database data.Database,
	auditLogger AuditLogger,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)

		// 1. Check if DCR is enabled (RFC 7591 §3)
		if !settings.DynamicClientRegistrationEnabled {
			writeDCRError(w, "access_denied", "Dynamic client registration is not enabled", http.StatusForbidden)
			return
		}

		// 2. Parse request (RFC 7591 §3.1)
		var req api.DynamicClientRegistrationRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeDCRError(w, api.DCRErrorInvalidClientMetadata, "Invalid request body", http.StatusBadRequest)
			return
		}

		// 3. Apply defaults (RFC 7591 §2)
		applyDCRDefaults(&req)

		// 4. Validate request
		if err := validateDCRRequest(&req); err != nil {
			writeDCRError(w, api.DCRErrorInvalidClientMetadata, err.Error(), http.StatusBadRequest)
			return
		}

		// 5. Validate redirect URIs (RFC 7591 §5)
		if err := validateDCRRedirectURIs(&req); err != nil {
			writeDCRError(w, api.DCRErrorInvalidRedirectURI, err.Error(), http.StatusBadRequest)
			return
		}

		// 6. Generate client identifier (RFC 7591 §3.2.1)
		clientIdentifier := generateDCRClientIdentifier()

		// 7. Determine if public or confidential client
		isPublic := req.TokenEndpointAuthMethod == "none"

		// 8. Generate client secret for confidential clients (RFC 7591 §3.2.1)
		var clientSecretEncrypted []byte
		var clientSecret string

		if !isPublic {
			clientSecret = stringutil.GenerateSecurityRandomString(60)
			var err error
			clientSecretEncrypted, err = encryption.EncryptText(clientSecret, settings.AESEncryptionKey)
			if err != nil {
				slog.Error("DCR: Failed to encrypt client secret", "error", err)
				writeDCRError(w, "server_error", "Internal server error", http.StatusInternalServerError)
				return
			}
		}

		// 9. Create client model
		client := &models.Client{
			ClientIdentifier:      clientIdentifier,
			ClientSecretEncrypted: clientSecretEncrypted,
			Description:           req.ClientName,
			IsPublic:              isPublic,
			Enabled:               true,
			ConsentRequired:       false,
			AuthorizationCodeEnabled: containsGrantType(req.GrantTypes, "authorization_code"),
			ClientCredentialsEnabled: containsGrantType(req.GrantTypes, "client_credentials"),
			DefaultAcrLevel:          enums.AcrLevel2Optional,
			IncludeOpenIDConnectClaimsInAccessToken: enums.ThreeStateSettingDefault.String(),
			// Token expiration settings use global defaults from settings
			TokenExpirationInSeconds:                settings.TokenExpirationInSeconds,
			RefreshTokenOfflineIdleTimeoutInSeconds: settings.RefreshTokenOfflineIdleTimeoutInSeconds,
			RefreshTokenOfflineMaxLifetimeInSeconds: settings.RefreshTokenOfflineMaxLifetimeInSeconds,
		}

		// 10. Save client to database
		if err := database.CreateClient(nil, client); err != nil {
			slog.Error("DCR: Database error creating client", "error", err)
			writeDCRError(w, "server_error", "Failed to register client", http.StatusInternalServerError)
			return
		}

		// 11. Save redirect URIs
		for _, uri := range req.RedirectURIs {
			redirectURI := &models.RedirectURI{
				ClientId: client.Id,
				URI:      uri,
			}
			if err := database.CreateRedirectURI(nil, redirectURI); err != nil {
				slog.Error("DCR: Failed to create redirect URI", "error", err, "uri", uri)
				// Rollback client creation
				database.DeleteClient(nil, client.Id)
				writeDCRError(w, "server_error", "Failed to register redirect URIs", http.StatusInternalServerError)
				return
			}
		}

		// 12. Audit log
		auditLogger.Log(constants.AuditDynamicClientRegistration, map[string]interface{}{
			"clientId":         client.Id,
			"clientIdentifier": client.ClientIdentifier,
			"grantTypes":       req.GrantTypes,
			"isPublic":         isPublic,
			"sourceIP":         getClientIP(r),
		})

		// 13. Build response (RFC 7591 §3.2.1)
		response := api.DynamicClientRegistrationResponse{
			ClientID:                clientIdentifier,
			ClientIDIssuedAt:        time.Now().Unix(),
			ClientSecretExpiresAt:   0, // Never expires
			RedirectURIs:            req.RedirectURIs,
			TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
			GrantTypes:              req.GrantTypes,
			ClientName:              req.ClientName,
		}

		// Only include secret for confidential clients (RFC 7591 §3.2.1)
		if !isPublic {
			response.ClientSecret = clientSecret
		}

		// 14. Send response
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.WriteHeader(http.StatusCreated)
		httpHelper.EncodeJson(w, r, response)
	}
}

// applyDCRDefaults applies RFC 7591 §2 default values
func applyDCRDefaults(req *api.DynamicClientRegistrationRequest) {
	// Default token_endpoint_auth_method (RFC 7591 §2)
	if req.TokenEndpointAuthMethod == "" {
		req.TokenEndpointAuthMethod = "client_secret_basic"
	}

	// Default grant_types (RFC 7591 §2)
	if len(req.GrantTypes) == 0 {
		req.GrantTypes = []string{"authorization_code"}
	}
}

// validateDCRRequest validates request per RFC 7591 §2
func validateDCRRequest(req *api.DynamicClientRegistrationRequest) error {
	// Validate token_endpoint_auth_method
	allowedAuthMethods := map[string]bool{
		"none":                true,
		"client_secret_basic": true,
		"client_secret_post":  true,
	}
	if !allowedAuthMethods[req.TokenEndpointAuthMethod] {
		return fmt.Errorf("unsupported token_endpoint_auth_method: %s", req.TokenEndpointAuthMethod)
	}

	// Validate grant_types
	supportedGrants := map[string]bool{
		"authorization_code": true,
		"client_credentials": true,
		"refresh_token":      true,
	}
	for _, gt := range req.GrantTypes {
		if !supportedGrants[gt] {
			return fmt.Errorf("unsupported grant_type: %s", gt)
		}
	}

	// Validate client_name length if provided (matches database column size)
	if len(req.ClientName) > 128 {
		return fmt.Errorf("client_name cannot exceed 128 characters")
	}

	return nil
}

// validateDCRRedirectURIs validates redirect URIs per RFC 7591 §5
func validateDCRRedirectURIs(req *api.DynamicClientRegistrationRequest) error {
	// Check if redirect URIs are required
	requiresRedirectURIs := containsGrantType(req.GrantTypes, "authorization_code")

	if requiresRedirectURIs && len(req.RedirectURIs) == 0 {
		return fmt.Errorf("redirect_uris required for authorization_code grant type")
	}

	// Validate each redirect URI
	isPublic := req.TokenEndpointAuthMethod == "none"

	for _, uri := range req.RedirectURIs {
		if err := validateRedirectURI(uri, isPublic); err != nil {
			return err
		}
	}

	return nil
}

// validateRedirectURI validates a single redirect URI per RFC 7591 §5
func validateRedirectURI(uri string, isPublic bool) error {
	parsed, err := url.ParseRequestURI(uri)
	if err != nil {
		return fmt.Errorf("invalid redirect_uri format: %s", uri)
	}

	// For public clients (MCP use case), only allow localhost or custom schemes
	// This prevents phishing attacks via DCR
	if isPublic {
		// Allow localhost HTTP (MCP use case)
		if parsed.Scheme == "http" {
			if strings.HasPrefix(parsed.Host, "localhost") ||
				strings.HasPrefix(parsed.Host, "127.0.0.1") ||
				strings.HasPrefix(parsed.Host, "[::1]") ||
				strings.HasPrefix(parsed.Host, "localhost:") ||
				strings.HasPrefix(parsed.Host, "127.0.0.1:") ||
				strings.HasPrefix(parsed.Host, "[::1]:") {
				return nil
			}
			return fmt.Errorf("public clients can only use localhost for http redirect_uris")
		}

		// Allow custom schemes (native apps)
		if parsed.Scheme != "https" {
			return nil
		}

		// Reject HTTPS for public clients registered via DCR
		return fmt.Errorf("public clients registered via DCR cannot use https redirect_uris (security restriction)")
	}

	// For confidential clients, allow HTTPS or localhost
	if parsed.Scheme == "https" {
		return nil
	}

	if parsed.Scheme == "http" {
		if strings.HasPrefix(parsed.Host, "localhost") ||
			strings.HasPrefix(parsed.Host, "127.0.0.1") ||
			strings.HasPrefix(parsed.Host, "[::1]") ||
			strings.HasPrefix(parsed.Host, "localhost:") ||
			strings.HasPrefix(parsed.Host, "127.0.0.1:") ||
			strings.HasPrefix(parsed.Host, "[::1]:") {
			return nil
		}
		return fmt.Errorf("http redirect_uris must use localhost")
	}

	return fmt.Errorf("redirect_uri must use https, localhost http, or custom scheme")
}

// generateDCRClientIdentifier generates unique client identifier (RFC 7591 §3.2.1)
func generateDCRClientIdentifier() string {
	return "dcr_" + uuid.NewString()
}

// containsGrantType checks if grant type is in the list
func containsGrantType(grantTypes []string, grantType string) bool {
	for _, gt := range grantTypes {
		if gt == grantType {
			return true
		}
	}
	return false
}

// getClientIP extracts client IP from request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (if behind proxy)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fallback to RemoteAddr
	return r.RemoteAddr
}

// writeDCRError writes RFC 7591 §3.2.2 error response
func writeDCRError(w http.ResponseWriter, errorCode, description string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(statusCode)

	errorResp := api.DynamicClientRegistrationError{
		Error:            errorCode,
		ErrorDescription: description,
	}
	json.NewEncoder(w).Encode(errorResp)
}
