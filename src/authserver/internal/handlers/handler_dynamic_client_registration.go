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
	"github.com/leodip/goiabada/core/urlutil"
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
			clientSecretEncrypted, err = encryption.EncryptData(clientSecret)
			if err != nil {
				slog.Error("DCR: Failed to encrypt client secret", "error", err)
				writeDCRError(w, "server_error", "Internal server error", http.StatusInternalServerError)
				return
			}
		}

		// 9. Create client model
		client := &models.Client{
			ClientIdentifier:                        clientIdentifier,
			ClientSecretEncrypted:                   clientSecretEncrypted,
			Description:                             req.ClientName,
			IsPublic:                                isPublic,
			Enabled:                                 true,
			ConsentRequired:                         false,
			AuthorizationCodeEnabled:                containsGrantType(req.GrantTypes, "authorization_code"),
			ClientCredentialsEnabled:                containsGrantType(req.GrantTypes, "client_credentials"),
			DefaultAcrLevel:                         enums.AcrLevel2Optional,
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
				_ = database.DeleteClient(nil, client.Id)
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

// excludedURIChars are the characters RFC 3986 excludes from URIs. They must be
// percent-encoded to appear at all, so a redirect URI carrying one literally is malformed.
const excludedURIChars = "<>\"{}|\\^` "

// deniedRedirectURISchemes are schemes a redirect URI may not use. Three groups, and the
// reason differs per group, which is why they are commented separately rather than merged
// into one anonymous list.
var deniedRedirectURISchemes = map[string]bool{
	// Script or local execution.
	"javascript": true, "data": true, "vbscript": true,
	"file": true, "blob": true, "about": true,
	// Browser-internal schemes. Not app callbacks, and view-source is a navigation
	// primitive.
	"chrome": true, "chrome-extension": true, "moz-extension": true,
	"view-source": true, "filesystem": true, "resource": true,
	// Network protocols a browser cannot deliver an authorization response to. ftp is the
	// one that matters: without it, a public client could register a remote callback, which
	// is exactly what the loopback restriction above exists to prevent.
	"ftp": true, "ftps": true, "ws": true, "wss": true,
	"gopher": true, "telnet": true,
}

// validateRedirectURI validates a single redirect URI per RFC 7591 §5
func validateRedirectURI(uri string, isPublic bool) error {
	parsed, err := url.ParseRequestURI(uri)
	if err != nil {
		return fmt.Errorf("invalid redirect_uri format: %s", uri)
	}

	// RFC 6749 section 3.1.2 requires an absolute-URI (RFC 3986 section 4.3) and forbids a
	// fragment. Both are checked by the shared predicate. Without this, "//evil.example/cb"
	// registers cleanly and is later emitted as a protocol-relative Location, handing the
	// authorization code to that host.
	//
	// This is the registration half only. Stored rows and rows added through the admin API
	// are not re-validated, so the gate that closes every entry point belongs in
	// ValidateClientAndRedirectURI. See issue #122.
	if !urlutil.IsAbsoluteRedirectURI(uri) {
		return fmt.Errorf("redirect_uri must be an absolute URI with a scheme and no fragment: %s", uri)
	}

	// Characters RFC 3986 excludes from URIs entirely. A redirect URI carrying them is
	// malformed, and it is also how markup reaches the admin console, which renders stored
	// redirect URIs into the page.
	//
	// Checked ahead of the client-type branches on purpose: an https URI on a confidential
	// client reaches the same place, so gating this inside the custom-scheme branch would
	// miss it.
	if strings.ContainsAny(uri, excludedURIChars) {
		return fmt.Errorf("redirect_uri contains characters that are not permitted in a URI: %s", uri)
	}

	// Schemes that cannot receive an authorization response, or that execute script.
	//
	// This denylist cannot be the primary defence and is not one: the verified markup
	// payload used the scheme "x", which no list of names would catch. The character gate
	// above is what stops that class. This gate stops the schemes that carry no excluded
	// characters at all, such as javascript: and ftp:.
	if deniedRedirectURISchemes[strings.ToLower(parsed.Scheme)] {
		return fmt.Errorf("redirect_uri scheme %q is not permitted: %s", parsed.Scheme, uri)
	}

	// For public clients (MCP use case), only allow loopback http or custom schemes.
	//
	// The host comparison is exact, via the shared predicate in core/urlutil. It used to be
	// a strings.HasPrefix test, which accepted any host merely starting with a loopback
	// name, localhost.attacker.com included. See issue #105.
	if isPublic {
		// Allow loopback HTTP (MCP use case)
		if parsed.Scheme == "http" {
			if urlutil.IsLoopbackHost(parsed.Host) {
				return nil
			}
			return fmt.Errorf("public clients can only use http redirect_uris on the loopback hosts 127.0.0.1, [::1] or localhost: %s", uri)
		}

		// Allow custom schemes (native apps)
		if parsed.Scheme != "https" {
			return nil
		}

		// Reject HTTPS for public clients registered via DCR
		return fmt.Errorf("public clients registered via DCR cannot use https redirect_uris (security restriction): %s", uri)
	}

	// For confidential clients, allow HTTPS or loopback http. Same exact-host comparison as
	// the public branch above: the prefix bug was duplicated across both.
	if parsed.Scheme == "https" {
		return nil
	}

	if parsed.Scheme == "http" {
		if urlutil.IsLoopbackHost(parsed.Host) {
			return nil
		}
		return fmt.Errorf("http redirect_uris must use the loopback hosts 127.0.0.1, [::1] or localhost: %s", uri)
	}

	// Custom schemes are for public clients only, which is what this branch not accepting
	// them means. The message used to offer "custom scheme" here, which was never true.
	return fmt.Errorf("confidential clients must use an https redirect_uri, or http on a loopback host: %s", uri)
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

// getClientIP returns the client IP for audit logging. The RealIP middleware
// (MiddlewareRealIP) has already resolved r.RemoteAddr to the trustworthy client
// IP from the socket peer and, when configured, the forwarded headers, so we do
// not re-parse X-Forwarded-For here (doing so would reintroduce a spoofable path).
func getClientIP(r *http.Request) string {
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
	_ = json.NewEncoder(w).Encode(errorResp)
}
