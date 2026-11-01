package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/leodip/goiabada/authserver/internal/apiresponse"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/middleware"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/internal/urlmatch"
	"github.com/leodip/goiabada/authserver/internal/uuid"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/inputvalidation"
	"github.com/leodip/goiabada/core/logging"
	"github.com/leodip/goiabada/core/loopback"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/securerandom"
)

// dynamicClientRegistrationDatabase is what RFC 7591 registration needs: the client, redirect URIs
// and sign-out redirect URIs it creates, and the transaction that makes them one write.
type dynamicClientRegistrationDatabase interface {
	CreateClient(ctx context.Context, tx *sql.Tx, client *record.Client) error
	CreateRedirectURI(ctx context.Context, tx *sql.Tx, redirectURI *record.RedirectURI) error
	CreatePostLogoutRedirectURI(ctx context.Context, tx *sql.Tx, postLogoutRedirectURI *record.PostLogoutRedirectURI) error
	RunInTransaction(ctx context.Context, fn func(tx *sql.Tx) error) error
}

// clientNameMaxLength bounds a registration's client_name, in inputvalidation.TextLength's
// characters, at the description the admin API's client create and update take at most
// (handler_api_clients.go).
const clientNameMaxLength = 100

// HandleDynamicClientRegistrationPost implements RFC 7591 §3 Client Registration Endpoint
func HandleDynamicClientRegistrationPost(
	database dynamicClientRegistrationDatabase,
	auditLogger AuditLogger,
	dataCipher *encryption.DataCipher,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		settings, ok := reqctx.SettingsFrom(r.Context())
		if !ok {
			apiresponse.LogInternalServerError(r, reqctx.ErrNoSettings)
			writeDCRError(w, r, "server_error", "Internal server error", http.StatusInternalServerError)
			return
		}

		// 1. Check if DCR is enabled (RFC 7591 §3)
		if !settings.DynamicClientRegistrationEnabled {
			refuseDCR(w, r, "access_denied", "Dynamic client registration is not enabled", http.StatusForbidden)
			return
		}

		// 2. Parse request (RFC 7591 §3.1)
		var req oidc.DynamicClientRegistrationRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			refuseDCR(w, r, oidc.DCRErrorInvalidClientMetadata, "Invalid request body", http.StatusBadRequest)
			return
		}

		// 3. Apply defaults (RFC 7591 §2)
		applyDCRDefaults(&req)

		// 4. Validate request
		if err := validateDCRRequest(&req); err != nil {
			refuseDCR(w, r, oidc.DCRErrorInvalidClientMetadata, err.Error(), http.StatusBadRequest)
			return
		}

		// 5. Validate redirect URIs (RFC 7591 §5)
		if err := validateDCRRedirectURIs(&req); err != nil {
			refuseDCR(w, r, oidc.DCRErrorInvalidRedirectURI, err.Error(), http.StatusBadRequest)
			return
		}

		// 5b. Validate the sign-out redirect URIs under the same rules (#147 decision 7). A refusal is
		// invalid_client_metadata, not invalid_redirect_uri: OpenID Connect Dynamic Client
		// Registration 1.0 section 3.3 keeps that code for redirect_uris, and a registrant's library
		// would point its developer at the wrong field.
		if err := validateDCRPostLogoutRedirectURIs(&req); err != nil {
			refuseDCR(w, r, oidc.DCRErrorInvalidClientMetadata, err.Error(), http.StatusBadRequest)
			return
		}

		// 5c. Keep the privacy policy and terms of service only on a redirect URI's scheme and host
		// (RFC 7591 section 5), dropping either otherwise and registering the client all the same
		// (#622 decision 12). Refusing them would break, on upgrade, every client whose legal pages
		// live on another host than its redirect URIs, every native and loopback client among them,
		// since these fields were ignored until now.
		policyURI := keptDCRDocumentURI(req.PolicyURI, req.RedirectURIs)
		tosURI := keptDCRDocumentURI(req.TOSURI, req.RedirectURIs)

		// 6. Generate client identifier (RFC 7591 §3.2.1)
		clientIdentifier := generateDCRClientIdentifier()

		// 7. Determine if public or confidential client
		isPublic := req.TokenEndpointAuthMethod == "none"

		// 8. Generate client secret for confidential clients (RFC 7591 §3.2.1)
		var clientSecretEncrypted []byte
		var clientSecret string

		if !isPublic {
			clientSecret = securerandom.String(60)
			var err error
			clientSecretEncrypted, err = dataCipher.Encrypt(clientSecret)
			if err != nil {
				apiresponse.LogInternalServerError(r, errs.Wrap(err, "DCR: failed to encrypt client secret"))
				writeDCRError(w, r, "server_error", "Internal server error", http.StatusInternalServerError)
				return
			}
		}

		// 9. Create client model
		implicitGrantEnabled, ropcEnabled := false, false
		client := &record.Client{
			ClientIdentifier:      clientIdentifier,
			ClientSecretEncrypted: clientSecretEncrypted,
			Description:           req.ClientName,
			PrivacyPolicyURL:      policyURI,
			TermsOfServiceURL:     tosURI,
			IsPublic:              isPublic,
			Enabled:               true,
			// A self-registered client is one nobody here has vetted, and RFC 7591 section 5
			// requires all of its metadata be treated as self-asserted. Consent is the only
			// control that binds such a client's identity to the user's authority, so it is on
			// by default: RFC 6749 section 10.2 says the server SHOULD engage the resource owner
			// to identify a client it cannot authenticate, and SHOULD NOT process repeated
			// authorization requests without active resource owner interaction. An administrator
			// who has reviewed a specific client can untick it on the client settings page.
			// Turning this back off by default makes every self-registered client silently
			// grantable for any scope the user holds (#108).
			ConsentRequired: true,
			// Set here and nowhere else. Nothing on the update path can change it, deliberately:
			// it is a fact about where the client came from, not a trust setting (#108).
			CreatedViaDCR:            true,
			AuthorizationCodeEnabled: containsGrantType(req.GrantTypes, oidc.GrantTypeAuthorizationCode),
			ClientCredentialsEnabled: containsGrantType(req.GrantTypes, oidc.GrantTypeClientCredentials),
			// The two legacy flows are off on the client itself, not left to inherit. A
			// registration can't ask for either, since validateDCRRequest refuses implicit and
			// password, but a client whose switch is unset follows the global setting, so turning
			// either flow on under Admin, General handed it to every client anyone had registered,
			// whatever its registration said. An administrator who has reviewed one can still turn
			// a flow on for it, on its OAuth2 flows tab.
			ImplicitGrantEnabled:                    &implicitGrantEnabled,
			ResourceOwnerPasswordCredentialsEnabled: &ropcEnabled,
			DefaultAcrLevel:                         record.AcrLevel2Optional,
			IncludeOpenIDConnectClaimsInAccessToken: record.ThreeStateSettingDefault.String(),
			IncludeOpenIDConnectClaimsInIdToken:     record.ThreeStateSettingDefault.String(),
			// Token expiration settings use global defaults from settings
			TokenExpirationInSeconds:                settings.TokenExpirationInSeconds,
			RefreshTokenOfflineIdleTimeoutInSeconds: settings.RefreshTokenOfflineIdleTimeoutInSeconds,
			RefreshTokenOfflineMaxLifetimeInSeconds: settings.RefreshTokenOfflineMaxLifetimeInSeconds,
		}

		// A public client always requires PKCE and never holds client credentials, and the
		// server enforces both whatever the columns hold. They are written all the same, through
		// the one rule every writer of a public client applies, so the row, the admin API's
		// response and the admin console's page say what the server does (#245). validateDCRRequest
		// has already refused a public client asking for client_credentials, so here it only sets
		// PKCE (#428).
		client.ApplyPublicClientInvariants()

		// 10. Save the client, its redirect URIs and its sign-out redirect URIs as one write (#428,
		// #147). Everything the request can be refused for was decided above, so a failure here is
		// the server's, and the transaction is what leaves no half-registered client behind: a
		// client row whose URIs were not all written, holding a secret its requester never
		// received. The body is safe to rerun after a deadlock: CreateClient reassigns the id and
		// timestamps on each attempt, each URI row is built inside it, and it writes nothing to the
		// response.
		err := database.RunInTransaction(r.Context(), func(tx *sql.Tx) error {
			if err := database.CreateClient(r.Context(), tx, client); err != nil {
				return errs.Wrap(err, "DCR: unable to create the client")
			}
			for _, uri := range req.RedirectURIs {
				redirectURI := &record.RedirectURI{
					ClientId: client.Id,
					URI:      uri,
				}
				if err := database.CreateRedirectURI(r.Context(), tx, redirectURI); err != nil {
					return errs.Wrap(err, "DCR: unable to create a redirect URI")
				}
			}
			for _, uri := range req.PostLogoutRedirectURIs {
				postLogoutRedirectURI := &record.PostLogoutRedirectURI{
					ClientId: client.Id,
					URI:      uri,
				}
				if err := database.CreatePostLogoutRedirectURI(r.Context(), tx, postLogoutRedirectURI); err != nil {
					return errs.Wrap(err, "DCR: unable to create a sign-out redirect URI")
				}
			}
			return nil
		})
		if err != nil {
			apiresponse.LogInternalServerError(r, err)
			// One answer whichever write failed, since the whole registration was undone.
			writeDCRError(w, r, "server_error", "Failed to register client", http.StatusInternalServerError)
			return
		}

		// 11. Audit log, after the commit, so an event never records a client that does not exist
		auditLogger.Log(r.Context(), audit.EventDynamicClientRegistration, map[string]interface{}{
			"client_id":         client.Id,
			"client_identifier": client.ClientIdentifier,
			"grant_types":       req.GrantTypes,
			"is_public":         isPublic,
			"ip":                middleware.ClientIP(r),
		})

		// 12. Build response (RFC 7591 §3.2.1)
		response := oidc.DynamicClientRegistrationResponse{
			ClientID:                clientIdentifier,
			ClientIDIssuedAt:        time.Now().Unix(),
			ClientSecretExpiresAt:   0, // Never expires
			RedirectURIs:            req.RedirectURIs,
			PostLogoutRedirectURIs:  req.PostLogoutRedirectURIs,
			TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
			GrantTypes:              req.GrantTypes,
			ClientName:              req.ClientName,
			// What was stored, so a dropped value is absent (RFC 7591 section 3.2.1).
			PolicyURI: policyURI,
			TOSURI:    tosURI,
		}

		// Only include secret for confidential clients (RFC 7591 §3.2.1)
		if !isPublic {
			response.ClientSecret = clientSecret
		}

		// 13. Send response
		writeDCRResponse(w, r, response)
	}
}

// applyDCRDefaults applies RFC 7591 §2 default values
func applyDCRDefaults(req *oidc.DynamicClientRegistrationRequest) {
	// Default token_endpoint_auth_method (RFC 7591 §2)
	if req.TokenEndpointAuthMethod == "" {
		req.TokenEndpointAuthMethod = "client_secret_basic"
	}

	// Default grant_types (RFC 7591 §2)
	if len(req.GrantTypes) == 0 {
		req.GrantTypes = []string{oidc.GrantTypeAuthorizationCode.String()}
	}
}

// validateDCRRequest validates request per RFC 7591 §2
func validateDCRRequest(req *oidc.DynamicClientRegistrationRequest) error {
	// Validate token_endpoint_auth_method
	allowedAuthMethods := map[string]bool{
		"none":                true,
		"client_secret_basic": true,
		"client_secret_post":  true,
	}
	if !allowedAuthMethods[req.TokenEndpointAuthMethod] {
		return errs.Errorf("unsupported token_endpoint_auth_method: %s", req.TokenEndpointAuthMethod)
	}

	// Validate grant_types against the grant table's registrable trait (#437)
	for _, gt := range req.GrantTypes {
		if !oidc.GrantType(gt).Registrable() {
			return errs.Errorf("unsupported grant_type: %s", gt)
		}
	}

	// RFC 6749 section 4.4: the client credentials grant MUST only be used by confidential
	// clients, and RFC 7591 section 2.1 names refusing such an inconsistent registration with
	// invalid_client_metadata as the way to honour its SHOULD. Refused rather than substituted:
	// dropping the grant would answer a client_credentials-only request with a 201 for a client
	// holding no usable grant, a silent success hiding the registrant's bug. The token endpoint
	// refuses the grant for a public client anyway; this keeps the row from saying otherwise
	// (#428).
	if req.TokenEndpointAuthMethod == "none" && containsGrantType(req.GrantTypes, oidc.GrantTypeClientCredentials) {
		return errs.Errorf("a public client (token_endpoint_auth_method none) cannot use the client_credentials grant")
	}

	// client_name is written to clients.description, so it takes the bound every description
	// write through the admin API takes, 100, and not the column's 128. At 128 a registration
	// could store a description the client's own Settings tab then refused to save, blocking
	// every save of that tab until an administrator shortened it.
	if inputvalidation.TextLength(req.ClientName) > clientNameMaxLength {
		return errs.Errorf("client_name cannot exceed %d characters", clientNameMaxLength)
	}

	// client_name is written to clients.description, the same column the admin API refuses
	// angle brackets in, so every write path to it applies one rule and a self-registered
	// client cannot hold markup the admin API would have refused (#275). RFC 7591 section
	// 3.2.2 defines invalid_client_metadata for a rejected metadata value, and the caller
	// answers with it. The message is English like the handler's other refusals: DCR errors
	// are protocol responses and are not localized.
	if inputvalidation.ContainsAngleBrackets(req.ClientName) {
		return errs.Errorf("client_name cannot contain the characters < or >")
	}

	return nil
}

// validateDCRRedirectURIs validates redirect URIs per RFC 7591 §5
func validateDCRRedirectURIs(req *oidc.DynamicClientRegistrationRequest) error {
	// Check if redirect URIs are required
	requiresRedirectURIs := containsGrantType(req.GrantTypes, oidc.GrantTypeAuthorizationCode)

	if requiresRedirectURIs && len(req.RedirectURIs) == 0 {
		return errs.Errorf("redirect_uris required for authorization_code grant type")
	}

	return validateDCRURIList(req.RedirectURIs, req.TokenEndpointAuthMethod == "none", redirectURIField)
}

// validateDCRPostLogoutRedirectURIs validates a registration's sign-out redirect URIs under every
// rule its redirect URIs get, client-type table included (#147 decision 7). The field is optional
// whatever the grant types, as redirect_uris is when the authorization code flow isn't asked for.
func validateDCRPostLogoutRedirectURIs(req *oidc.DynamicClientRegistrationRequest) error {
	return validateDCRURIList(req.PostLogoutRedirectURIs, req.TokenEndpointAuthMethod == "none", postLogoutRedirectURIField)
}

// dcrURIField names the registration field a list of URIs came in, the way a refusal names it, so
// a registrant learns which of the two lists to change.
type dcrURIField struct {
	// entry is one value of the list, such as "redirect_uri".
	entry string
	// list is the field itself, such as "redirect_uris".
	list string
}

var (
	redirectURIField = dcrURIField{entry: "redirect_uri", list: "redirect_uris"}
	// The entry spelling carries the field's own name, so every refusal of a sign-out redirect URI
	// names post_logout_redirect_uris, as decision 7 asks.
	postLogoutRedirectURIField = dcrURIField{entry: "post_logout_redirect_uris entry", list: "post_logout_redirect_uris"}
)

// validateDCRURIList applies the bounds and the per-URI rules to one of a registration's URI lists.
// Each list is bounded on its own: the sign-out list's 60 are counted apart from the redirect URIs.
func validateDCRURIList(uris []string, isPublic bool, field dcrURIField) error {
	// The bounds are the admin API's too, since they are facts about storage rather than about
	// the door, and every refusal names the field, so an integrator learns the one thing to change
	// (#428). RFC 7591 sets no bound of its own.
	if len(uris) > record.RedirectURIsMaxPerClient {
		return errs.Errorf("%s cannot hold more than %d entries", field.list, record.RedirectURIsMaxPerClient)
	}

	seen := make(map[string]bool, len(uris))
	for _, uri := range uris {
		// Bytes, before parsing, so an overlong value is never parsed, and not echoed: the
		// refusal names the bound instead of repeating a value that broke it.
		if len(uri) > record.RedirectURIMaxBytes {
			return errs.Errorf("a %s cannot exceed %d bytes", field.entry, record.RedirectURIMaxBytes)
		}
		// A repeat would be stored as a second row, and a save removing the URI would then
		// leave the other copy live. Matching at the authorization endpoint and at sign-out is
		// exact, so the comparison here is too.
		if seen[uri] {
			return errs.Errorf("%s is listed more than once: %s", field.entry, uri)
		}
		seen[uri] = true
		if err := validateRedirectURI(uri, isPublic, field); err != nil {
			return err
		}
	}

	return nil
}

// keptDCRDocumentURI returns a registration's policy_uri or tos_uri when it is kept, and "" when it
// is dropped. It is kept when it is an absolute http or https URL naming a host, of at most
// clientDocumentURIMaxLength characters, carrying none of the characters RFC 3986 excludes, whose
// scheme and host are those of one of the redirect URIs: RFC 7591 section 5 says the server SHOULD
// check that they are, since a client could otherwise have the consent screen link a page of its
// choosing as its own. Schemes and hosts compare without regard to case (RFC 3986 sections 3.1 and
// 3.2.2), and the port is no part of the host. The redirect URIs were validated before this runs.
func keptDCRDocumentURI(uri string, redirectURIs []string) string {
	if uri == "" || inputvalidation.TextLength(uri) > clientDocumentURIMaxLength || strings.ContainsAny(uri, excludedURIChars) {
		return ""
	}
	parsed, err := url.Parse(uri)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" {
		return ""
	}
	for _, redirectURI := range redirectURIs {
		redirect, err := url.Parse(redirectURI)
		if err != nil {
			continue
		}
		if strings.EqualFold(redirect.Scheme, parsed.Scheme) && strings.EqualFold(redirect.Hostname(), parsed.Hostname()) {
			return uri
		}
	}
	return ""
}

// clientDocumentURIMaxLength bounds a kept policy_uri or tos_uri at the 256 characters the admin API
// takes for a client's privacy policy and terms of service URLs, their columns' width.
const clientDocumentURIMaxLength = 256

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

// validateRedirectURI validates a single redirect URI per RFC 7591 §5, or a single sign-out
// redirect URI, which gets every one of the same checks (#147 decision 7); field names which in the
// refusal.
func validateRedirectURI(uri string, isPublic bool, field dcrURIField) error {
	parsed, err := url.ParseRequestURI(uri)
	if err != nil {
		return errs.Errorf("invalid %s format: %s", field.entry, uri)
	}

	// RFC 6749 section 3.1.2 requires an absolute-URI (RFC 3986 section 4.3) and forbids a
	// fragment. The shared predicate checks both, and also refuses an http or https URI with
	// no host, which is a value the grammar admits but a browser resolves to somewhere else
	// entirely. Without it, "//evil.example/cb" and "https:///evil.example/cb" register
	// cleanly and are later emitted verbatim into a Location, handing the authorization code
	// to that host.
	//
	// This is one of three intakes rather than the only one. The admin API applies the same
	// predicate, and the authorization endpoint applies it to the requested URI before
	// matching, which is what covers rows stored before any of these rules existed. Keep the
	// rule in the predicate rather than here, so the three cannot drift (#122).
	if !urlmatch.IsAbsoluteRedirectURI(uri) {
		return errs.Errorf("%s must be an absolute URI: a scheme is required, a fragment is not permitted, percent-escapes must be well formed, and an http or https URI must name a host: %s", field.entry, uri)
	}

	// Characters RFC 3986 excludes from URIs entirely. A redirect URI carrying them is
	// malformed, and it is also how markup reaches the admin console, which renders stored
	// redirect URIs into the page.
	//
	// Checked ahead of the client-type branches on purpose: an https URI on a confidential
	// client reaches the same place, so gating this inside the custom-scheme branch would
	// miss it.
	if strings.ContainsAny(uri, excludedURIChars) {
		return errs.Errorf("%s contains characters that are not permitted in a URI: %s", field.entry, uri)
	}

	// Schemes that cannot receive an authorization response, or that execute script.
	//
	// This denylist cannot be the primary defence and is not one: the verified markup
	// payload used the scheme "x", which no list of names would catch. The character gate
	// above is what stops that class. This gate stops the schemes that carry no excluded
	// characters at all, such as javascript: and ftp:.
	if deniedRedirectURISchemes[strings.ToLower(parsed.Scheme)] {
		return errs.Errorf("%s scheme %q is not permitted: %s", field.entry, parsed.Scheme, uri)
	}

	// RFC 9700 section 2.6: http only on the loopback interface (RFC 8252 section 7.3),
	// whatever the client type. The rule is the predicate the admin API applies too, so the
	// two intakes cannot drift (#575). Its host comparison is exact: this used to be a
	// strings.HasPrefix test, which accepted any host merely starting with a loopback name,
	// localhost.attacker.com included, in both client-type branches below (#105).
	if loopback.IsPlainHTTPOff(uri) {
		return errs.Errorf("http %s must use the loopback hosts 127.0.0.1, [::1] or localhost: %s", field.list, uri)
	}

	// For public clients (MCP use case), only allow loopback http or custom schemes.
	if isPublic {
		// Allow loopback HTTP (MCP use case); any other host was refused above.
		if parsed.Scheme == "http" {
			return nil
		}

		// Allow custom schemes (native apps)
		if parsed.Scheme != "https" {
			return nil
		}

		// Reject HTTPS for public clients registered via DCR
		return errs.Errorf("public clients registered via DCR cannot use https %s (security restriction): %s", field.list, uri)
	}

	// For confidential clients, allow HTTPS or loopback http.
	if parsed.Scheme == "https" || parsed.Scheme == "http" {
		return nil
	}

	// Custom schemes are for public clients only, which is what this branch not accepting
	// them means. The message used to offer "custom scheme" here, which was never true.
	return errs.Errorf("confidential clients must use an https %s, or http on a loopback host: %s", field.entry, uri)
}

// generateDCRClientIdentifier generates unique client identifier (RFC 7591 §3.2.1)
//
// The dcr_ prefix is cosmetic: it is useful to a human reading a client list or a log line, and
// nothing may depend on it. An administrator can name a client dcr_anything through the admin
// console, so testing the prefix answers "was this named like a self-registered client", not
// "did this client register itself". The clients.created_via_dcr column answers the second, and
// it is what every such test reads (#108).
//
// The identifier a client is registered under is fixed from here on: HandleClientUpdatePut
// refuses to rename a client whose created_via_dcr is set. That is not what makes the prefix
// trustworthy, since it never was; it keeps the prefix and the column from drifting apart for
// the human reading them, which is the only thing the prefix is for (#108, decision 16).
func generateDCRClientIdentifier() string {
	return "dcr_" + uuid.New()
}

// containsGrantType checks if grant type is in the list
func containsGrantType(grantTypes []string, want oidc.GrantType) bool {
	for _, gt := range grantTypes {
		if gt == want.String() {
			return true
		}
	}
	return false
}

// refuseDCR answers a registration the endpoint turns down, a 400 of RFC 7591 section 3.2.2 or the
// 403 of a server taking none, and records it at Warn, the level the logging convention gives a
// refused request. The request log's status was all the server recorded until the demo's
// registrations were checked against the docs: a registrant refused for a redirect URI or a grant
// type learned why from the answer, and its operator had nothing to read. The record carries the
// error code and the description the registrant was answered with, escaped and bounded, since it
// interpolates request text. No audit event: nothing was created, and the request names no client
// of this server to record it against.
func refuseDCR(w http.ResponseWriter, r *http.Request, errorCode, description string, statusCode int) {
	slog.WarnContext(r.Context(), "client registration refused",
		"error_code", errorCode,
		"reason", logging.FieldForLog(description))
	writeDCRError(w, r, errorCode, description, statusCode)
}

// writeDCRError writes RFC 7591 §3.2.2 error response.
//
// The description goes through the conformer the authorization and token endpoints use. RFC 7591
// section 3.2.2 makes error_description "human-readable ASCII text", and descriptions here
// interpolate request text -- a grant type, a redirect URI -- so without it a registrant's quote,
// backslash or non-ASCII character comes back raw, at whatever length it was sent (#428).
//
// The status is committed before the body is encoded, so a failed write has nothing left to
// answer, and it is recorded at Debug, as writeDCRResponse records its own.
func writeDCRError(w http.ResponseWriter, r *http.Request, errorCode, description string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(statusCode)

	errorResp := oidc.DynamicClientRegistrationError{
		Error:            errorCode,
		ErrorDescription: oauth.ConformErrorDescription(description),
	}
	if err := json.NewEncoder(w).Encode(errorResp); err != nil {
		slog.DebugContext(r.Context(), "unable to write the registration error response", "error", err)
	}
}

// writeDCRResponse writes RFC 7591 section 3.2.1's 201 with the registered metadata.
//
// The body is encoded before anything is written, so an encoding failure can still be answered in
// section 3.2.2's envelope with a 500 rather than after a committed 201, where it could only have
// been logged. Once the 201 is out a failed write has nothing left to answer, so it is recorded at
// Debug, as the health check records its own (#435).
func writeDCRResponse(w http.ResponseWriter, r *http.Request, response any) {
	body, err := json.Marshal(response)
	if err != nil {
		apiresponse.LogInternalServerError(r, errs.Wrap(err, "unable to encode the registration response"))
		writeDCRError(w, r, "server_error", "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusCreated)
	if _, err := w.Write(append(body, '\n')); err != nil {
		slog.DebugContext(r.Context(), "unable to write the registration response", "error", err)
	}
}
