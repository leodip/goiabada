package validators

import (
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/oidc"
	"github.com/leodip/goiabada/core/urlutil"
)

type AuthorizeValidator struct {
	database data.Database
}

type ValidateClientAndRedirectURIInput struct {
	RequestId    string
	ClientId     string
	RedirectURI  string
	ResponseType string // Needed to determine if auth code or implicit flow is being requested
}

type ValidateUnsupportedRequestParametersInput struct {
	HasRequest    bool
	HasRequestURI bool
}

type ValidateRequestInput struct {
	ResponseType         string
	CodeChallengeMethod  string
	CodeChallenge        string
	ResponseMode         string
	PKCERequired         bool
	ImplicitGrantEnabled bool   // Whether implicit flow is allowed for this client
	Scope                string // Needed to validate openid requirement for id_token
	Nonce                string // Needed to validate nonce requirement for id_token
}

func NewAuthorizeValidator(database data.Database) *AuthorizeValidator {
	return &AuthorizeValidator{
		database: database,
	}
}

func (val *AuthorizeValidator) ValidateScopes(scope string) error {

	// trim leading and trailing whitespace
	scope = strings.TrimSpace(scope)

	if len(scope) == 0 {
		return customerrors.NewErrorDetailWithHttpStatusCode("invalid_scope",
			"The 'scope' parameter is missing. Ensure to include one or more scopes, separated by spaces. Scopes can be an OpenID Connect scope, a resource:permission scope, or a combination of both.",
			http.StatusBadRequest)
	}

	// remove duplicated spaces
	space := regexp.MustCompile(`\s+`)
	scope = space.ReplaceAllString(scope, " ")

	scopes := strings.Split(scope, " ")

	for _, scopeStr := range scopes {

		// these scopes don't need further validation
		if oidc.IsIdTokenScope(scopeStr) || oidc.IsOfflineAccessScope(scopeStr) {
			continue
		}

		userInfoScope := fmt.Sprintf("%v:%v", constants.AuthServerResourceIdentifier, constants.UserinfoPermissionIdentifier)
		if scopeStr == userInfoScope {
			return customerrors.NewErrorDetailWithHttpStatusCode("invalid_scope",
				fmt.Sprintf("The '%v' scope is automatically included in the access token when an OpenID Connect scope is present. There's no need to request it explicitly. Please remove it from your request.", userInfoScope),
				http.StatusBadRequest)
		}

		parts := strings.Split(scopeStr, ":")
		if len(parts) != 2 {
			return customerrors.NewErrorDetailWithHttpStatusCode("invalid_scope",
				fmt.Sprintf("Invalid scope format: '%v'. Scopes must adhere to the resource-identifier:permission-identifier format. For instance: backend-service:create-product.", scopeStr),
				http.StatusBadRequest)
		}

		res, err := val.database.GetResourceByResourceIdentifier(nil, parts[0])
		if err != nil {
			return err
		}
		if res == nil {
			return customerrors.NewErrorDetailWithHttpStatusCode("invalid_scope",
				fmt.Sprintf("Invalid scope: '%v'. Could not find a resource with identifier '%v'.", scopeStr, parts[0]),
				http.StatusBadRequest)
		}

		permissions, err := val.database.GetPermissionsByResourceId(nil, res.Id)
		if err != nil {
			return err
		}

		permissionExists := false
		for _, perm := range permissions {
			if perm.PermissionIdentifier == parts[1] {
				permissionExists = true
				break
			}
		}

		if !permissionExists {
			return customerrors.NewErrorDetailWithHttpStatusCode("invalid_scope",
				fmt.Sprintf("Scope '%v' is invalid. The resource identified by '%v' does not have a permission with identifier '%v'.", scopeStr, parts[0], parts[1]),
				http.StatusBadRequest)
		}
	}
	return nil
}

// ValidateClientAndRedirectURI answers RFC 6749 4.1.2.1: a missing or invalid client_id, or a
// missing, non-absolute or unregistered redirect_uri, "MUST NOT automatically redirect the
// user-agent to the invalid redirection URI". Every rejection here therefore reaches a rendered
// page and never an error_description, which is why these seven are *i18n.LocalizedError and
// render in the visitor's locale, while the validations that run after this one return
// customerrors.ErrorDetail and stay English (#213).
//
// The declared return type stays error rather than *i18n.LocalizedError: a database failure is
// returned unwrapped from here, and the handler tells the two apart by type assertion.
func (val *AuthorizeValidator) ValidateClientAndRedirectURI(input *ValidateClientAndRedirectURIInput) error {
	if len(input.ClientId) == 0 {
		return i18n.NewLocalizedError(i18n.ErrCodeAuthorizeClientIdMissing, nil)
	}

	client, err := val.database.GetClientByClientIdentifier(nil, input.ClientId)
	if err != nil {
		return err
	}
	if client == nil {
		return i18n.NewLocalizedError(i18n.ErrCodeAuthorizeClientNotFound, nil)
	}
	if !client.Enabled {
		return i18n.NewLocalizedError(i18n.ErrCodeAuthorizeClientDisabled, nil)
	}

	// Parse response_type to determine which flow is being requested
	// For implicit flow, we check later in ValidateRequest if it's actually enabled
	// Here we just need to verify the client supports at least one of the requested flows
	rtInfo := oauth.ParseResponseType(input.ResponseType)

	if rtInfo.IsImplicitFlow() {
		// For implicit flow, we don't require AuthorizationCodeEnabled
		// The actual implicit grant enablement is checked in ValidateRequest
		// We just need the client to be enabled (already checked above)
	} else {
		// Authorization code flow requires AuthorizationCodeEnabled
		if !client.AuthorizationCodeEnabled {
			return i18n.NewLocalizedError(i18n.ErrCodeAuthorizeAuthCodeNotEnabled, nil)
		}
	}

	// RFC 8252 section 7.3 port flexibility for http loopback redirect URIs is for the
	// authorization code flow only. Without this gate the relaxation would also permit
	// arbitrary loopback ports for implicit responses, which carry tokens directly in the
	// fragment where PKCE cannot mitigate interception.
	//
	// Tested on the token sequence rather than on rtInfo's booleans: ParseResponseType
	// ignores unrecognised values and collapses duplicates, so HasCode && !HasToken &&
	// !HasIdToken is also true for "code foo" and "code code". And not as
	// !rtInfo.IsImplicitFlow(), because response_type is not validated until
	// ValidateRequest, which runs after this check, so that negative test is true for
	// "code token" and for garbage such as "foo". This check is what scopes loopback port
	// flexibility to the authorization code flow (#41).
	responseTypes := strings.Fields(input.ResponseType)
	allowLoopbackPortFlexibility := len(responseTypes) == 1 && responseTypes[0] == "code"

	if len(input.RedirectURI) == 0 {
		return i18n.NewLocalizedError(i18n.ErrCodeAuthorizeRedirectURIMissing, nil)
	}

	// RFC 6749 section 3.1.2: "The redirection endpoint URI MUST be an absolute URI as
	// defined by [RFC3986] Section 4.3", and it "MUST NOT include a fragment component".
	//
	// This gate is here, at the authorization endpoint, and not only at the two registration
	// intakes, because a registration-time check cannot reach rows that were stored before
	// the rule existed. Those rows are still matched below and still emitted into a Location
	// afterwards, so the requested value is tested on every request rather than trusted
	// because it is registered (#122).
	//
	// Only the requested value is tested, and a second check inside the registration match would be
	// dead code rather than defence in depth: RedirectURIMatches returns false unless the
	// registered scheme is "http", so no absolute requested value can ever match a
	// non-absolute registered one. Swept 63 registered/requested pairs to confirm it, 0
	// matched.
	//
	// Placed before ClientLoadRedirectURIs so a garbage value costs no query.
	if !urlutil.IsAbsoluteRedirectURI(input.RedirectURI) {
		// The client identifier is a bounded stored value, so it is safe to log. The
		// requested URI is unbounded attacker-controlled input and is deliberately left
		// out: the operator reads the offending value off the client's page.
		slog.Warn("AuthServer: rejected an authorization request whose redirect_uri is not an absolute URI, or is an http/https URI naming no host",
			"clientIdentifier", client.ClientIdentifier)
		return i18n.NewLocalizedError(i18n.ErrCodeAuthorizeRedirectURINotAbsolute, nil)
	}

	err = val.database.ClientLoadRedirectURIs(nil, client)
	if err != nil {
		return err
	}

	registered := make([]string, 0, len(client.RedirectURIs))
	for _, r := range client.RedirectURIs {
		registered = append(registered, r.URI)
	}
	if !urlutil.RedirectURIIsRegistered(registered, input.RedirectURI, allowLoopbackPortFlexibility) {
		return i18n.NewLocalizedError(i18n.ErrCodeAuthorizeRedirectURINotRegistered, nil)
	}
	return nil
}

func (val *AuthorizeValidator) ValidateUnsupportedRequestParameters(input *ValidateUnsupportedRequestParametersInput) error {
	if input.HasRequest {
		return customerrors.NewErrorDetailWithHttpStatusCode(
			"request_not_supported",
			"The request parameter is not supported.",
			http.StatusBadRequest,
		)
	}
	if input.HasRequestURI {
		return customerrors.NewErrorDetailWithHttpStatusCode(
			"request_uri_not_supported",
			"The request_uri parameter is not supported.",
			http.StatusBadRequest,
		)
	}
	return nil
}

// supportedResponseModes are the values this server can encode an authorization response in.
//
// One definition, because two callers now depend on the same set: ValidateRequest below, and the
// authorize handler, which answers an unsupported value with a local 400 before this validator
// runs. A copy in the handler would let a mode added here be refused there (#213).
var supportedResponseModes = []string{"query", "fragment", "form_post"}

// IsSupportedResponseMode reports whether responseMode names a mechanism this server can return
// an authorization response through. An empty value is supported: response_mode is OPTIONAL and
// absence selects the default for the response type, per OAuth 2.0 Multiple Response Type
// Encoding Practices section 2.1.
func IsSupportedResponseMode(responseMode string) bool {
	return responseMode == "" || slices.Contains(supportedResponseModes, responseMode)
}

func (val *AuthorizeValidator) ValidateRequest(input *ValidateRequestInput) error {

	// Check for empty/missing response_type first
	if strings.TrimSpace(input.ResponseType) == "" {
		return customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
			"The response_type parameter is missing.", http.StatusBadRequest)
	}

	// Parse response_type (can be space-separated for OIDC, e.g., "id_token token")
	rtInfo := oauth.ParseResponseType(input.ResponseType)
	isImplicitFlow := rtInfo.IsImplicitFlow()

	// Validate response_type combinations
	// Supported: "code", "token", "id_token", "id_token token" (or "token id_token")
	// Count how many recognized response types are present
	responseTypeCount := 0
	if rtInfo.HasCode {
		responseTypeCount++
	}
	if rtInfo.HasToken {
		responseTypeCount++
	}
	if rtInfo.HasIdToken {
		responseTypeCount++
	}

	validResponseType := false
	switch responseTypeCount {
	case 1:
		validResponseType = true // Any single valid type is OK (code, token, or id_token)
	case 2:
		// Only "id_token token" or "token id_token" is valid for 2 tokens
		validResponseType = rtInfo.HasToken && rtInfo.HasIdToken && !rtInfo.HasCode
	}

	if !validResponseType {
		return customerrors.NewErrorDetailWithHttpStatusCode("unsupported_response_type",
			"The authorization server does not support this response_type. Supported values: code, token, id_token, id_token token.",
			http.StatusBadRequest)
	}

	// Check if implicit flow is authorized for this client
	if isImplicitFlow && !input.ImplicitGrantEnabled {
		return customerrors.NewErrorDetailWithHttpStatusCode("unauthorized_client",
			"The client is not authorized to use the implicit grant type. To enable it, go to the client's settings in the admin console under 'OAuth2 flows', or enable it globally in 'Settings > General'.",
			http.StatusBadRequest)
	}

	// OIDC: id_token requires openid scope
	if rtInfo.HasIdToken {
		scopes := strings.Fields(input.Scope)
		hasOpenid := false
		for _, s := range scopes {
			if s == "openid" {
				hasOpenid = true
				break
			}
		}
		if !hasOpenid {
			return customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
				"The 'openid' scope is required when requesting an id_token.",
				http.StatusBadRequest)
		}
	}

	// OIDC: nonce is REQUIRED for implicit flow with id_token (OIDC Core 3.2.2.1)
	if rtInfo.HasIdToken && isImplicitFlow && input.Nonce == "" {
		return customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
			"The 'nonce' parameter is required for implicit flow when requesting an id_token.",
			http.StatusBadRequest)
	}

	// PKCE validation only applies to authorization code flow
	if rtInfo.HasCode && !isImplicitFlow {
		// Check if PKCE parameters were provided
		pkceProvided := input.CodeChallengeMethod != "" || input.CodeChallenge != ""

		if input.PKCERequired {
			// PKCE is required - validate that it's provided and correct
			if input.CodeChallengeMethod != "S256" {
				return customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
					"PKCE is required. Ensure code_challenge_method is set to 'S256'.", http.StatusBadRequest)
			}

			if len(input.CodeChallenge) < 43 || len(input.CodeChallenge) > 128 {
				return customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
					"The code_challenge parameter is either missing or incorrect. It should be 43 to 128 characters long.",
					http.StatusBadRequest)
			}
		} else if pkceProvided {
			// PKCE is optional but was provided - validate format (strict mode)
			if input.CodeChallengeMethod != "S256" {
				return customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
					"Invalid code_challenge_method. Only 'S256' is supported.", http.StatusBadRequest)
			}

			if len(input.CodeChallenge) < 43 || len(input.CodeChallenge) > 128 {
				return customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
					"The code_challenge parameter is incorrect. It should be 43 to 128 characters long.",
					http.StatusBadRequest)
			}
		}
		// If PKCE is not required and not provided, that's fine - skip validation
	}

	// Response mode validation.
	//
	// The authorize handler answers an unsupported response_mode itself, with a local 400 and no
	// error parameters, so this branch is not reached from there any more: OIDC Core 3.1.2.6 says
	// an error cannot be encoded in a mode the server does not understand, which makes it the one
	// failure that must not become a redirect (#213 decision 11). It stays because the rule
	// belongs to the validator rather than to one caller, and a second caller of ValidateRequest
	// would not inherit the handler's branch.
	if !IsSupportedResponseMode(input.ResponseMode) {
		return customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
			"Invalid response_mode parameter. Supported values are: query, fragment, form_post.",
			http.StatusBadRequest)
	}

	// Per RFC 6749 4.2.2 and OIDC Core 3.2.2.5: implicit grant tokens MUST be in fragment
	// If response_mode is explicitly set for implicit flow, it must be fragment
	if isImplicitFlow && len(input.ResponseMode) > 0 && input.ResponseMode != "fragment" {
		return customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
			"Implicit flow requires response_mode=fragment or no response_mode (fragment is the default for implicit flow).",
			http.StatusBadRequest)
	}

	return nil
}

// ValidatePrompt validates and normalizes the OIDC prompt parameter.
// It returns the normalized prompt string (trimmed, deduplicated, single-space-delimited)
// or an error if the prompt value is invalid or contains conflicting values.
//
// Per OIDC Core 1.0 Section 3.1.2.1:
// - Valid values: none, login, consent, select_account (select_account not implemented)
// - prompt=none cannot be combined with other values
// - Other values can be combined (e.g., "login consent")
func (val *AuthorizeValidator) ValidatePrompt(prompt string) (string, error) {
	// Empty or whitespace-only prompt is valid (treated as absent)
	trimmed := strings.TrimSpace(prompt)
	if trimmed == "" {
		return "", nil
	}

	// Parse prompt values (handles multiple spaces, deduplicates)
	values := parsePromptValues(trimmed)
	if len(values) == 0 {
		return "", nil
	}

	// Validate each value
	validValues := map[string]bool{
		"none":    true,
		"login":   true,
		"consent": true,
		// "select_account" is not implemented in this phase
	}

	hasNone := false
	for _, v := range values {
		if !validValues[v] {
			return "", customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
				fmt.Sprintf("Invalid prompt value: %s", v), http.StatusBadRequest)
		}
		if v == "none" {
			hasNone = true
		}
	}

	// Check for conflicts: none cannot be combined with other values
	if hasNone && len(values) > 1 {
		return "", customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
			"prompt=none cannot be combined with other values", http.StatusBadRequest)
	}

	// Return normalized string (single-space-delimited)
	return strings.Join(values, " "), nil
}

// parsePromptValues parses a prompt string into individual values.
// It handles multiple spaces and deduplicates values while preserving order.
func parsePromptValues(prompt string) []string {
	// strings.Fields handles multiple spaces and trims
	fields := strings.Fields(prompt)

	// Deduplicate while preserving order
	seen := make(map[string]bool)
	result := []string{}
	for _, f := range fields {
		if !seen[f] {
			seen[f] = true
			result = append(result, f)
		}
	}
	return result
}
