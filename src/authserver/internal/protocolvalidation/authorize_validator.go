package protocolvalidation

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/permissions"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/urlmatch"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/oauth"
)

// authorizeValidatorDatabase is what the authorize request validator needs: the client and its
// registered redirect URIs.
//
// It embeds the scope resolver's port because a requested scope is resolved by permissions.ResolveScope.
type authorizeValidatorDatabase interface {
	permissions.ScopeResolverDatabase

	ClientLoadRedirectURIs(ctx context.Context, tx *sql.Tx, client *record.Client) error
	GetClientByClientIdentifier(ctx context.Context, tx *sql.Tx, clientIdentifier string) (*record.Client, error)
}

type AuthorizeValidator struct {
	database authorizeValidatorDatabase
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
	Nonce                string // Needed to validate nonce requirement for id_token, and bounded (#437)
	State                string // Bounded, because the ceremony stores it (#437)
	MaxAge               string // The raw max_age parameter, empty when absent
}

func NewAuthorizeValidator(database authorizeValidatorDatabase) *AuthorizeValidator {
	return &AuthorizeValidator{
		database: database,
	}
}

// ValidateScopes validates the scope parameter of an authorization request, exactly as the client
// sent it. A scope that is not one space between each two values, with none at either end, is
// refused as malformed before anything else is read of it (RFC 6749 section 3.3, #244), which is why
// it takes the raw value: normalizing first would hide the very runs of spaces it refuses.
//
// The rest is judged with duplicates dropped (oidc.NormalizeScope), which is what
// AuthContext.SetScope stores. What is stored can only be shorter, when the response type does not
// honour offline_access (ResponseTypeInfo.ScopeHonoured), so the bound below still counts at least
// the value that is saved in the consent, the code and the refresh token (#437). It validates the
// request rather than the stored value so that a request for offline_access alone is refused for
// what it is on every response type, and not called missing where the response type emptied it.
func (val *AuthorizeValidator) ValidateScopes(ctx context.Context, scope string) error {

	if err := ValidateSpaceDelimited("scope", "invalid_scope", scope); err != nil {
		return err
	}
	scope = oidc.NormalizeScope(scope)

	scopes := oidc.SplitScope(scope)

	if len(scopes) == 0 {
		return oauth.NewErrorDetailWithHTTPStatus("invalid_scope",
			"The 'scope' parameter is missing. Ensure to include one or more scopes, separated by spaces. Scopes can be an OpenID Connect scope, a resource:permission scope, or a combination of both.",
			http.StatusBadRequest)
	}

	// Before the first lookup, so a scope of hundreds of values costs no query. The column it must
	// fit is three tables wide (record.ScopeMaxBytes), and one that did not fit would be granted
	// here and refused as a 500 after the user had signed in (#437).
	if err := scopeBound.check(scope); err != nil {
		return err
	}

	// offline_access asks for a refresh token to outlive the session, and asks for nothing else: on
	// its own the request names no resource and no claim, and an access token cannot be signed
	// without an audience. Accepted, it was granted here and the code exchange then answered 500
	// after it had claimed the code (#244). It is refused as an invalid scope, which RFC 6749
	// 4.1.2.1 names for a scope that is "invalid, unknown, or malformed".
	if !slices.ContainsFunc(scopes, func(s string) bool { return !oidc.IsOfflineAccessScope(s) }) {
		return oauth.NewErrorDetailWithHTTPStatus("invalid_scope",
			"The 'scope' parameter holds only 'offline_access', which grants nothing by itself. Include at least one other scope, such as 'openid' or a resource:permission scope.",
			http.StatusBadRequest)
	}

	for _, scopeStr := range scopes {

		// these scopes don't need further validation
		if oidc.IsClaimScope(scopeStr) || oidc.IsOfflineAccessScope(scopeStr) {
			continue
		}

		// The rejection wording below is this endpoint's own and differs from the token
		// endpoint's for the same outcome; both are asserted verbatim by the integration suite,
		// so the shared resolver hands back an outcome and never a message (#124).
		resolution, err := permissions.ResolveScope(ctx, val.database, scopeStr)
		if err != nil {
			return err
		}

		switch resolution.Outcome {
		case permissions.ScopeMalformed:
			return oauth.NewErrorDetailWithHTTPStatus("invalid_scope",
				fmt.Sprintf("Invalid scope format: '%v'. Scopes must adhere to the resource-identifier:permission-identifier format. For instance: backend-service:create-product.", scopeStr),
				http.StatusBadRequest)
		case permissions.ScopeResourceUnknown:
			return oauth.NewErrorDetailWithHTTPStatus("invalid_scope",
				fmt.Sprintf("Invalid scope: '%v'. Could not find a resource with identifier '%v'.", scopeStr, resolution.ResourceIdentifier),
				http.StatusBadRequest)
		case permissions.ScopePermissionUnknown:
			return oauth.NewErrorDetailWithHTTPStatus("invalid_scope",
				fmt.Sprintf("Scope '%v' is invalid. The resource identified by '%v' does not have a permission with identifier '%v'.", scopeStr, resolution.ResourceIdentifier, resolution.PermissionIdentifier),
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
// oauth.ErrorDetail and stay English (#213).
//
// The declared return type stays error rather than *i18n.LocalizedError: a database failure is
// returned unwrapped from here, and the handler tells the two apart by type assertion.
func (val *AuthorizeValidator) ValidateClientAndRedirectURI(ctx context.Context, input *ValidateClientAndRedirectURIInput) error {
	if len(input.ClientId) == 0 {
		return i18n.NewLocalizedError(i18n.ErrCodeAuthorizeClientIdMissing, nil)
	}

	client, err := val.database.GetClientByClientIdentifier(ctx, nil, input.ClientId)
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
	rtInfo := ParseResponseType(input.ResponseType)

	// Authorization code flow requires AuthorizationCodeEnabled. Implicit flow does not: the
	// actual implicit grant enablement is checked in ValidateRequest, and here the client only
	// needs to be enabled, which is checked above.
	if !rtInfo.IsImplicitFlow() && !client.AuthorizationCodeEnabled {
		return i18n.NewLocalizedError(i18n.ErrCodeAuthorizeAuthCodeNotEnabled, nil)
	}

	// RFC 8252 section 7.3 port flexibility for http loopback redirect URIs is for the
	// authorization code flow only. Without this gate the relaxation would also permit
	// arbitrary loopback ports for implicit responses, which carry tokens directly in the
	// fragment where PKCE cannot mitigate interception.
	//
	// Read as IsCodeOnly rather than as !rtInfo.IsImplicitFlow(), because response_type is not
	// validated until ValidateRequest, which runs after this check, so that negative test is true
	// for "code token" and for garbage such as "foo". IsCodeOnly is true for the exact type "code"
	// alone, which is what scopes loopback port flexibility to the authorization code flow
	// (#41, #244).
	allowLoopbackPortFlexibility := rtInfo.IsCodeOnly()

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
	// dead code rather than defence in depth: urlmatch.RedirectURIIsRegistered admits a value beyond
	// exact equality only when the registered scheme is "http", so no absolute requested value can
	// ever match a non-absolute registered one. Swept 63 registered/requested pairs to confirm it,
	// 0 matched.
	//
	// Placed before ClientLoadRedirectURIs so a garbage value costs no query.
	if !urlmatch.IsAbsoluteRedirectURI(input.RedirectURI) {
		// The client identifier is a bounded stored value, so it is safe to log. The
		// requested URI is unbounded attacker-controlled input and is deliberately left
		// out: the operator reads the offending value off the client's page.
		slog.WarnContext(ctx, "rejected an authorization request whose redirect_uri is not an absolute uri, or is an http or https uri naming no host",
			"client_identifier", client.ClientIdentifier)
		return i18n.NewLocalizedError(i18n.ErrCodeAuthorizeRedirectURINotAbsolute, nil)
	}

	err = val.database.ClientLoadRedirectURIs(ctx, nil, client)
	if err != nil {
		return err
	}

	registered := make([]string, 0, len(client.RedirectURIs))
	for _, r := range client.RedirectURIs {
		registered = append(registered, r.URI)
	}
	if !urlmatch.RedirectURIIsRegistered(registered, input.RedirectURI, allowLoopbackPortFlexibility) {
		return i18n.NewLocalizedError(i18n.ErrCodeAuthorizeRedirectURINotRegistered, nil)
	}
	return nil
}

func (val *AuthorizeValidator) ValidateUnsupportedRequestParameters(input *ValidateUnsupportedRequestParametersInput) error {
	if input.HasRequest {
		return oauth.NewErrorDetailWithHTTPStatus(
			"request_not_supported",
			"The request parameter is not supported.",
			http.StatusBadRequest,
		)
	}
	if input.HasRequestURI {
		return oauth.NewErrorDetailWithHTTPStatus(
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

// SupportedResponseModes is the discovery document's response_modes_supported: the set above, so
// discovery can never advertise a mode ValidateRequest refuses or omit one it accepts (#437). It
// returns a fresh slice, so a caller cannot reach the set.
func SupportedResponseModes() []string {
	return slices.Clone(supportedResponseModes)
}

// supportedResponseTypes are the response_type values ValidateRequest accepts, as discovery and
// the unsupported_response_type description spell them. "token id_token" is accepted too, being the
// same set of tokens (RFC 6749 section 3.1.1: order does not matter); this is the canonical
// spelling of each.
var supportedResponseTypes = []string{"code", "token", "id_token", "id_token token"}

// ImplicitNotAuthorizedErrorMsg is the refusal for a client that may not use the implicit grant. Two
// places emit it: ValidateRequest, which refuses a new request, and /auth/issue, which refuses a
// ceremony whose client had the grant switched off while it sat on a step. They have to say the same
// thing, as ROPCNotAuthorizedErrorMsg does for its two (#197). The global switch is named as
// reaching only a client that inherits it: a client's own Enabled or Disabled wins over it, and
// every self-registered client is Disabled, so "or enable it globally" sent their operators to a
// switch that changes nothing for them (#542 live check).
const ImplicitNotAuthorizedErrorMsg = "The client is not authorized to use the implicit grant type. " +
	"To enable it, go to the client's settings in the admin console under 'OAuth2 flows'. " +
	"The switch in 'Admin > General' enables it only for a client set to inherit the global setting."

// SupportedResponseTypes is the discovery document's response_types_supported. It lists every
// response type the server implements whatever the implicit switch says, as OIDC Discovery 1.0
// section 3 defines the field ("values that this OP supports"); a client not allowed the implicit
// grant is refused unauthorized_client (#437). It returns a fresh slice.
func SupportedResponseTypes() []string {
	return slices.Clone(supportedResponseTypes)
}

func (val *AuthorizeValidator) ValidateRequest(input *ValidateRequestInput) error {

	// Check for empty/missing response_type first
	if input.ResponseType == "" {
		return oauth.NewErrorDetailWithHTTPStatus("invalid_request",
			"The response_type parameter is missing.", http.StatusBadRequest)
	}

	// Then its grammar: values separated by single spaces, with none at either end (RFC 6749
	// 3.1.1). A value of spaces alone is malformed rather than missing: something was sent (#244).
	if err := ValidateSpaceDelimited("response_type", "invalid_request", input.ResponseType); err != nil {
		return err
	}

	// Parse response_type (can be space-separated for OIDC, e.g., "id_token token")
	rtInfo := ParseResponseType(input.ResponseType)
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

	// A value the parser did not recognise, or one it saw twice, makes the request unsupported
	// however many recognised types remain: RFC 6749 3.1.1 makes response_type a list of values
	// and 3.1.2.4 answers one the server does not support with unsupported_response_type. The
	// count above counted "code foo" and "code code" as the single type they collapse to, and
	// accepted both as "code" (#244).
	if rtInfo.Unrecognised || rtInfo.Repeated {
		validResponseType = false
	}

	if !validResponseType {
		return oauth.NewErrorDetailWithHTTPStatus("unsupported_response_type",
			"The authorization server does not support this response_type. Supported values: "+
				strings.Join(supportedResponseTypes, ", ")+".",
			http.StatusBadRequest)
	}

	// Check if implicit flow is authorized for this client
	if isImplicitFlow && !input.ImplicitGrantEnabled {
		return oauth.NewErrorDetailWithHTTPStatus("unauthorized_client",
			ImplicitNotAuthorizedErrorMsg, http.StatusBadRequest)
	}

	// OIDC: id_token requires openid scope
	if rtInfo.HasIdToken {
		if !slices.Contains(oidc.SplitScope(input.Scope), "openid") {
			return oauth.NewErrorDetailWithHTTPStatus("invalid_request",
				"The 'openid' scope is required when requesting an id_token.",
				http.StatusBadRequest)
		}
	}

	// OIDC: nonce is REQUIRED for implicit flow with id_token (OIDC Core 3.2.2.1)
	if rtInfo.HasIdToken && isImplicitFlow && input.Nonce == "" {
		return oauth.NewErrorDetailWithHTTPStatus("invalid_request",
			"The 'nonce' parameter is required for implicit flow when requesting an id_token.",
			http.StatusBadRequest)
	}

	// The two free-form values the ceremony carries to codes.state and codes.nonce. RFC 6749 and
	// OIDC Core set no length on either, so the bound is the columns' (record.StateMaxBytes,
	// record.NonceMaxBytes), and it holds for every response type: the ceremony carries both
	// whatever is issued, and one rule is simpler to state to an integrator than three. Without
	// it a longer value is accepted here and refused by the column, as a 500, at /auth/issue
	// after the user has signed in (#437).
	if err := stateBound.check(input.State); err != nil {
		return err
	}
	if err := nonceBound.check(input.Nonce); err != nil {
		return err
	}

	// PKCE validation only applies to authorization code flow
	if rtInfo.HasCode && !isImplicitFlow {
		// Check if PKCE parameters were provided
		pkceProvided := input.CodeChallengeMethod != "" || input.CodeChallenge != ""

		if input.PKCERequired {
			// PKCE is required - validate that it's provided and correct
			if input.CodeChallengeMethod != "S256" {
				return oauth.NewErrorDetailWithHTTPStatus("invalid_request",
					"PKCE is required. Ensure code_challenge_method is set to 'S256'.", http.StatusBadRequest)
			}

			if !hasPKCELength(input.CodeChallenge) {
				return oauth.NewErrorDetailWithHTTPStatus("invalid_request",
					"The code_challenge parameter is either missing or incorrect. It should be 43 to 128 characters long.",
					http.StatusBadRequest)
			}
			if !isPKCECharset(input.CodeChallenge) {
				return codeChallengeCharsetRefusal()
			}
		} else if pkceProvided {
			// PKCE is optional but was provided - validate format (strict mode)
			if input.CodeChallengeMethod != "S256" {
				return oauth.NewErrorDetailWithHTTPStatus("invalid_request",
					"Invalid code_challenge_method. Only 'S256' is supported.", http.StatusBadRequest)
			}

			if !hasPKCELength(input.CodeChallenge) {
				return oauth.NewErrorDetailWithHTTPStatus("invalid_request",
					"The code_challenge parameter is incorrect. It should be 43 to 128 characters long.",
					http.StatusBadRequest)
			}
			if !isPKCECharset(input.CodeChallenge) {
				return codeChallengeCharsetRefusal()
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
		return oauth.NewErrorDetailWithHTTPStatus("invalid_request",
			"Invalid response_mode parameter. Supported values are: query, fragment, form_post.",
			http.StatusBadRequest)
	}

	// A response type that returns tokens may not be encoded in the query. OAuth 2.0 Multiple
	// Response Type Encoding Practices section 3 says of id_token "the query encoding MUST NOT be
	// used", section 5 says the same of id_token token, and RFC 6749 4.2.2 puts the implicit
	// grant's token response in the fragment. The form_post encoding is a different matter: OAuth 2.0
	// Form Post Response Mode section 4 says "it is safe to return Authorization Response parameters
	// whose default Response Modes are the query encoding or the fragment encoding using the
	// form_post Response Mode", so the request may name it, or the fragment, or nothing (#231).
	if isImplicitFlow && input.ResponseMode == "query" {
		return oauth.NewErrorDetailWithHTTPStatus("invalid_request",
			"Implicit flow does not support response_mode=query. Use response_mode=fragment (the default for implicit flow) or response_mode=form_post.",
			http.StatusBadRequest)
	}

	// A max_age that is not a non-negative integer is an invalid parameter value, which RFC 6749
	// 4.1.2.1 answers with invalid_request. It used to be parsed with strconv.Atoi at every hop and
	// a failure dropped, so "abc" constrained nothing and "-1" forced a login (#243).
	if _, err := oidc.ParseMaxAge(input.MaxAge); err != nil {
		return oauth.NewErrorDetailWithHTTPStatus("invalid_request",
			"The max_age parameter must be a non-negative integer.", http.StatusBadRequest)
	}

	return nil
}

// ValidatePrompt validates and normalizes the OIDC prompt parameter.
// It returns the normalized prompt string (deduplicated, single-space-delimited)
// or an error if the prompt value is malformed, invalid or contains conflicting values.
//
// Per OIDC Core 1.0 Section 3.1.2.1:
// - A space delimited list: one space between each two values, none at either end (#244)
// - Values the specification defines: none, login, consent, select_account
// - prompt=none cannot be combined with other values
// - Other values can be combined (e.g., "login consent")
//
// select_account is a known value this server cannot honour, as it has no way to ask an end user to
// pick one of several accounts. It is answered account_selection_required, the code OIDC Core
// 3.1.2.6 names for "the End-User is REQUIRED to select a session at the Authorization Server",
// rather than invalid_request, which said the value was not one: the request is well formed and the
// server is what cannot serve it. discovery's prompt_values_supported does not list it (#244).
func (val *AuthorizeValidator) ValidatePrompt(prompt string) (string, error) {
	// An empty prompt is valid (treated as absent). One of spaces alone, or padded with them, is not:
	// it used to be trimmed and read as absent or as the value inside (#244).
	if prompt == "" {
		return "", nil
	}
	if err := ValidateSpaceDelimited("prompt", "invalid_request", prompt); err != nil {
		return "", err
	}

	// Parse prompt values (deduplicates)
	values := parsePromptValues(prompt)

	// Validate each value
	validValues := map[string]bool{
		"none":           true,
		"login":          true,
		"consent":        true,
		"select_account": true,
	}

	hasNone := false
	for _, v := range values {
		if !validValues[v] {
			return "", oauth.NewErrorDetailWithHTTPStatus("invalid_request",
				fmt.Sprintf("Invalid prompt value: %s", v), http.StatusBadRequest)
		}
		if v == "none" {
			hasNone = true
		}
	}

	// Check for conflicts: none cannot be combined with other values
	if hasNone && len(values) > 1 {
		return "", oauth.NewErrorDetailWithHTTPStatus("invalid_request",
			"prompt=none cannot be combined with other values", http.StatusBadRequest)
	}

	// After the two refusals above, so that "none select_account" is still the combination error
	// and an unknown value still names itself.
	if slices.Contains(values, "select_account") {
		return "", oauth.NewErrorDetailWithHTTPStatus("account_selection_required",
			"prompt=select_account is not supported: the authorization server cannot ask the end user to select an account.",
			http.StatusBadRequest)
	}

	// Return normalized string (single-space-delimited)
	return strings.Join(values, " "), nil
}

// parsePromptValues parses a well-formed prompt string into individual values, deduplicating them
// while preserving order.
func parsePromptValues(prompt string) []string {
	// The one splitter every space-delimited parameter reads through, so this and the handler's
	// silence test read a prompt the same way (#244).
	fields := oauth.SplitSpaceDelimited(prompt)

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
