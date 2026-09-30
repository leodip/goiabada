package issuance

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/userclaims"
	"github.com/leodip/goiabada/authserver/internal/uuidutil"
	coreconstants "github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/errs"
)

// tokenGenerationInput contains all data needed to generate access/id tokens
// regardless of the OAuth flow being used (auth code, implicit, ROPC).
type tokenGenerationInput struct {
	// User and Client (always required)
	User   *models.User
	Client *models.Client

	// Scope
	Scope string

	// Authentication context
	AcrLevel        models.AcrLevel // e.g., models.AcrLevel1, models.AcrLevel2Optional
	AuthMethods     []string        // e.g., ["pwd"], ["pwd", "otp"]
	AuthenticatedAt time.Time

	// Optional claims
	SessionIdentifier string // Empty means don't include "sid" claim
	Nonce             string // Empty means don't include "nonce" claim
	AccessToken       string // For id_token: if non-empty, include "at_hash" claim (implicit flow)

	// AuthStateGeneration is the generation of the credential that authorized THIS
	// issuance, never the user's current value. Callers set it explicitly, because the
	// correct source differs per flow and reading the convenient one is the bug decision
	// 13 of #106 exists to prevent.
	AuthStateGeneration int64
	// GrantIsOffline suppresses the sid claim on ACCESS tokens only. An offline grant
	// outlives the browser session by design, so binding its access tokens to a session
	// identifier the middleware will later fail to resolve breaks exactly the use case
	// offline_access exists for (#106 decision 9). ID tokens keep sid regardless, because
	// RP-initiated logout matches on it.
	GrantIsOffline bool
}

// generateAccessToken builds an access token for the authorization code flow.
//
// parentRefreshToken is nil on the initial code exchange and set when refreshing. It
// decides both the generation and whether the grant is offline, and it has to: on a
// refresh the code is the wrong source for either. Its generation can lag the token's
// (the token may have been promoted while the code was not), and its scope can differ
// from the request's, since a caller may down-scope offline_access away without the
// grant ceasing to be offline (#106 decisions 9 and 13).
//
// tx is the transaction the grant runs in, nil for one that runs in none, as generateAccessTokenCore
// states. A refresh hands over the one its rotation runs in (#132, #437).
func (t *TokenIssuer) generateAccessToken(ctx context.Context, tx *sql.Tx, settings *models.Settings, code *models.Code, scope string,
	now time.Time, signingKey *rsa.PrivateKey, keyIdentifier string,
	parentRefreshToken *models.RefreshToken) (string, error) {

	input := t.createTokenInputFromCode(code)
	input.Scope = scope // Use the provided scope (may differ from code.Scope for refresh)

	if parentRefreshToken == nil {
		input.AuthStateGeneration = code.AuthStateGeneration
		input.GrantIsOffline = grantIsOffline(code.Scope, code.SessionIdentifier)
	} else {
		input.AuthStateGeneration = parentRefreshToken.AuthStateGeneration
		input.GrantIsOffline = parentRefreshToken.RefreshTokenType == TokenTypeOffline.String()
	}

	return t.generateAccessTokenCore(ctx, tx, settings, input, now, signingKey, keyIdentifier)
}

func (t *TokenIssuer) generateIdToken(ctx context.Context, tx *sql.Tx, settings *models.Settings, code *models.Code, scope string,
	now time.Time, signingKey *rsa.PrivateKey, keyIdentifier string) (string, error) {

	input := t.createTokenInputFromCode(code)
	input.Scope = scope // Use the provided scope (may differ from code.Scope for refresh)
	return t.generateIdTokenCore(ctx, tx, settings, input, now, signingKey, keyIdentifier)
}

// claimMapper builds the user-claims mapper for one token type. The two fields after the port are
// issuance's side of the two divergences userclaims keeps as inputs rather than merging: the base
// URL is the one injected into this issuer, and the include flag is the token type's own (#387
// decision 5). updated_at was a third until it turned out to be a defect: issuance wrote it for
// any scope but a lone openid, and in an access token for a lone openid too, because the audience
// loop used to append a scope to the slice the claim block read. It now rides with the profile
// scope, as it does at /userinfo and as this repository's own documentation has always said.
func (t *TokenIssuer) claimMapper(inclusion userclaims.Inclusion) userclaims.Mapper {
	return userclaims.Mapper{
		Database:  t.database,
		BaseURL:   t.baseURL,
		Inclusion: inclusion,
	}
}

// tokenLifetimeSeconds is how long an access or ID token lives: the client's own lifetime when it
// sets one, else the server's. A client's 0 means it inherits the setting. Every grant reads it
// here; client credentials once kept its own copy of the lifetime and read the setting alone,
// ignoring an override every other grant honoured (#437).
func tokenLifetimeSeconds(settings *models.Settings, client *models.Client) int {
	if client.TokenExpirationInSeconds > 0 {
		return client.TokenExpirationInSeconds
	}
	return settings.TokenExpirationInSeconds
}

// generateAccessTokenCore creates an access token using the unified tokenGenerationInput.
// This is the single implementation used by all OAuth flows (auth code, implicit, ROPC).
//
// tx is the transaction the issuance runs in, nil when it runs in none, and it reaches the one read
// the builder makes, the claim mapper's picture lookup. A caller that holds a transaction hands it
// over, because on sqlitedb's single connection a read on nil waits for the connection that
// transaction holds until the context expires, and the picture claim is dropped without an error
// (#437).
func (t *TokenIssuer) generateAccessTokenCore(ctx context.Context, tx *sql.Tx, settings *models.Settings, input *tokenGenerationInput,
	now time.Time, signingKey *rsa.PrivateKey, keyIdentifier string) (string, error) {

	claims := make(jwt.MapClaims)

	// Standard claims (same for all flows)
	claims["iss"] = settings.Issuer
	claims["sub"] = input.User.Subject
	claims["iat"] = now.Unix()
	claims["nbf"] = now.Unix()
	claims["auth_time"] = input.AuthenticatedAt.Unix()
	claims["jti"] = uuidutil.New()
	claims["acr"] = input.AcrLevel.String()
	// Omit amr rather than signing an empty array. OIDC Core 1.0 section 2 makes amr OPTIONAL, so
	// absent says nothing about how the user authenticated, where "amr": [] positively asserts that
	// no method was used. Reinstating the unconditional assignment would sign that false claim for
	// any grant whose session carries an empty auth_methods, which the column permits (#240).
	if len(input.AuthMethods) > 0 {
		claims["amr"] = input.AuthMethods
	}
	claims["auth_state_generation"] = input.AuthStateGeneration

	// Optional sid claim, suppressed for offline grants: see GrantIsOffline.
	if len(input.SessionIdentifier) > 0 && !input.GrantIsOffline {
		claims["sid"] = input.SessionIdentifier
	}

	scopes := strings.Split(input.Scope, " ")

	// Build audience collection from scopes
	audCollection := []string{}
	for _, s := range scopes {
		if oidc.IsClaimScope(s) {
			// A claim scope is answered at /userinfo, which the authserver resource serves, so it
			// names authserver as an audience. A groups-only grant, which carries no openid and
			// may carry no resource scope, would otherwise have no audience at all.
			if !slices.Contains(audCollection, coreconstants.AuthServerResourceIdentifier) {
				audCollection = append(audCollection, coreconstants.AuthServerResourceIdentifier)
			}
			continue
		}
		if !oidc.IsOfflineAccessScope(s) {
			parts := strings.Split(s, ":")
			if len(parts) != 2 {
				return "", errs.Errorf("invalid scope: %v", s)
			}
			if !slices.Contains(audCollection, parts[0]) {
				audCollection = append(audCollection, parts[0])
			}
		}
	}
	switch {
	case len(audCollection) == 0:
		return "", errs.Errorf("unable to generate an access token without an audience. scope: '%v'", input.Scope)
	case len(audCollection) == 1:
		claims["aud"] = audCollection[0]
	case len(audCollection) > 1:
		claims["aud"] = audCollection
	}

	claims["typ"] = TokenTypeBearer.String()

	tokenExpirationInSeconds := tokenLifetimeSeconds(settings, input.Client)

	claims["exp"] = now.Add(time.Duration(time.Second * time.Duration(tokenExpirationInSeconds))).Unix()
	claims["scope"] = input.Scope

	// Optional nonce claim
	if len(input.Nonce) > 0 {
		claims["nonce"] = input.Nonce
	}

	// OpenID Connect claims in access token (if enabled)
	includeOpenIDConnectClaimsInAccessToken := settings.IncludeOpenIDConnectClaimsInAccessToken
	if input.Client.IncludeOpenIDConnectClaimsInAccessToken == models.ThreeStateSettingOn.String() ||
		input.Client.IncludeOpenIDConnectClaimsInAccessToken == models.ThreeStateSettingOff.String() {
		includeOpenIDConnectClaimsInAccessToken = input.Client.IncludeOpenIDConnectClaimsInAccessToken == models.ThreeStateSettingOn.String()
	}

	mapper := t.claimMapper(userclaims.InclusionAccessToken)

	if slices.Contains(scopes, "openid") && includeOpenIDConnectClaimsInAccessToken {
		mapper.AddOpenIdConnectClaims(ctx, tx, claims, input.User, scopes)
	}

	// groups and attributes (using the IncludeInAccessToken filter), outside the OIDC claim
	// settings above: a client that turned the OIDC claims off still receives these.
	mapper.AddGroupClaims(claims, input.User, scopes)
	mapper.AddAttributeClaims(claims, input.User, scopes)

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyIdentifier
	accessToken, err := token.SignedString(signingKey)
	if err != nil {
		return "", errs.Wrap(err, "unable to sign access_token")
	}
	return accessToken, nil
}

// generateIdTokenCore creates an id_token using the unified tokenGenerationInput.
// This is the single implementation used by all OAuth flows (auth code, implicit, ROPC). tx is
// generateAccessTokenCore's.
func (t *TokenIssuer) generateIdTokenCore(ctx context.Context, tx *sql.Tx, settings *models.Settings, input *tokenGenerationInput,
	now time.Time, signingKey *rsa.PrivateKey, keyIdentifier string) (string, error) {

	claims := make(jwt.MapClaims)

	// Standard claims (same for all flows)
	claims["iss"] = settings.Issuer
	claims["sub"] = input.User.Subject
	claims["iat"] = now.Unix()
	claims["nbf"] = now.Unix()
	claims["auth_time"] = input.AuthenticatedAt.Unix()
	claims["jti"] = uuidutil.New()
	claims["acr"] = input.AcrLevel.String()
	// Omitted when no method was recorded, for the reason given in generateAccessTokenCore (#240).
	if len(input.AuthMethods) > 0 {
		claims["amr"] = input.AuthMethods
	}

	// Optional sid claim
	if len(input.SessionIdentifier) > 0 {
		claims["sid"] = input.SessionIdentifier
	}

	scopes := strings.Split(input.Scope, " ")

	// ID token audience is always the client identifier
	claims["aud"] = input.Client.ClientIdentifier

	tokenExpirationInSeconds := tokenLifetimeSeconds(settings, input.Client)

	claims["exp"] = now.Add(time.Duration(time.Second * time.Duration(tokenExpirationInSeconds))).Unix()

	// Optional nonce claim
	if len(input.Nonce) > 0 {
		claims["nonce"] = input.Nonce
	}

	// Optional at_hash claim (for implicit flow when id_token is issued alongside access_token)
	// Per OIDC Core 3.2.2.10
	if len(input.AccessToken) > 0 {
		claims["at_hash"] = t.calculateAtHash(input.AccessToken)
	}

	// OpenID Connect claims in ID token (if enabled)
	// Per OIDC Core 5.4, scope claims (email, profile, etc.) MAY be in ID tokens
	// but SHOULD be available from /userinfo endpoint for strict conformance.
	includeOpenIDConnectClaimsInIdToken := settings.IncludeOpenIDConnectClaimsInIdToken
	if input.Client.IncludeOpenIDConnectClaimsInIdToken == models.ThreeStateSettingOn.String() ||
		input.Client.IncludeOpenIDConnectClaimsInIdToken == models.ThreeStateSettingOff.String() {
		includeOpenIDConnectClaimsInIdToken = input.Client.IncludeOpenIDConnectClaimsInIdToken == models.ThreeStateSettingOn.String()
	}

	mapper := t.claimMapper(userclaims.InclusionIdToken)

	if includeOpenIDConnectClaimsInIdToken {
		mapper.AddOpenIdConnectClaims(ctx, tx, claims, input.User, scopes)
	}

	// groups and attributes (using the IncludeInIdToken filter), outside the OIDC claim setting
	// above, as they are in the access token.
	mapper.AddGroupClaims(claims, input.User, scopes)
	mapper.AddAttributeClaims(claims, input.User, scopes)

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyIdentifier
	idToken, err := token.SignedString(signingKey)
	if err != nil {
		return "", errs.Wrap(err, "unable to sign id_token")
	}
	return idToken, nil
}

// createTokenInputFromCode creates a tokenGenerationInput from an authorization code.
// Used by the authorization code flow.
func (t *TokenIssuer) createTokenInputFromCode(code *models.Code) *tokenGenerationInput {
	return &tokenGenerationInput{
		User:              &code.User,
		Client:            &code.Client,
		Scope:             code.Scope,
		AcrLevel:          code.AcrLevel,
		AuthMethods:       authMethodsToArray(code.AuthMethods),
		AuthenticatedAt:   code.AuthenticatedAt,
		SessionIdentifier: code.SessionIdentifier,
		Nonce:             code.Nonce,
	}
}

// createTokenInputFromImplicit creates a tokenGenerationInput from an ImplicitGrantInput.
// Used by the implicit flow (deprecated in OAuth 2.1).
func (t *TokenIssuer) createTokenInputFromImplicit(input *ImplicitGrantInput) *tokenGenerationInput {
	return &tokenGenerationInput{
		User:              input.User,
		Client:            input.Client,
		Scope:             input.Scope,
		AcrLevel:          input.AcrLevel,
		AuthMethods:       authMethodsToArray(input.AuthMethods),
		AuthenticatedAt:   input.AuthenticatedAt,
		SessionIdentifier: input.SessionIdentifier,
		Nonce:             input.Nonce,

		AuthStateGeneration: input.AuthStateGeneration,
		// Implicit is always session-bound: there is no refresh token, so nothing outlives
		// the session and sid stays on the access token.
		GrantIsOffline: false,
	}
}

// createTokenInputFromROPC creates a tokenGenerationInput from an ROPCGrantInput.
// Used by the ROPC flow (deprecated in OAuth 2.1).
// ROPC always uses password-only authentication (ACR: urn:goiabada:level1, AMR: ["pwd"]).
//
// Level 1 because that is what password-only means in discovery's acr_values_supported and on the
// docs site's ACR page. Until #433 this wrote urn:goiabada:pwd, a value outside both that nothing
// reads back; OIDC Core 1.0 section 2 leaves acr values to the parties, so the published list is
// the contract, and a value outside it tells a client nothing it can check.
func (t *TokenIssuer) createTokenInputFromROPC(input *ROPCGrantInput) *tokenGenerationInput {
	return &tokenGenerationInput{
		User:              input.User,
		Client:            input.Client,
		Scope:             input.Scope,
		AcrLevel:          models.AcrLevel1,
		AuthMethods:       []string{oidc.AuthMethodPassword.String()},
		AuthenticatedAt:   input.AuthenticatedAt,
		SessionIdentifier: "", // ROPC is sessionless: see ROPCGrantInput
		Nonce:             "", // ROPC doesn't use nonce
	}
}

// calculateAtHash computes the at_hash claim per OIDC Core 3.2.2.10
// at_hash = base64url(left_half(SHA256(access_token)))
func (t *TokenIssuer) calculateAtHash(accessToken string) string {
	hash := sha256.Sum256([]byte(accessToken))
	leftHalf := hash[:len(hash)/2] // Left-most half (16 bytes for SHA256)
	return base64.RawURLEncoding.EncodeToString(leftHalf)
}

// generateROPCAccessToken creates an access token for ROPC flow.
// generateROPCAccessToken builds an access token for the ROPC flow.
//
// parentRefreshToken is nil on the initial password grant, where the generation comes from
// the User snapshot the password validation returned, and set when refreshing, where it
// comes from the parent token. The distinction matters because the refresh path reloads
// the user: reading that reloaded user would stamp a grant authenticated under an older
// generation with the current one, laundering it forward (#106 decision 13).
//
// ROPC grants are always offline, so no access token here ever carries sid.
func (t *TokenIssuer) generateROPCAccessToken(ctx context.Context, tx *sql.Tx, settings *models.Settings, input *ROPCGrantInput, scope string,
	now time.Time, signingKey *rsa.PrivateKey, keyIdentifier string,
	parentRefreshToken *models.RefreshToken) (string, error) {

	tokenInput := t.createTokenInputFromROPC(input)
	tokenInput.Scope = scope // Use the provided scope
	tokenInput.GrantIsOffline = true

	if parentRefreshToken == nil {
		tokenInput.AuthStateGeneration = input.User.AuthStateGeneration
	} else {
		tokenInput.AuthStateGeneration = parentRefreshToken.AuthStateGeneration
	}

	return t.generateAccessTokenCore(ctx, tx, settings, tokenInput, now, signingKey, keyIdentifier)
}

// generateROPCIdToken creates an id_token for ROPC flow.
func (t *TokenIssuer) generateROPCIdToken(ctx context.Context, tx *sql.Tx, settings *models.Settings, input *ROPCGrantInput, scope string,
	now time.Time, signingKey *rsa.PrivateKey, keyIdentifier string) (string, error) {

	tokenInput := t.createTokenInputFromROPC(input)
	tokenInput.Scope = scope // Use the provided scope
	return t.generateIdTokenCore(ctx, tx, settings, tokenInput, now, signingKey, keyIdentifier)
}

// authMethodsToArray converts a space-separated auth methods string to a JSON array
// as required by OIDC Core 1.0 Section 2. The amr claim MUST be a JSON array of strings.
//
// Examples:
//   - "pwd" -> ["pwd"]
//   - "pwd otp" -> ["pwd", "otp"]
//   - "" -> []
func authMethodsToArray(authMethods string) []string {
	if authMethods == "" {
		return []string{}
	}
	return strings.Fields(authMethods)
}
