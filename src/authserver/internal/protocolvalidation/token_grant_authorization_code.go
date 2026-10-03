package protocolvalidation

import (
	"context"
	"net/http"
	"time"

	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/urlutil"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/oauth"
)

// AuthorizationCodeGrant is a validated code redemption: the code, loaded with its client and user,
// not yet claimed. The claim is the issuer's, and it is what makes the redemption single-use (#77).
type AuthorizationCodeGrant struct {
	Code *models.Code
}

func (*AuthorizationCodeGrant) GrantType() oidc.GrantType { return oidc.GrantTypeAuthorizationCode }

// AuthorizationCodeNotSupportedErrorMsg is the refusal for a client that may not use the authorization
// code flow. Two places emit it: the token endpoint, which refuses a redemption, and /auth/issue, which
// refuses a ceremony whose client had the flow switched off while it sat on a step. They have to say
// the same thing, because an operator switching the flow off is doing one act with two consequences.
// Exported for the second user, which lives in the handlers package (#197).
const AuthorizationCodeNotSupportedErrorMsg = "The client associated with the provided client_id does not support authorization code flow."

// validateAuthorizationCodeGrant validates a code redemption (RFC 6749 section 4.1.3) for a client
// ValidateTokenRequest has already found and found enabled.
func (val *TokenValidator) validateAuthorizationCodeGrant(ctx context.Context, client *models.Client,
	input *ValidateTokenRequestInput) (*AuthorizationCodeGrant, error) {
	if !client.AuthorizationCodeEnabled {
		return nil, oauth.NewErrorDetailWithHTTPStatus("unauthorized_client",
			AuthorizationCodeNotSupportedErrorMsg, http.StatusBadRequest)
	}

	if len(input.Code) == 0 {
		return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_request",
			"Missing required code parameter.", http.StatusBadRequest)
	}

	if len(input.RedirectURI) == 0 {
		return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_request",
			"Missing required redirect_uri parameter.", http.StatusBadRequest)
	}

	// Note: code_verifier validation is done later after loading the code entity
	// to check if PKCE was used during authorization

	codeHash := hashutil.HashString(input.Code)
	codeEntity, err := val.database.GetCodeByCodeHash(ctx, nil, codeHash, false)
	if err != nil {
		return nil, err
	}

	// If the code was not found among unused codes, retry against the full
	// code set to detect reuse. We can only act on a reuse hit after the
	// request authenticates against the used code (client_id + redirect_uri
	// + client_secret/PKCE); otherwise an attacker could force-revoke a
	// victim's session by replaying observed codes with wrong credentials.
	wasReused := false
	if codeEntity == nil {
		codeEntity, err = val.database.GetCodeByCodeHash(ctx, nil, codeHash, true)
		if err != nil {
			return nil, err
		}
		if codeEntity == nil {
			return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant", "Code is invalid.",
				http.StatusBadRequest)
		}
		wasReused = true
	}

	if codeEntity.RedirectURI != input.RedirectURI {
		return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant", "Invalid redirect_uri.",
			http.StatusBadRequest)
	}

	err = val.database.CodeLoadClient(ctx, nil, codeEntity)
	if err != nil {
		return nil, err
	}

	err = val.database.CodeLoadUser(ctx, nil, codeEntity)
	if err != nil {
		return nil, err
	}

	if codeEntity.Client.ClientIdentifier != input.ClientId {
		return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
			"The client_id provided does not match the client_id from code.",
			http.StatusBadRequest)
	}

	err = val.authenticateClient(client, input.ClientSecret)
	if err != nil {
		return nil, err
	}

	// The PKCE boundary for a public client (#245). A public client authenticates with
	// nothing, so a code that carries no challenge is bound to nothing and whoever presents
	// it gets the tokens: that is the parameter-stripping attack in RFC 9700 section 4.8.1.
	// Refusing it here is what reaches a code minted before the rule existed, and a code
	// minted while the client was still confidential and redeemed after it became public.
	//
	// Keyed on IsPublic, read now, rather than on IsPKCERequired. Keying on the requirement
	// would refuse every outstanding grant of a CONFIDENTIAL client whose administrator
	// merely turns PKCE on, as a side effect of hardening, and those grants are still
	// authenticated by the secret.
	//
	// Empty counts as absent: the column is nullable and an empty string reaches it, so a
	// .Valid check with no != "" beside it would let one of the two states through.
	//
	// invalid_grant per RFC 6749 section 5.2, which covers a grant that is invalid. The
	// description is plain rather than generic like the refusals below: a caller already
	// knows whether its own client is public and whether it sent a verifier, so this leaks
	// nothing.
	if client.IsPublic && (!codeEntity.CodeChallenge.Valid || codeEntity.CodeChallenge.String == "") {
		return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
			"This code was issued without PKCE, and public clients are required to use PKCE. Please start a new authorization request with a code_challenge.",
			http.StatusBadRequest)
	}

	// PKCE validation: if code_challenge was stored, code_verifier is required
	if codeEntity.CodeChallenge.Valid && codeEntity.CodeChallenge.String != "" {
		// PKCE was used during authorization - verify the code_verifier
		if len(input.CodeVerifier) == 0 {
			return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_request",
				"Missing required code_verifier parameter.", http.StatusBadRequest)
		}

		// The verifier's grammar is RFC 7636 4.1's, checked here rather than left to the comparison:
		// a value outside it was never a verifier, whatever it hashes to. It sits with the
		// comparison, below client authentication and above the reuse return and every account
		// check, so it answers about the verifier alone and reads nothing of the account (#137,
		// #244).
		if !isPKCEValue(input.CodeVerifier) {
			return nil, codeVerifierMalformedRefusal()
		}

		codeChallenge := oauth.GeneratePKCECodeChallenge(input.CodeVerifier)
		if codeEntity.CodeChallenge.String != codeChallenge {
			return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
				"Invalid code_verifier (PKCE).", http.StatusBadRequest)
		}
	} else if len(input.CodeVerifier) > 0 {
		// PKCE was not used during authorization but code_verifier was provided
		// This is an error - strict mode
		return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_request",
			"The code_verifier parameter was provided, but PKCE was not used during authorization.", http.StatusBadRequest)
	}
	// If PKCE was not used and code_verifier was not provided, that's fine

	if wasReused {
		return nil, &AuthCodeReusedError{
			Detail: oauth.NewErrorDetailWithHTTPStatus("invalid_grant", "Code is invalid.",
				http.StatusBadRequest),
			Code: codeEntity,
		}
	}

	// Everything from here to the end of the method reads the state of the grant or of its user,
	// and all of it sits below client authentication and PKCE, so a presenter holding a stolen
	// code learns from the answer whether that state moved only after proving it may redeem the
	// code. Until #137 the user-enabled, generation and expiry checks ran above both, and a wrong
	// verifier answered "Invalid code_verifier (PKCE)." for an untouched account and "Code is
	// invalid." for one whose password had changed: the wording was generic, but which of the two
	// came back was the signal. A check added above authentication reopens that.
	//
	// All of it also sits below the wasReused return, so #77's containment cascade is not
	// pre-empted by a refusal that happens to apply to the used code as well. Reuse is the
	// stronger signal and already revokes everything these would have refused, and the reuse
	// error carries the code entity that drives revocation.RevokeOnAuthCodeReuseTx.

	// A disabled user's code is refused with the flat wording the generation check below gives,
	// never with one naming the account (#137). UserDisabledError is what still tells the handler
	// to write EventUserDisabled.
	if !codeEntity.User.Enabled {
		return nil, userDisabled("Code is invalid.")
	}

	// The generation boundary (#106). A code carries the generation its ceremony
	// authenticated under, so a code issued before a credential change no longer
	// matches and cannot be redeemed. That covers both an outstanding code and a
	// ceremony that straddled the change, neither of which the revocation sweep can
	// reach: the sweep can only act on rows that exist when it runs.
	if codeEntity.AuthStateGeneration != codeEntity.User.AuthStateGeneration {
		return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
			"Code is invalid.", http.StatusBadRequest)
	}

	// Named plainly, unlike the refusals around it: a code's age says nothing about the account,
	// and the caller has proved it may redeem the code, so it knows when it was issued.
	const authCodeExpirationInSeconds = 60
	if time.Now().UTC().After(codeEntity.CreatedAt.Time.Add(time.Second * time.Duration(authCodeExpirationInSeconds))) {
		return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
			"Code has expired.", http.StatusBadRequest)
	}

	// The termination boundary (#129 decision 4). Ending a session marks every code
	// that session authorized, so a code marked here belongs to a grant that was
	// explicitly cut off.
	if codeEntity.Revoked {
		return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
			"Code is invalid.", http.StatusBadRequest)
	}

	// The ownership boundary (#133). A ceremony can no longer bind a code to a session
	// belonging to somebody else, so nothing minted after that fix can reach this. What it
	// catches is a code minted before it, in the window between an account switch and the
	// upgrade: the browser held A's session, B authenticated, and the code carries B as its
	// user with A's session identifier stamped on it.
	//
	// Redeeming one yields tokens that name B correctly, and only one claim on them is
	// wrong. amr and auth_time came from B's own ceremony: the password handler set
	// AuthenticatedAt, and BumpUserSession overwrote the session's methods with B's.
	// acr is the inherited one, because SetAcrLevel took the maximum of the target and
	// A's session level, so the grant can claim a second factor B never presented.
	// createTokenInputFromCode re-copies the code's acr on every rotation, so that one
	// false claim persists for the life of the grant rather than decaying.
	//
	// Three conditions, and the last two are what stop this refusing anything legitimate:
	// the code names a session at all, that row still exists, and it belongs to someone
	// else. A missing row is accepted DELIBERATELY. Sessions are swept once they idle out
	// or reach their maximum lifetime, so "gone" is the ordinary state of the session
	// behind an older grant, and refusing on absence would break every one of them. The
	// cost of that choice is stated: this reaches a pre-fix grant only while its session
	// row survives, which by default is two hours of idling or twenty-four of lifetime.
	//
	// Both columns compared are NOT NULL, so the zero-equals-zero vacuity that an
	// incomplete test fixture can produce cannot arise against a real database.
	if codeEntity.SessionIdentifier != "" {
		codeSession, getUserSessionErr := val.database.GetUserSessionBySessionIdentifier(ctx, nil, codeEntity.SessionIdentifier)
		if getUserSessionErr != nil {
			return nil, getUserSessionErr
		}
		if codeSession != nil && codeSession.UserId != codeEntity.UserId {
			return nil, oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
				"Code is invalid.", http.StatusBadRequest)
		}
	}

	// The registration boundary (#241 decision 5). The comparison near the top of this arm
	// weighs the submitted redirect_uri against the one stored on the code, and the stored
	// one is a copy taken at minting that nothing ever rematches against the client. So
	// without this, a code delivered one second before an administrator removes a callback
	// is still redeemable for the rest of its 60 second life, and the tokens it yields
	// outlive that by their whole lifetime.
	//
	// Read from the client loaded and authenticated at the top of ValidateTokenRequest,
	// whose identifier this arm has already matched against the code's.
	//
	// The flexibility flag is unconditionally TRUE here, and needs no response type to reach
	// that: a code exists only for response_type=code. ValidateRequest admits exactly code,
	// token, id_token and id_token token, and the last three are dispatched to the implicit
	// branch, which mints none, so holding a code IS the proof of the code flow. The error
	// emitter's gate reaches the same rule from the other side, deriving the flag from the
	// ceremony's response type, because it runs where no code exists yet to prove it
	// (redirectWillBeEmitted). RFC 8252 flexibility is therefore required rather
	// than optional here, because a native app's code stores the requested URI with its
	// ephemeral loopback port and would never exact-match the registered portless form. It
	// can only be more permissive than the gate this same stored value already passed at
	// /auth/authorize, so it admits nothing that was refused there.
	//
	// Placed at the very END of the arm, below the revoked and ownership checks, and below
	// client authentication and PKCE for the #137 reason the group's opening comment gives: an
	// unauthenticated presenter of a stolen code must not learn from the answer whether the
	// grant's state moved. Last rather than merely late because this is the one refusal about
	// the grant's state that says what happened; a revoked or cross-bound code must keep the
	// flat "Code is invalid." it has today, and it would not if this ran first.
	//
	// A failed load is PROPAGATED, not read as a refusal, matching the ownership lookup
	// above: an unreachable database says nothing about whether the URI is registered.
	err = val.database.ClientLoadRedirectURIs(ctx, nil, client)
	if err != nil {
		return nil, err
	}
	registered := make([]string, 0, len(client.RedirectURIs))
	for _, redirectURI := range client.RedirectURIs {
		registered = append(registered, redirectURI.URI)
	}
	if !urlutil.RedirectURIIsRegistered(registered, codeEntity.RedirectURI, true) {
		return nil, ErrCodeRedirectURIDeregistered
	}

	return &AuthorizationCodeGrant{Code: codeEntity}, nil
}
