package issuance

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/uuid"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
)

// ErrPasswordGrantClientRenamed is returned by IssuePasswordGrant when the client the request named
// no longer holds that identifier by the time the grant writes its first refresh token: a rename
// committed in between, or a deletion. Nothing is issued. The token endpoint answers it as it
// answers a request naming an identifier no client holds, invalid_client (#710 decision 5). A
// package-level sentinel on stdlib errors.New, for the reason ErrIssuingClientGone states.
var ErrPasswordGrantClientRenamed = errors.New("the client the password grant named no longer holds that identifier")

// ROPCGrantInput contains the parameters needed to generate tokens for ROPC flow.
// RFC 6749 Section 4.3 - Resource Owner Password Credentials Grant
// SECURITY NOTE: ROPC is deprecated in OAuth 2.1 due to credential exposure risks.
// ROPCGrantInput carries the parameters for a password grant.
//
// There is deliberately NO session identifier here. ROPC has no browser session: the
// grant is a direct credential exchange. A field used to exist, populated from whatever
// session cookie happened to accompany the request, and it reached the ID token, so a
// password grant for one user could be handed an ID token carrying a DIFFERENT user's
// session identifier whenever the browser was logged in as somebody else. Nothing needed
// it: ROPC refresh tokens are always Offline type and store a max lifetime rather than a
// session identifier, and the refresh path already hard-coded it empty. Removed rather
// than defaulted, so it cannot be reintroduced by an eager caller (#106).
type ROPCGrantInput struct {
	Client *record.Client
	User   *record.User
	Scope  string
	// AuthenticatedAt is when the password was checked, and so what every token of the grant
	// issues as auth_time. The issuer writes it, not the caller: IssuePasswordGrant
	// stamps the moment of the password grant, and a refresh copies the instant its parent
	// token recorded (#125).
	AuthenticatedAt time.Time
	// DPoPThumbprint binds the access token to the request's proof key, empty for a bearer token, and
	// a public client's refresh token too (#42 decision 11).
	DPoPThumbprint string
}

// IssuePasswordGrant creates tokens for Resource Owner Password Credentials flow.
// RFC 6749 Section 4.3
// SECURITY NOTE: ROPC is deprecated in OAuth 2.1 due to credential exposure risks.
//
// Unlike implicit flow, ROPC issues refresh tokens.
// ROPC refresh tokens store UserID and ClientID directly (no Code entity needed).
//
// The response is the token endpoint's one wire shape, as every other grant's is. A struct of
// its own used to differ only in three omitempty tags, on the access token, token type and
// expires_in, none of which is ever empty here: the settings refuse a lifetime of 0 or less, and
// a client's 0 means it inherits that setting (#437).
func (t *TokenIssuer) IssuePasswordGrant(ctx context.Context, settings *record.Settings,
	input *ROPCGrantInput) (*oauth.TokenResponse, error) {

	tokenExpirationInSeconds := tokenLifetimeSeconds(settings, input.Client)

	response := &oauth.TokenResponse{
		TokenType: ResponseTokenType(input.DPoPThumbprint),
		ExpiresIn: int64(tokenExpirationInSeconds),
	}

	privKey, keyIdentifier, err := t.loadSigningKey(ctx, nil)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()

	// Load user groups and attributes for token claims
	err = t.database.UserLoadGroups(ctx, nil, input.User)
	if err != nil {
		return nil, err
	}

	err = t.database.GroupsLoadAttributes(ctx, nil, input.User.Groups)
	if err != nil {
		return nil, err
	}

	err = t.database.UserLoadAttributes(ctx, nil, input.User)
	if err != nil {
		return nil, err
	}

	// The password was checked for this request, so this is the authentication instant. The first
	// refresh token records it, and every refresh carries it forward (#125). A copy, so the
	// caller's input is not written through.
	grant := *input
	grant.AuthenticatedAt = now
	input = &grant

	// The grant's identifier is the jti its first refresh token takes, fixed before the access token
	// that names it (#676 decision 1).
	grantID := uuid.New()

	// Generate access token
	// nil parent: initial password grant, so the validated User snapshot is the source.
	accessTokenStr, err := t.generateROPCAccessToken(ctx, nil, settings, input, input.Scope, now, privKey, keyIdentifier, nil, grantID)
	if err != nil {
		return nil, err
	}
	response.AccessToken = accessTokenStr
	response.Scope = input.Scope

	// Generate id_token if openid scope is present
	scopes := strings.Split(input.Scope, " ")
	if slices.Contains(scopes, "openid") {
		idTokenStr, idTokenErr := t.generateROPCIDToken(ctx, nil, settings, input, input.Scope, now, privKey, keyIdentifier)
		if idTokenErr != nil {
			return nil, idTokenErr
		}
		response.IDToken = idTokenStr
	}

	// The first refresh token, with direct UserID/ClientID (no Code entity needed), written in a
	// transaction that first takes the client's row with a locking read, which writes nothing, and
	// reads the identifier again. A rename of the client revokes its grants in the rename's
	// transaction, and a password grant has no code for that sweep to mark and, until this row is
	// written, no family to record, so the row is what orders the two (#710 decision 5): either this
	// commits first and the rename's sweep finds the token, or the rename commits first and this
	// reads the identifier it gave the client. Then the request named an identifier the client no
	// longer holds, and the grant is refused with nothing issued: the access and ID tokens signed
	// above are never handed out. A client deleted meanwhile is refused the same way.
	//
	// Compared byte for byte with the copy the token endpoint loaded by the identifier the request
	// named, which is the row's own spelling, so an engine's case-folding lookup cannot make an
	// unchanged client look renamed, and a rename that changed only the case is one.
	//
	// Opened through RunInTransaction, so a deadlock reruns the read and the insert together (#301).
	// Safe to rerun: the body reads the row afresh and writes one fixed row, and the token it signs is
	// the committing attempt's.
	var refreshToken string
	var refreshExpiresIn int64
	err = t.database.RunInTransaction(ctx, func(tx *sql.Tx) error {
		current, readErr := t.database.GetClientByIDForUpdate(ctx, tx, input.Client.ID)
		if readErr != nil {
			return readErr
		}
		if current == nil || current.ClientIdentifier != input.Client.ClientIdentifier {
			return errs.WithStack(ErrPasswordGrantClientRenamed)
		}
		var writeErr error
		refreshToken, refreshExpiresIn, writeErr = t.generateRefreshTokenForROPC(ctx, tx, settings, input, input.Scope, now, privKey, keyIdentifier, nil, grantID)
		return writeErr
	})
	if err != nil {
		return nil, err
	}
	response.RefreshToken = refreshToken
	response.RefreshExpiresIn = refreshExpiresIn

	return response, nil
}
