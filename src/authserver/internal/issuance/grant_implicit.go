package issuance

import (
	"context"
	"crypto/rsa"
	"database/sql"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// ImplicitGrantInput contains the parameters needed to generate tokens for implicit flow.
// SECURITY NOTE: Implicit flow is deprecated in OAuth 2.1.
type ImplicitGrantInput struct {
	Client *record.Client
	User   *record.User
	Scope  string
	// AcrLevel and AuthMethods are what the tokens' acr and amr claims are written from.
	AcrLevel    record.AcrLevel
	AuthMethods string
	// SessionIdentifier is the session the tokens are bound to, through their sid claim, and the
	// row IssueImplicit takes before it signs anything. An identifier with no row is refused
	// ErrIssuingSessionGone, as it is for a code; an empty one is a caller's bug that
	// AcquireUserSessionRow reports as an error, and /auth/issue never reaches the issuer with
	// one, since a ceremony with no session is refused before it (#197).
	SessionIdentifier string
	Nonce             string
	AuthenticatedAt   time.Time
	// AuthStateGeneration comes from the AuthContext. Implicit issues no refresh token,
	// so this ceremony's own generation is the only possible source (#106 decision 13).
	AuthStateGeneration int64
}

// ImplicitGrantResponse contains the tokens generated for implicit flow.
// Per RFC 6749 4.2.2, NO refresh token is issued for implicit flow.
type ImplicitGrantResponse struct {
	AccessToken string
	IdToken     string
	TokenType   string
	ExpiresIn   int64
	Scope       string
}

// IssueImplicitTx signs the tokens of the OAuth2/OIDC implicit flow in a transaction it opens and
// commits, through IssueImplicit. Per RFC 6749 4.2.2, NO refresh token is issued.
// SECURITY NOTE: Implicit flow is deprecated in OAuth 2.1.
//
// ErrIssuingSessionGone leaves the body as an error, so nothing is committed and the helper rolls
// back once and hands it straight back: it is not a deadlock, so it is not rerun. It reaches the
// caller only AFTER that rollback, and the order is not optional, for the reason
// IssueAuthCodeTx states: /auth/issue answers it through the server-side session store, which
// writes on a nil transaction, and on SQLite the whole process shares the one connection this
// transaction holds (#139).
func (t *TokenIssuer) IssueImplicitTx(ctx context.Context, settings *record.Settings,
	input *ImplicitGrantInput, issueAccessToken bool, issueIdToken bool) (*ImplicitGrantResponse, error) {

	// Opened through RunInTransaction, so a deadlock reruns the body (#301). It is safe to rerun:
	// input is only read, the user's groups and attributes are loaded afresh each time, and
	// response is whatever the attempt that committed signed.
	var response *ImplicitGrantResponse
	err := t.database.RunInTransaction(ctx, func(tx *sql.Tx) error {
		var err error
		response, err = t.IssueImplicit(ctx, tx, settings, input, issueAccessToken, issueIdToken)
		return err
	})
	if err != nil {
		return nil, err
	}
	return response, nil
}

// IssueImplicit takes the session row the tokens are bound to and then signs them, every statement
// on the caller's transaction, which is REQUIRED for the reason IssueAuthCode states: the
// acquisition orders this ceremony against a termination of that session only while the row is
// held, and an autocommitted statement releases it at once (#139). IssueImplicitTx is the caller
// that opens one; this form exists so the data tier's ordering test can hold the transaction open
// across a termination's arrival and still run the statements that ship.
//
// Implicit writes no row, so what the acquisition protects is the signing itself. A termination
// that committed first leaves no row, and the tokens are not signed; one that arrives later waits
// for this commit, so the tokens were signed while the session was alive, and the termination
// ends the session they name through their sid claim. Before #197 an implicit ceremony read the
// session once, several statements ahead of the signing, and a termination that committed in the
// gap was invisible to it; an implicit ceremony with no session identifier at all was exempt from
// the check, and signed tokens naming no session that could ever be ended.
//
// Every read below runs on tx and none may be reverted to nil. sqlitedb sets SetMaxOpenConns(1), so
// a read issued on nil while tx holds the single connection waits for a connection tx itself owns:
// a hang rather than an error, and where the read is the claim mapper's picture lookup, which
// swallows its failure, a picture claim that is silently dropped instead (#139, #437).
//
// This is the ordering #139 keeps on purpose, applied to the flow that mints no code, and no other
// is imposed: concurrent transactions on the same account can still deadlock on MySQL,
// PostgreSQL or SQL Server, and RunInTransaction reruns the loser. Do not add ordering here to
// prevent a deadlock; add a test that forces it and shows the retry resolves it (#301).
func (t *TokenIssuer) IssueImplicit(ctx context.Context, tx *sql.Tx, settings *record.Settings,
	input *ImplicitGrantInput, issueAccessToken bool, issueIdToken bool) (*ImplicitGrantResponse, error) {

	if tx == nil {
		return nil, errs.New("issuing implicit tokens requires a transaction: the session row it takes first is released by an autocommitted statement")
	}

	// Existence only, as IssueAuthCode asks it: ownership and the two timeouts were asked by the
	// caller a few statements ago, and the only thing this narrower question misses is an idle
	// timeout elapsing in the microseconds between the two (#139 decision 7).
	live, err := t.database.AcquireUserSessionRow(ctx, tx, input.SessionIdentifier)
	if err != nil {
		return nil, err
	}
	if !live {
		// Nothing has been signed, so nothing is left behind.
		return nil, errs.WithStack(ErrIssuingSessionGone)
	}

	tokenExpirationInSeconds := tokenLifetimeSeconds(settings, input.Client)

	response := &ImplicitGrantResponse{
		TokenType: TokenTypeBearer.String(),
		ExpiresIn: int64(tokenExpirationInSeconds),
	}

	privKey, keyIdentifier, err := t.loadSigningKey(ctx, tx)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()

	// Load user groups and attributes for token claims
	err = t.database.UserLoadGroups(ctx, tx, input.User)
	if err != nil {
		return nil, err
	}

	err = t.database.GroupsLoadAttributes(ctx, tx, input.User.Groups)
	if err != nil {
		return nil, err
	}

	err = t.database.UserLoadAttributes(ctx, tx, input.User)
	if err != nil {
		return nil, err
	}

	response.Scope = input.Scope

	// Generate access token if requested (response_type contains "token")
	if issueAccessToken {
		accessToken, err := t.generateImplicitAccessToken(ctx, tx, settings, input, now, privKey, keyIdentifier)
		if err != nil {
			return nil, err
		}
		response.AccessToken = accessToken
	}

	// Generate id_token if requested (response_type contains "id_token")
	if issueIdToken {
		// For id_token token response, include at_hash in id_token (OIDC Core 3.2.2.10)
		idToken, err := t.generateImplicitIdToken(ctx, tx, settings, input, now, privKey, keyIdentifier, response.AccessToken)
		if err != nil {
			return nil, err
		}
		response.IdToken = idToken
	}

	return response, nil
}

// generateImplicitAccessToken creates an access token for implicit flow.
func (t *TokenIssuer) generateImplicitAccessToken(ctx context.Context, tx *sql.Tx, settings *record.Settings,
	input *ImplicitGrantInput, now time.Time, signingKey *rsa.PrivateKey, keyIdentifier string) (string, error) {

	tokenInput := t.createTokenInputFromImplicit(input)
	return t.generateAccessTokenCore(ctx, tx, settings, tokenInput, now, signingKey, keyIdentifier)
}

// generateImplicitIdToken creates an id_token for implicit flow.
// Per OIDC Core 3.2.2.10, at_hash is REQUIRED when id_token is issued alongside access_token.
func (t *TokenIssuer) generateImplicitIdToken(ctx context.Context, tx *sql.Tx, settings *record.Settings,
	input *ImplicitGrantInput, now time.Time, signingKey *rsa.PrivateKey, keyIdentifier string, accessToken string) (string, error) {

	tokenInput := t.createTokenInputFromImplicit(input)
	tokenInput.AccessToken = accessToken // For at_hash claim
	return t.generateIdTokenCore(ctx, tx, settings, tokenInput, now, signingKey, keyIdentifier)
}
