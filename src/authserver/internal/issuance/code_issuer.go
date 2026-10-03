package issuance

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/useragent"
	"github.com/leodip/goiabada/authserver/internal/uuidutil"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/securerandom"
)

// ErrIssuingClientGone is returned by IssueAuthCode when the client the ceremony is issuing for
// no longer has a row. It is a sentinel rather than a wrapped message because /auth/issue branches
// on it: the condition is the client's registration disappearing mid-ceremony, which is answered
// by restarting the browser at level 1 (or login_required for a silent request), not by a 500.
//
// Stdlib errors.New and not errs.New, which is the rule for every package-level sentinel in
// this tree: errs.New captures a stack where it is called, and a package-level var is called
// during init, so the frames would be runtime.doInit rather than the site that raised it. Worse,
// errs.WithStack is the identity on an error whose tree already carries a stack, so the
// WithStack below would silently record nothing. Matched with errors.Is, so it loses no
// diagnosis by having no frames of its own (#279 decision 5).
var ErrIssuingClientGone = errors.New("the client this ceremony is issuing for no longer exists")

// ErrIssuingSessionGone is returned by IssueAuthCode, and by IssueImplicit for the tokens it signs,
// when the session the ceremony binds its grant to no longer has a row. /auth/issue answers it as
// it answers ErrIssuingClientGone: the browser restarts at level 1, or a silent request is told
// login_required. What removed the row cannot be told from here, which is #129's own finding: an
// explicit termination, a logout in another tab and either background reaper all look alike (#139
// decisions 3 and 9). A package-level sentinel on stdlib errors.New, for the reason
// ErrIssuingClientGone states.
var ErrIssuingSessionGone = errors.New("the session this ceremony is issuing for no longer exists")

// codeIssuerDatabase is what the code issuer needs: the session row it takes, the client it issues
// for, the code row it writes, and the transaction the three share.
type codeIssuerDatabase interface {
	AcquireUserSessionRow(ctx context.Context, tx *sql.Tx, sessionIdentifier string) (bool, error)
	CreateCode(ctx context.Context, tx *sql.Tx, code *models.Code) error
	GetClientByClientIdentifier(ctx context.Context, tx *sql.Tx, clientIdentifier string) (*models.Client, error)
	RunInTransaction(ctx context.Context, fn func(tx *sql.Tx) error) error
}

type CodeIssuer struct {
	database codeIssuerDatabase
}

// CreateCodeInput is what one authorization code is written from: the fields createAuthCode reads
// and nothing else. It used to embed the whole ceremony.AuthContext, which made issuance depend on
// every field of the ceremony's state machine to read seventeen of them; the handler that holds the
// context copies them across (#437).
type CreateCodeInput struct {
	ClientId            string
	RedirectURI         string
	ResponseMode        string
	Scope               string
	ConsentedScope      string
	CodeChallenge       string
	CodeChallengeMethod string
	State               string
	Nonce               string
	UserAgent           string
	IpAddress           string
	UserId              int64
	AcrLevel            models.AcrLevel
	AuthMethods         string
	// AuthenticatedAt overrides the code's auth_time when set (prompt=none reuses the session's);
	// nil or zero means the moment of issuance.
	AuthenticatedAt     *time.Time
	AuthStateGeneration int64
	SessionIdentifier   string
}

func NewCodeIssuer(database codeIssuerDatabase) *CodeIssuer {
	return &CodeIssuer{
		database: database,
	}
}

// IssueAuthCodeTx issues one authorization code in a transaction it opens and commits, through
// IssueAuthCode. Either sentinel, ErrIssuingSessionGone or ErrIssuingClientGone, leaves the body
// as an error, so nothing is committed and the helper rolls back once and hands it straight back:
// neither is a deadlock, so neither is rerun.
//
// The sentinels reach the caller only AFTER that rollback, and the order is not optional (#139).
// /auth/issue answers them through the server-side session store, which writes on a nil
// transaction, and redirects through a client read on a nil transaction. On SQLite the whole
// process shares one connection, the one this transaction holds, so a refusal answered while it
// was open would wait on itself.
//
// A commit that returns an error leaves the code row's fate indeterminate, the contract
// revocation.TerminateUserSessionTx documents; the caller answers it with a 500 rather than a code.
func (ci *CodeIssuer) IssueAuthCodeTx(ctx context.Context, input *CreateCodeInput) (*models.Code, error) {
	// Opened through RunInTransaction, so a deadlock reruns the body (#301). It is safe to rerun:
	// input is only read, and code is whatever the attempt that committed minted.
	var code *models.Code
	err := ci.database.RunInTransaction(ctx, func(tx *sql.Tx) error {
		var err error
		code, err = ci.IssueAuthCode(ctx, tx, input)
		return err
	})
	if err != nil {
		return nil, err
	}
	return code, nil
}

// IssueAuthCode takes the session row the ceremony binds its code to and then inserts the code,
// every statement on the caller's transaction, which is REQUIRED: the acquisition orders this
// ceremony against a termination of that session only while the row is held, and an autocommitted
// statement releases it at once (#139). IssueAuthCodeTx is the caller that opens one; this form
// exists so the data tier's ordering test can hold the transaction open across a termination's
// arrival and still run the statements that ship.
//
// The observation that the session is still there and the insert that binds a grant to it go in
// ONE transaction, and the acquisition is what orders this ceremony against a termination of that
// session. A liveness read ahead of it cannot do this on its own, however recently it ran: a read
// on one connection followed by an insert on another lets a termination commit in between, and
// worse, a code inserted after that termination's sweep and before its COMMIT is invisible to the
// sweep, and the termination is invisible to any compensating read, which still sees the
// uncommitted-deleted session row. The termination deletes the session row as its first
// statement, so both sides write the same row before touching anything else and one of them waits.
// Either this transaction waits and the acquisition then matches no rows, so nothing is issued, or
// the termination waits and its code sweep runs after this insert committed, so the code it hands
// the client is marked revoked and redemption answers invalid_grant. There is no third case: that
// row is the only object both sides touch and neither takes any other lock before it.
//
// This is the one ordering the repository keeps on purpose, and it is an integrity rule rather
// than a deadlock rule: it exists so a code can never slip between a termination's sweep and its
// commit. No other order is imposed. Concurrent transactions on the same account can still
// deadlock on MySQL, PostgreSQL or SQL Server; the loser is rolled back with nothing half applied
// and rerun by RunInTransaction, bounded, before the error surfaces. SQLite has one connection and
// cannot deadlock. Do not add ordering here to prevent a deadlock; add a test that forces it and
// shows the retry resolves it (#301).
func (ci *CodeIssuer) IssueAuthCode(ctx context.Context, tx *sql.Tx, input *CreateCodeInput) (*models.Code, error) {
	if tx == nil {
		return nil, errs.New("issuing an authorization code requires a transaction: the session row it takes first is released by an autocommitted statement")
	}

	// Existence only, deliberately. Ownership and the two timeouts were asked by the caller a few
	// statements ago and are not re-asked here: the only thing this narrower question misses is an
	// idle timeout elapsing in the microseconds between the two, and buying that would cost a
	// SELECT on every authorization code issued (#139 decision 7).
	live, err := ci.database.AcquireUserSessionRow(ctx, tx, input.SessionIdentifier)
	if err != nil {
		return nil, err
	}
	if !live {
		// No code row is written at all, so nothing is left behind to reap.
		return nil, errs.WithStack(ErrIssuingSessionGone)
	}

	return ci.createAuthCode(ctx, tx, input)
}

// createAuthCode inserts one authorization code. Both of its statements run on tx, which
// IssueAuthCode was handed: the insert has to be ordered against a concurrent session termination,
// and the client lookup has to join it because sqlitedb sets SetMaxOpenConns(1), so a
// nil-transaction read issued while tx holds the single connection waits for a connection tx itself
// owns. That is a hang rather than an error, so neither statement may be reverted to nil (#139).
func (ci *CodeIssuer) createAuthCode(ctx context.Context, tx *sql.Tx, input *CreateCodeInput) (*models.Code, error) {

	responseMode := input.ResponseMode
	if responseMode == "" {
		responseMode = "query"
	}

	client, err := ci.database.GetClientByClientIdentifier(ctx, tx, input.ClientId)
	if err != nil {
		return nil, err
	}

	// A client the ceremony started against can be gone by the time this runs, and since #139 that
	// is a reliable schedule rather than a narrow race: issuance takes a shared lock on the client
	// row, so a deletion that got there first makes this transaction WAIT and then proceed into
	// this lookup, which now finds nothing. Dereferencing it for client.Id below was a panic, so
	// the condition is answered as an error and the caller answers it the way it answers a session
	// that has gone (#248 part 5).
	if client == nil {
		return nil, errs.WithStack(ErrIssuingClientGone)
	}

	space := regexp.MustCompile(`\s+`)

	scope := ""
	if len(input.ConsentedScope) > 0 {
		scope = space.ReplaceAllString(input.ConsentedScope, " ")
	} else {
		scope = space.ReplaceAllString(input.Scope, " ")
	}
	scope = strings.TrimSpace(scope)

	authCode := strings.ReplaceAll(uuidutil.New(), "-", "") + securerandom.String(96)
	authCodeHash := hashutil.HashString(authCode)
	// Handle PKCE fields - store as NULL if not provided
	var codeChallenge, codeChallengeMethod sql.NullString
	if input.CodeChallenge != "" {
		codeChallenge = sql.NullString{String: input.CodeChallenge, Valid: true}
		codeChallengeMethod = sql.NullString{String: input.CodeChallengeMethod, Valid: true}
	}

	// Use provided AuthenticatedAt if set (for prompt=none), otherwise use current time
	authenticatedAt := time.Now().UTC()
	if input.AuthenticatedAt != nil && !input.AuthenticatedAt.IsZero() {
		authenticatedAt = *input.AuthenticatedAt
	}

	code := &models.Code{
		Code:                authCode,
		CodeHash:            authCodeHash,
		ClientId:            client.Id,
		AuthenticatedAt:     authenticatedAt,
		UserId:              input.UserId,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		RedirectURI:         input.RedirectURI,
		Scope:               scope,
		State:               input.State,
		Nonce:               input.Nonce,
		// The header is bounded here, at the one writer of codes.user_agent, rather than where
		// it is read off the request: a browser sending more than the 512 bytes the column
		// holds otherwise makes this insert fail, and /auth/issue answers 500 to it after a
		// completed ceremony. PostgreSQL and MySQL refuse the length, and both also refuse a
		// stray latin1 byte, which RFC 9110 10.1.5 permits in a User-Agent; Bound handles both
		// (#281).
		UserAgent:         useragent.Bound(input.UserAgent, 512),
		ResponseMode:      responseMode,
		IpAddress:         input.IpAddress,
		AcrLevel:          input.AcrLevel,
		AuthMethods:       input.AuthMethods,
		SessionIdentifier: input.SessionIdentifier,
		Used:              false,
		// From the AuthContext, which captured it when this ceremony authenticated.
		// Redemption compares it against the user's current value, so a code issued by a
		// ceremony that straddled a credential change is rejected (#106 decision 11).
		AuthStateGeneration: input.AuthStateGeneration,
	}

	err = ci.database.CreateCode(ctx, tx, code)
	if err != nil {
		return nil, err
	}

	return code, nil
}
