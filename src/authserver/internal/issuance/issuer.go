package issuance

import (
	"context"
	"database/sql"

	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/record"
)

// tokenIssuerDatabase is what the token issuer needs: the claim on the code or refresh token being
// redeemed, the containment of a replayed refresh token's family and the record of it that a
// rotation checks, the user row a rotation takes first and the presented token's row it re-reads,
// the signing key, the claims
// that go into the tokens, and, for the implicit grant, the session row it takes and the
// transaction it takes it in.
type tokenIssuerDatabase interface {
	AcquireUserRow(ctx context.Context, tx *sql.Tx, userID int64) error
	AcquireUserSessionRow(ctx context.Context, tx *sql.Tx, sessionIdentifier string) (bool, error)
	CodeLoadClient(ctx context.Context, tx *sql.Tx, code *record.Code) error
	CodeLoadUser(ctx context.Context, tx *sql.Tx, code *record.Code) error
	CreateRefreshToken(ctx context.Context, tx *sql.Tx, refreshToken *record.RefreshToken) error
	GetClientByIDForUpdate(ctx context.Context, tx *sql.Tx, clientID int64) (*record.Client, error)
	GetCurrentSigningKey(ctx context.Context, tx *sql.Tx) (*record.KeyPair, error)
	GetRefreshTokenByID(ctx context.Context, tx *sql.Tx, refreshTokenID int64) (*record.RefreshToken, error)
	GetUserByID(ctx context.Context, tx *sql.Tx, userID int64) (*record.User, error)
	GetUserSessionBySessionIdentifier(ctx context.Context, tx *sql.Tx, sessionIdentifier string) (*record.UserSession, error)
	GroupsLoadAttributes(ctx context.Context, tx *sql.Tx, groups []record.Group) error
	IsRefreshTokenFamilyRevoked(ctx context.Context, tx *sql.Tx, firstRefreshTokenJTI string) (bool, error)
	MarkCodeAsUsed(ctx context.Context, tx *sql.Tx, codeID int64) (bool, error)
	MarkRefreshTokenAsRevoked(ctx context.Context, tx *sql.Tx, refreshTokenID int64) (bool, error)
	RecordRefreshTokenFamilyRevoked(ctx context.Context, tx *sql.Tx, firstRefreshTokenJTI string, reason string) (bool, error)
	RefreshTokenLoadClient(ctx context.Context, tx *sql.Tx, refreshToken *record.RefreshToken) error
	RefreshTokenLoadUser(ctx context.Context, tx *sql.Tx, refreshToken *record.RefreshToken) error
	RevokeRefreshTokenFamily(ctx context.Context, tx *sql.Tx, firstRefreshTokenJTI string) (int64, error)
	RunInTransaction(ctx context.Context, fn func(tx *sql.Tx) error) error
	UserHasProfilePicture(ctx context.Context, tx *sql.Tx, userID int64) (bool, error)
	UserLoadAttributes(ctx context.Context, tx *sql.Tx, user *record.User) error
	UserLoadGroups(ctx context.Context, tx *sql.Tx, user *record.User) error
}

// sessionBumper keeps a browser session alive when a refresh token bound to it is redeemed, which is
// the one session write a token grant makes. *usersession.Manager satisfies it.
type sessionBumper interface {
	BumpUserSession(ctx context.Context, sessionIdentifier string, clientID int64,
		authMethods string, acrLevel record.ACRLevel, ipAddress string) (*record.UserSession, error)
}

type TokenIssuer struct {
	database            tokenIssuerDatabase
	baseURL             string
	adminConsoleBaseURL string
	dataCipher          *encryption.DataCipher
	sessions            sessionBumper
}

func NewTokenIssuer(database tokenIssuerDatabase, baseURL string, adminConsoleBaseURL string,
	dataCipher *encryption.DataCipher, sessions sessionBumper) *TokenIssuer {
	return &TokenIssuer{
		database:            database,
		baseURL:             baseURL,
		adminConsoleBaseURL: adminConsoleBaseURL,
		dataCipher:          dataCipher,
		sessions:            sessions,
	}
}
