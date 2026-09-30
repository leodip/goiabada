package issuance

import (
	"context"
	"database/sql"

	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/models"
)

// tokenIssuerDatabase is what the token issuer needs: the claim on the code or refresh token being
// redeemed, the containment of a replayed refresh token's family and the record of it that a
// rotation checks, the user row a rotation takes first and the presented token's row it re-reads,
// the signing key, the claims
// that go into the tokens, and, for the implicit grant, the session row it takes and the
// transaction it takes it in.
type tokenIssuerDatabase interface {
	AcquireUserRow(ctx context.Context, tx *sql.Tx, userId int64) error
	AcquireUserSessionRow(ctx context.Context, tx *sql.Tx, sessionIdentifier string) (bool, error)
	CodeLoadClient(ctx context.Context, tx *sql.Tx, code *models.Code) error
	CodeLoadUser(ctx context.Context, tx *sql.Tx, code *models.Code) error
	CreateRefreshToken(ctx context.Context, tx *sql.Tx, refreshToken *models.RefreshToken) error
	GetCurrentSigningKey(ctx context.Context, tx *sql.Tx) (*models.KeyPair, error)
	GetRefreshTokenById(ctx context.Context, tx *sql.Tx, refreshTokenId int64) (*models.RefreshToken, error)
	GetUserSessionBySessionIdentifier(ctx context.Context, tx *sql.Tx, sessionIdentifier string) (*models.UserSession, error)
	GroupsLoadAttributes(ctx context.Context, tx *sql.Tx, groups []models.Group) error
	IsRefreshTokenFamilyRevoked(ctx context.Context, tx *sql.Tx, firstRefreshTokenJti string) (bool, error)
	MarkCodeAsUsed(ctx context.Context, tx *sql.Tx, codeId int64) (bool, error)
	MarkRefreshTokenAsRevoked(ctx context.Context, tx *sql.Tx, refreshTokenId int64) (bool, error)
	RecordRefreshTokenFamilyRevoked(ctx context.Context, tx *sql.Tx, firstRefreshTokenJti string, reason string) (bool, error)
	RefreshTokenLoadClient(ctx context.Context, tx *sql.Tx, refreshToken *models.RefreshToken) error
	RefreshTokenLoadUser(ctx context.Context, tx *sql.Tx, refreshToken *models.RefreshToken) error
	RevokeRefreshTokenFamily(ctx context.Context, tx *sql.Tx, firstRefreshTokenJti string) (int64, error)
	RunInTransaction(ctx context.Context, fn func(tx *sql.Tx) error) error
	UserHasProfilePicture(ctx context.Context, tx *sql.Tx, userId int64) (bool, error)
	UserLoadAttributes(ctx context.Context, tx *sql.Tx, user *models.User) error
	UserLoadGroups(ctx context.Context, tx *sql.Tx, user *models.User) error
}

// sessionBumper keeps a browser session alive when a refresh token bound to it is redeemed, which is
// the one session write a token grant makes. *usersession.Manager satisfies it.
type sessionBumper interface {
	BumpUserSession(ctx context.Context, sessionIdentifier string, clientId int64,
		authMethods string, acrLevel models.AcrLevel, ipAddress string) (*models.UserSession, error)
}

type TokenIssuer struct {
	database   tokenIssuerDatabase
	baseURL    string
	dataCipher *encryption.DataCipher
	sessions   sessionBumper
}

func NewTokenIssuer(database tokenIssuerDatabase, baseURL string, dataCipher *encryption.DataCipher,
	sessions sessionBumper) *TokenIssuer {
	return &TokenIssuer{
		database:   database,
		baseURL:    baseURL,
		dataCipher: dataCipher,
		sessions:   sessions,
	}
}
