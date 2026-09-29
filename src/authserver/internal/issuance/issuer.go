package issuance

import (
	"context"
	"database/sql"

	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/models"
)

// tokenIssuerDatabase is what the token issuer needs: the signing key, the code or refresh token
// being redeemed, and the claims that go into the tokens.
type tokenIssuerDatabase interface {
	CodeLoadClient(ctx context.Context, tx *sql.Tx, code *models.Code) error
	CodeLoadUser(ctx context.Context, tx *sql.Tx, code *models.Code) error
	CreateRefreshToken(ctx context.Context, tx *sql.Tx, refreshToken *models.RefreshToken) error
	GetCurrentSigningKey(ctx context.Context, tx *sql.Tx) (*models.KeyPair, error)
	GetUserSessionBySessionIdentifier(ctx context.Context, tx *sql.Tx, sessionIdentifier string) (*models.UserSession, error)
	GroupsLoadAttributes(ctx context.Context, tx *sql.Tx, groups []models.Group) error
	RefreshTokenLoadClient(ctx context.Context, tx *sql.Tx, refreshToken *models.RefreshToken) error
	RefreshTokenLoadUser(ctx context.Context, tx *sql.Tx, refreshToken *models.RefreshToken) error
	UserHasProfilePicture(ctx context.Context, tx *sql.Tx, userId int64) (bool, error)
	UserLoadAttributes(ctx context.Context, tx *sql.Tx, user *models.User) error
	UserLoadGroups(ctx context.Context, tx *sql.Tx, user *models.User) error
}

type TokenIssuer struct {
	database   tokenIssuerDatabase
	baseURL    string
	dataCipher *encryption.DataCipher
}

func NewTokenIssuer(database tokenIssuerDatabase, baseURL string, dataCipher *encryption.DataCipher) *TokenIssuer {
	return &TokenIssuer{
		database:   database,
		baseURL:    baseURL,
		dataCipher: dataCipher,
	}
}
