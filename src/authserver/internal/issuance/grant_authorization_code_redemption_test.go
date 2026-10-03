package issuance

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"testing"
	"time"

	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Seam 3 for the authorization code grant's redemption: the claim on the code comes before anything
// is minted, and a claim that did not change the row mints nothing (#77). These assertions were the
// token handler's until the redemption moved into the issuer (#437); the mint itself is pinned by
// the TestMintAuthorizationCodeTokens_* cases.

// armCodeMint arms every read and write minting a code's tokens makes, on a fixture whose scope is
// openid alone, and notes "mint" at the first of them.
func armCodeMint(t *testing.T, mockDB *mocks_data.Database, note func(string)) *record.Code {
	t.Helper()
	now := time.Now().UTC()
	code := &record.Code{
		Id:                2,
		ClientId:          2,
		UserId:            2,
		Scope:             "openid",
		AuthenticatedAt:   now.Add(-2 * time.Minute),
		SessionIdentifier: "sid-2",
		AcrLevel:          "urn:goiabada:level1",
		AuthMethods:       "pwd",
		Client:            record.Client{Id: 2, ClientIdentifier: "the-client"},
		User:              record.User{Id: 2, Subject: fake.UUID(), Email: "someone@example.com"},
	}
	mockDB.On("CodeLoadClient", mock.Anything, (*sql.Tx)(nil), code).Run(func(mock.Arguments) { note("mint") }).Return(nil).Once()
	mockDB.On("GetCurrentSigningKey", mock.Anything, (*sql.Tx)(nil)).Return(&record.KeyPair{
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: encryptPEM(t, getTestPrivateKey(t)),
	}, nil).Once()
	mockDB.On("CodeLoadUser", mock.Anything, (*sql.Tx)(nil), code).Return(nil).Once()
	mockDB.On("UserLoadGroups", mock.Anything, (*sql.Tx)(nil), &code.User).Return(nil).Once()
	mockDB.On("GroupsLoadAttributes", mock.Anything, (*sql.Tx)(nil), code.User.Groups).Return(nil).Once()
	mockDB.On("UserLoadAttributes", mock.Anything, (*sql.Tx)(nil), &code.User).Return(nil).Once()
	mockDB.On("GetUserSessionBySessionIdentifier", mock.Anything, (*sql.Tx)(nil), "sid-2").Return(&record.UserSession{
		Id: 1, UserId: 2, Started: now.Add(-30 * time.Minute), LastAccessed: now.Add(-5 * time.Minute),
	}, nil).Once()
	mockDB.On("CreateRefreshToken", mock.Anything, (*sql.Tx)(nil), mock.AnythingOfType("*record.RefreshToken")).
		Run(func(mock.Arguments) { note("insert") }).Return(nil).Once()
	return code
}

func codeGrantSettings() *record.Settings {
	return &record.Settings{
		Issuer:                          "https://test-issuer.com",
		TokenExpirationInSeconds:        600,
		UserSessionIdleTimeoutInSeconds: 1200,
		UserSessionMaxLifetimeInSeconds: 2400,
	}
}

func TestIssueAuthorizationCodeGrant_ClaimsBeforeMinting(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	issuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)

	var order []string
	note := func(what string) { order = append(order, what) }
	code := armCodeMint(t, mockDB, note)
	mockDB.On("MarkCodeAsUsed", mock.Anything, (*sql.Tx)(nil), code.Id).
		Run(func(mock.Arguments) { note("claim") }).Return(true, nil).Once()

	response, err := issuer.IssueAuthorizationCodeGrant(context.Background(), codeGrantSettings(), code)

	require.NoError(t, err)
	assert.Equal(t, "openid", response.Scope)
	assert.NotEmpty(t, response.AccessToken)
	assert.NotEmpty(t, response.IdToken)
	assert.NotEmpty(t, response.RefreshToken)
	assert.Equal(t, []string{"claim", "mint", "insert"}, order,
		"the code is claimed before anything is minted, so two redemptions never both mint (#77)")
	mockDB.AssertExpectations(t)
}

// A redemption that lost the claim mints nothing and says so with the sentinel the token handler
// answers. The strict double is the assertion that nothing else was read or written: no signing
// key, no user, no refresh token row.
func TestIssueAuthorizationCodeGrant_ALostClaimMintsNothing(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	issuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)
	logs := logtest.CaptureSlog(t)

	code := &record.Code{Id: 42}
	mockDB.On("MarkCodeAsUsed", mock.Anything, (*sql.Tx)(nil), code.Id).Return(false, nil).Once()

	response, err := issuer.IssueAuthorizationCodeGrant(context.Background(), codeGrantSettings(), code)

	assert.ErrorIs(t, err, ErrCodeNotClaimed)
	assert.Nil(t, response)
	mockDB.AssertExpectations(t)

	// A lost claim is an ordinary outcome of a race, traced at Debug and never raised.
	records := logs.Records()
	require.Len(t, records, 1)
	assert.Equal(t, slog.LevelDebug, records[0].Level)
	assert.Equal(t, "code could not be claimed, rejecting the redemption", records[0].Message)
	assert.Equal(t, int64(42), records[0].Attrs["code_id"])
	assert.Equal(t, "authorization_code", records[0].Attrs["grant_type"])
}

// A claim the database could not make is a fault, not a lost race: it comes back as itself, never
// as ErrCodeNotClaimed, and nothing is minted.
func TestIssueAuthorizationCodeGrant_AClaimFailureIsAFault(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	issuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)

	failure := errs.New("connection refused")
	code := &record.Code{Id: 1}
	mockDB.On("MarkCodeAsUsed", mock.Anything, (*sql.Tx)(nil), code.Id).Return(false, failure).Once()

	response, err := issuer.IssueAuthorizationCodeGrant(context.Background(), codeGrantSettings(), code)

	assert.ErrorIs(t, err, failure)
	assert.False(t, errors.Is(err, ErrCodeNotClaimed))
	assert.Nil(t, response)
	mockDB.AssertExpectations(t)
}

// A mint that fails after a won claim leaves the code spent: the failure comes back and nothing
// gives the code back, which is the price of never issuing two token sets from one code (#77).
func TestIssueAuthorizationCodeGrant_AFailedMintAfterTheClaimIsAFault(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	issuer := NewTokenIssuer(mockDB, "http://localhost:8081", testDataCipher, nil)

	failure := errs.New("connection refused")
	code := &record.Code{Id: 1}
	mockDB.On("MarkCodeAsUsed", mock.Anything, (*sql.Tx)(nil), code.Id).Return(true, nil).Once()
	mockDB.On("CodeLoadClient", mock.Anything, (*sql.Tx)(nil), code).Return(failure).Once()

	response, err := issuer.IssueAuthorizationCodeGrant(context.Background(), codeGrantSettings(), code)

	assert.ErrorIs(t, err, failure)
	assert.Nil(t, response)
	mockDB.AssertExpectations(t)
}
