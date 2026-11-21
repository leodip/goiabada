package issuance

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// A rename of a client revokes its grants in the rename's transaction (#710 decision 5). A password
// grant has no code for that sweep to mark and, until its first refresh token is written, no family
// to record, so the grant is ordered against the rename through the client's row: it writes its
// first refresh token in a transaction that takes that row, without changing it, and reads the
// identifier again. Committed first, the rename's sweep finds its token; run after the rename, it
// finds the identifier it was asked for is no longer the client's and issues nothing. What an
// engine does with the two transactions is the data tier's; this file holds the statements and
// their order.

// passwordGrantTx is the transaction the password grant writes its first refresh token in.
var passwordGrantTx = &sql.Tx{}

// expectPasswordGrantClientRow registers that transaction and the locking read of the client in it,
// answering row.
func expectPasswordGrantClientRow(db *datamocks.Database, clientID int64, row *record.Client) *datamocks.RunInTransactionStub {
	stub := datamocks.ExpectRunInTransaction(db, passwordGrantTx)
	db.On("GetClientByIDForUpdate", mock.Anything, passwordGrantTx, clientID).Return(row, nil).Once()
	return stub
}

// passwordGrantIssuer is a password grant's issuer over a strict mock, with what every grant reads
// before its first refresh token registered.
func passwordGrantIssuer(t *testing.T) (*TokenIssuer, *datamocks.Database, *ROPCGrantInput, *record.Settings) {
	t.Helper()

	db := datamocks.NewDatabase(t)
	user := &record.User{ID: 1, Subject: fake.UUID(), Email: "user@example.com", Enabled: true}
	client := &record.Client{ID: 5, ClientIdentifier: "ropc-client"}

	db.On("GetCurrentSigningKey", mock.Anything, mock.Anything).Return(&record.KeyPair{
		ID:            1,
		KeyIdentifier: "test-key-id",
		PrivateKeyPEM: encryptPEM(t, getTestPrivateKey(t)),
		PublicKeyPEM:  getTestPublicKey(t),
	}, nil)
	db.On("UserLoadGroups", mock.Anything, mock.Anything, user).Return(nil)
	db.On("GroupsLoadAttributes", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	db.On("UserLoadAttributes", mock.Anything, mock.Anything, user).Return(nil)

	settings := &record.Settings{
		Issuer:                                  "https://test-issuer.com",
		TokenExpirationInSeconds:                600,
		RefreshTokenOfflineIdleTimeoutInSeconds: 1800,
		RefreshTokenOfflineMaxLifetimeInSeconds: 3600,
	}
	issuer := NewTokenIssuer(db, "http://localhost:8081", "http://localhost:9091", testDataCipher, nil)
	return issuer, db, &ROPCGrantInput{Client: client, User: user, Scope: "openid"}, settings
}

// The first refresh token is written on the transaction that read the client's row with its lock,
// after that read, and the client's identifier is unchanged, so the grant is issued.
func TestIssuePasswordGrant_WritesItsFirstRefreshTokenUnderTheClientsRow(t *testing.T) {
	issuer, db, input, settings := passwordGrantIssuer(t)
	stub := expectPasswordGrantClientRow(db, 5, &record.Client{ID: 5, ClientIdentifier: "ropc-client"})
	var written *record.RefreshToken
	db.On("CreateRefreshToken", mock.Anything, passwordGrantTx, mock.AnythingOfType("*record.RefreshToken")).
		Run(func(args mock.Arguments) { written = args.Get(2).(*record.RefreshToken) }).
		Return(nil).Once()

	response, err := issuer.IssuePasswordGrant(context.Background(), settings, input)

	require.NoError(t, err)
	require.NotNil(t, response)
	assert.NotEmpty(t, response.AccessToken)
	assert.NotEmpty(t, response.IDToken)
	assert.NotEmpty(t, response.RefreshToken)
	require.NoError(t, stub.BodyErr)
	require.NotNil(t, written)
	assert.Equal(t, int64(5), written.ClientID.Int64)
	assert.Less(t, callIndexOn(t, db, "GetClientByIDForUpdate"), callIndexOn(t, db, "CreateRefreshToken"),
		"the client's row is read under its lock before the refresh token is written")
}

// The client was renamed, or deleted, after the request named it: the grant is refused with the
// sentinel the token endpoint answers invalid_client for, writes no refresh token and hands back
// no token at all.
func TestIssuePasswordGrant_AClientNoLongerHoldingTheIdentifierIsRefused(t *testing.T) {
	cases := []struct {
		name string
		row  *record.Client
	}{
		{"renamed meanwhile", &record.Client{ID: 5, ClientIdentifier: "renamed-client"}},
		{"renamed by case only", &record.Client{ID: 5, ClientIdentifier: "ROPC-client"}},
		{"deleted meanwhile", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			issuer, db, input, settings := passwordGrantIssuer(t)
			stub := expectPasswordGrantClientRow(db, 5, tc.row)

			response, err := issuer.IssuePasswordGrant(context.Background(), settings, input)

			require.ErrorIs(t, err, ErrPasswordGrantClientRenamed)
			assert.Nil(t, response, "nothing is issued")
			require.ErrorIs(t, stub.BodyErr, ErrPasswordGrantClientRenamed, "the transaction is rolled back")
			db.AssertNotCalled(t, "CreateRefreshToken", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// A failed read of the row is a fault, never read as a client that is still there.
func TestIssuePasswordGrant_AFailedReadOfTheClientsRowIsAFault(t *testing.T) {
	issuer, db, input, settings := passwordGrantIssuer(t)
	datamocks.ExpectRunInTransaction(db, passwordGrantTx)
	boom := errors.New("connection reset")
	db.On("GetClientByIDForUpdate", mock.Anything, passwordGrantTx, int64(5)).Return(nil, boom).Once()

	response, err := issuer.IssuePasswordGrant(context.Background(), settings, input)

	require.ErrorIs(t, err, boom)
	require.NotErrorIs(t, err, ErrPasswordGrantClientRenamed)
	assert.Nil(t, response)
	db.AssertNotCalled(t, "CreateRefreshToken", mock.Anything, mock.Anything, mock.Anything)
}

// callIndexOn answers the position of a method's first call on the mock.
func callIndexOn(t *testing.T, db *datamocks.Database, method string) int {
	t.Helper()
	for i, call := range db.Calls {
		if call.Method == method {
			return i
		}
	}
	t.Fatalf("%s was never called", method)
	return -1
}
