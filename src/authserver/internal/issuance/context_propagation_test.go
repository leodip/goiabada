package issuance

import (
	"context"
	"database/sql"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Seam 4 of #386 for the issuers, and thin for the reason section 5 gives: what the insert does
// with a context belongs to the data tier.
//
// CreateAuthCode is the signature this stage moved, and its insert is the statement #139 orders
// against a concurrent termination: it runs on the transaction that already holds the session
// row. A context that stopped at this boundary would leave that transaction uncancellable, which
// on SQLite is a wait with no end (probe/cancel.out), so the claim worth an assertion is that the
// ctx the issuer was handed is the one the insert is issued under.

type issuerCtxKey struct{}

// theIssuersCallersContext matches only the context this test handed to CreateAuthCode, so an
// insert issued on a context the issuer invented matches nothing and the strict mock reports an
// unexpected call.
func theIssuersCallersContext() interface{} {
	return mock.MatchedBy(func(ctx context.Context) bool {
		return ctx.Value(issuerCtxKey{}) == "caller"
	})
}

func issuanceCallerContext() context.Context {
	return context.WithValue(context.Background(), issuerCtxKey{}, "caller")
}

func propagationCodeInput() *CreateCodeInput {
	return &CreateCodeInput{
		AuthContext: ceremony.AuthContext{
			ClientId:     "test-client",
			UserId:       123,
			Scope:        "openid profile",
			RedirectURI:  "https://example.com/callback",
			ResponseMode: "query",
			IpAddress:    "127.0.0.1",
			AcrLevel:     string(models.AcrLevel1),
			AuthMethods:  "pwd",
		},
		SessionIdentifier: "session-propagation",
	}
}

// The accept arm: the insert carries the caller's own context, and it carries the caller's own
// transaction with it. Both matchers are assertions rather than stubs -- a mock.Anything in
// either position would pass on an issuer that opened its own.
func TestCreateAuthCode_InsertsUnderTheCallersContext(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	issuanceTx := &sql.Tx{}

	mockDB.On("GetClientByClientIdentifier", mock.Anything, issuanceTx, "test-client").
		Return(&models.Client{Id: 1, ClientIdentifier: "test-client"}, nil).Once()
	mockDB.On("CreateCode", theIssuersCallersContext(), issuanceTx, mock.AnythingOfType("*models.Code")).
		Return(nil).Once()

	code, err := NewCodeIssuer(mockDB).CreateAuthCode(issuanceCallerContext(), issuanceTx, propagationCodeInput())

	require.NoError(t, err)
	assert.NotNil(t, code)
	mockDB.AssertExpectations(t)
}

// The reject arm: a client that has gone by the time issuance runs is answered with
// ErrIssuingClientGone before the insert, so no code is written and there is no context to get
// wrong. Without it the accept arm would also pass on an issuer that inserted unconditionally.
func TestCreateAuthCode_AGoneClientReachesNoInsert(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	issuanceTx := &sql.Tx{}

	mockDB.On("GetClientByClientIdentifier", mock.Anything, issuanceTx, "test-client").Return(nil, nil).Once()

	code, err := NewCodeIssuer(mockDB).CreateAuthCode(issuanceCallerContext(), issuanceTx, propagationCodeInput())

	assert.ErrorIs(t, err, ErrIssuingClientGone)
	assert.Nil(t, code)
	mockDB.AssertNotCalled(t, "CreateCode", mock.Anything, mock.Anything, mock.Anything)
}
