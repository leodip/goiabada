package audit

import (
	"context"
	"testing"

	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/stretchr/testify/mock"
)

// Seam 4 of #386 for the audit logger, and thin for the reason section 5 gives: what the insert
// does with a context belongs to the data tier.
//
// AssertAuditLogContext already holds every call site to passing the request's context INTO Log.
// What this file adds is the other half, which no guard can see: that Log passes the context it
// was given on to the two database calls it makes, rather than opening one of its own. Both took
// a context only from this stage.

type auditCtxKey struct{}

// theCallersContext matches only the context handed to Log, so a read or an insert issued on
// context.Background() matches nothing and the strict mock reports an unexpected call.
func theCallersContext() interface{} {
	return mock.MatchedBy(func(ctx context.Context) bool {
		return ctx.Value(auditCtxKey{}) == "caller"
	})
}

func auditCallersContext() context.Context {
	return context.WithValue(context.Background(), auditCtxKey{}, "caller")
}

// The accept arm: the settings fallback read and the audit insert both go out on the caller's
// context. The settings read is the one worth naming -- it happens only when the middleware did
// not already put the row on the context, which is every root registration and every worker
// event, so it is the read least likely to be exercised by accident.
func TestAuditLogger_Log_ReadsAndWritesUnderTheCallersContext(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)

	mockDB.On("GetSettingsById", theCallersContext(), mock.Anything, int64(1)).
		Return(&models.Settings{AuditLogsInDatabaseEnabled: true}, nil).Once()
	mockDB.On("CreateAuditLog", theCallersContext(), mock.Anything, mock.Anything).
		Return(nil).Once()

	NewAuditLogger(mockDB).Log(auditCallersContext(), AuditAuthSuccessPwd, map[string]interface{}{"userId": 1})

	mockDB.AssertExpectations(t)
}

// The reject arm: with database persistence off, the insert is never reached and there is no
// context to get wrong. Without it the accept arm would also pass on a logger that wrote
// unconditionally.
func TestAuditLogger_Log_DatabasePersistenceOffReachesNoInsertPort(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)

	mockDB.On("GetSettingsById", theCallersContext(), mock.Anything, int64(1)).
		Return(&models.Settings{AuditLogsInDatabaseEnabled: false}, nil).Once()

	NewAuditLogger(mockDB).Log(auditCallersContext(), AuditAuthSuccessPwd, map[string]interface{}{"userId": 1})

	mockDB.AssertNotCalled(t, "CreateAuditLog", mock.Anything, mock.Anything, mock.Anything)
}
