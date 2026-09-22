package audit

import (
	"context"
	"testing"

	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/stretchr/testify/assert"
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

// aLiveContext matches only a context that still carries the caller's values and is NOT done, so
// a call issued on a cancelled context matches nothing and the strict mock reports it.
func aLiveContext() interface{} {
	return mock.MatchedBy(func(ctx context.Context) bool {
		return ctx.Value(auditCtxKey{}) == "caller" && ctx.Err() == nil
	})
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

// A live context is what both database calls get even when the caller's is already cancelled,
// which is the one place Log does NOT simply pass its argument on (#386, final review round 1
// finding 9).
//
// Every one of the 126 call sites logs its event AFTER the outcome it records is durable: the
// token was issued, the password was changed, the user was deleted. Before this change the audit
// write took no context at all and therefore always ran. Handing it the request's context made it
// inherit a cancellation that says nothing about the audit write and everything about a browser
// that has gone -- and net/http cancels that context when the client disconnects, so anyone who
// wanted an event unrecorded had only to hang up. What survives cancellation is the deadline: a
// detached context with no bound at all is how a stuck dependency holds the handler's goroutine
// for ever, which is what the request's context used to prevent by accident.
func TestAuditLogger_Log_ACancelledCallerStillGetsItsEventWritten(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)

	mockDB.On("GetSettingsById", aLiveContext(), mock.Anything, int64(1)).
		Return(&models.Settings{AuditLogsInDatabaseEnabled: true}, nil).Once()
	mockDB.On("CreateAuditLog", aLiveContext(), mock.Anything, mock.Anything).
		Return(nil).Once()

	ctx, cancel := context.WithCancel(auditCallersContext())
	cancel()

	NewAuditLogger(mockDB).Log(ctx, AuditAuthSuccessPwd, map[string]interface{}{"userId": 1})

	mockDB.AssertExpectations(t)
}

// And the detached context is bounded rather than open-ended, asserted at the port because the
// bound is the whole reason the detachment is safe.
func TestAuditLogger_Log_TheDetachedContextCarriesADeadline(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)

	deadlines := 0
	bounded := mock.MatchedBy(func(ctx context.Context) bool {
		if _, ok := ctx.Deadline(); ok {
			deadlines++
			return true
		}
		return false
	})
	mockDB.On("GetSettingsById", bounded, mock.Anything, int64(1)).
		Return(&models.Settings{AuditLogsInDatabaseEnabled: true}, nil).Once()
	mockDB.On("CreateAuditLog", bounded, mock.Anything, mock.Anything).Return(nil).Once()

	NewAuditLogger(mockDB).Log(auditCallersContext(), AuditAuthSuccessPwd, map[string]interface{}{"userId": 1})

	mockDB.AssertExpectations(t)
	assert.Positive(t, deadlines, "both database calls ran under a deadline of the logger's own")
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
