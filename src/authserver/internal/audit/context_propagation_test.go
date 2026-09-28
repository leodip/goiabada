package audit

import (
	"context"
	"testing"

	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Seam 4 of #386 for the audit logger, and thin for the reason section 5 gives: what the insert
// does with a context belongs to the data tier.
//
// AssertAuditLogContext already holds every call site to passing the request's context INTO Log.
// What this file adds is the other half, which no guard can see: that Log passes the context it
// was given on to the switches read and the insert, rather than opening one of its own. Since
// #433 the switches are read through a port, so what the fake recorded is asserted directly.

type auditCtxKey struct{}

// theCallersContext matches only the context handed to Log, so an insert issued on
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

// The accept arm: the switches read and the audit insert both go out on the caller's context. The
// switches read is the one worth naming -- it is what finds the request's settings, and on a
// context of Log's own the adapter would read the settings row for every event.
func TestAuditLogger_Log_ReadsAndWritesUnderTheCallersContext(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	switches := databaseOnly()

	mockDB.On("CreateAuditLog", theCallersContext(), mock.Anything, mock.Anything).
		Return(nil).Once()

	NewAuditLogger(mockDB, switches).Log(auditCallersContext(), AuditAuthSuccessPwd, map[string]interface{}{"userId": 1})

	mockDB.AssertExpectations(t)
	require.Len(t, switches.asked, 1)
	assert.Equal(t, "caller", switches.asked[0].Value(auditCtxKey{}))
}

// A live context is what both reads get even when the caller's is already cancelled, which is the
// one place Log does NOT simply pass its argument on (#386, final review round 1 finding 9).
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
	switches := databaseOnly()

	mockDB.On("CreateAuditLog", aLiveContext(), mock.Anything, mock.Anything).
		Return(nil).Once()

	ctx, cancel := context.WithCancel(auditCallersContext())
	cancel()

	NewAuditLogger(mockDB, switches).Log(ctx, AuditAuthSuccessPwd, map[string]interface{}{"userId": 1})

	mockDB.AssertExpectations(t)
	require.Len(t, switches.asked, 1)
	assert.Equal(t, "caller", switches.asked[0].Value(auditCtxKey{}))
	assert.Equal(t, []bool{true}, switches.liveWhenAsked, "the switches were asked on a live context")
}

// And the detached context is bounded rather than open-ended, asserted at both ports because the
// bound is the whole reason the detachment is safe.
func TestAuditLogger_Log_TheDetachedContextCarriesADeadline(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)
	switches := databaseOnly()

	bounded := mock.MatchedBy(func(ctx context.Context) bool {
		_, ok := ctx.Deadline()
		return ok
	})
	mockDB.On("CreateAuditLog", bounded, mock.Anything, mock.Anything).Return(nil).Once()

	NewAuditLogger(mockDB, switches).Log(auditCallersContext(), AuditAuthSuccessPwd, map[string]interface{}{"userId": 1})

	mockDB.AssertExpectations(t)
	require.Len(t, switches.asked, 1)
	_, hasDeadline := switches.asked[0].Deadline()
	assert.True(t, hasDeadline, "the switches read ran under a deadline of the logger's own")
}

// The reject arm: with database persistence off, the insert is never reached and there is no
// context to get wrong. Without it the accept arm would also pass on a logger that wrote
// unconditionally.
func TestAuditLogger_Log_DatabasePersistenceOffReachesNoInsertPort(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)

	NewAuditLogger(mockDB, noTarget()).Log(auditCallersContext(), AuditAuthSuccessPwd, map[string]interface{}{"userId": 1})

	mockDB.AssertNotCalled(t, "CreateAuditLog", mock.Anything, mock.Anything, mock.Anything)
}
