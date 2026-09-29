package handlers

import (
	"database/sql"
	"testing"

	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/stretchr/testify/assert"
)

// The two test helpers the handler tests here reach for when the code under test revokes
// something. Both are copies of helpers declared in revocation_test.go, which were package-private
// to this package until #387 moved that file to internal/revocation, one package away, and a test
// helper cannot be exported to it. Two more left with their callers in #435: methodOrder with the
// reuse response's sequence test, to internal/revocation, and stubRevocationSweepTx with the
// password reset tests, to accounthandlers, which also carries its own revokeTx.
//
// Copying is the answer the tree already gives to this shape -- run_in_transaction_stub_test.go
// exists in five packages, and apihandlers keeps its own assertNotAttemptedOnClientDatabase and
// callIndex beside the one file that calls them -- and sharing them instead is a change of its
// own, because the copies have already diverged.

// revokeTx is an opaque non-nil transaction. revocation.RevokeUserAuthState requires one, so
// passing nil here would exercise a shape production never runs. The mocks never dereference it;
// it only has to be the same pointer the helper forwards.
var revokeTx = &sql.Tx{}

// assertNotAttempted fails if any of the named methods appears in the mock's recorded calls. The
// strict mock would already reject an unexpected call; this states which writes each failure path
// must not have reached, so the intent survives a later edit to the expectations.
func assertNotAttempted(t *testing.T, db *mocks_data.Database, methods ...string) {
	t.Helper()
	for _, call := range db.Calls {
		for _, method := range methods {
			assert.NotEqual(t, method, call.Method, "%v must not be attempted on this path", method)
		}
	}
}
