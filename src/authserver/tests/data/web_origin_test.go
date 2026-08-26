package datatests

import (
	"database/sql"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/core/models"
)

func TestCreateWebOrigin(t *testing.T) {
	client := createTestClient(t)
	webOrigin := &models.WebOrigin{
		Origin:   "https://example.com",
		ClientId: client.Id,
	}

	err := database.CreateWebOrigin(nil, webOrigin)
	if err != nil {
		t.Fatalf("Failed to create web origin: %v", err)
	}

	if webOrigin.Id == 0 {
		t.Error("Expected non-zero ID after creation")
	}
	if !webOrigin.CreatedAt.Valid || webOrigin.CreatedAt.Time.IsZero() {
		t.Error("Expected CreatedAt to be set")
	}

	retrievedWebOrigin, err := database.GetWebOriginById(nil, webOrigin.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve created web origin: %v", err)
	}

	if retrievedWebOrigin.Origin != webOrigin.Origin {
		t.Errorf("Expected Origin %s, got %s", webOrigin.Origin, retrievedWebOrigin.Origin)
	}
	if retrievedWebOrigin.ClientId != webOrigin.ClientId {
		t.Errorf("Expected ClientId %d, got %d", webOrigin.ClientId, retrievedWebOrigin.ClientId)
	}
}

func TestGetWebOriginById(t *testing.T) {
	client := createTestClient(t)
	webOrigin := createTestWebOrigin(t, client.Id)

	retrievedWebOrigin, err := database.GetWebOriginById(nil, webOrigin.Id)
	if err != nil {
		t.Fatalf("Failed to get web origin by ID: %v", err)
	}

	if retrievedWebOrigin.Id != webOrigin.Id {
		t.Errorf("Expected ID %d, got %d", webOrigin.Id, retrievedWebOrigin.Id)
	}
	if retrievedWebOrigin.Origin != webOrigin.Origin {
		t.Errorf("Expected Origin %s, got %s", webOrigin.Origin, retrievedWebOrigin.Origin)
	}

	nonExistentWebOrigin, err := database.GetWebOriginById(nil, 99999)
	if err != nil {
		t.Errorf("Expected no error for non-existent web origin, got: %v", err)
	}
	if nonExistentWebOrigin != nil {
		t.Errorf("Expected nil for non-existent web origin, got a web origin with ID: %d", nonExistentWebOrigin.Id)
	}
}

func TestGetWebOriginsByClientId(t *testing.T) {
	client := createTestClient(t)
	webOrigin1 := createTestWebOrigin(t, client.Id)
	webOrigin2 := createTestWebOrigin(t, client.Id)

	webOrigins, err := database.GetWebOriginsByClientId(nil, client.Id)
	if err != nil {
		t.Fatalf("Failed to get web origins by client ID: %v", err)
	}

	if len(webOrigins) != 2 {
		t.Errorf("Expected 2 web origins, got %d", len(webOrigins))
	}

	foundWebOrigin1 := false
	foundWebOrigin2 := false
	for _, webOrigin := range webOrigins {
		if webOrigin.Id == webOrigin1.Id {
			foundWebOrigin1 = true
		}
		if webOrigin.Id == webOrigin2.Id {
			foundWebOrigin2 = true
		}
	}

	if !foundWebOrigin1 || !foundWebOrigin2 {
		t.Error("Not all created web origins were found in GetWebOriginsByClientId result")
	}
}

func TestGetAllWebOrigins(t *testing.T) {
	// First, delete all existing web origins
	existingWebOrigins, err := database.GetAllWebOrigins(nil)
	if err != nil {
		t.Fatalf("Failed to get existing web origins: %v", err)
	}
	for _, webOrigin := range existingWebOrigins {
		err := database.DeleteWebOrigin(nil, webOrigin.Id)
		if err != nil {
			t.Fatalf("Failed to delete existing web origin: %v", err)
		}
	}

	// Create a client and two web origins for testing
	client := createTestClient(t)
	webOrigin1 := createTestWebOrigin(t, client.Id)
	webOrigin2 := createTestWebOrigin(t, client.Id)

	webOrigins, err := database.GetAllWebOrigins(nil)
	if err != nil {
		t.Fatalf("Failed to get all web origins: %v", err)
	}

	if len(webOrigins) != 2 {
		t.Errorf("Expected exactly 2 web origins, got %d", len(webOrigins))
	}

	foundWebOrigin1 := false
	foundWebOrigin2 := false
	for _, webOrigin := range webOrigins {
		if webOrigin.Id == webOrigin1.Id {
			foundWebOrigin1 = true
		}
		if webOrigin.Id == webOrigin2.Id {
			foundWebOrigin2 = true
		}
	}

	if !foundWebOrigin1 || !foundWebOrigin2 {
		t.Error("Not all created web origins were found in GetAllWebOrigins result")
	}
}

func TestDeleteWebOrigin(t *testing.T) {
	client := createTestClient(t)
	webOrigin := createTestWebOrigin(t, client.Id)

	err := database.DeleteWebOrigin(nil, webOrigin.Id)
	if err != nil {
		t.Fatalf("Failed to delete web origin: %v", err)
	}

	deletedWebOrigin, err := database.GetWebOriginById(nil, webOrigin.Id)
	if err != nil {
		t.Fatalf("Error while checking for deleted web origin: %v", err)
	}
	if deletedWebOrigin != nil {
		t.Errorf("Web origin still exists after deletion")
	}

	err = database.DeleteWebOrigin(nil, 99999)
	if err != nil {
		t.Errorf("Expected no error when deleting non-existent web origin, got: %v", err)
	}
}

// WebOriginExists is what MiddlewareCors consults on every CORS-checked request
// after #250, in place of reading the whole table. Its answer decides whether a
// browser is allowed to read a response from /auth/token, /auth/logout or
// /userinfo, and every test above it injects a mocked Database, so this tier is
// the only one that can tell whether the real query works at all.
//
// The two cases that are not the happy path are the ones that matter, per
// testing.md section 4. A miss must be a clean false with no error, since an
// error mistaken for absence and absence mistaken for an error are both silent
// here. And a query failure must be an ERROR rather than a benign false: false
// fails closed with nothing explaining why, and the one-character variant that
// returns true instead would fail open, with the whole unit suite green either
// way.
func TestWebOriginExists(t *testing.T) {
	client := createTestClient(t)
	webOrigin := createTestWebOrigin(t, client.Id)

	exists, err := database.WebOriginExists(nil, webOrigin.Origin)
	if err != nil {
		t.Fatalf("WebOriginExists for a registered origin: %v", err)
	}
	if !exists {
		t.Errorf("expected %s to exist", webOrigin.Origin)
	}

	// A near miss rather than an unrelated string: the same origin with one
	// character added still has to answer false, or the lookup is matching on a
	// prefix rather than on equality, which is what CORS compares.
	exists, err = database.WebOriginExists(nil, webOrigin.Origin+"x")
	if err != nil {
		t.Errorf("expected no error for an unregistered origin, got: %v", err)
	}
	if exists {
		t.Errorf("expected %sx not to exist", webOrigin.Origin)
	}

	exists, err = database.WebOriginExists(nil, "")
	if err != nil {
		t.Errorf("expected no error for an empty origin, got: %v", err)
	}
	if exists {
		t.Error("expected an empty origin not to exist")
	}
}

// The transaction contract, on the shape transaction_test.go pins for the
// interface as a whole: a method that took its tx and then read through the pool
// would answer about a different snapshot than its caller is writing in, and no
// mock-backed test can see that.
func TestWebOriginExists_Transaction(t *testing.T) {
	client := createTestClient(t)
	random := gofakeit.LetterN(6)
	origin := "https://" + random + ".tx.example.com"

	tx := beginTx(t)
	webOrigin := &models.WebOrigin{Origin: origin, ClientId: client.Id}
	if err := database.CreateWebOrigin(tx, webOrigin); err != nil {
		t.Fatalf("CreateWebOrigin in a transaction: %v", err)
	}

	exists, err := webOriginExistsWithin(t, tx, origin, 15*time.Second)
	if err != nil {
		t.Fatalf("WebOriginExists inside the transaction: %v", err)
	}
	if !exists {
		t.Error("a write made through the transaction must be visible to a read through the same transaction")
	}

	if err := database.RollbackTransaction(tx); err != nil {
		t.Fatalf("RollbackTransaction: %v", err)
	}

	exists, err = database.WebOriginExists(nil, origin)
	if err != nil {
		t.Fatalf("WebOriginExists after the rollback: %v", err)
	}
	if exists {
		t.Error("a rolled-back write must leave no origin to find")
	}

	// The failure path. tx is finished, so the query cannot run. This must be an
	// error and not a false: false is indistinguishable from "no client has
	// registered that origin", which is the answer that quietly denies every
	// cross-origin request for as long as the database is unhappy.
	if _, err := database.WebOriginExists(tx, origin); err == nil {
		t.Error("expected an error from a finished transaction, not a benign false")
	}
}

// webOriginExistsWithin is the enlisted read, with a deadline on it.
//
// Without the deadline, an implementation that ignored its transaction and read
// through the pool does not answer wrongly on sqlite, it BLOCKS behind the
// caller's own uncommitted write. Measured rather than reasoned: the mutation
// swapping tx for nil in WebOriginExists was caught, but as a test-binary timeout
// panic 600 seconds later rather than as the assertion above. The deadline turns
// that back into a failure that names what went wrong, and costs a goroutine.
func webOriginExistsWithin(t *testing.T, tx *sql.Tx, origin string, within time.Duration) (bool, error) {
	t.Helper()

	type answer struct {
		exists bool
		err    error
	}
	// Buffered, so the query's goroutine can finish and be collected once the
	// deferred rollback releases it, rather than leaking on a send nobody reads.
	done := make(chan answer, 1)
	go func() {
		exists, err := database.WebOriginExists(tx, origin)
		done <- answer{exists, err}
	}()

	select {
	case a := <-done:
		return a.exists, a.err
	case <-time.After(within):
		t.Fatalf("WebOriginExists did not answer within %s: a read that blocks behind the caller's "+
			"own open transaction is a read that is not enlisted in it", within)
		return false, nil
	}
}

func createTestWebOrigin(t *testing.T, clientId int64) *models.WebOrigin {
	random := gofakeit.LetterN(6)
	webOrigin := &models.WebOrigin{
		Origin:   "https://" + random + ".example.com",
		ClientId: clientId,
	}
	err := database.CreateWebOrigin(nil, webOrigin)
	if err != nil {
		t.Fatalf("Failed to create test web origin: %v", err)
	}
	return webOrigin
}
