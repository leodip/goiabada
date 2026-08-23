package datatests

import (
	"sync"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/models"
)

func TestCreateKeyPair(t *testing.T) {
	keyPair := createTestKeyPair(t)

	if keyPair.Id == 0 {
		t.Error("Expected non-zero ID after creation")
	}
	if !keyPair.CreatedAt.Valid || keyPair.CreatedAt.Time.IsZero() {
		t.Error("Expected CreatedAt to be set")
	}
	if !keyPair.UpdatedAt.Valid || keyPair.UpdatedAt.Time.IsZero() {
		t.Error("Expected UpdatedAt to be set")
	}

	retrievedKeyPair, err := database.GetKeyPairById(nil, keyPair.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve created key pair: %v", err)
	}

	compareKeyPairs(t, keyPair, retrievedKeyPair)
}

func TestUpdateKeyPair(t *testing.T) {
	keyPair := createTestKeyPair(t)

	// Update all properties
	keyPair.State = enums.KeyStatePrevious.String()
	keyPair.KeyIdentifier = "updated_" + gofakeit.UUID()
	keyPair.Type = "EC"
	keyPair.Algorithm = "ES256"
	keyPair.PrivateKeyPEM = []byte(gofakeit.LoremIpsumSentence(120))
	keyPair.PublicKeyPEM = []byte(gofakeit.LoremIpsumSentence(60))
	keyPair.PublicKeyASN1_DER = []byte(gofakeit.LoremIpsumSentence(40))
	keyPair.PublicKeyJWK = []byte(gofakeit.LoremIpsumSentence(50))

	time.Sleep(timestampTick)

	err := database.UpdateKeyPair(nil, keyPair)
	if err != nil {
		t.Fatalf("Failed to update key pair: %v", err)
	}

	updatedKeyPair, err := database.GetKeyPairById(nil, keyPair.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve updated key pair: %v", err)
	}

	// Verify all properties
	if updatedKeyPair.State != keyPair.State {
		t.Errorf("Expected State %s, got %s", keyPair.State, updatedKeyPair.State)
	}
	if updatedKeyPair.KeyIdentifier != keyPair.KeyIdentifier {
		t.Errorf("Expected KeyIdentifier %s, got %s", keyPair.KeyIdentifier, updatedKeyPair.KeyIdentifier)
	}
	if updatedKeyPair.Type != keyPair.Type {
		t.Errorf("Expected Type %s, got %s", keyPair.Type, updatedKeyPair.Type)
	}
	if updatedKeyPair.Algorithm != keyPair.Algorithm {
		t.Errorf("Expected Algorithm %s, got %s", keyPair.Algorithm, updatedKeyPair.Algorithm)
	}
	if string(updatedKeyPair.PrivateKeyPEM) != string(keyPair.PrivateKeyPEM) {
		t.Errorf("Expected PrivateKeyPEM %s, got %s", keyPair.PrivateKeyPEM, updatedKeyPair.PrivateKeyPEM)
	}
	if string(updatedKeyPair.PublicKeyPEM) != string(keyPair.PublicKeyPEM) {
		t.Errorf("Expected PublicKeyPEM %s, got %s", keyPair.PublicKeyPEM, updatedKeyPair.PublicKeyPEM)
	}
	if string(updatedKeyPair.PublicKeyASN1_DER) != string(keyPair.PublicKeyASN1_DER) {
		t.Errorf("Expected PublicKeyASN1_DER %s, got %s", keyPair.PublicKeyASN1_DER, updatedKeyPair.PublicKeyASN1_DER)
	}
	if string(updatedKeyPair.PublicKeyJWK) != string(keyPair.PublicKeyJWK) {
		t.Errorf("Expected PublicKeyJWK %s, got %s", keyPair.PublicKeyJWK, updatedKeyPair.PublicKeyJWK)
	}

	if !updatedKeyPair.UpdatedAt.Time.After(updatedKeyPair.CreatedAt.Time) {
		t.Error("Expected UpdatedAt to be after CreatedAt")
	}
}

func TestGetKeyPairById(t *testing.T) {
	keyPair := createTestKeyPair(t)

	retrievedKeyPair, err := database.GetKeyPairById(nil, keyPair.Id)
	if err != nil {
		t.Fatalf("Failed to get key pair by ID: %v", err)
	}

	compareKeyPairs(t, keyPair, retrievedKeyPair)

	nonExistentKeyPair, err := database.GetKeyPairById(nil, 99999)
	if err != nil {
		t.Errorf("Expected no error for non-existent key pair, got: %v", err)
	}
	if nonExistentKeyPair != nil {
		t.Errorf("Expected nil for non-existent key pair, got a key pair with ID: %d", nonExistentKeyPair.Id)
	}
}

func TestGetAllSigningKeys(t *testing.T) {

	// delete all key pairs
	keyPairs, err := database.GetAllSigningKeys(nil)
	if err != nil {
		t.Fatalf("Failed to get all signing keys: %v", err)
	}

	for _, kp := range keyPairs {
		err := database.DeleteKeyPair(nil, kp.Id)
		if err != nil {
			t.Fatalf("Failed to delete key pair: %v", err)
		}
	}

	keyPair1 := createTestKeyPair(t)
	keyPair2 := createTestKeyPair(t)

	keyPairs, err = database.GetAllSigningKeys(nil)
	if err != nil {
		t.Fatalf("Failed to get all signing keys: %v", err)
	}

	if len(keyPairs) != 2 {
		t.Errorf("Expected 2 key pairs, got %d", len(keyPairs))
	}

	foundKeyPair1 := false
	foundKeyPair2 := false
	for _, kp := range keyPairs {
		if kp.Id == keyPair1.Id {
			foundKeyPair1 = true
		}
		if kp.Id == keyPair2.Id {
			foundKeyPair2 = true
		}
	}

	if !foundKeyPair1 || !foundKeyPair2 {
		t.Error("Not all created key pairs were found in GetAllSigningKeys result")
	}
}

func TestGetCurrentSigningKey(t *testing.T) {
	// delete all key pairs
	keyPairs, err := database.GetAllSigningKeys(nil)
	if err != nil {
		t.Fatalf("Failed to get all signing keys: %v", err)
	}

	for _, kp := range keyPairs {
		err := database.DeleteKeyPair(nil, kp.Id)
		if err != nil {
			t.Fatalf("Failed to delete key pair: %v", err)
		}
	}

	// The absent case runs here, while the table is still empty, and it has to: create
	// the current key first and there is nothing left to observe. GetCurrentSigningKey
	// returns an error rather than (nil, nil) because every caller dereferences the
	// result, so a missing current key is a panic at eight sites instead of a
	// diagnosable failure (#251). Reverse that and this assertion fails.
	if _, err := database.GetCurrentSigningKey(nil); err == nil {
		t.Fatal("Expected an error when no key pair is in the current state, got nil")
	}

	keyPair := createTestKeyPair(t)
	keyPair.State = enums.KeyStateCurrent.String()
	err = database.UpdateKeyPair(nil, keyPair)
	if err != nil {
		t.Fatalf("Failed to update key pair: %v", err)
	}

	currentKeyPair, err := database.GetCurrentSigningKey(nil)
	if err != nil {
		t.Fatalf("Failed to get current signing key: %v", err)
	}

	if currentKeyPair == nil {
		t.Fatal("Expected to find a current signing key, but got nil")
	}

	compareKeyPairs(t, keyPair, currentKeyPair)
}

func TestDeleteKeyPair(t *testing.T) {
	keyPair := createTestKeyPair(t)

	err := database.DeleteKeyPair(nil, keyPair.Id)
	if err != nil {
		t.Fatalf("Failed to delete key pair: %v", err)
	}

	deletedKeyPair, err := database.GetKeyPairById(nil, keyPair.Id)
	if err != nil {
		t.Fatalf("Error while checking for deleted key pair: %v", err)
	}
	if deletedKeyPair != nil {
		t.Errorf("Key pair still exists after deletion")
	}

	err = database.DeleteKeyPair(nil, 99999)
	if err != nil {
		t.Errorf("Expected no error when deleting non-existent key pair, got: %v", err)
	}
}

func createTestKeyPair(t *testing.T) *models.KeyPair {
	keyPair := &models.KeyPair{
		State:             enums.KeyStateCurrent.String(),
		KeyIdentifier:     gofakeit.UUID(),
		Type:              "RSA",
		Algorithm:         "RS256",
		PrivateKeyPEM:     []byte(gofakeit.LoremIpsumSentence(100)),
		PublicKeyPEM:      []byte(gofakeit.LoremIpsumSentence(50)),
		PublicKeyASN1_DER: []byte(gofakeit.LoremIpsumSentence(30)),
		PublicKeyJWK:      []byte(gofakeit.LoremIpsumSentence(40)),
	}
	err := database.CreateKeyPair(nil, keyPair)
	if err != nil {
		t.Fatalf("Failed to create test key pair: %v", err)
	}
	return keyPair
}

func compareKeyPairs(t *testing.T, expected, actual *models.KeyPair) {
	if actual.Id != expected.Id {
		t.Errorf("Expected ID %d, got %d", expected.Id, actual.Id)
	}
	if actual.State != expected.State {
		t.Errorf("Expected State %s, got %s", expected.State, actual.State)
	}
	if actual.KeyIdentifier != expected.KeyIdentifier {
		t.Errorf("Expected KeyIdentifier %s, got %s", expected.KeyIdentifier, actual.KeyIdentifier)
	}
	if actual.Type != expected.Type {
		t.Errorf("Expected Type %s, got %s", expected.Type, actual.Type)
	}
	if actual.Algorithm != expected.Algorithm {
		t.Errorf("Expected Algorithm %s, got %s", expected.Algorithm, actual.Algorithm)
	}
	if string(actual.PrivateKeyPEM) != string(expected.PrivateKeyPEM) {
		t.Errorf("Expected PrivateKeyPEM %s, got %s", expected.PrivateKeyPEM, actual.PrivateKeyPEM)
	}
	if string(actual.PublicKeyPEM) != string(expected.PublicKeyPEM) {
		t.Errorf("Expected PublicKeyPEM %s, got %s", expected.PublicKeyPEM, actual.PublicKeyPEM)
	}
	if string(actual.PublicKeyASN1_DER) != string(expected.PublicKeyASN1_DER) {
		t.Errorf("Expected PublicKeyASN1_DER %s, got %s", expected.PublicKeyASN1_DER, actual.PublicKeyASN1_DER)
	}
	if string(actual.PublicKeyJWK) != string(expected.PublicKeyJWK) {
		t.Errorf("Expected PublicKeyJWK %s, got %s", expected.PublicKeyJWK, actual.PublicKeyJWK)
	}
}

// contentionHold is how long the winning transaction keeps its row lock in
// TestUpdateKeyPairState_Concurrent before committing. Long enough that the loser's
// wait is unmistakable against scheduling noise, short enough to pay four times
// (once per engine) without the suite noticing.
const contentionHold = 300 * time.Millisecond

// clearKeyPairState deletes every key pair sitting in state, so a row can be created
// there or moved into it. Stage 4's UNIQUE (state) refuses an update into an occupied
// state, and the data-test database is shared and never dropped, so a row left in
// 'previous' by an earlier case or an earlier run would fail every current -> previous
// transition below on all four engines. This is the same ordering production observes:
// the rotator deletes the previous key before demoting the current one (#251).
func clearKeyPairState(t *testing.T, state string) {
	t.Helper()

	keyPairs, err := database.GetAllSigningKeys(nil)
	if err != nil {
		t.Fatalf("Failed to get all signing keys: %v", err)
	}
	for _, kp := range keyPairs {
		if kp.State != state {
			continue
		}
		if err := database.DeleteKeyPair(nil, kp.Id); err != nil {
			t.Fatalf("Failed to delete key pair in state %s: %v", state, err)
		}
	}
}

// createKeyPairInState creates a key pair already in state, clearing whatever held
// that state first.
func createKeyPairInState(t *testing.T, state string) *models.KeyPair {
	t.Helper()

	clearKeyPairState(t, state)

	keyPair := &models.KeyPair{
		State:             state,
		KeyIdentifier:     gofakeit.UUID(),
		Type:              "RSA",
		Algorithm:         "RS256",
		PrivateKeyPEM:     []byte(gofakeit.LoremIpsumSentence(100)),
		PublicKeyPEM:      []byte(gofakeit.LoremIpsumSentence(50)),
		PublicKeyASN1_DER: []byte(gofakeit.LoremIpsumSentence(30)),
		PublicKeyJWK:      []byte(gofakeit.LoremIpsumSentence(40)),
	}
	if err := database.CreateKeyPair(nil, keyPair); err != nil {
		t.Fatalf("Failed to create test key pair in state %s: %v", state, err)
	}
	return keyPair
}

func TestUpdateKeyPairState_TransitionsAndReadsBack(t *testing.T) {
	current := enums.KeyStateCurrent.String()
	previous := enums.KeyStatePrevious.String()

	keyPair := createKeyPairInState(t, current)
	clearKeyPairState(t, previous)

	moved, err := database.UpdateKeyPairState(nil, keyPair.Id, current, previous)
	if err != nil {
		t.Fatalf("Failed to update key pair state: %v", err)
	}
	if !moved {
		t.Fatal("Expected the transition to be made by this call")
	}

	retrieved, err := database.GetKeyPairById(nil, keyPair.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve key pair: %v", err)
	}
	if retrieved.State != previous {
		t.Errorf("Expected State %s, got %s", previous, retrieved.State)
	}
}

func TestUpdateKeyPairState_RepeatedCallDoesNotTransition(t *testing.T) {
	current := enums.KeyStateCurrent.String()
	previous := enums.KeyStatePrevious.String()

	keyPair := createKeyPairInState(t, current)
	clearKeyPairState(t, previous)

	moved, err := database.UpdateKeyPairState(nil, keyPair.Id, current, previous)
	if err != nil {
		t.Fatalf("Failed to update key pair state: %v", err)
	}
	if !moved {
		t.Fatal("Expected the first call to make the transition")
	}

	// The id still matches, so the state = fromState predicate is the only thing that
	// can reject this. Remove it and the same row transitions twice, which is exactly
	// what lets a losing rotation act on a snapshot the winner has already moved past.
	moved, err = database.UpdateKeyPairState(nil, keyPair.Id, current, previous)
	if err != nil {
		t.Fatalf("Expected no error on the repeated call, got: %v", err)
	}
	if moved {
		t.Error("Expected the repeated call to report no transition: the row is no longer in the from-state")
	}
}

func TestUpdateKeyPairState_WrongFromStateDoesNotTransition(t *testing.T) {
	current := enums.KeyStateCurrent.String()
	next := enums.KeyStateNext.String()
	previous := enums.KeyStatePrevious.String()

	// A row in 'next' asked to make the current -> previous transition. This varies
	// exactly one thing from TestUpdateKeyPairState_TransitionsAndReadsBack.
	keyPair := createKeyPairInState(t, next)
	clearKeyPairState(t, previous)

	moved, err := database.UpdateKeyPairState(nil, keyPair.Id, current, previous)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if moved {
		t.Error("Expected no transition for a row that is not in the from-state")
	}

	retrieved, err := database.GetKeyPairById(nil, keyPair.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve key pair: %v", err)
	}
	if retrieved.State != next {
		t.Errorf("Expected State to be left at %s, got %s", next, retrieved.State)
	}
}

func TestUpdateKeyPairState_MissingIdDoesNotTransition(t *testing.T) {
	moved, err := database.UpdateKeyPairState(nil, 99999,
		enums.KeyStateCurrent.String(), enums.KeyStatePrevious.String())
	if err != nil {
		t.Fatalf("Expected no error for a non-existent key pair, got: %v", err)
	}
	if moved {
		t.Error("Expected no transition for a non-existent key pair")
	}
}

func TestUpdateKeyPairState_ZeroIdIsAnError(t *testing.T) {
	moved, err := database.UpdateKeyPairState(nil, 0,
		enums.KeyStateCurrent.String(), enums.KeyStatePrevious.String())
	if err == nil {
		t.Fatal("Expected an error for a zero key pair id, got nil")
	}
	if moved {
		t.Error("Expected no transition for a zero key pair id")
	}
}

func TestUpdateKeyPairState_EnlistsInCallersTransaction(t *testing.T) {
	current := enums.KeyStateCurrent.String()
	previous := enums.KeyStatePrevious.String()

	keyPair := createKeyPairInState(t, current)
	clearKeyPairState(t, previous)

	tx, err := database.BeginTransaction()
	if err != nil {
		t.Fatalf("Failed to begin transaction: %v", err)
	}

	moved, err := database.UpdateKeyPairState(tx, keyPair.Id, current, previous)
	if err != nil {
		_ = database.RollbackTransaction(tx)
		t.Fatalf("Failed to update key pair state: %v", err)
	}
	if !moved {
		_ = database.RollbackTransaction(tx)
		t.Fatal("Expected the transition to be made by this call")
	}

	if err := database.RollbackTransaction(tx); err != nil {
		t.Fatalf("Failed to roll back transaction: %v", err)
	}

	// A statement that ignored the caller's tx and used the pool instead would have
	// committed, and the rollback would not have undone it.
	retrieved, err := database.GetKeyPairById(nil, keyPair.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve key pair: %v", err)
	}
	if retrieved.State != current {
		t.Errorf("Expected the rollback to leave State at %s, got %s", current, retrieved.State)
	}
}

// TestUpdateKeyPairState_Concurrent is the property seam 2 owns: two transactions
// racing the same transition produce exactly one winner, the loser reporting false
// rather than an error. This is probe/probe_251_test.go.txt's Q3 lifted onto the
// interface method.
//
// One winner is not on its own evidence of a race: two calls run end to end in
// sequence produce the same pair of answers, because the second finds the row no
// longer in the from-state. So each goroutine times the span from just before
// BeginTransaction to just after UpdateKeyPairState returns, and the loser's span
// must be at least a third of contentionHold, which it can only be if it was blocked
// while the winner still held. A sequential run measures the loser at near zero.
//
// The mechanism differs per engine and the observable does not: on postgres, mysql
// and mssql the loser waits on the row lock, and on sqlite it waits on the pool,
// which SetMaxOpenConns(1) limits to one connection. Asserting that the two
// transactions overlapped would be unprovable on sqlite, where that setting makes
// overlap impossible by construction, so the assertion is on being blocked (#251).
func TestUpdateKeyPairState_Concurrent(t *testing.T) {
	current := enums.KeyStateCurrent.String()
	previous := enums.KeyStatePrevious.String()

	keyPair := createKeyPairInState(t, current)
	clearKeyPairState(t, previous)

	type outcome struct {
		moved bool
		err   error
		span  time.Duration
	}
	outcomes := make([]outcome, 2)

	// Both goroutines wait on the same barrier so they reach the row together.
	start := make(chan struct{})
	var wg sync.WaitGroup

	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start

			began := time.Now()
			tx, err := database.BeginTransaction()
			if err != nil {
				outcomes[i] = outcome{err: err, span: time.Since(began)}
				return
			}
			moved, err := database.UpdateKeyPairState(tx, keyPair.Id, current, previous)
			span := time.Since(began)
			if err != nil {
				_ = database.RollbackTransaction(tx)
				outcomes[i] = outcome{err: err, span: span}
				return
			}

			// The winner holds its lock while the loser is still trying, so the
			// loser's wait is observable.
			time.Sleep(contentionHold)

			if err := database.CommitTransaction(tx); err != nil {
				outcomes[i] = outcome{moved: moved, err: err, span: span}
				return
			}
			outcomes[i] = outcome{moved: moved, span: span}
		}(i)
	}

	close(start)
	wg.Wait()

	wins := 0
	var loser outcome
	for i, o := range outcomes {
		if o.err != nil {
			t.Fatalf("goroutine %d: expected no error, got: %v", i, o.err)
		}
		if o.moved {
			wins++
		} else {
			loser = o
		}
	}

	if wins != 1 {
		t.Fatalf("Expected exactly 1 winner among 2 concurrent transitions, got %d", wins)
	}

	minWait := contentionHold / 3
	if loser.span < minWait {
		t.Errorf("Expected the loser to be blocked for at least %v while the winner held, "+
			"but it returned after %v: the two transitions did not contend", minWait, loser.span)
	}
}
