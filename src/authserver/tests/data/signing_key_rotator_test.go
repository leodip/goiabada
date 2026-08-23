package datatests

import (
	"errors"
	"testing"

	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
)

// This is seam 1 at the data tier, on all four engines: the rotator's composition against
// real SQL rather than against a mock's idea of it. The unit tests in
// core/oauth/signing_key_rotator_test.go own which calls are made in which order and what
// happens on every refusal; only this one can say the resulting statements are accepted by
// mysql, postgres, mssql and sqlite and leave the key set the rotation claims.
//
// The concurrency property is deliberately not asserted here. The replacement key is
// generated before the transaction opens and a 4096-bit generation takes about 300ms with
// wide variance, so two goroutines calling Rotate() may not overlap at all, and when they
// do not, both rotations succeed, which is correct behaviour that would fail such a test.
// The race is covered where it is deterministic: TestUpdateKeyPairState_Concurrent in
// key_pair_test.go, and the two losing branches driven directly at the unit tier.

// seedOneKeyPerState leaves exactly one row in each state and returns them. Exactly one,
// because stage 4's UNIQUE (state) must not be able to falsify this case, and because the
// data-test database is shared and never dropped, so rows from an earlier run would
// otherwise decide what the rotation finds.
func seedOneKeyPerState(t *testing.T) (previous, current, next *models.KeyPair) {
	t.Helper()

	previous = createKeyPairInState(t, enums.KeyStatePrevious.String())
	current = createKeyPairInState(t, enums.KeyStateCurrent.String())
	next = createKeyPairInState(t, enums.KeyStateNext.String())
	return previous, current, next
}

func TestSigningKeyRotator_Rotate_MovesEveryKeyOneStep(t *testing.T) {
	previous, current, next := seedOneKeyPerState(t)

	if err := oauth.NewSigningKeyRotator(database).Rotate(); err != nil {
		t.Fatalf("Rotate failed: %v", err)
	}

	keyPairs, err := database.GetAllSigningKeys(nil)
	if err != nil {
		t.Fatalf("Failed to get all signing keys: %v", err)
	}
	if len(keyPairs) != 3 {
		t.Fatalf("Expected 3 key pairs after rotating, got %d", len(keyPairs))
	}

	byState := map[string]*models.KeyPair{}
	for i := range keyPairs {
		kp := &keyPairs[i]
		if existing, duplicate := byState[kp.State]; duplicate {
			t.Fatalf("Two key pairs in state %s: ids %d and %d", kp.State, existing.Id, kp.Id)
		}
		byState[kp.State] = kp
	}

	// The old current key is now the only previous one. This is the key that signed every
	// token still in flight, and retaining it is what OIDC Core 10.1.1 asks for.
	newPrevious := byState[enums.KeyStatePrevious.String()]
	if newPrevious == nil {
		t.Fatal("Expected a previous key after rotating")
	}
	if newPrevious.Id != current.Id {
		t.Errorf("Expected the old current key (id %d) to be previous, got id %d",
			current.Id, newPrevious.Id)
	}

	// The old next key is now current, so the deployment can still sign.
	newCurrent := byState[enums.KeyStateCurrent.String()]
	if newCurrent == nil {
		t.Fatal("Expected a current key after rotating")
	}
	if newCurrent.Id != next.Id {
		t.Errorf("Expected the old next key (id %d) to be current, got id %d",
			next.Id, newCurrent.Id)
	}

	// The key that was previous before the rotation is gone, which is the one deletion
	// the rotation is entitled to make.
	deleted, err := database.GetKeyPairById(nil, previous.Id)
	if err != nil {
		t.Fatalf("Failed to look up the old previous key: %v", err)
	}
	if deleted != nil {
		t.Errorf("Expected the old previous key (id %d) to be gone, it is still in state %s",
			previous.Id, deleted.State)
	}

	// A freshly generated next key, not a row moved from somewhere else.
	newNext := byState[enums.KeyStateNext.String()]
	if newNext == nil {
		t.Fatal("Expected a next key after rotating")
	}
	if newNext.Id == previous.Id || newNext.Id == current.Id || newNext.Id == next.Id {
		t.Errorf("Expected a newly created next key, got the seeded id %d", newNext.Id)
	}
	if newNext.KeyIdentifier == next.KeyIdentifier {
		t.Error("Expected the new next key to carry a fresh key identifier")
	}
	if newNext.Type != "RSA" || newNext.Algorithm != "RS256" {
		t.Errorf("Expected an RSA/RS256 key, got %s/%s", newNext.Type, newNext.Algorithm)
	}
	if len(newNext.PublicKeyASN1_DER) == 0 || len(newNext.PublicKeyJWK) == 0 {
		t.Error("Expected the new next key to carry its DER and JWK encodings")
	}

	// The private key survives the round trip through the column encrypted (#83), so it
	// decrypts back to a PEM rather than being stored in the clear.
	decrypted, err := encryption.DecryptData(newNext.PrivateKeyPEM)
	if err != nil {
		t.Fatalf("Failed to decrypt the new next key's private key: %v", err)
	}
	if len(decrypted) == 0 {
		t.Error("Expected the decrypted private key to be non-empty")
	}

	// GetCurrentSigningKey is what every token issuer asks, so the promotion has to be
	// visible through it and not only through GetAllSigningKeys.
	signingKey, err := database.GetCurrentSigningKey(nil)
	if err != nil {
		t.Fatalf("Failed to get the current signing key: %v", err)
	}
	if signingKey.Id != next.Id {
		t.Errorf("Expected the current signing key to be id %d, got id %d", next.Id, signingKey.Id)
	}
}

// TestSigningKeyRotator_Rotate_RefusesWithNoNextKeyAndKeepsThePrevious is the issue's own
// first test: a rotation attempted with no next row refuses without deleting the previous
// key. Against a real engine, so the refusal's rollback is a real rollback.
func TestSigningKeyRotator_Rotate_RefusesWithNoNextKeyAndKeepsThePrevious(t *testing.T) {
	previous, current, _ := seedOneKeyPerState(t)
	clearKeyPairState(t, enums.KeyStateNext.String())

	err := oauth.NewSigningKeyRotator(database).Rotate()
	if err == nil {
		t.Fatal("Expected the rotation to be refused")
	}
	if !errors.Is(err, oauth.ErrKeySetIncomplete) {
		t.Fatalf("Expected ErrKeySetIncomplete, got %v", err)
	}

	// Nothing moved. The previous key is the whole point: the old code deleted it before
	// discovering it could not rotate, retiring every token it had signed (#251).
	survivor, err := database.GetKeyPairById(nil, previous.Id)
	if err != nil {
		t.Fatalf("Failed to look up the previous key: %v", err)
	}
	if survivor == nil {
		t.Fatal("The previous key was deleted by a rotation that then refused")
	}
	if survivor.State != enums.KeyStatePrevious.String() {
		t.Errorf("Expected the previous key to be untouched, it is in state %s", survivor.State)
	}

	stillCurrent, err := database.GetKeyPairById(nil, current.Id)
	if err != nil {
		t.Fatalf("Failed to look up the current key: %v", err)
	}
	if stillCurrent == nil || stillCurrent.State != enums.KeyStateCurrent.String() {
		t.Error("Expected the current key to be untouched by the refused rotation")
	}

	keyPairs, err := database.GetAllSigningKeys(nil)
	if err != nil {
		t.Fatalf("Failed to get all signing keys: %v", err)
	}
	if len(keyPairs) != 2 {
		t.Errorf("Expected the refused rotation to write nothing, found %d key pairs", len(keyPairs))
	}
}
