package datatests

import (
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/authserver/internal/enums"
	"github.com/leodip/goiabada/authserver/internal/models"
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

	time.Sleep(time.Millisecond * 100)

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
		database.DeleteKeyPair(nil, kp.Id)
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
		database.DeleteKeyPair(nil, kp.Id)
	}

	keyPair := createTestKeyPair(t)
	keyPair.State = enums.KeyStateCurrent.String()
	database.UpdateKeyPair(nil, keyPair)

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
