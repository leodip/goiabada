package datatests

import (
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/data/sqlitedb"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/models"
)

// TestRotateEncryptionKeyIfNeeded exercises env-to-env key rotation (issue #83):
// idempotent, canary-based detection, and fail-closed on a mismatch. Uses an
// isolated file-based sqlite DB and explicit keys.
func TestRotateEncryptionKeyIfNeeded(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "rotate.db")
	db, err := sqlitedb.NewSQLiteDatabase(&sqlitedb.DatabaseConfig{DSN: dbPath}, false)
	if err != nil {
		t.Fatalf("NewSQLiteDatabase: %v", err)
	}
	if err := db.Migrate(); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	keyA := []byte("0123456789abcdef0123456789abcdef")
	keyB := []byte("fedcba9876543210fedcba9876543210")
	keyC := []byte("aaaabbbbccccddddaaaabbbbccccdddd")

	encA := func(s string) []byte {
		b, err := encryption.EncryptText(s, keyA)
		if err != nil {
			t.Fatalf("EncryptText: %v", err)
		}
		return b
	}

	// No data yet: no canary, so nothing to rotate.
	if rotated, err := db.RotateEncryptionKeyIfNeeded(keyB, keyA); err != nil || rotated {
		t.Errorf("rotate on empty db = (%v, %v), want (false, nil)", rotated, err)
	}

	const pem = "-----BEGIN RSA PRIVATE KEY-----\nfakepem\n-----END RSA PRIVATE KEY-----\n"
	const clientSec = "client-secret"
	// The pending TOTP enrolment (#247), carried through the rotation alongside the client secret
	// so this test covers both halves of aesProtectedColumns: a settings-level secret and a
	// user-level one.
	const otpEnrolment = "otpauth://totp/Goiabada:u@example.com?secret=JBSWY3DPEHPK3PXP"

	if err := db.CreateKeyPair(nil, &models.KeyPair{
		State: "current", KeyIdentifier: uuid.NewString(), Type: "RSA", Algorithm: "RS256",
		PrivateKeyPEM: encA(pem), // canary, encrypted under keyA
	}); err != nil {
		t.Fatalf("CreateKeyPair: %v", err)
	}
	client := &models.Client{
		ClientIdentifier:      "c-" + uuid.NewString(),
		ClientSecretEncrypted: encA(clientSec),
	}
	if err := db.CreateClient(nil, client); err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	user := &models.User{
		Subject:                      uuid.New(),
		Username:                     uuid.NewString(),
		Email:                        uuid.NewString() + "@example.com",
		PasswordHash:                 "x",
		OtpEnrollmentSecretEncrypted: encA(otpEnrolment),
	}
	if err := db.CreateUser(nil, user); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// Same key, or no previous key: no-op.
	if rotated, err := db.RotateEncryptionKeyIfNeeded(keyA, keyA); err != nil || rotated {
		t.Errorf("same key = (%v, %v), want (false, nil)", rotated, err)
	}
	if rotated, err := db.RotateEncryptionKeyIfNeeded(keyA, nil); err != nil || rotated {
		t.Errorf("no previous = (%v, %v), want (false, nil)", rotated, err)
	}

	// Data is under keyA; asking to rotate between keyB (current) and keyC
	// (previous) matches neither -> fail-closed.
	if _, err := db.RotateEncryptionKeyIfNeeded(keyB, keyC); err == nil {
		t.Error("expected error when data decrypts under neither key")
	}

	// Rotate keyA -> keyB.
	rotated, err := db.RotateEncryptionKeyIfNeeded(keyB, keyA)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if !rotated {
		t.Fatal("expected rotation to occur")
	}

	gotClient, err := db.GetClientById(nil, client.Id)
	if err != nil {
		t.Fatalf("GetClientById: %v", err)
	}
	if dec, err := encryption.DecryptText(gotClient.ClientSecretEncrypted, keyB); err != nil || dec != clientSec {
		t.Errorf("client secret after rotate = (%q, %v), want (%q, nil)", dec, err, clientSec)
	}
	keys, err := db.GetAllSigningKeys(nil)
	if err != nil {
		t.Fatalf("GetAllSigningKeys: %v", err)
	}
	if dec, err := encryption.DecryptText(keys[0].PrivateKeyPEM, keyB); err != nil || dec != pem {
		t.Errorf("keypair PEM after rotate not decryptable under keyB: %v", err)
	}
	gotUser, err := db.GetUserById(nil, user.Id)
	if err != nil {
		t.Fatalf("GetUserById: %v", err)
	}
	if dec, err := encryption.DecryptText(gotUser.OtpEnrollmentSecretEncrypted, keyB); err != nil || dec != otpEnrolment {
		t.Errorf("pending OTP enrolment after rotate = (%q, %v), want (%q, nil)", dec, err, otpEnrolment)
	}
	if _, err := encryption.DecryptText(gotUser.OtpEnrollmentSecretEncrypted, keyA); err == nil {
		t.Error("pending OTP enrolment still decrypts under the retired key: is the column missing " +
			"from commondb.aesProtectedColumns?")
	}

	// Idempotent: data is already under keyB, so a repeat is a no-op.
	if rotated, err := db.RotateEncryptionKeyIfNeeded(keyB, keyA); err != nil || rotated {
		t.Errorf("second rotate = (%v, %v), want (false, nil)", rotated, err)
	}
}
