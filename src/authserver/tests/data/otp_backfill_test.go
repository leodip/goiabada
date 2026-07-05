package datatests

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/data/sqlitedb"
	"github.com/leodip/goiabada/core/models"
)

// TestBackfillEncryptedOTPSecrets exercises the one-time migration of legacy
// plaintext TOTP secrets to the encrypted column (issue #82). It uses an
// isolated in-memory database: every createTestUser row in the shared test
// database carries a plaintext otp_secret that the backfill would rewrite, so
// running it against the shared database would corrupt other tests.
func TestBackfillEncryptedOTPSecrets(t *testing.T) {
	// A file-based DB in a temp dir: the sqlite driver requires WAL journal mode,
	// which an in-memory database cannot provide.
	dbPath := filepath.Join(t.TempDir(), "otp_backfill.db")
	db, err := sqlitedb.NewSQLiteDatabase(&sqlitedb.DatabaseConfig{DSN: dbPath}, false)
	if err != nil {
		t.Fatalf("NewSQLiteDatabase: %v", err)
	}
	if err := db.Migrate(); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	key := []byte("0123456789abcdef0123456789abcdef") // 32 bytes

	create := func(u *models.User) *models.User {
		u.Subject = uuid.New()
		u.Username = uuid.NewString()
		u.Email = uuid.NewString() + "@example.com"
		u.PasswordHash = "x"
		if err := db.CreateUser(nil, u); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		return u
	}

	// Legacy row: plaintext secret, no encrypted value.
	const legacySeed = "PLAINTEXTSEEDAAA"
	legacy := create(&models.User{OTPSecret: legacySeed, OTPEnabled: true})

	// Row with no OTP at all.
	noOtp := create(&models.User{})

	// Already-encrypted row: SetOTPSecret encrypts and blanks the plaintext, so
	// the backfill must leave it untouched.
	const preSeed = "ALREADYENC123456"
	alreadyEnc := &models.User{OTPEnabled: true}
	if err := alreadyEnc.SetOTPSecret(preSeed, key); err != nil {
		t.Fatalf("SetOTPSecret: %v", err)
	}
	alreadyEnc = create(alreadyEnc)
	encBefore := append([]byte(nil), alreadyEnc.OTPSecretEncrypted...)

	// Exactly the one legacy row should be migrated.
	migrated, err := db.BackfillEncryptedOTPSecrets(key)
	if err != nil {
		t.Fatalf("BackfillEncryptedOTPSecrets: %v", err)
	}
	if migrated != 1 {
		t.Errorf("migrated = %d, want 1", migrated)
	}

	// Legacy row: plaintext cleared; encrypted value decrypts to the seed.
	gotLegacy, err := db.GetUserById(nil, legacy.Id)
	if err != nil {
		t.Fatalf("GetUserById(legacy): %v", err)
	}
	if gotLegacy.OTPSecret != "" {
		t.Errorf("legacy OTPSecret plaintext = %q, want empty", gotLegacy.OTPSecret)
	}
	if dec, err := gotLegacy.GetOTPSecret(key); err != nil || dec != legacySeed {
		t.Errorf("legacy decrypted = (%q, %v), want (%q, nil)", dec, err, legacySeed)
	}

	// No-OTP row: untouched.
	gotNoOtp, err := db.GetUserById(nil, noOtp.Id)
	if err != nil {
		t.Fatalf("GetUserById(noOtp): %v", err)
	}
	if gotNoOtp.OTPSecret != "" || len(gotNoOtp.OTPSecretEncrypted) != 0 {
		t.Errorf("noOtp row modified: secret=%q enc len=%d", gotNoOtp.OTPSecret, len(gotNoOtp.OTPSecretEncrypted))
	}

	// Already-encrypted row: ciphertext unchanged.
	gotEnc, err := db.GetUserById(nil, alreadyEnc.Id)
	if err != nil {
		t.Fatalf("GetUserById(alreadyEnc): %v", err)
	}
	if !bytes.Equal(gotEnc.OTPSecretEncrypted, encBefore) {
		t.Error("already-encrypted row's ciphertext changed")
	}

	// Idempotent: a second run migrates nothing and leaves the legacy row valid.
	migrated2, err := db.BackfillEncryptedOTPSecrets(key)
	if err != nil {
		t.Fatalf("second BackfillEncryptedOTPSecrets: %v", err)
	}
	if migrated2 != 0 {
		t.Errorf("second run migrated = %d, want 0", migrated2)
	}
	gotLegacy2, _ := db.GetUserById(nil, legacy.Id)
	if dec2, err := gotLegacy2.GetOTPSecret(key); err != nil || dec2 != legacySeed {
		t.Errorf("legacy after second run = (%q, %v), want (%q, nil)", dec2, err, legacySeed)
	}

	// Fail-closed: an invalid (non-32-byte) AES key is rejected.
	if _, err := db.BackfillEncryptedOTPSecrets([]byte("too-short")); err == nil {
		t.Error("expected error for non-32-byte AES key, got nil")
	}
}
