package datatests

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/data/sqlitedb"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/models"
)

// TestReencryptDataToNewKey verifies the startup re-encryption migration (issue
// #83): every AES-protected secret is re-keyed from the old key to the new key,
// the RSA private key (plaintext PEM) becomes encrypted, and the legacy
// aes_encryption_key column is blanked. It uses an isolated file-based sqlite DB
// and explicit keys, independent of the shared harness and the process cipher.
func TestReencryptDataToNewKey(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "reencrypt.db")
	db, err := sqlitedb.NewSQLiteDatabase(&sqlitedb.DatabaseConfig{DSN: dbPath}, false)
	if err != nil {
		t.Fatalf("NewSQLiteDatabase: %v", err)
	}
	if err := db.Migrate(); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	oldKey := []byte("0123456789abcdef0123456789abcdef")
	newKey := []byte("fedcba9876543210fedcba9876543210")

	encOld := func(s string) []byte {
		b, err := encryption.EncryptText(s, oldKey)
		if err != nil {
			t.Fatalf("EncryptText: %v", err)
		}
		return b
	}

	const (
		smtpPass   = "smtp-password"
		clientSec  = "client-secret-value"
		otpSeed    = "JBSWY3DPEHPK3PXP"
		emailCode  = "email-verif-code"
		preRegCode = "prereg-verif-code"
		pemPlain   = "-----BEGIN RSA PRIVATE KEY-----\nMIIabc123fakepemcontent\n-----END RSA PRIVATE KEY-----\n"
	)

	// settings: legacy key present + an encrypted SMTP password.
	settings := &models.Settings{
		AESEncryptionKeyLegacy: oldKey,
		SMTPPasswordEncrypted:  encOld(smtpPass),
	}
	if err := db.CreateSettings(nil, settings); err != nil {
		t.Fatalf("CreateSettings: %v", err)
	}

	client := &models.Client{
		ClientIdentifier:      "reencrypt-client-" + uuid.NewString(),
		ClientSecretEncrypted: encOld(clientSec),
	}
	if err := db.CreateClient(nil, client); err != nil {
		t.Fatalf("CreateClient: %v", err)
	}

	user := &models.User{
		Subject:                        uuid.New(),
		Username:                       uuid.NewString(),
		Email:                          uuid.NewString() + "@example.com",
		PasswordHash:                   "x",
		OTPSecretEncrypted:             encOld(otpSeed),
		EmailVerificationCodeEncrypted: encOld(emailCode),
	}
	if err := db.CreateUser(nil, user); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	preReg := &models.PreRegistration{
		Email:                     uuid.NewString() + "@example.com",
		PasswordHash:              "x",
		VerificationCodeEncrypted: encOld(preRegCode),
	}
	if err := db.CreatePreRegistration(nil, preReg); err != nil {
		t.Fatalf("CreatePreRegistration: %v", err)
	}

	// RSA key pair stored as PLAINTEXT PEM (the pre-#83 state).
	keyPair := &models.KeyPair{
		State:         "current",
		KeyIdentifier: uuid.NewString(),
		Type:          "RSA",
		Algorithm:     "RS256",
		PrivateKeyPEM: []byte(pemPlain),
	}
	if err := db.CreateKeyPair(nil, keyPair); err != nil {
		t.Fatalf("CreateKeyPair: %v", err)
	}

	// Run the migration.
	if err := db.ReencryptDataToNewKey(oldKey, newKey); err != nil {
		t.Fatalf("ReencryptDataToNewKey: %v", err)
	}

	// Helper: a column must now decrypt with newKey to want.
	mustDecryptNew := func(name string, ct []byte, want string) {
		got, err := encryption.DecryptText(ct, newKey)
		if err != nil {
			t.Errorf("%s: decrypt with new key failed: %v", name, err)
			return
		}
		if got != want {
			t.Errorf("%s: got %q, want %q", name, got, want)
		}
	}

	gotSettings, err := db.GetSettingsById(nil, settings.Id)
	if err != nil {
		t.Fatalf("GetSettingsById: %v", err)
	}
	mustDecryptNew("settings.smtp_password", gotSettings.SMTPPasswordEncrypted, smtpPass)
	if len(gotSettings.AESEncryptionKeyLegacy) != 0 {
		t.Errorf("legacy aes_encryption_key not blanked: len=%d", len(gotSettings.AESEncryptionKeyLegacy))
	}

	gotClient, err := db.GetClientById(nil, client.Id)
	if err != nil {
		t.Fatalf("GetClientById: %v", err)
	}
	mustDecryptNew("clients.client_secret", gotClient.ClientSecretEncrypted, clientSec)

	gotUser, err := db.GetUserById(nil, user.Id)
	if err != nil {
		t.Fatalf("GetUserById: %v", err)
	}
	mustDecryptNew("users.otp_secret", gotUser.OTPSecretEncrypted, otpSeed)
	mustDecryptNew("users.email_verification_code", gotUser.EmailVerificationCodeEncrypted, emailCode)

	gotPreReg, err := db.GetPreRegistrationById(nil, preReg.Id)
	if err != nil {
		t.Fatalf("GetPreRegistrationById: %v", err)
	}
	mustDecryptNew("pre_registrations.verification_code", gotPreReg.VerificationCodeEncrypted, preRegCode)

	// RSA private key: now encrypted (no plaintext PEM prefix) and decrypts to the original.
	keys, err := db.GetAllSigningKeys(nil)
	if err != nil {
		t.Fatalf("GetAllSigningKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key pair, got %d", len(keys))
	}
	if bytes.HasPrefix(keys[0].PrivateKeyPEM, []byte("-----BEGIN")) {
		t.Error("private key PEM is still plaintext after migration")
	}
	mustDecryptNew("key_pairs.private_key_pem", keys[0].PrivateKeyPEM, pemPlain)
}
