package datatests

import (
	"database/sql"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/core/models"
)

func TestCreatePreRegistration(t *testing.T) {
	preReg := createTestPreRegistration(t)

	if preReg.Id == 0 {
		t.Error("Expected non-zero ID after creation")
	}
	if !preReg.CreatedAt.Valid || preReg.CreatedAt.Time.IsZero() {
		t.Error("Expected CreatedAt to be set")
	}
	if !preReg.UpdatedAt.Valid || preReg.UpdatedAt.Time.IsZero() {
		t.Error("Expected UpdatedAt to be set")
	}

	retrievedPreReg, err := database.GetPreRegistrationById(nil, preReg.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve created pre-registration: %v", err)
	}

	validatePreRegistration(t, preReg, retrievedPreReg)
}

func TestUpdatePreRegistration(t *testing.T) {
	preReg := createTestPreRegistration(t)

	preReg.Email = "updated_" + gofakeit.Email()
	preReg.PasswordHash = gofakeit.Password(true, true, true, true, false, 16)
	preReg.VerificationCodeEncrypted = []byte(gofakeit.UUID())
	preReg.VerificationCodeIssuedAt = sql.NullTime{Time: time.Now().UTC().Truncate(time.Microsecond), Valid: true}

	time.Sleep(timestampTick)

	err := database.UpdatePreRegistration(nil, preReg)
	if err != nil {
		t.Fatalf("Failed to update pre-registration: %v", err)
	}

	updatedPreReg, err := database.GetPreRegistrationById(nil, preReg.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve updated pre-registration: %v", err)
	}

	validatePreRegistration(t, preReg, updatedPreReg)

	if !updatedPreReg.UpdatedAt.Time.After(updatedPreReg.CreatedAt.Time) {
		t.Error("Expected UpdatedAt to be after CreatedAt")
	}
}

func TestGetPreRegistrationById(t *testing.T) {
	preReg := createTestPreRegistration(t)

	retrievedPreReg, err := database.GetPreRegistrationById(nil, preReg.Id)
	if err != nil {
		t.Fatalf("Failed to get pre-registration by ID: %v", err)
	}

	validatePreRegistration(t, preReg, retrievedPreReg)

	nonExistentPreReg, err := database.GetPreRegistrationById(nil, 99999)
	if err != nil {
		t.Errorf("Expected no error for non-existent pre-registration, got: %v", err)
	}
	if nonExistentPreReg != nil {
		t.Errorf("Expected nil for non-existent pre-registration, got a pre-registration with ID: %d", nonExistentPreReg.Id)
	}
}

func TestGetPreRegistrationByEmail(t *testing.T) {
	preReg := createTestPreRegistration(t)

	retrievedPreReg, err := database.GetPreRegistrationByEmail(nil, preReg.Email)
	if err != nil {
		t.Fatalf("Failed to get pre-registration by email: %v", err)
	}

	validatePreRegistration(t, preReg, retrievedPreReg)

	nonExistentPreReg, err := database.GetPreRegistrationByEmail(nil, "non_existent_email@example.com")
	if err != nil {
		t.Errorf("Expected no error for non-existent pre-registration, got: %v", err)
	}
	if nonExistentPreReg != nil {
		t.Errorf("Expected nil for non-existent pre-registration, got a pre-registration with ID: %d", nonExistentPreReg.Id)
	}
}

func TestDeletePreRegistration(t *testing.T) {
	preReg := createTestPreRegistration(t)

	err := database.DeletePreRegistration(nil, preReg.Id)
	if err != nil {
		t.Fatalf("Failed to delete pre-registration: %v", err)
	}

	deletedPreReg, err := database.GetPreRegistrationById(nil, preReg.Id)
	if err != nil {
		t.Fatalf("Error while checking for deleted pre-registration: %v", err)
	}
	if deletedPreReg != nil {
		t.Errorf("Pre-registration still exists after deletion")
	}

	err = database.DeletePreRegistration(nil, 99999)
	if err != nil {
		t.Errorf("Expected no error when deleting non-existent pre-registration, got: %v", err)
	}
}

func createTestPreRegistration(t *testing.T) *models.PreRegistration {
	// The code hash is unique per row and never empty, which is what the production
	// caller does: verification_code_hash is UNIQUE, so two rows sharing the '' default
	// would be refused by the index (#112).
	preReg := &models.PreRegistration{
		Email:                     gofakeit.Email(),
		PasswordHash:              gofakeit.Password(true, true, true, true, false, 16),
		VerificationCodeEncrypted: []byte(gofakeit.UUID()),
		VerificationCodeIssuedAt:  sql.NullTime{Time: time.Now().UTC().Truncate(time.Microsecond), Valid: true},
		VerificationCodeHash:      codeHashOf(t, gofakeit.UUID()),
	}
	err := database.CreatePreRegistration(nil, preReg)
	if err != nil {
		t.Fatalf("Failed to create test pre-registration: %v", err)
	}
	return preReg
}

func validatePreRegistration(t *testing.T, expected, actual *models.PreRegistration) {
	if actual.Id != expected.Id {
		t.Errorf("Expected ID %d, got %d", expected.Id, actual.Id)
	}
	if actual.Email != expected.Email {
		t.Errorf("Expected Email %s, got %s", expected.Email, actual.Email)
	}
	if actual.PasswordHash != expected.PasswordHash {
		t.Errorf("Expected PasswordHash %s, got %s", expected.PasswordHash, actual.PasswordHash)
	}
	if string(actual.VerificationCodeEncrypted) != string(expected.VerificationCodeEncrypted) {
		t.Errorf("Expected VerificationCodeEncrypted %v, got %v", expected.VerificationCodeEncrypted, actual.VerificationCodeEncrypted)
	}
	if !actual.VerificationCodeIssuedAt.Time.Equal(expected.VerificationCodeIssuedAt.Time) {
		t.Errorf("Expected VerificationCodeIssuedAt %v, got %v", expected.VerificationCodeIssuedAt, actual.VerificationCodeIssuedAt)
	}
	if actual.VerificationCodeHash != expected.VerificationCodeHash {
		t.Errorf("Expected VerificationCodeHash %s, got %s", expected.VerificationCodeHash, actual.VerificationCodeHash)
	}
}

// TestGetPreRegistrationByVerificationCodeHash is the identity half of seam 2 for the
// activation flow: the link carries the code and no address, so this lookup is the only
// thing that says which pending registration an activation link belongs to (#112).
func TestGetPreRegistrationByVerificationCodeHash(t *testing.T) {
	preReg := createTestPreRegistration(t)

	// 8. The hash that was stored finds the row it was stored on.
	found, err := database.GetPreRegistrationByVerificationCodeHash(nil, preReg.VerificationCodeHash)
	if err != nil {
		t.Fatalf("lookup by the stored hash failed: %v", err)
	}
	if found == nil {
		t.Fatal("the stored hash must find the pre-registration it was stored on")
	}
	validatePreRegistration(t, preReg, found)

	// 9. A hash no row carries is a miss, not an error.
	missing, err := database.GetPreRegistrationByVerificationCodeHash(nil, codeHashOf(t, gofakeit.UUID()))
	if err != nil {
		t.Errorf("a hash no row carries must not be an error, got: %v", err)
	}
	if missing != nil {
		t.Errorf("a hash no row carries must return nil, got pre-registration id %d", missing.Id)
	}
}

// TestGetPreRegistrationByVerificationCodeHash_EmptyNeverMatches is case 10: the dormant
// empty value is not findable.
//
// Exactly ONE dormant row is seeded, unlike the users mirror, because
// verification_code_hash is UNIQUE and a second empty value would be refused by the
// index. That is
// the whole reason migration 000028 empties the table: rows written before it would all
// carry the empty string and CREATE UNIQUE INDEX would abort at startup on any
// deployment holding two.
func TestGetPreRegistrationByVerificationCodeHash_EmptyNeverMatches(t *testing.T) {
	// A fixed address rather than a random one, so this case can find and remove its own
	// leftovers. The shared test database outlives the run and the UNIQUE index allows one
	// '' row at a time, so a run interrupted before the cleanup below would otherwise leave
	// this case failing on every later run against that database, with no way to identify
	// the offending row through the interface: the lookup refuses '' by design, so nothing
	// can find it by hash.
	const dormantEmail = "dormant-code-hash@goiabada.test"
	deleteDormant := func() {
		if leftover, err := database.GetPreRegistrationByEmail(nil, dormantEmail); err == nil && leftover != nil {
			_ = database.DeletePreRegistration(nil, leftover.Id)
		}
	}
	deleteDormant()
	t.Cleanup(deleteDormant)

	dormant := &models.PreRegistration{
		Email:        dormantEmail,
		PasswordHash: gofakeit.Password(true, true, true, true, false, 16),
	}
	if err := database.CreatePreRegistration(nil, dormant); err != nil {
		t.Fatalf("Failed to create the dormant pre-registration: %v", err)
	}

	if dormant.VerificationCodeHash != "" {
		t.Fatalf("a pre-registration written without a code hash must carry '', got %q", dormant.VerificationCodeHash)
	}

	found, err := database.GetPreRegistrationByVerificationCodeHash(nil, "")
	if err != nil {
		t.Errorf("an empty hash must not be an error, got: %v", err)
	}
	if found != nil {
		t.Errorf("an empty hash matched pre-registration id %d; the dormant value must never be findable", found.Id)
	}

	// The same fact from the other side: a real hash nobody holds still misses while the
	// dormant row is present, so the guard is not the only thing answering.
	found, err = database.GetPreRegistrationByVerificationCodeHash(nil, codeHashOf(t, "a code nobody was ever issued"))
	if err != nil {
		t.Errorf("a hash no row carries must not be an error, got: %v", err)
	}
	if found != nil {
		t.Errorf("a hash no row carries matched pre-registration id %d", found.Id)
	}
}

// TestGetPreRegistrationByVerificationCodeHash_Transaction is cases 11 and 12: the lookup
// runs on the caller's transaction, and a failure propagates as an error rather than as a
// benign "no such code". It reads only through the transaction while that transaction is
// open, for the reasons the users mirror documents.
func TestGetPreRegistrationByVerificationCodeHash_Transaction(t *testing.T) {
	hash := codeHashOf(t, gofakeit.UUID())

	tx := beginTx(t)

	preReg := &models.PreRegistration{
		Email:                     gofakeit.Email(),
		PasswordHash:              gofakeit.Password(true, true, true, true, false, 16),
		VerificationCodeEncrypted: []byte(gofakeit.UUID()),
		VerificationCodeIssuedAt:  sql.NullTime{Time: time.Now().UTC().Truncate(time.Microsecond), Valid: true},
		VerificationCodeHash:      hash,
	}
	if err := database.CreatePreRegistration(tx, preReg); err != nil {
		t.Fatalf("Failed to create the pre-registration inside the transaction: %v", err)
	}

	// 11. Visible through the transaction that wrote it. A method ignoring its tx would
	// query the pool, which cannot see this write.
	inTx, err := database.GetPreRegistrationByVerificationCodeHash(tx, hash)
	if err != nil {
		t.Fatalf("lookup through the writing transaction failed: %v", err)
	}
	if inTx == nil {
		t.Fatal("a row written in this transaction must be visible through it (did the lookup ignore its tx?)")
	}
	if inTx.Id != preReg.Id {
		t.Errorf("found pre-registration id %d through the transaction, want %d", inTx.Id, preReg.Id)
	}

	if err := database.RollbackTransaction(tx); err != nil {
		t.Fatalf("RollbackTransaction failed: %v", err)
	}

	// 12a. Rolled back, so nothing carries the hash any more.
	afterRollback, err := database.GetPreRegistrationByVerificationCodeHash(nil, hash)
	if err != nil {
		t.Fatalf("lookup after rollback failed: %v", err)
	}
	if afterRollback != nil {
		t.Errorf("a rolled-back write must leave no findable hash, found pre-registration id %d", afterRollback.Id)
	}

	// 12b. The finished transaction is the forced fault.
	failed, err := database.GetPreRegistrationByVerificationCodeHash(tx, hash)
	if err == nil {
		t.Error("a lookup through a finished transaction must return an error, not a benign nil")
	}
	if failed != nil {
		t.Error("a failed lookup must never return a pre-registration")
	}
}

// TestCreatePreRegistration_DistinctCodeHashesCoexist is case 13, and it is what pins the
// index shape §4 chose. The UNIQUE index on verification_code_hash has to accept two rows
// carrying different hashes on all four engines; every other case in this file would pass
// with no index at all.
func TestCreatePreRegistration_DistinctCodeHashesCoexist(t *testing.T) {
	first := createTestPreRegistration(t)
	second := createTestPreRegistration(t)

	if first.VerificationCodeHash == second.VerificationCodeHash {
		t.Fatal("the two seeded rows must carry different hashes for this case to prove anything")
	}

	foundFirst, err := database.GetPreRegistrationByVerificationCodeHash(nil, first.VerificationCodeHash)
	if err != nil || foundFirst == nil || foundFirst.Id != first.Id {
		t.Fatalf("the first hash must find the first row: row=%v err=%v", foundFirst, err)
	}
	foundSecond, err := database.GetPreRegistrationByVerificationCodeHash(nil, second.VerificationCodeHash)
	if err != nil || foundSecond == nil || foundSecond.Id != second.Id {
		t.Fatalf("the second hash must find the second row: row=%v err=%v", foundSecond, err)
	}
}
