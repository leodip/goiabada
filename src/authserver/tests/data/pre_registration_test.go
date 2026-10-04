package datatests

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/emaillinks"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
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

	retrievedPreReg, err := database.GetPreRegistrationById(context.Background(), nil, preReg.Id)
	if err != nil {
		t.Fatalf("Failed to retrieve created pre-registration: %v", err)
	}

	validatePreRegistration(t, preReg, retrievedPreReg)
}

func TestUpdatePreRegistration(t *testing.T) {
	preReg := createTestPreRegistration(t)

	preReg.Email = "updated_" + fake.Email()
	preReg.VerificationCodeEncrypted = []byte(fake.UUID())
	preReg.VerificationCodeIssuedAt = sql.NullTime{Time: time.Now().UTC().Truncate(time.Microsecond), Valid: true}

	time.Sleep(timestampTick)

	err := database.UpdatePreRegistration(context.Background(), nil, preReg)
	if err != nil {
		t.Fatalf("Failed to update pre-registration: %v", err)
	}

	updatedPreReg, err := database.GetPreRegistrationById(context.Background(), nil, preReg.Id)
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

	retrievedPreReg, err := database.GetPreRegistrationById(context.Background(), nil, preReg.Id)
	if err != nil {
		t.Fatalf("Failed to get pre-registration by ID: %v", err)
	}

	validatePreRegistration(t, preReg, retrievedPreReg)

	nonExistentPreReg, err := database.GetPreRegistrationById(context.Background(), nil, 99999)
	if err != nil {
		t.Errorf("Expected no error for non-existent pre-registration, got: %v", err)
	}
	if nonExistentPreReg != nil {
		t.Errorf("Expected nil for non-existent pre-registration, got a pre-registration with ID: %d", nonExistentPreReg.Id)
	}
}

func TestGetPreRegistrationByEmail(t *testing.T) {
	preReg := createTestPreRegistration(t)

	retrievedPreReg, err := database.GetPreRegistrationByEmail(context.Background(), nil, preReg.Email)
	if err != nil {
		t.Fatalf("Failed to get pre-registration by email: %v", err)
	}

	validatePreRegistration(t, preReg, retrievedPreReg)

	nonExistentPreReg, err := database.GetPreRegistrationByEmail(context.Background(), nil, "non_existent_email@example.com")
	if err != nil {
		t.Errorf("Expected no error for non-existent pre-registration, got: %v", err)
	}
	if nonExistentPreReg != nil {
		t.Errorf("Expected nil for non-existent pre-registration, got a pre-registration with ID: %d", nonExistentPreReg.Id)
	}
}

func TestDeletePreRegistration(t *testing.T) {
	preReg := createTestPreRegistration(t)

	err := database.DeletePreRegistration(context.Background(), nil, preReg.Id)
	if err != nil {
		t.Fatalf("Failed to delete pre-registration: %v", err)
	}

	deletedPreReg, err := database.GetPreRegistrationById(context.Background(), nil, preReg.Id)
	if err != nil {
		t.Fatalf("Error while checking for deleted pre-registration: %v", err)
	}
	if deletedPreReg != nil {
		t.Errorf("Pre-registration still exists after deletion")
	}

	err = database.DeletePreRegistration(context.Background(), nil, 99999)
	if err != nil {
		t.Errorf("Expected no error when deleting non-existent pre-registration, got: %v", err)
	}
}

func createTestPreRegistration(t *testing.T) *record.PreRegistration {
	// The code hash is unique per row and never empty, which is what the production
	// caller does: verification_code_hash is UNIQUE, so two rows sharing the '' default
	// would be refused by the index (#112).
	preReg := &record.PreRegistration{
		Email:                     fake.Email(),
		VerificationCodeEncrypted: []byte(fake.UUID()),
		VerificationCodeIssuedAt:  sql.NullTime{Time: time.Now().UTC().Truncate(time.Microsecond), Valid: true},
		VerificationCodeHash:      codeHashOf(t, fake.UUID()),
	}
	err := database.CreatePreRegistration(context.Background(), nil, preReg)
	if err != nil {
		t.Fatalf("Failed to create test pre-registration: %v", err)
	}
	return preReg
}

func validatePreRegistration(t *testing.T, expected, actual *record.PreRegistration) {
	if actual.Id != expected.Id {
		t.Errorf("Expected ID %d, got %d", expected.Id, actual.Id)
	}
	if actual.Email != expected.Email {
		t.Errorf("Expected Email %s, got %s", expected.Email, actual.Email)
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
	found, err := database.GetPreRegistrationByVerificationCodeHash(context.Background(), nil, preReg.VerificationCodeHash)
	if err != nil {
		t.Fatalf("lookup by the stored hash failed: %v", err)
	}
	if found == nil {
		t.Fatal("the stored hash must find the pre-registration it was stored on")
	}
	validatePreRegistration(t, preReg, found)

	// 9. A hash no row carries is a miss, not an error.
	missing, err := database.GetPreRegistrationByVerificationCodeHash(context.Background(), nil, codeHashOf(t, fake.UUID()))
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
		if leftover, err := database.GetPreRegistrationByEmail(context.Background(), nil, dormantEmail); err == nil && leftover != nil {
			_ = database.DeletePreRegistration(context.Background(), nil, leftover.Id)
		}
	}
	deleteDormant()
	t.Cleanup(deleteDormant)

	dormant := &record.PreRegistration{
		Email: dormantEmail,
	}
	if err := database.CreatePreRegistration(context.Background(), nil, dormant); err != nil {
		t.Fatalf("Failed to create the dormant pre-registration: %v", err)
	}

	if dormant.VerificationCodeHash != "" {
		t.Fatalf("a pre-registration written without a code hash must carry '', got %q", dormant.VerificationCodeHash)
	}

	found, err := database.GetPreRegistrationByVerificationCodeHash(context.Background(), nil, "")
	if err != nil {
		t.Errorf("an empty hash must not be an error, got: %v", err)
	}
	if found != nil {
		t.Errorf("an empty hash matched pre-registration id %d; the dormant value must never be findable", found.Id)
	}

	// The same fact from the other side: a real hash nobody holds still misses while the
	// dormant row is present, so the guard is not the only thing answering.
	found, err = database.GetPreRegistrationByVerificationCodeHash(context.Background(), nil, codeHashOf(t, "a code nobody was ever issued"))
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
	hash := codeHashOf(t, fake.UUID())

	tx := beginTx(t)

	preReg := &record.PreRegistration{
		Email:                     fake.Email(),
		VerificationCodeEncrypted: []byte(fake.UUID()),
		VerificationCodeIssuedAt:  sql.NullTime{Time: time.Now().UTC().Truncate(time.Microsecond), Valid: true},
		VerificationCodeHash:      hash,
	}
	if err := database.CreatePreRegistration(context.Background(), tx, preReg); err != nil {
		t.Fatalf("Failed to create the pre-registration inside the transaction: %v", err)
	}

	// 11. Visible through the transaction that wrote it. A method ignoring its tx would
	// query the pool, which cannot see this write.
	inTx, err := database.GetPreRegistrationByVerificationCodeHash(context.Background(), tx, hash)
	if err != nil {
		t.Fatalf("lookup through the writing transaction failed: %v", err)
	}
	if inTx == nil {
		t.Fatal("a row written in this transaction must be visible through it (did the lookup ignore its tx?)")
	}
	if inTx.Id != preReg.Id {
		t.Errorf("found pre-registration id %d through the transaction, want %d", inTx.Id, preReg.Id)
	}

	if rollbackErr := database.RollbackTransaction(context.Background(), tx); rollbackErr != nil {
		t.Fatalf("RollbackTransaction failed: %v", rollbackErr)
	}

	// 12a. Rolled back, so nothing carries the hash any more.
	afterRollback, err := database.GetPreRegistrationByVerificationCodeHash(context.Background(), nil, hash)
	if err != nil {
		t.Fatalf("lookup after rollback failed: %v", err)
	}
	if afterRollback != nil {
		t.Errorf("a rolled-back write must leave no findable hash, found pre-registration id %d", afterRollback.Id)
	}

	// 12b. The finished transaction is the forced fault.
	failed, err := database.GetPreRegistrationByVerificationCodeHash(context.Background(), tx, hash)
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

	foundFirst, err := database.GetPreRegistrationByVerificationCodeHash(context.Background(), nil, first.VerificationCodeHash)
	if err != nil || foundFirst == nil || foundFirst.Id != first.Id {
		t.Fatalf("the first hash must find the first row: row=%v err=%v", foundFirst, err)
	}
	foundSecond, err := database.GetPreRegistrationByVerificationCodeHash(context.Background(), nil, second.VerificationCodeHash)
	if err != nil || foundSecond == nil || foundSecond.Id != second.Id {
		t.Fatalf("the second hash must find the second row: row=%v err=%v", foundSecond, err)
	}
}

// TestTryReplacePreRegistrationCode is the conditional replacement of a dead pending registration
// (#207 decision 6): a fresh code takes effect only while the row still holds the dead code the
// caller read, so of two repeats racing for one dead row exactly one replaces it and sends a link.
func TestTryReplacePreRegistrationCode(t *testing.T) {
	freshEncrypted := []byte("ENCRYPTEDFRESHCODE")
	issuedAt := time.Now().UTC().Truncate(time.Microsecond)

	t.Run("a row still holding the dead code takes the fresh one and nothing else", func(t *testing.T) {
		dead := createTestPreRegistration(t)
		freshHash := codeHashOf(t, fake.UUID())
		before, err := database.GetPreRegistrationById(context.Background(), nil, dead.Id)
		if err != nil || before == nil {
			t.Fatalf("Failed to reload the pre-registration: row=%v err=%v", before, err)
		}

		time.Sleep(timestampTick)

		replaced, err := database.TryReplacePreRegistrationCode(context.Background(), nil, dead.Id,
			dead.VerificationCodeHash, freshEncrypted, freshHash, issuedAt)
		if err != nil {
			t.Fatalf("TryReplacePreRegistrationCode failed: %v", err)
		}
		if !replaced {
			t.Fatal("the replacement must take effect on a row still holding the dead code")
		}

		after, err := database.GetPreRegistrationById(context.Background(), nil, dead.Id)
		if err != nil || after == nil {
			t.Fatalf("Failed to reload the pre-registration: row=%v err=%v", after, err)
		}
		expected := *dead
		expected.VerificationCodeEncrypted = freshEncrypted
		expected.VerificationCodeHash = freshHash
		expected.VerificationCodeIssuedAt = sql.NullTime{Time: issuedAt, Valid: true}
		validatePreRegistration(t, &expected, after)
		if !after.CreatedAt.Time.Equal(before.CreatedAt.Time) {
			t.Errorf("CreatedAt changed: was %v, now %v", before.CreatedAt.Time, after.CreatedAt.Time)
		}
		if !after.UpdatedAt.Time.After(before.UpdatedAt.Time) {
			t.Error("UpdatedAt must move forward with the replacement")
		}

		// The fresh link finds the row, and the dead one no longer does.
		found, err := database.GetPreRegistrationByVerificationCodeHash(context.Background(), nil, freshHash)
		if err != nil || found == nil || found.Id != dead.Id {
			t.Errorf("the fresh hash must find the replaced row: row=%v err=%v", found, err)
		}
		stale, err := database.GetPreRegistrationByVerificationCodeHash(context.Background(), nil, dead.VerificationCodeHash)
		if err != nil || stale != nil {
			t.Errorf("the dead hash must find nothing once replaced: row=%v err=%v", stale, err)
		}
	})

	t.Run("a row that changed underneath is left as it is", func(t *testing.T) {
		dead := createTestPreRegistration(t)
		firstHash := codeHashOf(t, fake.UUID())
		firstEncrypted := []byte("ENCRYPTEDFIRSTCODE")

		// The first of two repeats that read the same dead row.
		first, err := database.TryReplacePreRegistrationCode(context.Background(), nil, dead.Id,
			dead.VerificationCodeHash, firstEncrypted, firstHash, issuedAt)
		if err != nil || !first {
			t.Fatalf("the first replacement must take effect: replaced=%v err=%v", first, err)
		}

		// The second still names the dead code it read, which the row no longer holds.
		second, err := database.TryReplacePreRegistrationCode(context.Background(), nil, dead.Id,
			dead.VerificationCodeHash, freshEncrypted, codeHashOf(t, fake.UUID()), issuedAt.Add(time.Second))
		if err != nil {
			t.Fatalf("TryReplacePreRegistrationCode failed: %v", err)
		}
		if second {
			t.Fatal("a replacement naming a code the row no longer holds must not take effect")
		}

		after, err := database.GetPreRegistrationById(context.Background(), nil, dead.Id)
		if err != nil || after == nil {
			t.Fatalf("Failed to reload the pre-registration: row=%v err=%v", after, err)
		}
		expected := *dead
		expected.VerificationCodeEncrypted = firstEncrypted
		expected.VerificationCodeHash = firstHash
		expected.VerificationCodeIssuedAt = sql.NullTime{Time: issuedAt, Valid: true}
		validatePreRegistration(t, &expected, after)
	})

	t.Run("a row consumed underneath is not recreated", func(t *testing.T) {
		dead := createTestPreRegistration(t)
		if err := database.DeletePreRegistration(context.Background(), nil, dead.Id); err != nil {
			t.Fatalf("Failed to delete the pre-registration: %v", err)
		}

		replaced, err := database.TryReplacePreRegistrationCode(context.Background(), nil, dead.Id,
			dead.VerificationCodeHash, freshEncrypted, codeHashOf(t, fake.UUID()), issuedAt)
		if err != nil {
			t.Fatalf("TryReplacePreRegistrationCode failed: %v", err)
		}
		if replaced {
			t.Error("a replacement of a row that no longer exists must not report taking effect")
		}
		gone, err := database.GetPreRegistrationById(context.Background(), nil, dead.Id)
		if err != nil || gone != nil {
			t.Errorf("the deleted row must stay deleted: row=%v err=%v", gone, err)
		}
	})

	t.Run("an empty fresh hash is refused", func(t *testing.T) {
		dead := createTestPreRegistration(t)

		replaced, err := database.TryReplacePreRegistrationCode(context.Background(), nil, dead.Id,
			dead.VerificationCodeHash, freshEncrypted, "", issuedAt)
		if err == nil {
			t.Error("a fresh code with no hash could never be found by its link, and must be refused")
		}
		if replaced {
			t.Error("a refused replacement must not report taking effect")
		}
		after, err := database.GetPreRegistrationById(context.Background(), nil, dead.Id)
		if err != nil || after == nil {
			t.Fatalf("Failed to reload the pre-registration: row=%v err=%v", after, err)
		}
		validatePreRegistration(t, dead, after)
	})

	t.Run("it runs on the caller's transaction", func(t *testing.T) {
		dead := createTestPreRegistration(t)
		freshHash := codeHashOf(t, fake.UUID())

		tx := beginTx(t)
		replaced, err := database.TryReplacePreRegistrationCode(context.Background(), tx, dead.Id,
			dead.VerificationCodeHash, freshEncrypted, freshHash, issuedAt)
		if err != nil || !replaced {
			t.Fatalf("the replacement inside the transaction must take effect: replaced=%v err=%v", replaced, err)
		}
		inTx, err := database.GetPreRegistrationByVerificationCodeHash(context.Background(), tx, freshHash)
		if err != nil || inTx == nil || inTx.Id != dead.Id {
			t.Fatalf("the replacement must be visible through its transaction: row=%v err=%v", inTx, err)
		}
		if rollbackErr := database.RollbackTransaction(context.Background(), tx); rollbackErr != nil {
			t.Fatalf("RollbackTransaction failed: %v", rollbackErr)
		}

		after, err := database.GetPreRegistrationById(context.Background(), nil, dead.Id)
		if err != nil || after == nil {
			t.Fatalf("Failed to reload the pre-registration: row=%v err=%v", after, err)
		}
		validatePreRegistration(t, dead, after)
	})
}

// createPreRegistrationIssuedAt writes a pending registration whose code was issued at issuedAt,
// or with no issued-at at all when issuedAt is the zero time.
func createPreRegistrationIssuedAt(t *testing.T, issuedAt time.Time) *record.PreRegistration {
	t.Helper()
	preReg := &record.PreRegistration{
		Email:                     fake.Email(),
		VerificationCodeEncrypted: []byte(fake.UUID()),
		VerificationCodeIssuedAt:  sql.NullTime{Time: issuedAt, Valid: !issuedAt.IsZero()},
		VerificationCodeHash:      codeHashOf(t, fake.UUID()),
	}
	if err := database.CreatePreRegistration(context.Background(), nil, preReg); err != nil {
		t.Fatalf("Failed to create test pre-registration: %v", err)
	}
	return preReg
}

func preRegistrationExists(t *testing.T, preRegistrationId int64) bool {
	t.Helper()
	found, err := database.GetPreRegistrationById(context.Background(), nil, preRegistrationId)
	if err != nil {
		t.Fatalf("Failed to reload pre-registration %d: %v", preRegistrationId, err)
	}
	return found != nil
}

// TestDeleteDeadPreRegistrations is the sweep of pending registrations that can no longer complete
// (#207 decision 7). The worker hands it a cutoff ten minutes before the run; a row whose code was
// issued before the cutoff is dead and goes, and every row that can still complete stays,
// including one issued exactly at the cutoff. A row with no issued-at never had a usable code and
// goes too, as the replacement already treats it as dead.
func TestDeleteDeadPreRegistrations(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	deadBefore := now.Add(-10 * time.Minute)

	longDead := createPreRegistrationIssuedAt(t, now.Add(-3*time.Hour))
	justDead := createPreRegistrationIssuedAt(t, deadBefore.Add(-time.Second))
	neverIssued := createPreRegistrationIssuedAt(t, time.Time{})
	atTheCutoff := createPreRegistrationIssuedAt(t, deadBefore)
	inThePasswordWindow := createPreRegistrationIssuedAt(t, now.Add(-9*time.Minute))
	fresh := createPreRegistrationIssuedAt(t, now)

	if err := database.DeleteDeadPreRegistrations(context.Background(), nil, deadBefore); err != nil {
		t.Fatalf("DeleteDeadPreRegistrations failed: %v", err)
	}

	cases := []struct {
		name    string
		row     *record.PreRegistration
		swept   bool
		because string
	}{
		{"issued three hours ago", longDead, true, "its link and its password form are long expired"},
		{"issued a second before the cutoff", justDead, true, "it can no longer complete"},
		{"never issued a code", neverIssued, true, "no link can ever activate it"},
		{"issued exactly at the cutoff", atTheCutoff, false, "its password form is still open, for this instant"},
		{"issued nine minutes ago", inThePasswordWindow, false, "a link followed at 4:59 still has its form open"},
		{"issued now", fresh, false, "its link has not even expired"},
	}
	for _, tc := range cases {
		if exists := preRegistrationExists(t, tc.row.Id); exists == tc.swept {
			t.Errorf("a row %s: exists=%v, want swept=%v, because %s", tc.name, exists, tc.swept, tc.because)
		}
		// The registration's replacement reads the same rows through the predicate; the sweep must
		// never delete a row it would call live, nor keep one it would replace.
		if dead := emaillinks.IsPreRegistrationDead(tc.row.VerificationCodeIssuedAt.Time, now); dead != tc.swept {
			t.Errorf("a row %s: the replacement calls it dead=%v, the sweep swept=%v", tc.name, dead, tc.swept)
		}
	}

	// Sweeping nothing is not an error, and leaves the live rows as they are.
	if err := database.DeleteDeadPreRegistrations(context.Background(), nil, deadBefore); err != nil {
		t.Fatalf("a sweep finding nothing must not fail: %v", err)
	}
	if !preRegistrationExists(t, atTheCutoff.Id) || !preRegistrationExists(t, fresh.Id) {
		t.Error("a second sweep at the same cutoff must leave the live rows")
	}
}

// TestDeleteDeadPreRegistrations_Transaction: the sweep runs on the transaction it is handed, so a
// rollback leaves the dead row in place.
func TestDeleteDeadPreRegistrations_Transaction(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	dead := createPreRegistrationIssuedAt(t, now.Add(-time.Hour))

	tx := beginTx(t)
	if err := database.DeleteDeadPreRegistrations(context.Background(), tx, now.Add(-10*time.Minute)); err != nil {
		t.Fatalf("DeleteDeadPreRegistrations failed: %v", err)
	}
	inTx, err := database.GetPreRegistrationById(context.Background(), tx, dead.Id)
	if err != nil || inTx != nil {
		t.Fatalf("the sweep must be visible through its transaction: row=%v err=%v", inTx, err)
	}
	if rollbackErr := database.RollbackTransaction(context.Background(), tx); rollbackErr != nil {
		t.Fatalf("RollbackTransaction failed: %v", rollbackErr)
	}

	if !preRegistrationExists(t, dead.Id) {
		t.Error("a sweep rolled back must leave the row in place")
	}
}
