package datatests

import (
	"database/sql"
	"errors"
	"testing"

	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/testutil/fake"
)

// TestCreateUser_DuplicateEmailIsErrUniqueViolation is the tier this part of #279 exists for.
//
// The sentinel is only worth anything if every engine produces it, and the four drivers report a
// duplicate key four different ways: SQLite an extended result code, MySQL a number, PostgreSQL a
// SQLSTATE, SQL Server a number that arrives by value rather than by pointer. Each engine's own
// package unit-tests its classifier against constructed errors; nothing below this tier proves the
// classifier is reached by a real failure on a real engine, or that the driver returns the shape it
// was written for.
//
// It also covers the two insert paths, which are not the same path. SQLite and MySQL insert through
// ExecSql; PostgreSQL and SQL Server insert through QuerySql, because they need
// INSERT ... RETURNING / OUTPUT INSERTED for the generated id, and then re-check rows.Err() because
// the driver may defer a constraint violation to the result set. A translation wired into ExecSql
// alone passes on two engines and fails on the other two, and only this tier can tell.
func TestCreateUser_DuplicateEmailIsErrUniqueViolation(t *testing.T) {
	first := createTestUser(t)
	defer func() { _ = database.DeleteUser(nil, first.Id) }()

	// Everything else about the second user is fresh, so the email is the only key it can
	// collide on.
	second := &models.User{
		Enabled: true,
		Subject: fake.UUID(),
		Email:   first.Email,
	}

	err := database.CreateUser(nil, second)
	if err == nil {
		_ = database.DeleteUser(nil, second.Id)
		t.Fatal("a second user on a taken email was accepted; users.email is supposed to be unique")
	}
	if !errors.Is(err, data.ErrUniqueViolation) {
		t.Errorf("errors.Is(err, data.ErrUniqueViolation) = false on this engine, so the "+
			"handler above it cannot answer 409 here; err = %v", err)
	}
}

// TestInsert_AnUnrelatedConstraintIsNotErrUniqueViolation is the negative half, and it is the one
// that would be worst to get wrong: tagging every write failure would have the API answer 409 to
// callers whose request can never succeed, and the positive case above cannot detect that.
//
// A foreign-key violation is the failure used, because it is the one refusal all four engines make
// for a reason that is not a key collision. user_attributes.user_id references users.id with ON
// DELETE CASCADE on every engine, and SQLite enforces it too: the connection sets
// PRAGMA foreign_keys = ON and its constructor refuses to hand back a handle where the pragma did
// not take.
//
// It is also the closest neighbour of the condition being classified. SQLite gives both the same
// primary result code, SQLITE_CONSTRAINT, and PostgreSQL both the same SQLSTATE class, 23, so a
// classifier written one level too coarse on either engine passes the case above and fails here.
func TestInsert_AnUnrelatedConstraintIsNotErrUniqueViolation(t *testing.T) {
	attribute := &models.UserAttribute{
		Key:    "probe" + fake.LetterN(6),
		Value:  fake.LetterN(8),
		UserId: 999999999, // no such user
	}

	err := database.CreateUserAttribute(nil, attribute)
	if err == nil {
		_ = database.DeleteUserAttribute(nil, attribute.Id)
		t.Fatal("a user attribute for a non-existent user was accepted; the foreign key on " +
			"user_attributes.user_id is supposed to refuse it")
	}
	if errors.Is(err, data.ErrUniqueViolation) {
		t.Errorf("a foreign-key violation was tagged as a unique-key violation, which would have "+
			"the API answer 409 to a request no retry can satisfy; err = %v", err)
	}
}

// TestCreateUser_DuplicateEmailInsideATransactionIsErrUniqueViolation covers the other arm of the
// two writers. ExecSql and QuerySql each branch on whether they were handed a transaction, and the
// case above passes nil, so it exercises only the arm that opens its own connection. Most of
// Goiabada's writes are not like that: every issuance, revocation and credential change runs inside
// RunInTransaction, so the arm this covers is the one production actually uses.
//
// It is a separate case rather than a loop, because the two arms fail differently: an untagged
// error inside a transaction is rolled back and the caller sees only the wrapping.
func TestCreateUser_DuplicateEmailInsideATransactionIsErrUniqueViolation(t *testing.T) {
	first := createTestUser(t)
	defer func() { _ = database.DeleteUser(nil, first.Id) }()

	second := &models.User{
		Enabled: true,
		Subject: fake.UUID(),
		Email:   first.Email,
	}

	err := database.RunInTransaction(func(tx *sql.Tx) error {
		return database.CreateUser(tx, second)
	})
	if err == nil {
		_ = database.DeleteUser(nil, second.Id)
		t.Fatal("a second user on a taken email was accepted inside a transaction")
	}
	if !errors.Is(err, data.ErrUniqueViolation) {
		t.Errorf("errors.Is(err, data.ErrUniqueViolation) = false for a write inside a "+
			"transaction, which is how nearly every write in this tree runs; err = %v", err)
	}
}
