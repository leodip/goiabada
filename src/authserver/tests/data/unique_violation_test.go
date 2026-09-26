package datatests

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/testutil/fake"
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
	defer func() { _ = database.DeleteUser(context.Background(), nil, first.Id) }()

	// Everything else about the second user is fresh, so the email is the only key it can
	// collide on.
	second := &models.User{
		Enabled: true,
		Subject: fake.UUID(),
		Email:   first.Email,
	}

	err := database.CreateUser(context.Background(), nil, second)
	if err == nil {
		_ = database.DeleteUser(context.Background(), nil, second.Id)
		t.Fatal("a second user on a taken email was accepted; users.email is supposed to be unique")
	}
	if !errors.Is(err, data.ErrUniqueViolation) {
		t.Errorf("errors.Is(err, data.ErrUniqueViolation) = false on this engine, so the "+
			"handler above it cannot answer 409 here; err = %v", err)
	}
}

// TestUpdateUser_DuplicateEmailIsErrUniqueViolation is the UPDATE beside the INSERT above, and it
// is what both email PUTs stand on: each answers a lost race 409 only if the engine's refusal of an
// UPDATE arrives tagged the same way (#414 item 1, #425).
//
// It is not the insert path again. UpdateUser writes through ExecSql on all four engines, where
// PostgreSQL and SQL Server insert through QuerySql, so on those two this is the first case that
// takes a real unique violation through the other writer.
func TestUpdateUser_DuplicateEmailIsErrUniqueViolation(t *testing.T) {
	first := createTestUser(t)
	defer func() { _ = database.DeleteUser(context.Background(), nil, first.Id) }()
	second := createTestUser(t)
	defer func() { _ = database.DeleteUser(context.Background(), nil, second.Id) }()

	second.Email = first.Email

	err := database.UpdateUser(context.Background(), nil, second)
	if err == nil {
		t.Fatal("a user was moved onto a taken email; users.email is supposed to be unique")
	}
	if !errors.Is(err, data.ErrUniqueViolation) {
		t.Errorf("errors.Is(err, data.ErrUniqueViolation) = false for an UPDATE on this engine, "+
			"so the email PUTs cannot answer 409 here; err = %v", err)
	}
}

// TestCreateWebOrigin_ADuplicateOriginIsErrUniqueViolation is what the web-origin save's 409 rests
// on. web_origins carries a unique index on (origin, client_id), so two saves of one client adding
// the same origin at the same moment end with the engine refusing the second insert, and the save
// answers that 409 CONCURRENT_UPDATE only if the refusal arrives tagged as a unique violation on
// every engine (#428).
func TestCreateWebOrigin_ADuplicateOriginIsErrUniqueViolation(t *testing.T) {
	client := createTestClient(t)
	first := createTestWebOrigin(t, client.Id)

	second := &models.WebOrigin{Origin: first.Origin, ClientId: client.Id}
	err := database.CreateWebOrigin(context.Background(), nil, second)
	if err == nil {
		_ = database.DeleteWebOrigin(context.Background(), nil, second.Id)
		t.Fatal("a second web origin on the same (origin, client_id) was accepted; the pair is supposed to be unique")
	}
	if !errors.Is(err, data.ErrUniqueViolation) {
		t.Errorf("errors.Is(err, data.ErrUniqueViolation) = false for a duplicate web origin on this "+
			"engine, so the web-origin save cannot answer 409 here; err = %v", err)
	}
}

// TestCreatePermission_ADuplicateIdentifierIsErrUniqueViolation is the same for the resource
// permission save: permissions carries a unique index on (permission_identifier, resource_id), and
// two saves adding the same identifier to one resource at the same moment are answered 409 only if
// the engine's refusal arrives tagged (#428).
func TestCreatePermission_ADuplicateIdentifierIsErrUniqueViolation(t *testing.T) {
	resource := createTestResource(t)
	first := createTestPermission(t, resource)

	second := &models.Permission{
		PermissionIdentifier: first.PermissionIdentifier,
		Description:          "duplicate",
		ResourceId:           resource.Id,
	}
	err := database.CreatePermission(context.Background(), nil, second)
	if err == nil {
		_ = database.DeletePermission(context.Background(), nil, second.Id)
		t.Fatal("a second permission on the same (permission_identifier, resource_id) was accepted; the pair is supposed to be unique")
	}
	if !errors.Is(err, data.ErrUniqueViolation) {
		t.Errorf("errors.Is(err, data.ErrUniqueViolation) = false for a duplicate permission on this "+
			"engine, so the resource permission save cannot answer 409 here; err = %v", err)
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

	err := database.CreateUserAttribute(context.Background(), nil, attribute)
	if err == nil {
		_ = database.DeleteUserAttribute(context.Background(), nil, attribute.Id)
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
	defer func() { _ = database.DeleteUser(context.Background(), nil, first.Id) }()

	second := &models.User{
		Enabled: true,
		Subject: fake.UUID(),
		Email:   first.Email,
	}

	err := database.RunInTransaction(context.Background(), func(tx *sql.Tx) error {
		return database.CreateUser(context.Background(), tx, second)
	})
	if err == nil {
		_ = database.DeleteUser(context.Background(), nil, second.Id)
		t.Fatal("a second user on a taken email was accepted inside a transaction")
	}
	if !errors.Is(err, data.ErrUniqueViolation) {
		t.Errorf("errors.Is(err, data.ErrUniqueViolation) = false for a write inside a "+
			"transaction, which is how nearly every write in this tree runs; err = %v", err)
	}
}
