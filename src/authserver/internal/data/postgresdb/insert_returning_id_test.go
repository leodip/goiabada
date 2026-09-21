package postgresdb

import (
	"testing"

	"github.com/huandu/go-sqlbuilder"
)

// TestInsertReturningIdSQL_AppendsTheClause is the whole of PostgreSQL's half of the hook. It is
// asserted against a statement sqlbuilder actually built rather than a hand-written one, because
// what matters is that the clause is legal where it lands, and only the real builder's output
// says where that is.
func TestInsertReturningIdSQL_AppendsTheClause(t *testing.T) {
	insertBuilder := sqlbuilder.PostgreSQL.NewInsertBuilder()
	insertBuilder.InsertInto("clients")
	insertBuilder.Cols("client_identifier", "enabled")
	insertBuilder.Values("probe", true)
	built, _ := insertBuilder.Build()

	got, err := insertReturningIdSQL(built)
	if err != nil {
		t.Fatalf("insertReturningIdSQL returned %v, want nil; PostgreSQL's rewrite cannot fail", err)
	}
	if want := built + " RETURNING id"; got != want {
		t.Errorf("insertReturningIdSQL(%q) = %q, want %q", built, got, want)
	}
}

// TestInsertReturningIdSQL_ChangesNothingElse is the negative half: the statement the builder
// produced must reach the engine intact, since every placeholder and every column position in it
// is what the argument list was built against.
func TestInsertReturningIdSQL_ChangesNothingElse(t *testing.T) {
	const original = "INSERT INTO groups (group_identifier, description) VALUES ($1, $2)"

	got, err := insertReturningIdSQL(original)
	if err != nil {
		t.Fatalf("insertReturningIdSQL returned %v, want nil", err)
	}
	if want := original + " RETURNING id"; got != want {
		t.Errorf("insertReturningIdSQL rewrote the statement itself: got %q, want %q", got, want)
	}
}
