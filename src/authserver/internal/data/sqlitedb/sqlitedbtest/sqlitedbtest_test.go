package sqlitedbtest

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/data/sqlitedb"
)

// Every copy is at the head of the migration set, clean, and a database of its own: a table made in
// one is not in another.
func TestNewMigrated_EachCopyIsAtTheHeadAndItsOwn(t *testing.T) {
	ctx := context.Background()
	first, second := NewMigrated(t), NewMigrated(t)

	for name, db := range map[string]*sqlitedb.Database{"first": first, "second": second} {
		m, err := db.NewMigrator(ctx, nil)
		require.NoError(t, err)
		version, dirty, err := m.Version(ctx)
		require.NoError(t, err)
		assert.Equal(t, m.Head(), version, "the %s copy is at the head this binary carries", name)
		assert.False(t, dirty, "the %s copy is clean", name)
	}

	_, err := first.DB.ExecContext(ctx, "CREATE TABLE only_in_the_first (id INTEGER)")
	require.NoError(t, err)
	var tables int
	require.NoError(t, second.DB.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM sqlite_master WHERE name = 'only_in_the_first'").Scan(&tables))
	assert.Zero(t, tables, "a table made in one copy is not in another")
}
