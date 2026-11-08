package guard

// version-manager.sh deps sets modernc.org/libc to exactly the version the selected
// modernc.org/sqlite requires, which sqlite's documentation asks for: go get -u takes the newest
// libc whatever sqlite asks for. sqlite_libc_version reads that version from go mod graph.

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// sqliteGraph is a go mod graph answer holding several sqlite versions, the selected one neither
// first nor alone. v1.61.10 shares the selected version's prefix, and the module itself requires a
// newer libc than the selected sqlite does, as go get -u leaves it.
const sqliteGraph = `github.com/leodip/goiabada/authserver modernc.org/libc@v1.80.1
github.com/leodip/goiabada/authserver modernc.org/sqlite@v1.61.1
modernc.org/sqlite@v1.62.0 modernc.org/libc@v1.80.1
modernc.org/sqlite@v1.61.10 modernc.org/libc@v1.79.5
modernc.org/sqlite@v1.61.1 modernc.org/mathutil@v1.7.1
modernc.org/sqlite@v1.61.1 modernc.org/libc@v1.79.0
modernc.org/libc@v1.79.0 modernc.org/memory@v1.12.1
`

func TestSqliteLibcVersion_TheSelectedSqlitesOwnRequirementWins(t *testing.T) {
	out := versionManager(t, `sqlite_libc_version "$1" <<< "$2"`, "v1.61.1", sqliteGraph)
	assert.Equal(t, "v1.79.0", out)
}

func TestSqliteLibcVersion_AVersionWithNoLibcRequirementPrintsNothing(t *testing.T) {
	out := versionManager(t, `sqlite_libc_version "$1" <<< "$2"`, "v1.60.0", sqliteGraph)
	assert.Empty(t, out)
}
