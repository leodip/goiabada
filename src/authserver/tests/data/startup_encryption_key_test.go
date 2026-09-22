package datatests

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/datafactory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewDatabase_RefusesAnAESKeyOfTheWrongLength pins the guard that stands between a
// misconfigured deployment and a database written with a key nothing can read back.
//
// It is a case this tier could not hold until #351: the length used to come from the
// configuration singleton, so every entry path into NewDatabase carried the same key the process
// was started with and no test could hand it a different one. With the key a parameter the branch
// is one call away, which is half the reason decision 7 made it one.
//
// The refusal matters because of what runs immediately after it. runStartupDataTasks re-keys
// every protected column to this key when a previous key is supplied, so a short or absent key
// that got past here would not fail loudly; it would write ciphertext no correctly configured
// restart can decrypt.
//
// sqlite only, and for the reason TestNewDatabase_RefusesAnEmailCaseCollisionAtStartup gives: a
// DSN pointing at a throwaway file is the one way to reach NewDatabase without touching the
// shared database this tier runs against. The guard is engine-independent, being a length check
// in datafactory that runs before any engine sees the key.
func TestNewDatabase_RefusesAnAESKeyOfTheWrongLength(t *testing.T) {
	if engine := dbType(); engine != "sqlite" && engine != "" {
		t.Skip("needs a DSN to a throwaway database, which only sqlite has; the length check under test is engine-independent")
	}

	cfg := &config.DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "startup_key.db")}

	refusals := []struct {
		name string
		key  []byte
	}{
		{"no key at all", nil},
		{"an empty key", []byte{}},
		{"a key one byte short", make([]byte, 31)},
		{"a key one byte long", make([]byte, 33)},
	}
	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			opened, err := datafactory.NewDatabase(context.Background(), cfg, tc.key, nil, false)

			require.Error(t, err, "a key of %d bytes must not be accepted", len(tc.key))
			assert.Nil(t, opened, "a refused startup must hand back no database")
			assert.Contains(t, err.Error(), "GOIABADA_AES_ENCRYPTION_KEY",
				"the message is all the operator gets, so it has to name the variable they set")
		})
	}

	// And a 32-byte key opens the same file, which is what says the four refusals above are
	// caused by the length rather than by anything else about this throwaway database. Last on
	// purpose: by now the schema is at head, so this call exercises the guard and the startup
	// tasks and nothing else.
	t.Run("a 32-byte key is accepted", func(t *testing.T) {
		opened, err := datafactory.NewDatabase(context.Background(), cfg, make([]byte, 32), nil, false)

		require.NoError(t, err, "a 32-byte key is the configuration the guard exists to admit")
		assert.NotNil(t, opened, "an accepted startup must hand back a database")
	})
}
