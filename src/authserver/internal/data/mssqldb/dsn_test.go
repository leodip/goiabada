package mssqldb

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/leodip/goiabada/core/guard"
	"github.com/microsoft/go-mssqldb/msdsn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// dsnCases are the values a hand-built connection string could get wrong, each read back through
// the driver's own parser: the one that decides what a connection string means. Only the IPv6 host
// was broken before #424; the rest pin that url.URL keeps carrying them.
var dsnCases = []struct {
	name     string
	username string
	password string
	host     string
	database string
}{
	{"plain", "goiabada", "plain", "db", "goiabada"},
	{"percent in password", "goiabada", "p%40ss", "db", "goiabada"},
	{"hash in password", "goiabada", "p#ss", "db", "goiabada"},
	{"question mark in password", "goiabada", "p?ss", "db", "goiabada"},
	{"slash in password", "goiabada", "p/ss", "db", "goiabada"},
	{"at in password", "goiabada", "p@ss", "db", "goiabada"},
	{"colon in password", "goiabada", "p:ss", "db", "goiabada"},
	{"every special character in password", "goiabada", "%#?/@: all", "db", "goiabada"},
	{"at and colon in username", "us@r:x", "pw", "db", "goiabada"},
	{"space in database", "goiabada", "pw", "db", "my db"},
	{"slash, question mark and hash in database", "goiabada", "pw", "db", "a/b?c#d"},
	{"IPv6 host", "goiabada", "pw", "::1", "goiabada"},
}

func TestDSN_RoundTripsThroughTheDriver(t *testing.T) {
	for _, tc := range dsnCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &DatabaseConfig{Username: tc.username, Password: tc.password, Host: tc.host, Port: 1433, Name: tc.database}

			for _, conn := range []struct {
				which    string
				dsn      string
				database string
			}{
				{"DSN", DSN(cfg), tc.database},
				{"MaintenanceDSN", MaintenanceDSN(cfg), "master"},
			} {
				parsed, err := msdsn.Parse(conn.dsn)
				require.NoErrorf(t, err, "%s %q must parse", conn.which, conn.dsn)
				assert.Equalf(t, tc.username, parsed.User, "%s user", conn.which)
				assert.Equalf(t, tc.password, parsed.Password, "%s password", conn.which)
				assert.Equalf(t, tc.host, parsed.Host, "%s host", conn.which)
				assert.Equalf(t, uint64(1433), parsed.Port, "%s port", conn.which)
				assert.Equalf(t, conn.database, parsed.Database, "%s database", conn.which)
				// Kept from the strings this replaced: the dev and CI servers present no certificate
				// a client could verify.
				assert.Equalf(t, msdsn.Encryption(msdsn.EncryptionDisabled), parsed.Encryption, "%s encrypt", conn.which)
			}
		})
	}
}

// TestDSN_BracketedIPv6HostIsTheSameHost pins that `[::1]`, the one IPv6 spelling of
// GOIABADA_DB_HOST a Sprintf'd URL accepted, still names the host `::1` does. A plain
// net.JoinHostPort would have written `[[::1]]:1433`, which the driver's parser refuses (#424).
func TestDSN_BracketedIPv6HostIsTheSameHost(t *testing.T) {
	bare := &DatabaseConfig{Username: "goiabada", Password: "pw", Host: "::1", Port: 1433, Name: "goiabada"}
	bracketed := &DatabaseConfig{Username: "goiabada", Password: "pw", Host: "[::1]", Port: 1433, Name: "goiabada"}

	assert.Equal(t, DSN(bare), DSN(bracketed))
	assert.Equal(t, MaintenanceDSN(bare), MaintenanceDSN(bracketed))

	parsed, err := msdsn.Parse(DSN(bracketed))
	require.NoError(t, err)
	assert.Equal(t, "::1", parsed.Host)
	assert.Equal(t, uint64(1433), parsed.Port)
}

// TestDSN_MatchesTheSetupWizardsCaseFile holds DSN and MaintenanceDSN to the strings in
// cmd/goiabada-setup/testdata/connection-strings.json. The setup wizard checks an operator's
// database with copies of these two, since it may import no application (ARCHITECTURE.md rule 3),
// and its own tier holds the copies to the same file, so changing either side alone fails that
// side's tier (#430).
func TestDSN_MatchesTheSetupWizardsCaseFile(t *testing.T) {
	path := filepath.Join(guard.SourceRoot(t), "cmd", "goiabada-setup", "testdata", "connection-strings.json")
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var file struct {
		Cases []struct {
			Name, Engine, Host, Username, Password, Database, DSN string
			Port                                                  int
			MaintenanceDSN                                        string `json:"maintenanceDSN"`
		} `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(raw, &file))

	found := 0
	for _, c := range file.Cases {
		if c.Engine != "mssql" {
			continue
		}
		found++
		cfg := &DatabaseConfig{Username: c.Username, Password: c.Password, Host: c.Host, Port: c.Port, Name: c.Database}
		assert.Equalf(t, c.DSN, DSN(cfg), "%s: DSN", c.Name)
		assert.Equalf(t, c.MaintenanceDSN, MaintenanceDSN(cfg), "%s: MaintenanceDSN", c.Name)
	}
	require.NotZerof(t, found, "%s holds no mssql case", path)
}
