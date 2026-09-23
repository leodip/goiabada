package postgresdb

import (
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// dsnCases are the values a Sprintf'd URL got wrong before #424, each read back through pgx's own
// parser: the one that decides what a connection string means.
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
			cfg := &DatabaseConfig{Username: tc.username, Password: tc.password, Host: tc.host, Port: 5432, Name: tc.database}

			for _, conn := range []struct {
				which    string
				dsn      string
				database string
			}{
				{"DSN", DSN(cfg), tc.database},
				{"MaintenanceDSN", MaintenanceDSN(cfg), "postgres"},
			} {
				parsed, err := pgx.ParseConfig(conn.dsn)
				require.NoErrorf(t, err, "%s %q must parse", conn.which, conn.dsn)
				assert.Equalf(t, tc.username, parsed.User, "%s user", conn.which)
				assert.Equalf(t, tc.password, parsed.Password, "%s password", conn.which)
				assert.Equalf(t, tc.host, parsed.Host, "%s host", conn.which)
				assert.Equalf(t, uint16(5432), parsed.Port, "%s port", conn.which)
				assert.Equalf(t, conn.database, parsed.Database, "%s database", conn.which)
			}
		})
	}
}

// TestDSN_BracketedIPv6HostIsTheSameHost pins that `[::1]`, the one IPv6 spelling of
// GOIABADA_DB_HOST a Sprintf'd URL accepted, still names the host `::1` does. A plain
// net.JoinHostPort would have written `[[::1]]:5432`, which pgx refuses as an invalid IP literal
// (#424).
func TestDSN_BracketedIPv6HostIsTheSameHost(t *testing.T) {
	bare := &DatabaseConfig{Username: "goiabada", Password: "pw", Host: "::1", Port: 5432, Name: "goiabada"}
	bracketed := &DatabaseConfig{Username: "goiabada", Password: "pw", Host: "[::1]", Port: 5432, Name: "goiabada"}

	assert.Equal(t, DSN(bare), DSN(bracketed))
	assert.Equal(t, MaintenanceDSN(bare), MaintenanceDSN(bracketed))

	parsed, err := pgx.ParseConfig(DSN(bracketed))
	require.NoError(t, err)
	assert.Equal(t, "::1", parsed.Host)
	assert.Equal(t, uint16(5432), parsed.Port)
}
