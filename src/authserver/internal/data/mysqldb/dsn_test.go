package mysqldb

import (
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// dsnCases are the values a Sprintf'd DSN got wrong before #424, or could have, each read back
// through the driver's own parser: the one that decides what a connection string means.
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
	{"at in username", "us@r", "pw", "db", "goiabada"},
	{"space in database", "goiabada", "pw", "db", "my db"},
	{"slash, question mark and hash in database", "goiabada", "pw", "db", "a/b?c#d"},
	{"IPv6 host", "goiabada", "pw", "::1", "goiabada"},
}

func TestDSN_RoundTripsThroughTheDriver(t *testing.T) {
	for _, tc := range dsnCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &DatabaseConfig{Username: tc.username, Password: tc.password, Host: tc.host, Port: 3306, Name: tc.database}

			for _, conn := range []struct {
				which           string
				dsn             string
				database        string
				multiStatements bool
			}{
				{"DSN", DSN(cfg), tc.database, true},
				// No database selected, and never more than one statement at a time.
				{"MaintenanceDSN", MaintenanceDSN(cfg), "", false},
			} {
				parsed, err := mysqldriver.ParseDSN(conn.dsn)
				require.NoErrorf(t, err, "%s %q must parse", conn.which, conn.dsn)
				assert.Equalf(t, tc.username, parsed.User, "%s user", conn.which)
				assert.Equalf(t, tc.password, parsed.Passwd, "%s password", conn.which)
				assert.Equalf(t, "tcp", parsed.Net, "%s network", conn.which)
				assert.Equalf(t, net.JoinHostPort(tc.host, "3306"), parsed.Addr, "%s address", conn.which)
				assert.Equalf(t, conn.database, parsed.DBName, "%s database", conn.which)
				assert.Equalf(t, conn.multiStatements, parsed.MultiStatements, "%s multiStatements", conn.which)
				assert.Truef(t, parsed.ParseTime, "%s parseTime", conn.which)
				assert.Equalf(t, time.UTC, parsed.Loc, "%s loc", conn.which)
				assert.Equalf(t, "utf8mb4", dsnParam(t, conn.dsn, "charset"), "%s charset", conn.which)
			}
		})
	}
}

// TestDSN_BracketedIPv6HostIsTheSameHost pins that `[::1]`, the one IPv6 spelling of
// GOIABADA_DB_HOST a Sprintf'd DSN accepted, still names the host `::1` does. A plain
// net.JoinHostPort would have written `[[::1]]:3306`, which no dial can use (#424).
func TestDSN_BracketedIPv6HostIsTheSameHost(t *testing.T) {
	bare := &DatabaseConfig{Username: "goiabada", Password: "pw", Host: "::1", Port: 3306, Name: "goiabada"}
	bracketed := &DatabaseConfig{Username: "goiabada", Password: "pw", Host: "[::1]", Port: 3306, Name: "goiabada"}

	assert.Equal(t, DSN(bare), DSN(bracketed))
	assert.Equal(t, MaintenanceDSN(bare), MaintenanceDSN(bracketed))

	parsed, err := mysqldriver.ParseDSN(DSN(bracketed))
	require.NoError(t, err)
	assert.Equal(t, "[::1]:3306", parsed.Addr)
}

// TestDSN_ColonInUsernameIsTheKnownCeiling pins the limit mysqldb.DSN's ceiling comment names:
// the driver's grammar splits user from password at the first `:`, with no escape, so a username
// carrying one comes back as a different user. The day this fails the driver has grown an escape
// and the ceiling comment can go.
func TestDSN_ColonInUsernameIsTheKnownCeiling(t *testing.T) {
	parsed, err := mysqldriver.ParseDSN(DSN(&DatabaseConfig{Username: "us:r", Password: "pw", Host: "db", Port: 3306, Name: "goiabada"}))
	require.NoError(t, err)
	assert.Equal(t, "us", parsed.User, "the driver reads the user up to the first colon")
	assert.NotEqual(t, "pw", parsed.Passwd)
}

// dsnParam reads one parameter out of a DSN's query. The driver keeps the charset in an unexported
// field once parsed, so the string is where it can be seen.
func dsnParam(t *testing.T, dsn, key string) string {
	t.Helper()
	i := strings.LastIndex(dsn, "?")
	require.GreaterOrEqualf(t, i, 0, "%q carries no parameters", dsn)
	q, err := url.ParseQuery(dsn[i+1:])
	require.NoError(t, err)
	return q.Get(key)
}
