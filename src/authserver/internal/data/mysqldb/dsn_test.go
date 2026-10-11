package mysqldb

import (
	"crypto/tls"
	"encoding/json"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/core/guard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// connCases are the values a Sprintf'd DSN got wrong before #424, or could have, and the username
// with a `:` the driver's string grammar could not carry until the connection was opened from its
// configuration (#502), each read off the configuration the connector is built from.
var connCases = []struct {
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
	{"colon in username", "us:r", "pw", "db", "goiabada"},
	{"at and colon in username", "us@r:x", "p:w", "db", "goiabada"},
	{"space in database", "goiabada", "pw", "db", "my db"},
	{"slash, question mark and hash in database", "goiabada", "pw", "db", "a/b?c#d"},
	{"IPv6 host", "goiabada", "pw", "::1", "goiabada"},
}

func TestConnConfig_CarriesTheFieldsTheConnectorOpensFrom(t *testing.T) {
	for _, tc := range connCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &DatabaseConfig{Username: tc.username, Password: tc.password, Host: tc.host, Port: 3306, Name: tc.database}

			for _, conn := range []struct {
				which           string
				build           func(*DatabaseConfig) (*mysqldriver.Config, error)
				database        string
				multiStatements bool
			}{
				{"ConnConfig", ConnConfig, tc.database, true},
				// No database selected, and never more than one statement at a time.
				{"MaintenanceConnConfig", MaintenanceConnConfig, "", false},
			} {
				c, err := conn.build(cfg)
				require.NoErrorf(t, err, "%s", conn.which)
				_, err = mysqldriver.NewConnector(c)
				require.NoErrorf(t, err, "%s: the driver must accept the configuration", conn.which)

				// The fields as written, with no grammar between them and the server: a `:` in the
				// username reaches the server as part of the username.
				assert.Equalf(t, tc.username, c.User, "%s user", conn.which)
				assert.Equalf(t, tc.password, c.Passwd, "%s password", conn.which)
				assert.Equalf(t, "tcp", c.Net, "%s network", conn.which)
				assert.Equalf(t, net.JoinHostPort(tc.host, "3306"), c.Addr, "%s address", conn.which)
				assert.Equalf(t, conn.database, c.DBName, "%s database", conn.which)
				assert.Equalf(t, conn.multiStatements, c.MultiStatements, "%s multiStatements", conn.which)
				assert.Truef(t, c.ParseTime, "%s parseTime", conn.which)
				assert.Equalf(t, time.UTC, c.Loc, "%s loc", conn.which)
				assert.Equalf(t, "utf8mb4", charset(t, c), "%s charset", conn.which)
				// TLS when the server offers it, the certificate unchecked: the mode an unset
				// GOIABADA_DB_TLS_MODE reads as (#502), and what a server with
				// require_secure_transport needed (#542).
				assert.Equalf(t, "preferred", c.TLSConfig, "%s tls", conn.which)
				assert.Nilf(t, c.TLS, "%s carries no TLS configuration of its own", conn.which)
			}
		})
	}
}

// TestConnConfig_BracketedIPv6HostIsTheSameHost pins that `[::1]`, the one IPv6 spelling of
// GOIABADA_DB_HOST a Sprintf'd DSN accepted, still names the host `::1` does. A plain
// net.JoinHostPort would have written `[[::1]]:3306`, which no dial can use (#424).
func TestConnConfig_BracketedIPv6HostIsTheSameHost(t *testing.T) {
	for _, mode := range data.TLSModes() {
		t.Run(string(mode), func(t *testing.T) {
			bare, err := ConnConfig(&DatabaseConfig{Username: "goiabada", Password: "pw", Host: "::1", Port: 3306, Name: "goiabada",
				TLSMode: mode})
			require.NoError(t, err)
			bracketed, err := ConnConfig(&DatabaseConfig{Username: "goiabada", Password: "pw", Host: "[::1]", Port: 3306,
				Name: "goiabada", TLSMode: mode})
			require.NoError(t, err)

			assert.Equal(t, "[::1]:3306", bracketed.Addr)
			assert.Equal(t, bare.Addr, bracketed.Addr)
			if bare.TLS != nil {
				assert.Equal(t, bare.TLS.ServerName, bracketed.TLS.ServerName, "the host a certificate is checked against")
			}
		})
	}
}

// charset reads the character set the configuration asks for. The driver keeps it in an
// unexported field, so its own rendering of the configuration is where it can be seen.
func charset(t *testing.T, c *mysqldriver.Config) string {
	t.Helper()
	dsn := c.FormatDSN()
	i := strings.LastIndex(dsn, "?")
	require.GreaterOrEqualf(t, i, 0, "%q carries no parameters", dsn)
	q, err := url.ParseQuery(dsn[i+1:])
	require.NoError(t, err)
	return q.Get("charset")
}

// mysqlCase is a MySQL row of cmd/goiabada-setup/testdata/connection-strings.json.
type mysqlCase struct {
	Name, Engine, Host, Username, Password, Database string
	Port                                             int
	TLSMode                                          string       `json:"tlsMode"`
	MySQL                                            *mysqlFields `json:"mysql"`
	MySQLMaintenance                                 *mysqlFields `json:"mysqlMaintenance"`
}

// mysqlFields is a configuration as the shared case file pins it: the fields the connection is
// opened from, the TLS configuration among them, since no string carries them (#502).
type mysqlFields struct {
	User            string     `json:"user"`
	Passwd          string     `json:"passwd"`
	Net             string     `json:"net"`
	Addr            string     `json:"addr"`
	DBName          string     `json:"dbName"`
	MultiStatements bool       `json:"multiStatements"`
	ParseTime       bool       `json:"parseTime"`
	Loc             string     `json:"loc"`
	Charset         string     `json:"charset"`
	TLSConfig       string     `json:"tlsConfig"`
	TLS             *tlsFields `json:"tls"`
}

// tlsFields is what a TLS configuration of the builder's own decides: the host the certificate
// must name, whether the library's check is off, and whether a check of the chain alone replaces
// it. Roots are not pinned: the case file names no CA file.
type tlsFields struct {
	ServerName         string `json:"serverName"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
	VerifyConnection   bool   `json:"verifyConnection"`
}

func fieldsOf(t *testing.T, c *mysqldriver.Config) *mysqlFields {
	t.Helper()
	f := &mysqlFields{User: c.User, Passwd: c.Passwd, Net: c.Net, Addr: c.Addr, DBName: c.DBName,
		MultiStatements: c.MultiStatements, ParseTime: c.ParseTime, Loc: c.Loc.String(), Charset: charset(t, c),
		TLSConfig: c.TLSConfig}
	if c.TLS != nil {
		f.TLS = &tlsFields{ServerName: c.TLS.ServerName, InsecureSkipVerify: c.TLS.InsecureSkipVerify,
			VerifyConnection: c.TLS.VerifyConnection != nil}
	}
	return f
}

// TestConnConfig_MatchesTheSetupWizardsCaseFile holds ConnConfig and MaintenanceConnConfig to the
// fields in cmd/goiabada-setup/testdata/connection-strings.json. The setup wizard checks an
// operator's database with copies of these two, since it may import no application
// (ARCHITECTURE.md rule 3), and its own tier holds the copies to the same file, so changing either
// side alone fails that side's tier (#430, #502).
func TestConnConfig_MatchesTheSetupWizardsCaseFile(t *testing.T) {
	path := filepath.Join(guard.SourceRoot(t), "cmd", "goiabada-setup", "testdata", "connection-strings.json")
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var file struct {
		Cases []mysqlCase `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(raw, &file))

	found := 0
	modes := map[string]bool{}
	for _, c := range file.Cases {
		if c.Engine != "mysql" {
			continue
		}
		found++
		modes[c.TLSMode] = true
		require.NotNilf(t, c.MySQL, "%s: no mysql fields", c.Name)
		require.NotNilf(t, c.MySQLMaintenance, "%s: no mysqlMaintenance fields", c.Name)
		cfg := &DatabaseConfig{Username: c.Username, Password: c.Password, Host: c.Host, Port: c.Port, Name: c.Database,
			TLSMode: data.TLSMode(c.TLSMode)}
		conn, err := ConnConfig(cfg)
		require.NoError(t, err)
		maintenance, err := MaintenanceConnConfig(cfg)
		require.NoError(t, err)
		assert.Equalf(t, c.MySQL, fieldsOf(t, conn), "%s: ConnConfig", c.Name)
		assert.Equalf(t, c.MySQLMaintenance, fieldsOf(t, maintenance), "%s: MaintenanceConnConfig", c.Name)
	}
	require.NotZerof(t, found, "%s holds no mysql case", path)
	for _, mode := range data.TLSModes() {
		assert.Truef(t, modes[string(mode)], "%s holds no mysql case in %s", path, mode)
	}
}

// driverTLS is the TLS configuration the driver connects with, and whether it falls back to plain
// text when the server offers no TLS. A configuration of the builder's own is used as it is; a
// named one is what the driver's own parser makes of the name.
func driverTLS(t *testing.T, c *mysqldriver.Config) (*tls.Config, bool) {
	t.Helper()
	if c.TLS != nil {
		return c.TLS, c.AllowFallbackToPlaintext
	}
	parsed, err := mysqldriver.ParseDSN("tcp(" + c.Addr + ")/?tls=" + url.QueryEscape(c.TLSConfig))
	require.NoError(t, err)
	return parsed.TLS, parsed.AllowFallbackToPlaintext
}
