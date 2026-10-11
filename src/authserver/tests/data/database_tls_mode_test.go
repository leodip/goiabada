package datatests

import (
	"context"
	"crypto/x509"
	"database/sql"
	"net"
	"os"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/data/datafactory"
	"github.com/leodip/goiabada/authserver/internal/data/mssqldb"
	"github.com/leodip/goiabada/authserver/internal/data/mysqldb"
	"github.com/leodip/goiabada/authserver/internal/data/postgresdb"
	"github.com/stretchr/testify/require"
)

// requireTestAuthority reads the test authority's certificate, which every test database server
// serves a certificate from, and fails the test rather than skipping it when the test script
// provides none: the proof of a verified connection must not lapse quietly because a stack or a CI
// job stopped generating the authority (#502).
func requireTestAuthority(t *testing.T) *x509.CertPool {
	t.Helper()
	caFile := os.Getenv(testAuthorityCAFileVariable)
	require.NotEmpty(t, caFile, "%s must name the test authority's certificate; run the data tier "+
		"through run-tests.sh, on a stack whose databases serve it", testAuthorityCAFileVariable)
	pemBytes, err := os.ReadFile(caFile)
	require.NoError(t, err, "the test authority's certificate must be readable at %s=%s",
		testAuthorityCAFileVariable, caFile)
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(pemBytes), "%s must hold a PEM certificate", caFile)
	return roots
}

// TestOpenDatabase_EachTLSModeAgainstTheTestServer opens the engine under test the way the auth
// server does, from its configuration through datafactory.OpenDatabase, in each of the five modes,
// and asks the server whether the connection it answers on is encrypted. The test server serves TLS
// from the test authority, under a certificate naming the host the tier dials and no IP address. So
// disable connects in plain text and prefer and require encrypted, but for SQL Server's prefer,
// which encrypts the login alone when the server does not force encryption; verify-ca and verify-full
// connect with the test authority's CA file and are refused with the system's roots; and dialled by
// its IP address, verify-ca, which checks no host name, connects where verify-full is refused. Create
// is on, so the maintenance connection a creating start opens is held to the mode as well, and every
// refusal names the mode it was made in (#502).
func TestOpenDatabase_EachTLSModeAgainstTheTestServer(t *testing.T) {
	if dbType() == data.SQLite {
		t.Skip("sqlite has no server and no transport to protect")
	}

	testAuthority := requireTestAuthority(t)
	systemRoots, err := x509.SystemCertPool()
	require.NoError(t, err)

	addresses, err := net.LookupHost(appConfig.Database.Host)
	require.NoError(t, err)
	require.NotEmpty(t, addresses)
	ip := addresses[0]
	require.NotNil(t, net.ParseIP(ip), "the test server is dialled by a name, so its IP address is another name")

	type outcome int
	const (
		plainText outcome = iota
		encrypted
		unknownAuthority
		wrongHost
	)
	// On SQL Server prefer encrypts the login alone, and the session only when the server forces
	// encryption, which the test server does not.
	preferSession := encrypted
	if dbType() == data.MSSQL {
		preferSession = plainText
	}
	tests := []struct {
		name    string
		mode    data.TLSMode
		roots   *x509.CertPool
		host    string
		outcome outcome
	}{
		{name: "disable", mode: data.TLSDisable, outcome: plainText},
		{name: "prefer", mode: data.TLSPrefer, outcome: preferSession},
		{name: "require", mode: data.TLSRequire, outcome: encrypted},
		{name: "verify-ca with the test authority", mode: data.TLSVerifyCA, roots: testAuthority, outcome: encrypted},
		{name: "verify-full with the test authority", mode: data.TLSVerifyFull, roots: testAuthority, outcome: encrypted},
		{name: "verify-ca with the system roots", mode: data.TLSVerifyCA, outcome: unknownAuthority},
		{name: "verify-full with the system roots", mode: data.TLSVerifyFull, outcome: unknownAuthority},
		// Explicitly the system's pool rather than nil: no CA file means the system's roots.
		{name: "verify-full with the system's pool named", mode: data.TLSVerifyFull, roots: systemRoots, outcome: unknownAuthority},
		{name: "verify-ca by IP address", mode: data.TLSVerifyCA, roots: testAuthority, host: ip, outcome: encrypted},
		{name: "verify-full by IP address", mode: data.TLSVerifyFull, roots: testAuthority, host: ip, outcome: wrongHost},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := appConfig.Database
			cfg.Create = true
			cfg.TLSMode = string(tt.mode)
			cfg.TLSRoots = tt.roots
			if tt.host != "" {
				cfg.Host = tt.host
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			database, err := datafactory.OpenDatabase(ctx, &cfg, false)
			if err != nil {
				require.ErrorContains(t, err, "(tls mode "+string(tt.mode)+")", "a refusal names the mode in effect")
			}
			switch tt.outcome {
			case unknownAuthority:
				require.Error(t, err, "a certificate the roots do not know is refused")
				if dbType() == data.MSSQL {
					// go-mssqldb formats the handshake's error with %v, so only its text reaches here.
					require.ErrorContains(t, err, x509.UnknownAuthorityError{}.Error(),
						"the refusal must be the certificate's authority, not some other failure")
					return
				}
				var unknown x509.UnknownAuthorityError
				require.ErrorAs(t, err, &unknown, "the refusal must be the certificate's authority, not some other failure")
				return
			case wrongHost:
				require.Error(t, err, "a certificate not naming the host dialled is refused")
				if dbType() == data.MSSQL {
					// The test certificate names no IP address, which is what x509.HostnameError says
					// of an address it was asked to match.
					require.ErrorContains(t, err, "x509: cannot validate certificate for "+ip,
						"the refusal must be the host name, not some other failure")
					return
				}
				var hostname x509.HostnameError
				require.ErrorAs(t, err, &hostname, "the refusal must be the host name, not some other failure")
				return
			}
			require.NoError(t, err)
			t.Cleanup(func() { _ = database.Close() })

			var isEncrypted bool
			require.NoError(t, rawDB(t, database).QueryRowContext(ctx, encryptedConnectionQuery(t)).Scan(&isEncrypted))
			require.Equal(t, tt.outcome == encrypted, isEncrypted, "whether the server reports the connection as encrypted")
		})
	}
}

// rawDB is the pool under an engine OpenDatabase opened.
func rawDB(t *testing.T, database datafactory.Migratable) *sql.DB {
	t.Helper()
	switch db := database.(type) {
	case *mysqldb.Database:
		return db.DB
	case *postgresdb.Database:
		return db.DB
	case *mssqldb.Database:
		return db.DB
	}
	t.Fatalf("no pool to reach in %T", database)
	return nil
}

// encryptedConnectionQuery asks the server whether the connection it answers on is encrypted.
func encryptedConnectionQuery(t *testing.T) string {
	t.Helper()
	switch dbType() {
	case data.MySQL:
		return "SELECT VARIABLE_VALUE <> '' FROM performance_schema.session_status WHERE VARIABLE_NAME = 'Ssl_cipher'"
	case data.Postgres:
		return "SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()"
	case data.MSSQL:
		return "SELECT CAST(CASE WHEN encrypt_option = 'TRUE' THEN 1 ELSE 0 END AS BIT) " +
			"FROM sys.dm_exec_connections WHERE session_id = @@SPID"
	}
	t.Fatalf("no query for %q", dbType())
	return ""
}
