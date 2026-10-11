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
// disable connects in plain text and prefer and require encrypted; verify-ca and verify-full
// connect with the test authority's CA file and are refused with the system's roots; and dialled by
// its IP address, verify-ca, which checks no host name, connects where verify-full is refused. Create
// is on, so the maintenance connection a creating start opens is held to the mode as well (#502).
func TestOpenDatabase_EachTLSModeAgainstTheTestServer(t *testing.T) {
	switch dbType() {
	case data.SQLite:
		t.Skip("sqlite has no server and no transport to protect")
	case data.Postgres:
	default:
		t.Skip("this engine refuses every mode but prefer until it maps them")
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
	tests := []struct {
		name    string
		mode    data.TLSMode
		roots   *x509.CertPool
		host    string
		outcome outcome
	}{
		{name: "disable", mode: data.TLSDisable, outcome: plainText},
		{name: "prefer", mode: data.TLSPrefer, outcome: encrypted},
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
			switch tt.outcome {
			case unknownAuthority:
				require.Error(t, err, "a certificate the roots do not know is refused")
				var unknown x509.UnknownAuthorityError
				require.ErrorAs(t, err, &unknown, "the refusal must be the certificate's authority, not some other failure")
				return
			case wrongHost:
				require.Error(t, err, "a certificate not naming the host dialled is refused")
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
	if db, ok := database.(*postgresdb.Database); ok {
		return db.DB
	}
	t.Fatalf("no pool to reach in %T", database)
	return nil
}

// encryptedConnectionQuery asks the server whether the connection it answers on is encrypted.
func encryptedConnectionQuery(t *testing.T) string {
	t.Helper()
	if dbType() == data.Postgres {
		return "SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()"
	}
	t.Fatalf("no query for %q", dbType())
	return ""
}
