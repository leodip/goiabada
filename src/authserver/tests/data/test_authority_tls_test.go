package datatests

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"net/url"
	"testing"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/core/hostport"
	mssql "github.com/microsoft/go-mssqldb"
	"github.com/microsoft/go-mssqldb/msdsn"
	"github.com/stretchr/testify/require"
)

// testAuthorityCAFileVariable names the test authority's certificate, which
// src/.devcontainer/generate-db-tls.sh writes and every test database server serves a
// certificate from: run-tests.sh sets it for the data tier, to the file the dev stack and CI both
// mount at /db-tls (#502).
const testAuthorityCAFileVariable = "TEST_DB_TLS_CA_FILE"

// TestDatabaseServer_ServesTheTestAuthority is what shows the test stack's TLS took, on the engine
// this run is against: the server is dialled by the name the tiers use, through the driver alone,
// with Goiabada's connection builders nowhere in the path, and its certificate checked against the
// test authority and the host name. The same dial trusting only the system's roots is refused,
// which is what says the certificate came from the test authority rather than being checked by
// nothing. Each connection also asks the server whether it is encrypted, so a driver that fell
// back to plain text could not pass.
//
// A missing or unreadable CA file fails the test rather than skipping it: the later slices of #502
// prove verified connections against these servers, and that proof must not lapse quietly
// because a stack or a CI job stopped generating the authority.
func TestDatabaseServer_ServesTheTestAuthority(t *testing.T) {
	if dbType() == data.SQLite {
		t.Skip("sqlite has no server and no transport to protect")
	}

	testAuthority := requireTestAuthority(t)

	t.Run("checked against the test authority, it connects over TLS", func(t *testing.T) {
		db, encryptedQuery := openVerified(t, testAuthority)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		require.NoError(t, db.PingContext(ctx), "the server's certificate must verify against the test authority for %s",
			appConfig.Database.Host)

		var encrypted bool
		require.NoError(t, db.QueryRowContext(ctx, encryptedQuery).Scan(&encrypted))
		require.True(t, encrypted, "the server must report this connection as encrypted")
	})

	t.Run("checked against the system roots, it is refused", func(t *testing.T) {
		systemRoots, err := x509.SystemCertPool()
		require.NoError(t, err)
		db, _ := openVerified(t, systemRoots)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		err = db.PingContext(ctx)
		require.Error(t, err, "a certificate the system's roots accept is not one the test authority issued")
		if dbType() == data.MSSQL {
			// go-mssqldb formats the handshake's error with %v on the TDS path ("TLS Handshake
			// failed"), so on SQL Server only its text reaches here.
			require.ErrorContains(t, err, x509.UnknownAuthorityError{}.Error(),
				"the refusal must be the certificate's authority, not some other failure")
			return
		}
		var unknownAuthority x509.UnknownAuthorityError
		require.ErrorAs(t, err, &unknownAuthority, "the refusal must be the certificate's authority, not some other failure")
	})
}

// openVerified opens the configured engine's server through its driver alone, requiring TLS and
// checking the certificate against roots and the host name it is dialled by, and returns the query
// asking the server whether the connection it answers on is encrypted.
func openVerified(t *testing.T, roots *x509.CertPool) (*sql.DB, string) {
	t.Helper()
	cfg := &appConfig.Database
	tlsConfig := &tls.Config{RootCAs: roots, ServerName: cfg.Host, MinVersion: tls.VersionTLS12}
	credentials := url.UserPassword(cfg.Username, cfg.Password)

	var db *sql.DB
	var encryptedQuery string
	switch dbType() {
	case data.Postgres:
		u := url.URL{Scheme: "postgres", User: credentials, Host: hostport.Join(cfg.Host, cfg.Port),
			Path: "/postgres", RawQuery: "sslmode=disable&connect_timeout=10"}
		pgConfig, err := pgx.ParseConfig(u.String())
		require.NoError(t, err)
		// sslmode=disable only clears what the URL would have set; the connection takes this TLS
		// configuration and no fallback without it.
		pgConfig.TLSConfig = tlsConfig
		pgConfig.Fallbacks = nil
		db = stdlib.OpenDB(*pgConfig)
		encryptedQuery = "SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()"

	case data.MySQL:
		mysqlConfig := mysqldriver.NewConfig()
		mysqlConfig.User = cfg.Username
		mysqlConfig.Passwd = cfg.Password
		mysqlConfig.Net = "tcp"
		mysqlConfig.Addr = hostport.Join(cfg.Host, cfg.Port)
		mysqlConfig.Timeout = 10 * time.Second
		mysqlConfig.TLS = tlsConfig
		connector, err := mysqldriver.NewConnector(mysqlConfig)
		require.NoError(t, err)
		db = sql.OpenDB(connector)
		encryptedQuery = "SELECT VARIABLE_VALUE <> '' FROM performance_schema.session_status WHERE VARIABLE_NAME = 'Ssl_cipher'"

	case data.MSSQL:
		u := url.URL{Scheme: "sqlserver", User: credentials, Host: hostport.Join(cfg.Host, cfg.Port),
			RawQuery: "database=master&encrypt=true&dial+timeout=10"}
		msConfig, err := msdsn.Parse(u.String())
		require.NoError(t, err)
		msConfig.Encryption = msdsn.EncryptionRequired
		msConfig.TLSConfig = tlsConfig
		db = sql.OpenDB(mssql.NewConnectorConfig(msConfig))
		encryptedQuery = "SELECT CAST(CASE WHEN encrypt_option = 'TRUE' THEN 1 ELSE 0 END AS BIT) " +
			"FROM sys.dm_exec_connections WHERE session_id = @@SPID"

	default:
		t.Fatalf("no server to dial for %q", dbType())
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	return db, encryptedQuery
}
