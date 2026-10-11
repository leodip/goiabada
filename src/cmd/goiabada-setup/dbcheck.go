package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"net/url"
	"strconv"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/hostport"
	mssql "github.com/microsoft/go-mssqldb"
	"github.com/microsoft/go-mssqldb/msdsn"
)

// dbTarget is the database the operator described, in the auth server's DatabaseConfig terms.
type dbTarget struct {
	Host     string
	Port     int
	Username string
	Password string
	Name     string
	// TLSMode is GOIABADA_DB_TLS_MODE as the auth server will read it, empty for unset, which is
	// prefer. TLSRoots is the authorities GOIABADA_DB_TLS_CA_FILE holds, nil for the system's roots.
	TLSMode  string
	TLSRoots *x509.CertPool
}

// The connections below are copies of the auth server's, in
// authserver/internal/data/{postgresdb,mysqldb,mssqldb}/dsn.go, which this module may not import
// (ARCHITECTURE.md rule 3): PostgreSQL's and SQL Server's connection strings, and MySQL's driver
// configuration. A check that dials differently from the server tests something else:
// lib/pq with sslmode=require refused a server without TLS the auth server reaches, and a
// SQL Server string with no encrypt passed a server that forces encryption the auth server then
// could not (#430). testdata/connection-strings.json pins both copies, MySQL's as the fields it is
// opened from: the setup tier and each engine's dsn_test.go read it, so changing one side's builder
// alone fails that side.

// postgresDSN is postgresdb.DSN: url.URL escapes what RFC 3986 section 3.2.1 admits no unescaped
// `@`, `/`, `?`, `#` or `%` for in the userinfo, hostport.Join brackets an IPv6 literal, and the
// query carries the TLS mode, prefer while it is unset.
func postgresDSN(t dbTarget) string { return postgresURL(t, t.Name) }

// postgresMaintenanceDSN is postgresdb.MaintenanceDSN: the postgres database every cluster
// carries, where the server looks for the application database and creates it.
func postgresMaintenanceDSN(t dbTarget) string { return postgresURL(t, "postgres") }

// postgresTLSQuery is postgresdb's tlsQuery: every key the connection's TLS is decided by after
// sslmode, written so that no PGSSL* variable, service file or file under ~/.postgresql decides it.
const postgresTLSQuery = "&sslrootcert=&sslcert=&sslkey=&sslpassword=&sslsni=1&sslnegotiation=postgres"

func postgresURL(t dbTarget, database string) string {
	mode := t.TLSMode
	if mode == "" {
		mode = "prefer"
	}
	u := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(t.Username, t.Password),
		Host:     hostport.Join(t.Host, t.Port),
		Path:     "/" + database,
		RawQuery: "sslmode=" + url.QueryEscape(mode) + postgresTLSQuery,
	}
	return u.String()
}

// postgresConnection is postgresdb.ConnConfig: postgresDSN through pgx, with the CA file's
// authorities, which no URL can carry.
func postgresConnection(t dbTarget) (dbConnection, error) {
	return postgresConnectionFor(t, postgresDSN(t))
}

// postgresMaintenanceConnection is postgresdb.MaintenanceConnConfig.
func postgresMaintenanceConnection(t dbTarget) (dbConnection, error) {
	return postgresConnectionFor(t, postgresMaintenanceDSN(t))
}

// postgresConnectionFor is postgresdb's connConfig: dsn as pgx reads it, and for a mode that checks
// the certificate the CA file's authorities, nil leaving the system's roots. pgx's verify-ca check
// reads the roots off this same configuration.
func postgresConnectionFor(t dbTarget, dsn string) (dbConnection, error) {
	c, err := pgx.ParseConfig(dsn)
	if err != nil {
		return dbConnection{}, errs.Wrap(err, "unable to parse the connection URL")
	}
	if checksCertificate(t.TLSMode) && c.TLSConfig != nil {
		c.TLSConfig.RootCAs = t.TLSRoots
	}
	return dbConnection{driver: "pgx", dsn: dsn, postgres: c}, nil
}

// mysqlConnection is the connection mysqldb.ConnConfig configures: the driver's configuration
// rather than a string, with multiStatements on because a migration file is several statements
// sent as one Exec. The fields reach the server as written, a username containing `:` included,
// which the string's grammar split from the password at the first `:` (#502).
func mysqlConnection(t dbTarget) (dbConnection, error) {
	c, err := mysqlConfig(t)
	if err != nil {
		return dbConnection{}, err
	}
	c.DBName = t.Name
	c.MultiStatements = true
	return dbConnection{driver: "mysql", mysql: c}, nil
}

// mysqlMaintenanceConnection is mysqldb.MaintenanceConnConfig: no database selected, where the
// server creates it.
func mysqlMaintenanceConnection(t dbTarget) (dbConnection, error) {
	c, err := mysqlConfig(t)
	if err != nil {
		return dbConnection{}, err
	}
	return dbConnection{driver: "mysql", mysql: c}, nil
}

// mysqlConfig is mysqldb's driverConfig, and its applyTLS: tls=false for disable, preferred for
// prefer, skip-verify for require, and for the two verifying modes a TLS configuration carrying
// the roots, verify-ca's checking the chain alone. Only preferred falls back to plain text.
func mysqlConfig(t dbTarget) (*mysqldriver.Config, error) {
	c := mysqldriver.NewConfig()
	c.User = t.Username
	c.Passwd = t.Password
	c.Net = "tcp"
	c.Addr = hostport.Join(t.Host, t.Port)
	c.ParseTime = true
	c.Loc = time.UTC
	// Charset's option only sets a field and returns no error; Apply is the driver's one way in.
	_ = c.Apply(mysqldriver.Charset("utf8mb4", ""))
	mode := t.TLSMode
	if mode == "" {
		mode = "prefer"
	}
	switch mode {
	case "disable":
		c.TLSConfig = "false"
	case "prefer":
		c.TLSConfig = "preferred"
	case "require":
		c.TLSConfig = "skip-verify"
	case "verify-ca":
		c.TLS = &tls.Config{
			ServerName:         hostport.Unbracket(t.Host),
			RootCAs:            t.TLSRoots,
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true, //nolint:gosec // G402: VerifyConnection checks the chain against RootCAs
			VerifyConnection:   verifyChainOnly(t.TLSRoots),
		}
	case "verify-full":
		c.TLS = &tls.Config{ServerName: hostport.Unbracket(t.Host), RootCAs: t.TLSRoots, MinVersion: tls.VersionTLS12}
	default:
		return nil, errs.Errorf("GOIABADA_DB_TLS_MODE %q is not one of the five modes", mode)
	}
	return c, nil
}

// mssqlDSN is mssqldb.DSN: the query carries the TLS mode's parameters, none for prefer, which
// go-mssqldb reads as encrypting the login, and the whole session when the server forces
// encryption, without checking the server's certificate.
func mssqlDSN(t dbTarget) string { return mssqlURL(t, t.Name) }

// mssqlMaintenanceDSN is mssqldb.MaintenanceDSN: master, where the server creates the database.
func mssqlMaintenanceDSN(t dbTarget) string { return mssqlURL(t, "master") }

// mssqlTLSQuery is mssqldb's tlsQuery: what each mode adds to the query. The two verifying modes
// are one string; the CA file and verify-ca's check of the chain alone are added to the
// configuration the string is parsed into.
var mssqlTLSQuery = map[string]string{
	"disable":     "&encrypt=disable",
	"prefer":      "",
	"require":     "&encrypt=true&TrustServerCertificate=true",
	"verify-ca":   "&encrypt=true",
	"verify-full": "&encrypt=true",
}

func mssqlURL(t dbTarget, database string) string {
	mode := t.TLSMode
	if mode == "" {
		mode = "prefer"
	}
	q := url.Values{}
	q.Add("database", database)
	u := url.URL{
		Scheme:   "sqlserver",
		User:     url.UserPassword(t.Username, t.Password),
		Host:     hostport.Join(t.Host, t.Port),
		RawQuery: q.Encode() + mssqlTLSQuery[mode],
	}
	return u.String()
}

// mssqlConnection is mssqldb.ConnConfig: mssqlDSN through go-mssqldb, with the CA file's
// authorities, and verify-ca's check of the chain alone, which no string can carry.
func mssqlConnection(t dbTarget) (dbConnection, error) {
	return mssqlConnectionFor(t, mssqlDSN(t))
}

// mssqlMaintenanceConnection is mssqldb.MaintenanceConnConfig.
func mssqlMaintenanceConnection(t dbTarget) (dbConnection, error) {
	return mssqlConnectionFor(t, mssqlMaintenanceDSN(t))
}

// mssqlConnectionFor is mssqldb's connConfig: dsn as go-mssqldb reads it, and for a mode that checks
// the certificate the CA file's authorities, nil leaving the system's roots. verify-full keeps the
// driver's own check of the host name; verify-ca turns it off and checks the chain alone.
func mssqlConnectionFor(t dbTarget, dsn string) (dbConnection, error) {
	c, err := msdsn.Parse(dsn)
	if err != nil {
		return dbConnection{}, errs.Wrap(err, "unable to parse the connection URL")
	}
	if checksCertificate(t.TLSMode) && c.TLSConfig != nil {
		c.TLSConfig.RootCAs = t.TLSRoots
		if t.TLSMode == "verify-ca" {
			c.TLSConfig.InsecureSkipVerify = true
			c.TLSConfig.VerifyConnection = verifyChainOnly(t.TLSRoots)
		}
	}
	return dbConnection{driver: "sqlserver", dsn: dsn, mssql: &c}, nil
}

// checkTimeout bounds each connection's ping and query, the bound the DSNs used to carry as a
// parameter; the strings carry none now, so they stay the server's byte for byte.
const checkTimeout = 5 * time.Second

// dbConn is the little of a database connection the check uses, so its decisions can be tested
// without a database.
type dbConn interface {
	PingContext(ctx context.Context) error
	// count runs a query answering one integer.
	count(ctx context.Context, query string, args ...any) (int, error)
	Close() error
}

// dbConnection is one connection the check opens, as the auth server opens it: from the driver's
// configuration, which carries what no connection string can, the CA file's authorities and, for
// MySQL, a TLS configuration of its own and a username containing `:` (#502). PostgreSQL's and SQL
// Server's are read from dsn, kept beside them.
type dbConnection struct {
	driver   string
	dsn      string
	mysql    *mysqldriver.Config
	postgres *pgx.ConnConfig
	mssql    *msdsn.Config
}

// dbOpener opens a connection as sql.Open does: it only parses, and the ping is what dials.
type dbOpener func(c dbConnection) (dbConn, error)

type sqlConn struct{ *sql.DB }

func (c sqlConn) count(ctx context.Context, query string, args ...any) (int, error) {
	var n int
	err := c.QueryRowContext(ctx, query, args...).Scan(&n)
	return n, err
}

func openSQL(c dbConnection) (dbConn, error) {
	switch {
	case c.mysql != nil:
		connector, err := mysqldriver.NewConnector(c.mysql)
		if err != nil {
			return nil, err
		}
		return sqlConn{sql.OpenDB(connector)}, nil
	case c.postgres != nil:
		return sqlConn{stdlib.OpenDB(*c.postgres)}, nil
	case c.mssql != nil:
		return sqlConn{sql.OpenDB(mssql.NewConnectorConfig(*c.mssql))}, nil
	}
	return nil, errs.Errorf("no configuration to open the %s connection from", c.driver)
}

// testDatabaseConnection checks the database the operator described and reports whether the
// wizard may go on: true when the auth server can start against it, false when it cannot or the
// check could not tell.
func testDatabaseConnection(out *console, c *Config) bool {
	return checkConfiguredDatabase(out, openSQL, c)
}

// checkConfiguredDatabase is checkDatabase on the database c describes, dialled with its TLS mode
// and its CA file's authorities, as the auth server will dial it (#502 decision 7).
func checkConfiguredDatabase(out *console, open dbOpener, c *Config) bool {
	port, err := strconv.Atoi(c.DBPort)
	if err != nil {
		out.fail("Invalid port %q", c.DBPort)
		return false
	}
	return checkDatabase(out, open, c.Engine, dbTarget{Host: c.DBHost, Port: port, Username: c.DBUsername,
		Password: c.DBPassword, Name: c.DBName, TLSMode: c.DBTLSMode, TLSRoots: tlsRoots(c.DBTLSCA)})
}

// checkDatabase follows the auth server's startup order under the files the wizard writes, which
// leave GOIABADA_DB_CREATE at its default of true: the server's first connection is the
// maintenance one, where it looks for the application database and creates it, and only then does
// it open that database (New*Database in authserver/internal/data). So a fresh install, whose
// database does not exist yet, passes, and an account that reaches its database but not the
// maintenance one fails here as the server would fail at start. The check creates nothing (#430).
//
// A lookup that errors is a failed check naming the lookup, never "absent" or "empty": either
// answer would be a guess the operator then acts on.
func checkDatabase(out *console, open dbOpener, e *engine, t dbTarget) bool {
	out.printf("Testing database connection... ")
	maintenance, err := connect(open, e.maintenanceConnection, t)
	if err != nil {
		out.fail("Connection failed: %v", err)
		return false
	}
	defer func() { _ = maintenance.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), checkTimeout)
	defer cancel()
	found, err := maintenance.count(ctx, e.existenceQuery, t.Name)
	if err != nil {
		out.fail("Unable to check whether database %q exists: %v", t.Name, err)
		return false
	}
	out.success("Connection successful!")

	if found == 0 {
		out.info("Database %q does not exist yet. The auth server creates it on first start,", t.Name)
		out.println("  if the account may create databases.")
		return true
	}

	db, err := connect(open, e.connection, t)
	if err != nil {
		out.fail("Connection to database %q failed: %v", t.Name, err)
		return false
	}
	defer func() { _ = db.Close() }()
	return checkDatabaseEmpty(out, db, e, t.Name)
}

// connect opens the connection build describes for t and pings it under checkTimeout, closing it
// again if the ping fails.
func connect(open dbOpener, build func(dbTarget) (dbConnection, error), t dbTarget) (dbConn, error) {
	c, err := build(t)
	if err != nil {
		return nil, err
	}
	conn, err := open(c)
	if err != nil {
		return nil, errs.Wrap(err, "unable to open connection")
	}
	ctx, cancel := context.WithTimeout(context.Background(), checkTimeout)
	defer cancel()
	if err := conn.PingContext(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// checkDatabaseEmpty checks whether the database already holds Goiabada's tables, warns the
// operator if it does, and reports false when it could not tell.
func checkDatabaseEmpty(out *console, db dbConn, e *engine, name string) bool {
	out.printf("Checking if database is empty... ")

	ctx, cancel := context.WithTimeout(context.Background(), checkTimeout)
	defer cancel()
	count, err := db.count(ctx, e.emptinessQuery)
	if err != nil {
		out.fail("Unable to check whether database %q is empty: %v", name, err)
		return false
	}

	if count > 0 {
		out.println()
		out.warning("Database already contains Goiabada tables!")
		out.println()
		out.printf("  %sThe 'users' table exists, indicating this database was used before.%s\n", out.yellow, out.reset)
		out.printf("  %sIf you're deploying with different URLs than before, the OAuth client%s\n", out.yellow, out.reset)
		out.printf("  %sconfiguration will not match and authentication will fail.%s\n", out.yellow, out.reset)
		out.println()
		out.printf("  %sOptions:%s\n", out.bold, out.reset)
		out.println("    1. Use the same URLs as the previous deployment")
		out.println("    2. Use a fresh/empty database")
		out.println("    3. Manually update the OAuth client redirect URIs in the database")
		out.println()
	} else {
		out.success("Database is empty (ready for fresh deployment)")
	}
	return true
}
