package main

import (
	"context"
	"database/sql"
	"net/url"
	"strconv"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/hostport"
	_ "github.com/microsoft/go-mssqldb"
)

// dbTarget is the database the operator described, in the auth server's DatabaseConfig terms.
type dbTarget struct {
	Host     string
	Port     int
	Username string
	Password string
	Name     string
}

// The connection strings below are copies of the auth server's, in
// authserver/internal/data/{postgresdb,mysqldb,mssqldb}/dsn.go, which this module may not import
// (ARCHITECTURE.md rule 3). A check that dials differently from the server tests something else:
// lib/pq with sslmode=require refused a server without TLS the auth server reaches, and a
// SQL Server string with no encrypt passed a server that forces encryption the auth server then
// could not (#430). testdata/connection-strings.json pins both copies: the setup tier and each
// engine's dsn_test.go read it, so changing one side's builder alone fails that side.

// postgresDSN is postgresdb.DSN: url.URL escapes what RFC 3986 section 3.2.1 admits no unescaped
// `@`, `/`, `?`, `#` or `%` for in the userinfo, and hostport.Join brackets an IPv6 literal.
func postgresDSN(t dbTarget) string { return postgresURL(t, t.Name) }

// postgresMaintenanceDSN is postgresdb.MaintenanceDSN: the postgres database every cluster
// carries, where the server looks for the application database and creates it.
func postgresMaintenanceDSN(t dbTarget) string { return postgresURL(t, "postgres") }

func postgresURL(t dbTarget, database string) string {
	u := url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(t.Username, t.Password),
		Host:   hostport.Join(t.Host, t.Port),
		Path:   "/" + database,
	}
	return u.String()
}

// mysqlDSN is mysqldb.DSN, through the driver's own FormatDSN, with multiStatements on because a
// migration file is several statements sent as one Exec.
//
// ceiling: a username containing `:` cannot be expressed. The driver's DSN grammar splits the user
// from the password at the first `:` and has no escape for one; the server's builder has the same
// limit. Revisit when the server's mysqldb.DSN does.
func mysqlDSN(t dbTarget) string {
	c := mysqlConfig(t)
	c.DBName = t.Name
	c.MultiStatements = true
	return c.FormatDSN()
}

// mysqlMaintenanceDSN is mysqldb.MaintenanceDSN: no database selected, where the server creates it.
func mysqlMaintenanceDSN(t dbTarget) string { return mysqlConfig(t).FormatDSN() }

func mysqlConfig(t dbTarget) *mysqldriver.Config {
	c := mysqldriver.NewConfig()
	c.User = t.Username
	c.Passwd = t.Password
	c.Net = "tcp"
	c.Addr = hostport.Join(t.Host, t.Port)
	c.ParseTime = true
	c.Loc = time.UTC
	c.TLSConfig = "preferred"
	// Charset's option only sets a field and returns no error; Apply is the driver's one way in.
	_ = c.Apply(mysqldriver.Charset("utf8mb4", ""))
	return c
}

// mssqlDSN is mssqldb.DSN, with no encrypt parameter as there: the check must reach a server the way
// the auth server will, and go-mssqldb reads that as encrypting the login, and the whole session when
// the server forces encryption, without checking the server's certificate.
func mssqlDSN(t dbTarget) string { return mssqlURL(t, t.Name) }

// mssqlMaintenanceDSN is mssqldb.MaintenanceDSN: master, where the server creates the database.
func mssqlMaintenanceDSN(t dbTarget) string { return mssqlURL(t, "master") }

func mssqlURL(t dbTarget, database string) string {
	q := url.Values{}
	q.Add("database", database)
	u := url.URL{
		Scheme:   "sqlserver",
		User:     url.UserPassword(t.Username, t.Password),
		Host:     hostport.Join(t.Host, t.Port),
		RawQuery: q.Encode(),
	}
	return u.String()
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

// dbOpener opens a connection as sql.Open does: it only parses, and the ping is what dials.
type dbOpener func(driver, dsn string) (dbConn, error)

type sqlConn struct{ *sql.DB }

func (c sqlConn) count(ctx context.Context, query string, args ...any) (int, error) {
	var n int
	err := c.QueryRowContext(ctx, query, args...).Scan(&n)
	return n, err
}

func openSQL(driver, dsn string) (dbConn, error) {
	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, err
	}
	return sqlConn{db}, nil
}

// testDatabaseConnection checks the database the operator described and reports whether the
// wizard may go on: true when the auth server can start against it, false when it cannot or the
// check could not tell.
func testDatabaseConnection(out *console, e *engine, host, port, name, user, password string) bool {
	portNumber, err := strconv.Atoi(port)
	if err != nil {
		out.fail("Invalid port %q", port)
		return false
	}
	return checkDatabase(out, openSQL, e, dbTarget{Host: host, Port: portNumber, Username: user, Password: password, Name: name})
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
	maintenance, err := connect(open, e.driver, e.maintenanceDSN(t))
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

	db, err := connect(open, e.driver, e.dsn(t))
	if err != nil {
		out.fail("Connection to database %q failed: %v", t.Name, err)
		return false
	}
	defer func() { _ = db.Close() }()
	return checkDatabaseEmpty(out, db, e, t.Name)
}

// connect opens a connection and pings it under checkTimeout, closing it again if the ping fails.
func connect(open dbOpener, driver, dsn string) (dbConn, error) {
	conn, err := open(driver, dsn)
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
