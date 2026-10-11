package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"github.com/microsoft/go-mssqldb/msdsn"
)

// connectionStringCase is one case of testdata/connection-strings.json, which the auth server's
// three dsn_test.go files read too: the one statement of what the check and the server both dial.
type connectionStringCase struct {
	Name           string `json:"name"`
	Engine         string `json:"engine"`
	Host           string `json:"host"`
	Port           int    `json:"port"`
	Username       string `json:"username"`
	Password       string `json:"password"`
	Database       string `json:"database"`
	DSN            string `json:"dsn"`
	MaintenanceDSN string `json:"maintenanceDSN"`
	// MySQL and MySQLMaintenance are a MySQL case's two connections, which are opened from the
	// driver's configuration rather than a string, as the fields they are opened from (#502).
	MySQL            *mysqlFields `json:"mysql"`
	MySQLMaintenance *mysqlFields `json:"mysqlMaintenance"`
	// TLSMode is GOIABADA_DB_TLS_MODE, empty for a case that leaves it unset, which is prefer.
	TLSMode string `json:"tlsMode"`
}

// mysqlFields is a MySQL configuration as the case file pins it: the fields the connection is
// opened from. The auth server's mysqldb tier reads the same shape.
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

func mysqlFieldsOf(t *testing.T, c *mysqldriver.Config) *mysqlFields {
	t.Helper()
	dsn := c.FormatDSN()
	q, err := url.ParseQuery(dsn[strings.LastIndex(dsn, "?")+1:])
	if err != nil {
		t.Fatal(err)
	}
	f := &mysqlFields{User: c.User, Passwd: c.Passwd, Net: c.Net, Addr: c.Addr, DBName: c.DBName,
		MultiStatements: c.MultiStatements, ParseTime: c.ParseTime, Loc: c.Loc.String(), Charset: q.Get("charset"),
		TLSConfig: c.TLSConfig}
	if c.TLS != nil {
		f.TLS = &tlsFields{ServerName: c.TLS.ServerName, InsecureSkipVerify: c.TLS.InsecureSkipVerify,
			VerifyConnection: c.TLS.VerifyConnection != nil}
	}
	return f
}

// build is the connection e opens for the case, failing the test when it cannot be built.
func build(t *testing.T, which string, connection func(dbTarget) (dbConnection, error), target dbTarget) dbConnection {
	t.Helper()
	c, err := connection(target)
	if err != nil {
		t.Fatalf("%s: %v", which, err)
	}
	return c
}

func (c connectionStringCase) target() dbTarget {
	return dbTarget{Host: c.Host, Port: c.Port, Username: c.Username, Password: c.Password, Name: c.Database, TLSMode: c.TLSMode}
}

func readConnectionStringCases(t *testing.T) []connectionStringCase {
	t.Helper()
	raw, err := os.ReadFile("testdata/connection-strings.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Cases []connectionStringCase `json:"cases"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		t.Fatal(err)
	}
	if len(file.Cases) == 0 {
		t.Fatal("testdata/connection-strings.json holds no cases")
	}
	return file.Cases
}

// Each row's builders write the file's strings byte for byte, and every server engine has cases,
// so a row added without them fails here rather than dialling a string nothing pins (#430).
func TestConnectionStrings_MatchTheSharedCaseFile(t *testing.T) {
	covered := map[string]int{}
	modes := map[string]bool{}
	for _, c := range readConnectionStringCases(t) {
		t.Run(c.Engine+"/"+c.Name, func(t *testing.T) {
			e, ok := resolveEngine(c.Engine)
			if !ok || !e.hasServer || e.name != c.Engine {
				t.Fatalf("engine %q is not a server engine's name", c.Engine)
			}
			covered[e.name]++
			modes[e.name+" "+c.TLSMode] = true
			for _, conn := range []struct {
				which  string
				got    dbConnection
				dsn    string
				fields *mysqlFields
			}{
				{"connection", build(t, "connection", e.connection, c.target()), c.DSN, c.MySQL},
				{"maintenance connection", build(t, "maintenance connection", e.maintenanceConnection, c.target()),
					c.MaintenanceDSN, c.MySQLMaintenance},
			} {
				if conn.got.dsn != conn.dsn {
					t.Errorf("%s dsn is\n  %s\nwant\n  %s", conn.which, conn.got.dsn, conn.dsn)
				}
				switch {
				case c.Engine != "mysql" && (conn.got.mysql != nil || conn.fields != nil):
					t.Errorf("%s: only MySQL is opened from the driver's configuration", conn.which)
				case c.Engine == "mysql" && (conn.got.mysql == nil || conn.fields == nil):
					t.Errorf("%s: MySQL is opened from the driver's configuration, pinned as its fields", conn.which)
				case c.Engine == "mysql":
					if got := mysqlFieldsOf(t, conn.got.mysql); !reflect.DeepEqual(got, conn.fields) {
						t.Errorf("%s fields are\n  %+v %+v\nwant\n  %+v %+v", conn.which, *got, got.TLS, *conn.fields, conn.fields.TLS)
					}
				}
			}
		})
	}
	for _, e := range engines {
		if !e.hasServer {
			continue
		}
		for _, mode := range []string{"disable", "prefer", "require", "verify-ca", "verify-full"} {
			if !modes[e.name+" "+mode] {
				t.Errorf("%s has no case in %s in testdata/connection-strings.json", e.name, mode)
			}
		}
	}
	for _, e := range engines {
		if e.hasServer && covered[e.name] == 0 {
			t.Errorf("%s has no case in testdata/connection-strings.json", e.name)
		}
	}
}

// The file's strings are also what each driver reads back as the case's own values, through the
// driver's parser, at the versions this module links: a string both sides agree on is still wrong
// if the driver reads a different password out of it.
func TestConnectionStrings_TheDriverReadsTheCaseBack(t *testing.T) {
	for _, c := range readConnectionStringCases(t) {
		t.Run(c.Engine+"/"+c.Name, func(t *testing.T) {
			host := strings.Trim(c.Host, "[]")
			for _, conn := range []struct{ which, dsn, database string }{
				{"dsn", c.DSN, c.Database},
				{"maintenance dsn", c.MaintenanceDSN, map[string]string{"postgres": "postgres", "mysql": "", "mssql": "master"}[c.Engine]},
			} {
				var user, password, gotHost, database string
				var port int
				switch c.Engine {
				case "postgres":
					parsed, err := pgx.ParseConfig(conn.dsn)
					if err != nil {
						t.Fatalf("%s %q: %v", conn.which, conn.dsn, err)
					}
					user, password, gotHost, port, database = parsed.User, parsed.Password, parsed.Host, int(parsed.Port), parsed.Database
					checkPostgresTLS(t, conn.which, c, parsed)
				case "mysql":
					// No string to parse: the configuration the file pins, as the wizard builds it,
					// handed to the driver, which must accept it.
					builder := map[string]func(dbTarget) (dbConnection, error){
						"dsn": mysqlConnection, "maintenance dsn": mysqlMaintenanceConnection}[conn.which]
					parsed := build(t, conn.which, builder, c.target()).mysql
					if _, err := mysqldriver.NewConnector(parsed); err != nil {
						t.Fatalf("%s: the driver refuses the configuration: %v", conn.which, err)
					}
					user, password, database = parsed.User, parsed.Passwd, parsed.DBName
					if parsed.Addr != net.JoinHostPort(host, strconv.Itoa(c.Port)) {
						t.Errorf("%s address is %q", conn.which, parsed.Addr)
					}
					gotHost, port = host, c.Port
					checkMysqlTLS(t, conn.which, c, parsed)
				case "mssql":
					parsed, err := msdsn.Parse(conn.dsn)
					if err != nil {
						t.Fatalf("%s %q: %v", conn.which, conn.dsn, err)
					}
					user, password, gotHost, port, database = parsed.User, parsed.Password, parsed.Host, int(parsed.Port), parsed.Database
					checkMssqlTLS(t, conn.which, c, parsed)
				default:
					t.Fatalf("no parser for %q", c.Engine)
				}
				if user != c.Username || password != c.Password || gotHost != host || port != c.Port || database != conn.database {
					t.Errorf("%s reads back as user %q password %q host %q port %d database %q", conn.which, user, password, gotHost, port, database)
				}
			}
		})
	}
}

// checkPostgresTLS holds what pgx reads out of a case's string to the case's mode, as #502
// decision 2 defines it: whether the connection is encrypted, whether the certificate and the host
// are checked, and whether plain text follows a failed TLS attempt.
func checkPostgresTLS(t *testing.T, which string, c connectionStringCase, parsed *pgx.ConnConfig) {
	t.Helper()
	mode := c.TLSMode
	if mode == "" {
		mode = "prefer"
	}
	tlsConfig := parsed.TLSConfig
	plainTextAfter := len(parsed.Fallbacks) > 0 && parsed.Fallbacks[len(parsed.Fallbacks)-1].TLSConfig == nil
	var got string
	switch {
	case tlsConfig == nil && len(parsed.Fallbacks) == 0:
		got = "disable"
	case tlsConfig == nil:
		got = "plain text first"
	case tlsConfig.InsecureSkipVerify && tlsConfig.VerifyPeerCertificate == nil && plainTextAfter:
		got = "prefer"
	case len(parsed.Fallbacks) > 0:
		got = "TLS with a fallback"
	case tlsConfig.InsecureSkipVerify && tlsConfig.VerifyPeerCertificate == nil:
		got = "require"
	case tlsConfig.InsecureSkipVerify:
		got = "verify-ca"
	case tlsConfig.ServerName == strings.Trim(c.Host, "[]"):
		got = "verify-full"
	default:
		got = "a certificate check naming no host"
	}
	if got != mode {
		t.Errorf("%s reads back as %s, want %s", which, got, mode)
	}
	if tlsConfig != nil && (tlsConfig.RootCAs != nil || len(tlsConfig.Certificates) > 0) {
		t.Errorf("%s carries roots or a client certificate the string cannot have named", which)
	}
}

// checkMssqlTLS holds what go-mssqldb reads out of a case's string to the case's mode, as #502
// decision 2 defines it: whether the login or the whole session is encrypted, with no plain-text
// fallback outside prefer, and whether the certificate and the host are checked. The two verifying
// modes are one string: what makes verify-ca check the chain alone, and either of them trust the CA
// file, is added to the configuration the string is parsed into, which no string can carry.
func checkMssqlTLS(t *testing.T, which string, c connectionStringCase, parsed msdsn.Config) {
	t.Helper()
	mode := c.TLSMode
	if mode == "" {
		mode = "prefer"
	}
	tlsConfig := parsed.TLSConfig
	var got string
	switch {
	case parsed.Encryption == msdsn.EncryptionDisabled && tlsConfig == nil:
		got = "disable"
	case tlsConfig == nil:
		got = "encrypted with no TLS configuration"
	case parsed.Encryption == msdsn.EncryptionOff && tlsConfig.InsecureSkipVerify:
		got = "prefer"
	case parsed.Encryption != msdsn.EncryptionRequired:
		got = "an encryption no mode names"
	case tlsConfig.InsecureSkipVerify:
		got = "require"
	case tlsConfig.ServerName == strings.Trim(c.Host, "[]") && (mode == "verify-ca" || mode == "verify-full"):
		got = mode
	default:
		got = "a certificate check naming no host"
	}
	if got != mode {
		t.Errorf("%s reads back as %s, want %s", which, got, mode)
	}
	if tlsConfig != nil && (tlsConfig.RootCAs != nil || len(tlsConfig.Certificates) > 0) {
		t.Errorf("%s carries roots or a client certificate the string cannot have named", which)
	}
}

// checkMysqlTLS holds the TLS go-sql-driver/mysql connects with under a case's configuration to
// the case's mode, as #502 decision 2 defines it: whether the connection is encrypted, whether
// plain text follows when the server offers no TLS, and whether the certificate and the host are
// checked.
func checkMysqlTLS(t *testing.T, which string, c connectionStringCase, parsed *mysqldriver.Config) {
	t.Helper()
	mode := c.TLSMode
	if mode == "" {
		mode = "prefer"
	}
	tlsConfig, fallback := mysqlDriverTLS(t, parsed)
	var got string
	switch {
	case tlsConfig == nil:
		got = "disable"
	case fallback && tlsConfig.InsecureSkipVerify && tlsConfig.VerifyConnection == nil:
		got = "prefer"
	case fallback:
		got = "TLS with a fallback"
	case tlsConfig.InsecureSkipVerify && tlsConfig.VerifyConnection == nil:
		got = "require"
	case tlsConfig.InsecureSkipVerify:
		got = "verify-ca"
	case tlsConfig.ServerName == strings.Trim(c.Host, "[]"):
		got = "verify-full"
	default:
		got = "a certificate check naming no host"
	}
	if got != mode {
		t.Errorf("%s reads back as %s, want %s", which, got, mode)
	}
	if tlsConfig != nil && (tlsConfig.RootCAs != nil || len(tlsConfig.Certificates) > 0) {
		t.Errorf("%s carries roots or a client certificate the case cannot have named", which)
	}
}

// mysqlDriverTLS is the TLS configuration go-sql-driver/mysql connects with under c, and whether
// it falls back to plain text when the server offers no TLS. A configuration of the builder's own
// is used as it is; a named one is what the driver's own parser makes of the name.
func mysqlDriverTLS(t *testing.T, c *mysqldriver.Config) (*tls.Config, bool) {
	t.Helper()
	if c.TLS != nil {
		return c.TLS, c.AllowFallbackToPlaintext
	}
	parsed, err := mysqldriver.ParseDSN("tcp(" + c.Addr + ")/?tls=" + url.QueryEscape(c.TLSConfig))
	if err != nil {
		t.Fatalf("tls %q: %v", c.TLSConfig, err)
	}
	return parsed.TLS, parsed.AllowFallbackToPlaintext
}

// connectionKey names a connection in the fake's records: its string, or for MySQL the fields that
// tell its two connections apart.
func connectionKey(c dbConnection) string {
	if c.mysql != nil {
		return "mysql " + c.mysql.User + "@" + c.mysql.Addr + "/" + c.mysql.DBName
	}
	return c.dsn
}

// fakeDatabase is a database server the check dials through a dbOpener: each connection is known
// by its connectionKey, the failures are set per connection or per query, and every open, ping, query and close is
// recorded.
type fakeDatabase struct {
	openErr  map[string]error
	pingErr  map[string]error
	counts   map[string]int
	countErr map[string]error

	opened  []string
	queries []fakeQuery
	open    int
}

type fakeQuery struct {
	dsn, query string
	args       []any
	deadline   time.Duration
}

func (f *fakeDatabase) opener(driver string) dbOpener {
	return func(c dbConnection) (dbConn, error) {
		if c.driver != driver {
			return nil, errors.New("opened with driver " + c.driver + ", want " + driver)
		}
		dsn := connectionKey(c)
		f.opened = append(f.opened, dsn)
		if err := f.openErr[dsn]; err != nil {
			return nil, err
		}
		f.open++
		return &fakeConn{db: f, dsn: dsn}, nil
	}
}

type fakeConn struct {
	db     *fakeDatabase
	dsn    string
	closed bool
}

func (c *fakeConn) PingContext(ctx context.Context) error {
	if _, ok := ctx.Deadline(); !ok {
		return errors.New("pinged with no deadline")
	}
	return c.db.pingErr[c.dsn]
}

func (c *fakeConn) count(ctx context.Context, query string, args ...any) (int, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return 0, errors.New("queried with no deadline")
	}
	c.db.queries = append(c.db.queries, fakeQuery{dsn: c.dsn, query: query, args: args, deadline: time.Until(deadline)})
	if err := c.db.countErr[query]; err != nil {
		return 0, err
	}
	return c.db.counts[query], nil
}

func (c *fakeConn) Close() error {
	if !c.closed {
		c.closed = true
		c.db.open--
	}
	return nil
}

// The check's decisions, for every server engine: which connections it opens, in the auth
// server's startup order, what it asks each, what it reports and whether the wizard may go on. A
// lookup that fails is a failed check naming the lookup, never "absent" or "empty" (#430).
func TestCheckDatabase_FollowsTheServersStartupOrder(t *testing.T) {
	target := dbTarget{Host: "db.example.com", Port: 5555, Username: "goiabada", Password: "pw", Name: "goiabada"}
	refused := errors.New("connection refused")
	lookupFailed := errors.New("permission denied")

	for _, e := range engines {
		if !e.hasServer {
			continue
		}
		maintenance := connectionKey(build(t, "maintenance connection", e.maintenanceConnection, target))
		application := connectionKey(build(t, "connection", e.connection, target))
		existence := fakeQuery{dsn: maintenance, query: e.existenceQuery, args: []any{target.Name}}
		emptiness := fakeQuery{dsn: application, query: e.emptinessQuery}

		testCases := []struct {
			name    string
			db      fakeDatabase
			want    bool
			opened  []string
			queries []fakeQuery
			says    []string
			never   []string
		}{
			{
				name:   "the maintenance connection cannot be opened",
				db:     fakeDatabase{openErr: map[string]error{maintenance: refused}},
				opened: []string{maintenance},
				says:   []string{"Connection failed", "connection refused"},
				never:  []string{"Connection successful"},
			},
			{
				name:   "the maintenance connection fails its ping",
				db:     fakeDatabase{pingErr: map[string]error{maintenance: refused}},
				opened: []string{maintenance},
				says:   []string{"Connection failed", "connection refused"},
				never:  []string{"Connection successful"},
			},
			{
				name:    "the existence lookup fails",
				db:      fakeDatabase{countErr: map[string]error{e.existenceQuery: lookupFailed}},
				opened:  []string{maintenance},
				queries: []fakeQuery{existence},
				says:    []string{`Unable to check whether database "goiabada" exists`, "permission denied"},
				never:   []string{"does not exist yet", "Connection successful"},
			},
			{
				name:    "the database does not exist yet",
				db:      fakeDatabase{counts: map[string]int{e.existenceQuery: 0}},
				want:    true,
				opened:  []string{maintenance},
				queries: []fakeQuery{existence},
				says:    []string{"Connection successful", `Database "goiabada" does not exist yet`, "creates it on first start", "may create databases"},
				never:   []string{"Checking if database is empty"},
			},
			{
				name:    "the database exists and its connection fails",
				db:      fakeDatabase{counts: map[string]int{e.existenceQuery: 1}, pingErr: map[string]error{application: refused}},
				opened:  []string{maintenance, application},
				queries: []fakeQuery{existence},
				says:    []string{`Connection to database "goiabada" failed`, "connection refused"},
				never:   []string{"Checking if database is empty"},
			},
			{
				name:    "the database exists and cannot be opened",
				db:      fakeDatabase{counts: map[string]int{e.existenceQuery: 1}, openErr: map[string]error{application: refused}},
				opened:  []string{maintenance, application},
				queries: []fakeQuery{existence},
				says:    []string{`Connection to database "goiabada" failed`, "connection refused"},
			},
			{
				name:    "the emptiness lookup fails",
				db:      fakeDatabase{counts: map[string]int{e.existenceQuery: 1}, countErr: map[string]error{e.emptinessQuery: lookupFailed}},
				opened:  []string{maintenance, application},
				queries: []fakeQuery{existence, emptiness},
				says:    []string{`Unable to check whether database "goiabada" is empty`, "permission denied"},
				never:   []string{"Database is empty", "already contains"},
			},
			{
				name:    "the database exists and is empty",
				db:      fakeDatabase{counts: map[string]int{e.existenceQuery: 1, e.emptinessQuery: 0}},
				want:    true,
				opened:  []string{maintenance, application},
				queries: []fakeQuery{existence, emptiness},
				says:    []string{"Connection successful", "Database is empty"},
				never:   []string{"already contains", "does not exist"},
			},
			{
				name:    "the database exists and holds Goiabada's tables",
				db:      fakeDatabase{counts: map[string]int{e.existenceQuery: 1, e.emptinessQuery: 1}},
				want:    true,
				opened:  []string{maintenance, application},
				queries: []fakeQuery{existence, emptiness},
				says:    []string{"Database already contains Goiabada tables", "Use a fresh/empty database"},
				never:   []string{"Database is empty"},
			},
		}

		for _, testCase := range testCases {
			t.Run(e.name+"/"+testCase.name, func(t *testing.T) {
				var buf bytes.Buffer
				db := testCase.db
				got := checkDatabase(&console{w: &buf}, db.opener(build(t, "connection", e.connection, target).driver), e, target)
				output := buf.String()

				if got != testCase.want {
					t.Errorf("checkDatabase = %v, want %v; output:\n%s", got, testCase.want, output)
				}
				if !slices.Equal(db.opened, testCase.opened) {
					t.Errorf("opened\n  %q\nwant\n  %q", db.opened, testCase.opened)
				}
				if len(db.queries) != len(testCase.queries) {
					t.Fatalf("asked %d queries %+v, want %d", len(db.queries), db.queries, len(testCase.queries))
				}
				for i, q := range db.queries {
					want := testCase.queries[i]
					if q.dsn != want.dsn || q.query != want.query || !slices.Equal(q.args, want.args) {
						t.Errorf("query %d is %q %v on %q, want %q %v on %q", i, q.query, q.args, q.dsn, want.query, want.args, want.dsn)
					}
					if q.deadline <= 0 || q.deadline > checkTimeout {
						t.Errorf("query %d ran with %v left, want at most %v", i, q.deadline, checkTimeout)
					}
				}
				if db.open != 0 {
					t.Errorf("%d connections left open", db.open)
				}
				for _, s := range testCase.says {
					if !strings.Contains(output, s) {
						t.Errorf("output does not say %q:\n%s", s, output)
					}
				}
				for _, s := range testCase.never {
					if strings.Contains(output, s) {
						t.Errorf("output says %q:\n%s", s, output)
					}
				}
			})
		}
	}
}

// A port the flags or prompts let through that is not a number fails the check rather than
// dialling port 0.
func TestTestDatabaseConnection_RefusesAPortThatIsNotANumber(t *testing.T) {
	var buf bytes.Buffer
	if testDatabaseConnection(&console{w: &buf}, testEngine("postgres"), "db.example.com", "54x", "goiabada", "goiabada", "pw") {
		t.Fatal("the check passed with port 54x")
	}
	if !strings.Contains(buf.String(), `Invalid port "54x"`) {
		t.Errorf("output does not name the port:\n%s", buf.String())
	}
}
