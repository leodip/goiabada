package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
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
}

func (c connectionStringCase) target() dbTarget {
	return dbTarget{Host: c.Host, Port: c.Port, Username: c.Username, Password: c.Password, Name: c.Database}
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
	for _, c := range readConnectionStringCases(t) {
		t.Run(c.Engine+"/"+c.Name, func(t *testing.T) {
			e, ok := resolveEngine(c.Engine)
			if !ok || !e.hasServer || e.name != c.Engine {
				t.Fatalf("engine %q is not a server engine's name", c.Engine)
			}
			covered[e.name]++
			if got := e.dsn(c.target()); got != c.DSN {
				t.Errorf("dsn is\n  %s\nwant\n  %s", got, c.DSN)
			}
			if got := e.maintenanceDSN(c.target()); got != c.MaintenanceDSN {
				t.Errorf("maintenance dsn is\n  %s\nwant\n  %s", got, c.MaintenanceDSN)
			}
		})
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
				case "mysql":
					parsed, err := mysqldriver.ParseDSN(conn.dsn)
					if err != nil {
						t.Fatalf("%s %q: %v", conn.which, conn.dsn, err)
					}
					user, password, database = parsed.User, parsed.Passwd, parsed.DBName
					if parsed.Addr != net.JoinHostPort(host, strconv.Itoa(c.Port)) {
						t.Errorf("%s address is %q", conn.which, parsed.Addr)
					}
					gotHost, port = host, c.Port
				case "mssql":
					parsed, err := msdsn.Parse(conn.dsn)
					if err != nil {
						t.Fatalf("%s %q: %v", conn.which, conn.dsn, err)
					}
					user, password, gotHost, port, database = parsed.User, parsed.Password, parsed.Host, int(parsed.Port), parsed.Database
					if parsed.Encryption != msdsn.EncryptionDisabled {
						t.Errorf("%s encryption is %v, want disabled as the server has it", conn.which, parsed.Encryption)
					}
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

// fakeDatabase is a database server the check dials through a dbOpener: each connection is known
// by its DSN, the failures are set per DSN or per query, and every open, ping, query and close is
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
	return func(gotDriver, dsn string) (dbConn, error) {
		if gotDriver != driver {
			return nil, errors.New("opened with driver " + gotDriver + ", want " + driver)
		}
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
		maintenance, application := e.maintenanceDSN(target), e.dsn(target)
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
				got := checkDatabase(&console{w: &buf}, db.opener(e.driver), e, target)
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
