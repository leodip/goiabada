package mysqldb

import (
	"net"
	"strconv"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"
)

// DSN is the connection string for the application database cfg names, with multiStatements on,
// because a migration file is several statements sent as one Exec.
//
// Built through the driver's own FormatDSN rather than written by hand, so a database name
// carrying `/`, `?` or `#` and an IPv6 host survive the driver's parse; a Sprintf'd string
// broke on both (#424). The host goes through net.JoinHostPort for the brackets an IPv6 literal
// needs.
//
// ceiling: a username containing `:` cannot be expressed. The driver's DSN grammar splits the
// user from the password at the first `:` and has no escape for one, so FormatDSN writes it and
// ParseDSN reads a different user back; dsn_test.go pins that. Revisit when the driver gains an
// escape, or when this package opens connections through mysqldriver.NewConnector(cfg) instead of
// a string, which carries the fields without a grammar.
func DSN(cfg *DatabaseConfig) string {
	c := driverConfig(cfg)
	c.DBName = cfg.Name
	c.MultiStatements = true
	return c.FormatDSN()
}

// MaintenanceDSN is the connection string with no database selected, the connection a database
// is created and dropped from. No multiStatements: nothing sent over it is more than one statement.
func MaintenanceDSN(cfg *DatabaseConfig) string {
	return driverConfig(cfg).FormatDSN()
}

// driverConfig carries what both connections share: the credentials, the address, utf8mb4,
// parsed times and UTC, which is what the hand-built strings asked for before #424.
func driverConfig(cfg *DatabaseConfig) *mysqldriver.Config {
	c := mysqldriver.NewConfig()
	c.User = cfg.Username
	c.Passwd = cfg.Password
	c.Net = "tcp"
	c.Addr = net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	c.ParseTime = true
	c.Loc = time.UTC
	// Charset's option only sets a field and returns no error; Apply is the driver's one way in.
	_ = c.Apply(mysqldriver.Charset("utf8mb4", ""))
	return c
}
