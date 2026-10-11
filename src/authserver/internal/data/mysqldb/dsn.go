package mysqldb

import (
	"crypto/tls"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/hostport"
)

// ConnConfig is the driver configuration the application database's connection is opened with,
// through mysqldriver.NewConnector, with multiStatements on, because a migration file is several
// statements sent as one Exec.
//
// A configuration rather than a connection string (#502 decision 11). The verifying modes need a
// TLS configuration carrying the CA file's authorities, which no string can hold, and the fields
// reach the server as written: the string's grammar split the user from the password at the first
// `:`, with no escape, so a username carrying one reached the server as another user. The
// fields also carry a database name with `/`, `?` or `#` and an IPv6 host, which a Sprintf'd string
// broke on (#424). The host goes through hostport.Join for the brackets an IPv6 literal needs,
// which also reads `[::1]` as `::1`: the one IPv6 spelling the Sprintf'd string accepted.
func ConnConfig(cfg *DatabaseConfig) (*mysqldriver.Config, error) {
	c, err := driverConfig(cfg)
	if err != nil {
		return nil, err
	}
	c.DBName = cfg.Name
	c.MultiStatements = true
	return c, nil
}

// MaintenanceConnConfig is the configuration with no database selected, the connection a database
// is created and dropped from. No multiStatements: nothing sent over it is more than one statement.
func MaintenanceConnConfig(cfg *DatabaseConfig) (*mysqldriver.Config, error) {
	return driverConfig(cfg)
}

// driverConfig carries what both connections share: the credentials, the address, utf8mb4,
// parsed times and UTC, which is what the hand-built strings asked for before #424, and the TLS
// the mode asks for.
func driverConfig(cfg *DatabaseConfig) (*mysqldriver.Config, error) {
	c := mysqldriver.NewConfig()
	c.User = cfg.Username
	c.Passwd = cfg.Password
	c.Net = "tcp"
	c.Addr = hostport.Join(cfg.Host, cfg.Port)
	c.ParseTime = true
	c.Loc = time.UTC
	// Charset's option only sets a field and returns no error; Apply is the driver's one way in.
	_ = c.Apply(mysqldriver.Charset("utf8mb4", ""))
	if err := applyTLS(c, cfg); err != nil {
		return nil, err
	}
	return c, nil
}

// applyTLS sets the TLS each mode asks for, in go-sql-driver/mysql's terms (#502 decision 2):
//   - disable: tls=false, never encrypted.
//   - prefer: tls=preferred, TLS when the server offers it and plain text when it offers none, the
//     certificate unchecked. What the auth server did before the setting existed; until #542 it
//     asked for no TLS at all, so a server with require_secure_transport refused every connection.
//   - require: tls=skip-verify, always encrypted, the certificate unchecked.
//   - verify-ca and verify-full: a TLS configuration of the builder's own carrying the CA file's
//     authorities, nil leaving the system's roots. verify-full checks the host, an IP literal
//     against the certificate's IP addresses; verify-ca turns the library's check off and checks
//     the chain alone, since the driver has no such mode.
//
// Only preferred sets the driver's fallback to plain text; with any other TLS the driver refuses a
// server offering none.
func applyTLS(c *mysqldriver.Config, cfg *DatabaseConfig) error {
	mode := cfg.TLSMode.OrPrefer()
	switch mode {
	case data.TLSDisable:
		c.TLSConfig = "false"
	case data.TLSPrefer:
		c.TLSConfig = "preferred"
	case data.TLSRequire:
		c.TLSConfig = "skip-verify"
	case data.TLSVerifyCA:
		c.TLS = &tls.Config{
			ServerName: hostport.Unbracket(cfg.Host),
			RootCAs:    cfg.TLSRoots,
			MinVersion: tls.VersionTLS12,
			// The library's check compares the host too; VerifyChainOnly replaces it, on every
			// handshake.
			InsecureSkipVerify: true, //nolint:gosec // G402: VerifyConnection checks the chain against RootCAs
			VerifyConnection:   data.VerifyChainOnly(cfg.TLSRoots),
		}
	case data.TLSVerifyFull:
		c.TLS = &tls.Config{
			ServerName: hostport.Unbracket(cfg.Host),
			RootCAs:    cfg.TLSRoots,
			MinVersion: tls.VersionTLS12,
		}
	default:
		// The configuration's load refuses any other value, so only a configuration built directly
		// reaches this, and it must not connect as prefer under another name.
		return errs.Errorf("GOIABADA_DB_TLS_MODE %q is not one of the five modes", mode)
	}
	return nil
}
