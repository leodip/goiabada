package postgresdb

import (
	"net"
	"net/url"
	"strconv"
)

// maintenanceDatabase is the database every PostgreSQL cluster carries for connecting to when
// the one a connection is about is absent or being created or dropped.
const maintenanceDatabase = "postgres"

// DSN is the connection URL for the application database cfg names.
//
// A URL built by url.URL rather than by Sprintf, because RFC 3986 section 3.2.1 admits no
// unescaped `@`, `/`, `?`, `#` or `%` in the userinfo: a password carrying one either failed to
// parse or connected with the wrong password, and so did a database name with a space or `/?#`
// and an IPv6 host (#424).
func DSN(cfg *DatabaseConfig) string {
	return connectionURL(cfg, cfg.Name)
}

// MaintenanceDSN is the connection URL for the postgres maintenance database, the connection a
// database is created and dropped from.
func MaintenanceDSN(cfg *DatabaseConfig) string {
	return connectionURL(cfg, maintenanceDatabase)
}

func connectionURL(cfg *DatabaseConfig, database string) string {
	u := url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(cfg.Username, cfg.Password),
		Host:   net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port)),
		Path:   "/" + database,
	}
	return u.String()
}
