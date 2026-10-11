package postgresdb

import (
	"net/url"

	"github.com/jackc/pgx/v5"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/hostport"
)

// maintenanceDatabase is the database every PostgreSQL cluster carries for connecting to when
// the one a connection is about is absent or being created or dropped.
const maintenanceDatabase = "postgres"

// DSN is the connection URL for the application database cfg names.
//
// A URL built by url.URL rather than by Sprintf, because RFC 3986 section 3.2.1 admits no
// unescaped `@`, `/`, `?`, `#` or `%` in the userinfo: a password carrying one either failed to
// parse or connected with the wrong password, and so did a database name with a space or `/?#`
// and an IPv6 host (#424). The host goes through hostport.Join, which also reads `[::1]` as
// `::1`: the one IPv6 spelling the Sprintf'd URL accepted.
//
// The URL is not the whole connection: the CA file's authorities cannot be written into it, so
// the connection is opened from ConnConfig, which adds them.
func DSN(cfg *DatabaseConfig) string {
	return connectionURL(cfg, cfg.Name)
}

// MaintenanceDSN is the connection URL for the postgres maintenance database, the connection a
// database is created and dropped from.
func MaintenanceDSN(cfg *DatabaseConfig) string {
	return connectionURL(cfg, maintenanceDatabase)
}

// ConnConfig is the configuration the application database's connection is opened with: DSN as
// pgx reads it, and the CA file's authorities.
func ConnConfig(cfg *DatabaseConfig) (*pgx.ConnConfig, error) {
	return connConfig(cfg, DSN(cfg))
}

// MaintenanceConnConfig is ConnConfig for the postgres maintenance database.
func MaintenanceConnConfig(cfg *DatabaseConfig) (*pgx.ConnConfig, error) {
	return connConfig(cfg, MaintenanceDSN(cfg))
}

// connConfig reads dsn through pgx and hands a mode that checks the certificate the CA file's
// authorities, nil leaving the system's roots. pgx's verify-ca check reads the roots off this same
// configuration when the server's certificate arrives, so setting them here covers both modes.
func connConfig(cfg *DatabaseConfig, dsn string) (*pgx.ConnConfig, error) {
	c, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, errs.Wrap(err, "unable to parse the connection URL")
	}
	if cfg.TLSMode.OrPrefer().ChecksCertificate() && c.TLSConfig != nil {
		c.TLSConfig.RootCAs = cfg.TLSRoots
	}
	return c, nil
}

// tlsQuery is everything the connection's TLS is decided by, after sslmode, written into every URL
// so that nothing else decides it (#502 decision 5). pgx fills a key the URL leaves out from
// libpq's PGSSL* variables, from a service file PGSERVICE names, and from the root certificate and
// client pair under ~/.postgresql; a key the URL carries, even empty, wins over all three. So
// no root file, no client certificate and no key passphrase, which leaves the system's roots and
// the CA file ConnConfig adds; SNI on and the negotiation PostgreSQL's own, libpq's defaults.
const tlsQuery = "&sslrootcert=&sslcert=&sslkey=&sslpassword=&sslsni=1&sslnegotiation=postgres"

func connectionURL(cfg *DatabaseConfig, database string) string {
	u := url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(cfg.Username, cfg.Password),
		Host:   hostport.Join(cfg.Host, cfg.Port),
		Path:   "/" + database,
		// libpq's sslmode names are GOIABADA_DB_TLS_MODE's, so the mode is written as it is.
		RawQuery: "sslmode=" + url.QueryEscape(string(cfg.TLSMode.OrPrefer())) + tlsQuery,
	}
	return u.String()
}
