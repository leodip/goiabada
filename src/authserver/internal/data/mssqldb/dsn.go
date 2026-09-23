package mssqldb

import (
	"net/url"

	"github.com/leodip/goiabada/core/hostport"
)

// maintenanceDatabase is where a SQL Server database is created and dropped from.
const maintenanceDatabase = "master"

// DSN is the connection URL for the application database cfg names.
//
// The host goes through hostport.Join, because a Sprintf'd `host:port` gave an IPv6 literal no
// brackets and the driver read it as a host with no port (#424). hostport.Join also reads `[::1]`
// as `::1`, the one IPv6 spelling the Sprintf'd form accepted. The credentials and the database
// were already escaped by url.URL.
func DSN(cfg *DatabaseConfig) string {
	return connectionURL(cfg, cfg.Name)
}

// MaintenanceDSN is the connection URL for master, the connection a database is created and
// dropped from.
func MaintenanceDSN(cfg *DatabaseConfig) string {
	return connectionURL(cfg, maintenanceDatabase)
}

func connectionURL(cfg *DatabaseConfig, database string) string {
	q := url.Values{}
	q.Add("database", database)
	q.Add("encrypt", "disable")
	u := url.URL{
		Scheme:   "sqlserver",
		User:     url.UserPassword(cfg.Username, cfg.Password),
		Host:     hostport.Join(cfg.Host, cfg.Port),
		RawQuery: q.Encode(),
	}
	return u.String()
}
