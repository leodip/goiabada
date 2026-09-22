package mssqldb

import (
	"net"
	"net/url"
	"strconv"
)

// maintenanceDatabase is where a SQL Server database is created and dropped from.
const maintenanceDatabase = "master"

// DSN is the connection URL for the application database cfg names.
//
// The host goes through net.JoinHostPort, because a Sprintf'd `host:port` gave an IPv6 literal
// no brackets and the driver read it as a host with no port (#424). The credentials and the
// database were already escaped by url.URL.
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
		Host:     net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port)),
		RawQuery: q.Encode(),
	}
	return u.String()
}
