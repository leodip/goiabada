package mssqldb

import (
	"net/url"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/hostport"
	"github.com/microsoft/go-mssqldb/msdsn"
)

// maintenanceDatabase is where a SQL Server database is created and dropped from.
const maintenanceDatabase = "master"

// DSN is the connection URL for the application database cfg names.
//
// The host goes through hostport.Join, because a Sprintf'd `host:port` gave an IPv6 literal no
// brackets and the driver read it as a host with no port (#424). hostport.Join also reads `[::1]`
// as `::1`, the one IPv6 spelling the Sprintf'd form accepted. The credentials and the database
// were already escaped by url.URL.
//
// The URL is not the whole connection: the CA file's authorities, and verify-ca's check of the chain
// alone, cannot be written into it, so the connection is opened from ConnConfig, which adds them.
func DSN(cfg *DatabaseConfig) string {
	return connectionURL(cfg, cfg.Name)
}

// MaintenanceDSN is the connection URL for master, the connection a database is created and
// dropped from.
func MaintenanceDSN(cfg *DatabaseConfig) string {
	return connectionURL(cfg, maintenanceDatabase)
}

// ConnConfig is the configuration the application database's connection is opened with: DSN as
// go-mssqldb reads it, and what a mode that checks the certificate adds to it.
func ConnConfig(cfg *DatabaseConfig) (msdsn.Config, error) {
	return connConfig(cfg, DSN(cfg))
}

// MaintenanceConnConfig is ConnConfig for master.
func MaintenanceConnConfig(cfg *DatabaseConfig) (msdsn.Config, error) {
	return connConfig(cfg, MaintenanceDSN(cfg))
}

// connConfig reads dsn through go-mssqldb and hands a mode that checks the certificate the CA
// file's authorities, nil leaving the system's roots. verify-full keeps the driver's own check,
// which compares the host the URL names with the certificate's names, an IP literal with its IP
// addresses; the CA file is not given to the driver as its certificate parameter, whose path for a
// host containing `:` reads only the common name. verify-ca turns the driver's check off and checks
// the chain alone, since go-mssqldb has no such mode.
func connConfig(cfg *DatabaseConfig, dsn string) (msdsn.Config, error) {
	c, err := msdsn.Parse(dsn)
	if err != nil {
		return msdsn.Config{}, errs.Wrap(err, "unable to parse the connection URL")
	}
	mode := cfg.TLSMode.OrPrefer()
	if !mode.ChecksCertificate() || c.TLSConfig == nil {
		return c, nil
	}
	c.TLSConfig.RootCAs = cfg.TLSRoots
	if mode == data.TLSVerifyCA {
		c.TLSConfig.InsecureSkipVerify = true
		c.TLSConfig.VerifyConnection = data.VerifyChainOnly(cfg.TLSRoots)
	}
	return c, nil
}

// tlsQuery is what each mode adds to the URL's query, in go-mssqldb's parameters (#502 decision 2).
//
// prefer carries no encrypt parameter, which go-mssqldb reads as encrypting the login, and the whole
// session when the server forces encryption, as Azure SQL Database does, without checking the
// server's certificate: what it was before the setting existed. encrypt=disable, which these
// strings carried until #542 for every connection, sends the login in the clear and cannot reach a
// server that forces encryption at all. encrypt=true encrypts the whole session and refuses a
// server that offers no encryption, so no mode but prefer falls back to plain text; require
// trusts any certificate, and the verifying modes check it, in ConnConfig. Never encrypt=strict:
// TDS 8.0 needs SQL Server 2022 configured for it, and the dev server refused it.
var tlsQuery = map[data.TLSMode]string{
	data.TLSDisable:    "&encrypt=disable",
	data.TLSPrefer:     "",
	data.TLSRequire:    "&encrypt=true&TrustServerCertificate=true",
	data.TLSVerifyCA:   "&encrypt=true",
	data.TLSVerifyFull: "&encrypt=true",
}

func connectionURL(cfg *DatabaseConfig, database string) string {
	q := url.Values{}
	q.Add("database", database)
	u := url.URL{
		Scheme:   "sqlserver",
		User:     url.UserPassword(cfg.Username, cfg.Password),
		Host:     hostport.Join(cfg.Host, cfg.Port),
		RawQuery: q.Encode() + tlsQuery[cfg.TLSMode.OrPrefer()],
	}
	return u.String()
}
