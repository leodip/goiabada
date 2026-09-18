package config

import "github.com/leodip/goiabada/core/data"

// GetDataDatabaseConfig answers this process's GOIABADA_DB_* configuration in the shape core/data
// declares for itself. core/data stopped reading a configuration singleton in #351, so the
// hand-over happens on the auth server's side of the boundary, and every path that opens a
// database -- startup, the migrate subcommand, and the data and integration test harnesses --
// comes through here.
//
// It lives in this package because this package is the one all four callers already share. Written
// out at each of them, as it briefly was, the same eight-field copy exists four times and only one
// copy has a test.
func GetDataDatabaseConfig() *data.DatabaseConfig {
	return dataDatabaseConfig(&cfg.Database)
}

// dataDatabaseConfig is the mapping itself, taking its source rather than reading the singleton so
// that it is testable: eight fields copied by hand is eight chances to write one of them into the
// wrong place, and a swapped Host and Name is a server that cannot open its database with a
// configuration the operator set correctly.
func dataDatabaseConfig(dbConfig *DatabaseConfig) *data.DatabaseConfig {
	return &data.DatabaseConfig{
		Type:     dbConfig.Type,
		Username: dbConfig.Username,
		Password: dbConfig.Password,
		Host:     dbConfig.Host,
		Port:     dbConfig.Port,
		Name:     dbConfig.Name,
		DSN:      dbConfig.DSN,
		Create:   dbConfig.Create,
	}
}
