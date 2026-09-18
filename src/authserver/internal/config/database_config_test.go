package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDataDatabaseConfig_CarriesEveryFieldToItsOwnPlace covers the hand-over #351 created: core/data
// declares its own DatabaseConfig and no longer reads this process's configuration, so this
// mapping is the only thing between the GOIABADA_DB_* variables an operator sets and the database
// the server opens.
//
// Every field is a distinct value, so a line copying the wrong source, or the same source twice,
// fails here rather than at a deployment where the server reports it cannot reach a host nobody
// configured. The two string fields most easily swapped, Host and Name, carry values that would
// each be plausible in the other's place.
func TestDataDatabaseConfig_CarriesEveryFieldToItsOwnPlace(t *testing.T) {
	mapped := dataDatabaseConfig(&DatabaseConfig{
		Type:     "postgres",
		Username: "the-username",
		Password: "the-password",
		Host:     "db.example.com",
		Port:     5433,
		Name:     "goiabada_prod",
		DSN:      "the-dsn",
		Create:   true,
	})

	require.NotNil(t, mapped, "the mapping must produce a configuration")
	assert.Equal(t, "postgres", mapped.Type, "Type picks the engine, so nothing else can stand in for it")
	assert.Equal(t, "the-username", mapped.Username)
	assert.Equal(t, "the-password", mapped.Password)
	assert.Equal(t, "db.example.com", mapped.Host)
	assert.Equal(t, 5433, mapped.Port)
	assert.Equal(t, "goiabada_prod", mapped.Name)
	assert.Equal(t, "the-dsn", mapped.DSN)
	assert.True(t, mapped.Create, "Create is the one setting that defaults to true (#293), so a mapping that drops it is a server that stops creating its own database")
}

// TestDataDatabaseConfig_CarriesAZeroValuedConfiguration is the other half: the zero value maps to
// the zero value rather than to anything invented here. A default belongs in the configuration
// loader, where every other GOIABADA_* default lives and where the matrix stage 1 wrote asserts
// them; a second one applied on the way past would be invisible to that matrix.
func TestDataDatabaseConfig_CarriesAZeroValuedConfiguration(t *testing.T) {
	mapped := dataDatabaseConfig(&DatabaseConfig{})

	require.NotNil(t, mapped)
	assert.Equal(t, "", mapped.Type)
	assert.Equal(t, "", mapped.Username)
	assert.Equal(t, "", mapped.Password)
	assert.Equal(t, "", mapped.Host)
	assert.Equal(t, 0, mapped.Port)
	assert.Equal(t, "", mapped.Name)
	assert.Equal(t, "", mapped.DSN)
	assert.False(t, mapped.Create)
}
