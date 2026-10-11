package datafactory

import (
	"context"
	"log/slog"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The start's side of the connection's TLS settings: the warning a start relying on the default
// writes, the mode in the using database record, and an engine refusing a mode it does not map
// (#502). Every server engine is pointed at a port nothing listens on, as in TestOpenDatabase_Dispatch,
// so each is observed without a live server.

// tlsWarning is the record a start writes when it relies on the default mode.
const tlsWarning = "the database tls mode is unset, so the auth server does not check whose database it reached"

var serverEngines = []string{"mysql", "postgres", "mssql"}

// TestOpenDatabase_WarnsWhenTheTLSModeIsUnset: on the three server engines, a start whose mode
// neither the variable nor the flag set writes one Warn record naming the setting, the mode in
// effect and the host, and says how to make the start check the database's certificate.
func TestOpenDatabase_WarnsWhenTheTLSModeIsUnset(t *testing.T) {
	for _, engine := range serverEngines {
		t.Run(engine, func(t *testing.T) {
			capture := logtest.CaptureSlog(t)
			cfg := unreachable(engine, false)
			cfg.Host = "db.internal.example"

			_, _ = OpenDatabase(context.Background(), cfg, false)

			records := recordsNamed(capture, tlsWarning)
			require.Len(t, records, 1, "one warning per start: %s", capture.Text())
			assert.Equal(t, slog.LevelWarn, records[0].Level)
			assert.Equal(t, "GOIABADA_DB_TLS_MODE", records[0].Attrs["setting"])
			assert.Equal(t, "prefer", records[0].Attrs["tls_mode"])
			assert.Equal(t, "db.internal.example", records[0].Attrs["host"])
			remedy, _ := records[0].Attrs["remedy"].(string)
			assert.Contains(t, remedy, "verify-full", "the warning says how to make the start check")
			assert.Contains(t, remedy, "GOIABADA_DB_TLS_CA_FILE", "and how to name a private authority")
		})
	}
}

// TestOpenDatabase_SaysNothingOnceTheModeIsSet: any mode written on purpose is the operator's
// choice, prefer and disable included, and SQLite has no connection to warn about.
func TestOpenDatabase_SaysNothingOnceTheModeIsSet(t *testing.T) {
	for _, engine := range serverEngines {
		for _, mode := range []string{"prefer", "disable", "verify-full"} {
			t.Run(engine+" "+mode, func(t *testing.T) {
				capture := logtest.CaptureSlog(t)
				cfg := unreachable(engine, false)
				cfg.TLSMode = mode

				_, _ = OpenDatabase(context.Background(), cfg, false)

				assert.Empty(t, recordsNamed(capture, tlsWarning), "a mode set on purpose is not warned about: %s", capture.Text())
				assert.Len(t, recordsNamed(capture, "opening the database"), 1, "the start did reach the open: %s", capture.Text())
			})
		}
	}
	t.Run("sqlite with the mode unset", func(t *testing.T) {
		capture := logtest.CaptureSlog(t)
		database, err := OpenDatabase(context.Background(),
			&config.DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "tls.db")}, false)
		require.NoError(t, err)
		t.Cleanup(func() { _ = database.Close() })

		assert.Empty(t, recordsNamed(capture, tlsWarning), "SQLite has no connection to protect: %s", capture.Text())
	})
}

// TestOpenDatabase_TheUsingDatabaseRecordCarriesTheMode: the record each server engine writes as it
// starts carries the mode in effect, whether it was set or not.
func TestOpenDatabase_TheUsingDatabaseRecordCarriesTheMode(t *testing.T) {
	for _, engine := range serverEngines {
		for _, tc := range []struct{ configured, want string }{{"", "prefer"}, {"prefer", "prefer"}} {
			t.Run(engine+" configured "+tc.configured, func(t *testing.T) {
				capture := logtest.CaptureSlog(t)
				cfg := unreachable(engine, false)
				cfg.TLSMode = tc.configured

				_, _ = OpenDatabase(context.Background(), cfg, false)

				records := recordsNamed(capture, "using database")
				require.Len(t, records, 1, "%s", capture.Text())
				assert.Equal(t, tc.want, records[0].Attrs["tls_mode"])
			})
		}
	}
}

// TestOpenDatabase_PreferConnectsAsBefore: prefer, set or not, reaches the engine's connection
// as it always has, which is the failure an unreachable server answers.
func TestOpenDatabase_PreferConnectsAsBefore(t *testing.T) {
	for _, engine := range serverEngines {
		for _, mode := range []string{"", "prefer"} {
			t.Run(engine+" "+mode, func(t *testing.T) {
				cfg := unreachable(engine, false)
				cfg.TLSMode = mode

				_, err := OpenDatabase(context.Background(), cfg, false)

				require.Error(t, err)
				assert.True(t, strings.HasPrefix(err.Error(), "unable to connect to database:"),
					"prefer dials the server: %v", err)
			})
		}
	}
}

// TestOpenDatabase_PostgresDialsInEveryMode: PostgreSQL maps all five modes, so each reaches the
// server, the maintenance connection a creating start opens first included, and none is refused
// before it is dialled.
func TestOpenDatabase_PostgresDialsInEveryMode(t *testing.T) {
	for _, mode := range data.TLSModes() {
		for _, create := range []bool{false, true} {
			t.Run(string(mode)+" create "+strconv.FormatBool(create), func(t *testing.T) {
				cfg := unreachable("postgres", create)
				cfg.TLSMode = string(mode)

				_, err := OpenDatabase(context.Background(), cfg, false)

				require.Error(t, err)
				want := "unable to connect to database:"
				if create {
					want = "unable to check whether the database exists:"
				}
				assert.True(t, strings.HasPrefix(err.Error(), want), "%s dials the server: %v", mode, err)
				assert.Contains(t, err.Error(), "connection refused", "the failure is the server's absence")
			})
		}
	}
}

// TestOpenDatabase_AnEngineRefusesAModeItDoesNotMap: a mode an engine cannot honour yet stops the
// start before anything is dialled, naming the mode and the engine, so no setting is silently
// ignored.
func TestOpenDatabase_AnEngineRefusesAModeItDoesNotMap(t *testing.T) {
	for _, engine := range []string{"mysql", "mssql"} {
		for _, mode := range []data.TLSMode{data.TLSDisable, data.TLSRequire, data.TLSVerifyCA, data.TLSVerifyFull} {
			t.Run(engine+" "+string(mode), func(t *testing.T) {
				capture := logtest.CaptureSlog(t)
				cfg := unreachable(engine, true)
				cfg.TLSMode = string(mode)

				database, err := OpenDatabase(context.Background(), cfg, false)

				require.Error(t, err)
				var noDatabase Migratable
				assert.Equal(t, noDatabase, database)
				assert.Equal(t, "GOIABADA_DB_TLS_MODE "+string(mode)+" is not supported on "+engine+" in this build: set it to prefer",
					err.Error())
				assert.Empty(t, recordsNamed(capture, "database connection pool"), "nothing was opened")
			})
		}
	}
}

// TestEngineConfigs_AnUnsetTLSModeIsPrefer: with neither the variable nor the flag set, each
// server engine is handed prefer and the system's roots.
func TestEngineConfigs_AnUnsetTLSModeIsPrefer(t *testing.T) {
	c := sourceConfig()
	c.TLSMode = ""
	c.TLSRoots = nil

	assert.Equal(t, data.TLSPrefer, mysqlConfig(c).TLSMode, "mysqldb")
	assert.Equal(t, data.TLSPrefer, postgresConfig(c).TLSMode, "postgresdb")
	assert.Equal(t, data.TLSPrefer, mssqlConfig(c).TLSMode, "mssqldb")
	assert.Nil(t, mysqlConfig(c).TLSRoots)
}
