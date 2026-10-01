package main

import (
	"context"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/core/errs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// drop is one call a stand-in server received: which engine's drop was reached, and with what.
type drop struct {
	Engine data.Dialect
	Config config.DatabaseConfig
}

// recordDrops stands in for the three servers and answers the configurations it was handed,
// recording which engine's drop each one reached.
func recordDrops(t *testing.T, answer error) *[]drop {
	t.Helper()

	var dropped []drop
	original := dropByEngine
	t.Cleanup(func() { dropByEngine = original })

	dropByEngine = map[data.Dialect]func(ctx context.Context, cfg *config.DatabaseConfig) error{}
	for engine := range original {
		dropByEngine[engine] = func(_ context.Context, cfg *config.DatabaseConfig) error {
			dropped = append(dropped, drop{Engine: engine, Config: *cfg})
			return answer
		}
	}
	return &dropped
}

func TestRun_DropsEachDisposableDatabaseOnEachServerEngine(t *testing.T) {
	for _, engine := range []data.Dialect{data.MySQL, data.Postgres, data.MSSQL} {
		for _, name := range []string{"goiabada_data", "goiabada_integration"} {
			t.Run(string(engine)+"/"+name, func(t *testing.T) {
				dropped := recordDrops(t, nil)
				cfg := config.DatabaseConfig{Type: string(engine), Name: name, Host: "db", Port: 1, Username: "u", Password: "p"}

				require.NoError(t, run(context.Background(), &cfg))
				assert.Equal(t, []drop{{Engine: engine, Config: cfg}}, *dropped)
			})
		}
	}
}

// A quoted GOIABADA_DB_TYPE is parsed as the server parses it, so the drop reaches the engine the
// server would have opened rather than refusing a value the server accepts (#438 decision 6).
func TestRun_AQuotedTypeReachesItsOwnEngine(t *testing.T) {
	for _, tc := range []struct {
		configured string
		want       data.Dialect
	}{
		{configured: `"mysql"`, want: data.MySQL},
		{configured: `'postgres'`, want: data.Postgres},
	} {
		t.Run(tc.configured, func(t *testing.T) {
			dropped := recordDrops(t, nil)
			cfg := config.DatabaseConfig{Type: tc.configured, Name: "goiabada_data"}

			require.NoError(t, run(context.Background(), &cfg))
			assert.Equal(t, []drop{{Engine: tc.want, Config: cfg}}, *dropped)
		})
	}
}

// Every other name is refused before any server is reached. The devcontainer's own database,
// goiabada, is the one this is for; the others are what a near miss looks like.
func TestRun_RefusesEveryOtherName(t *testing.T) {
	for _, name := range []string{"goiabada", "", "GOIABADA_DATA", "goiabada_integration_old", " goiabada_data", "goiabada_data;"} {
		t.Run(name, func(t *testing.T) {
			dropped := recordDrops(t, nil)

			err := run(context.Background(), &config.DatabaseConfig{Type: "mysql", Name: name})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "refusing to drop")
			assert.Empty(t, *dropped)
		})
	}
}

// SQLite has no server to drop from, and run-tests.sh removes its file instead, so a sqlite
// configuration is refused rather than answered as done.
func TestRun_RefusesAnEngineWithNoServer(t *testing.T) {
	dropped := recordDrops(t, nil)

	err := run(context.Background(), &config.DatabaseConfig{Type: "sqlite", Name: "goiabada_integration"})
	require.Error(t, err)
	assert.Equal(t, `refusing to drop a "sqlite" database: only mysql, postgres and mssql have a server to drop it from`, err.Error())
	assert.Empty(t, *dropped)
}

// A type the server would refuse is refused here with the server's own words, before any server is
// reached. data.ParseDialect's table owns every input; these two are the ones this command used to
// answer with its own message.
func TestRun_RefusesATypeThatDoesNotParse(t *testing.T) {
	for _, tc := range []struct {
		configured string
		want       string
	}{
		{configured: "", want: "unsupported database type:  (string length 0). supported types are: mysql, sqlite, postgres, mssql"},
		{configured: "oracle", want: "unsupported database type: oracle (string length 6). supported types are: mysql, sqlite, postgres, mssql"},
	} {
		t.Run(tc.configured, func(t *testing.T) {
			dropped := recordDrops(t, nil)

			err := run(context.Background(), &config.DatabaseConfig{Type: tc.configured, Name: "goiabada_integration"})
			require.Error(t, err)
			assert.Equal(t, tc.want, err.Error())
			assert.Empty(t, *dropped)
		})
	}
}

func TestRun_ReportsTheServersRefusal(t *testing.T) {
	refused := errs.New("access denied")
	recordDrops(t, refused)

	err := run(context.Background(), &config.DatabaseConfig{Type: "postgres", Name: "goiabada_data"})
	require.ErrorIs(t, err, refused)
	assert.Contains(t, err.Error(), "unable to drop goiabada_data on postgres")
}

func TestDropByEngine_CoversExactlyTheThreeServerEngines(t *testing.T) {
	engines := make([]data.Dialect, 0, len(dropByEngine))
	for engine := range dropByEngine {
		engines = append(engines, engine)
	}
	assert.ElementsMatch(t, []data.Dialect{data.MySQL, data.Postgres, data.MSSQL}, engines)
}
