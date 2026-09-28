package main

import (
	"context"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/core/errs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordDrops stands in for the three servers and answers the configurations it was handed.
func recordDrops(t *testing.T, answer error) *[]config.DatabaseConfig {
	t.Helper()

	var dropped []config.DatabaseConfig
	original := dropByEngine
	t.Cleanup(func() { dropByEngine = original })

	dropByEngine = map[string]func(ctx context.Context, cfg *config.DatabaseConfig) error{}
	for engine := range original {
		dropByEngine[engine] = func(_ context.Context, cfg *config.DatabaseConfig) error {
			dropped = append(dropped, *cfg)
			return answer
		}
	}
	return &dropped
}

func TestRun_DropsEachDisposableDatabaseOnEachServerEngine(t *testing.T) {
	for _, engine := range []string{"mysql", "postgres", "mssql"} {
		for _, name := range []string{"goiabada_data", "goiabada_integration"} {
			t.Run(engine+"/"+name, func(t *testing.T) {
				dropped := recordDrops(t, nil)
				cfg := config.DatabaseConfig{Type: engine, Name: name, Host: "db", Port: 1, Username: "u", Password: "p"}

				require.NoError(t, run(context.Background(), &cfg))
				assert.Equal(t, []config.DatabaseConfig{cfg}, *dropped)
			})
		}
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
	for _, engine := range []string{"sqlite", "", "oracle"} {
		t.Run(engine, func(t *testing.T) {
			dropped := recordDrops(t, nil)

			err := run(context.Background(), &config.DatabaseConfig{Type: engine, Name: "goiabada_integration"})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "refusing to drop")
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
	engines := make([]string, 0, len(dropByEngine))
	for engine := range dropByEngine {
		engines = append(engines, engine)
	}
	assert.ElementsMatch(t, []string{"mysql", "postgres", "mssql"}, engines)
}
