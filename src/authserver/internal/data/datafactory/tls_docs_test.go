package datafactory

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"regexp"
	"strings"
	"testing"

	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/data/mssqldb"
	"github.com/leodip/goiabada/authserver/internal/data/mysqldb"
	"github.com/leodip/goiabada/authserver/internal/data/postgresdb"
	"github.com/leodip/goiabada/authserver/internal/data/tlstest"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The pages an operator reads about the database connection's TLS, held to what a start writes and
// what each engine answers a certificate it refuses, so a page cannot quote a message nobody sees
// or keep advice the auth server no longer follows (#502).

const databasePage = "site/src/content/docs/deploy/database.mdx"

// databasePageSection is the section of the Database page that heading opens, up to the next.
func databasePageSection(t *testing.T, heading string) string {
	t.Helper()
	page := troubleshootingPage(t, databasePage)
	_, section, found := strings.Cut(page, "\n"+heading+"\n")
	require.Truef(t, found, "%s has no section headed %s", databasePage, heading)
	if next := strings.Index(section, "\n## "); next >= 0 {
		section = section[:next]
	}
	return section
}

// TestDatabasePage_WhereTheDatabaseSitsIsTheTwoSettings: the section names both settings and every
// mode, quotes the warning a start relying on the default writes, as a start writes it, and no longer
// sends PostgreSQL operators to libpq's variables, which now stop the start.
func TestDatabasePage_WhereTheDatabaseSitsIsTheTwoSettings(t *testing.T) {
	section := databasePageSection(t, "## Where the database sits")

	capture := logtest.CaptureSlog(t)
	_, _ = OpenDatabase(context.Background(), unreachable("postgres", false), false)
	// Found by what it is rather than by its words, which are what the page is held to.
	var warnings []logtest.CapturedRecord
	for _, r := range capture.Records() {
		if r.Level == slog.LevelWarn && r.Attrs["setting"] == "GOIABADA_DB_TLS_MODE" {
			warnings = append(warnings, r)
		}
	}
	require.Len(t, warnings, 1, "a start with the mode unset warns: %s", capture.Text())

	assert.Contains(t, section, "`"+warnings[0].Message+"`", "the section quotes the warning a start writes")
	assert.Contains(t, troubleshootingPage(t, upgradePage), "`"+warnings[0].Message+"`",
		"the upgrade page quotes the warning an upgraded deployment writes")
	for _, setting := range []string{"GOIABADA_DB_TLS_MODE", "GOIABADA_DB_TLS_CA_FILE"} {
		assert.Contains(t, section, "`"+setting+"`", "the section names %s", setting)
	}
	for _, mode := range data.TLSModes() {
		assert.Contains(t, section, "`"+string(mode)+"`", "the section names the mode %s", mode)
	}
	for _, variable := range []string{"PGSSLMODE", "PGSSLROOTCERT"} {
		assert.NotContains(t, section, variable+"=", "the section no longer advises setting %s", variable)
	}
}

// TestDatabaseConnectPage_NamesTheTLSRefusals: the troubleshooting page quotes what each engine
// answers in a verifying mode when the certificate is another authority's, and in verify-full when
// it names another host or the host dialled is an IP address it does not carry, the handshakes
// being each engine's own TLS configuration against a certificate made here. It quotes the three
// engines' refusals of a server offering no TLS too, and names the mode in the start's record.
func TestDatabaseConnectPage_NamesTheTLSRefusals(t *testing.T) {
	page := troubleshootingPage(t, databaseConnectPage)

	// The page's example: the database's certificate names db-1.internal.example, the auth server
	// dials db.example.com, and 10.0.0.5 is its address.
	const (
		certified = "db-1.internal.example"
		dialled   = "db.example.com"
		address   = "10.0.0.5"
	)
	ours := tlstest.NewAuthority(t, "ours")
	theirs := tlstest.NewAuthority(t, "theirs")

	for _, engine := range serverEngines {
		t.Run(engine, func(t *testing.T) {
			for _, tc := range []struct {
				name   string
				mode   data.TLSMode
				host   string
				server tls.Certificate
			}{
				{"verify-ca, another authority", data.TLSVerifyCA, dialled, theirs.Issue(t, dialled)},
				{"verify-full, another authority", data.TLSVerifyFull, dialled, theirs.Issue(t, dialled)},
				{"verify-full, another host", data.TLSVerifyFull, dialled, ours.Issue(t, certified)},
				{"verify-full, an IP address the certificate does not carry", data.TLSVerifyFull, address, ours.Issue(t, certified)},
			} {
				t.Run(tc.name, func(t *testing.T) {
					cfg := &config.DatabaseConfig{Type: engine, Host: tc.host, Port: 1, Name: "goiabada",
						Username: "goiabada", Password: "unused", TLSMode: string(tc.mode), TLSRoots: ours.Pool()}

					err := tlstest.Handshake(t, engineTLSConfig(t, cfg), tc.server)
					require.Error(t, err, "the certificate is refused")

					refusal := x509Refusal.FindString(err.Error())
					require.NotEmpty(t, refusal, "the refusal is the certificate's: %v", err)
					assert.Contains(t, page, "`"+refusal+"`", "the page quotes what %s answers: %v", engine, err)
					// A check of Goiabada's own, verify-ca's on MySQL and SQL Server, opens with words
					// of its own before crypto/x509's, which the page quotes too.
					if opening, _, found := strings.Cut(err.Error(), ": x509: "); found && !strings.HasPrefix(opening, "tls: ") {
						assert.Contains(t, page, "`"+opening+"`", "the page quotes how %s's own check opens: %v", engine, err)
					}
				})
			}
		})
	}

	// A server offering no TLS, in a mode that never falls back to plain text. MySQL's is the
	// driver's own sentinel; pgx's and go-mssqldb's are unexported, so they are copied from the
	// drivers' source, pgconn.connectOne and tds.go's prelogin check.
	for _, refusal := range []string{mysqldriver.ErrNoTLS.Error(), "server refused TLS connection", "server does not support encryption"} {
		assert.Contains(t, page, "`"+refusal+"`", "the page quotes the refusal of a server offering no TLS")
	}

	capture := logtest.CaptureSlog(t)
	_, _ = OpenDatabase(context.Background(), unreachable("postgres", false), false)
	using := recordsNamed(capture, "using database")
	require.Len(t, using, 1, "%s", capture.Text())
	require.Contains(t, using[0].Attrs, "tls_mode", "the start's record carries the mode in effect")
	assert.Contains(t, page, "`using database`", "the page names the record to read the mode from")
	assert.Contains(t, page, "`tls_mode`", "and its attribute")
}

// x509Refusal is the certificate refusal inside a handshake's error: crypto/x509's own words, up to
// any hint it appends in parentheses.
var x509Refusal = regexp.MustCompile(`x509: [^(]*[^ (]`)

// engineTLSConfig is the TLS configuration the engine cfg names will hand its driver, as the start
// builds it from the configuration.
func engineTLSConfig(t *testing.T, cfg *config.DatabaseConfig) *tls.Config {
	t.Helper()
	switch cfg.Type {
	case "mysql":
		c, err := mysqldb.ConnConfig(mysqlConfig(cfg))
		require.NoError(t, err)
		require.NotNil(t, c.TLS, "a verifying mode hands MySQL a TLS configuration of its own")
		return c.TLS
	case "postgres":
		c, err := postgresdb.ConnConfig(postgresConfig(cfg))
		require.NoError(t, err)
		require.NotNil(t, c.TLSConfig)
		return c.TLSConfig
	case "mssql":
		c, err := mssqldb.ConnConfig(mssqlConfig(cfg))
		require.NoError(t, err)
		require.NotNil(t, c.TLSConfig)
		return c.TLSConfig
	}
	require.Fail(t, "no TLS configuration for "+cfg.Type)
	return nil
}

// The pattern reads crypto/x509's words and nothing around them.
func TestX509Refusal_ReadsTheCertificatesWordsAlone(t *testing.T) {
	err := errors.New(`unable to connect to database: failed to connect to ` +
		"`user=goiabada database=goiabada`: 10.0.0.5:5432 (db): tls error: tls: failed to verify certificate: " +
		`x509: certificate signed by unknown authority (possibly because of "crypto/rsa: verification error" ` +
		`while trying to verify candidate authority certificate "ours")`)
	assert.Equal(t, "x509: certificate signed by unknown authority", x509Refusal.FindString(err.Error()))
	assert.Equal(t, "x509: certificate is valid for a.example, not b.example",
		x509Refusal.FindString("TLS Handshake failed: tls: failed to verify certificate: x509: certificate is valid for a.example, not b.example"))
}
