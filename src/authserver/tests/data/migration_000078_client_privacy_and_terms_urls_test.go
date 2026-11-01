package datatests

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/data/migrator"
	"github.com/leodip/goiabada/authserver/internal/data/schemadump"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The two versions migration 000078 sits between. Literals: nothing in production code names this
// number.
const (
	beforeClientDocumentURLs000078 = 77
	clientDocumentURLs000078       = 78
)

// columns000078 are the two columns 000078 adds to clients (#622 decision 12).
var columns000078 = []string{"privacy_policy_url", "terms_of_service_url"}

// TestMigration000078_ClientPrivacyAndTermsURLs exercises the migration that gives a client its own
// privacy policy URL and terms of service URL (#622 decision 12), against a real engine of the
// configured dialect.
//
//  1. Both columns are absent at 000077, and once 000078 has run they are the only thing about
//     clients that moved: each NOT NULL, defaulting to the empty string, with the type, nullability,
//     default and collation website_url has on the same engine, the URL they are validated like.
//  2. A client written without them reads back empty, and one written with them reads them back
//     byte for byte through CreateClient, GetClientById and UpdateClient, at the 256 characters the
//     admin API allows.
//  3. The down migration restores clients to exactly the shape 000077 built, and 000078 applies
//     again after it.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000078_ClientPrivacyAndTermsURLs
func TestMigration000078_ClientPrivacyAndTermsURLs(t *testing.T) {
	ctx := context.Background()
	h := newIsolatedDB(t)

	require.NoErrorf(t, h.Migrator.Migrate(ctx, beforeClientDocumentURLs000078),
		"migrate an empty database up to 000077 on %s", dbType())

	before := dumpTable(t, h, "clients")
	for _, column := range columns000078 {
		_, exists := schemadump.TableShape(before).Column(column)
		require.Falsef(t, exists, "clients.%s must not exist at 000077 on %s", column, dbType())
	}

	require.NoErrorf(t, h.Migrator.Migrate(ctx, clientDocumentURLs000078), "apply 000078 on %s", dbType())
	assertClientDocumentURLsShape000078(t, h, before, "after apply")

	// The round trips write through the ORM, which writes every column the record carries, so they
	// run at head.
	if err := h.Migrator.Up(ctx); err != nil && !errors.Is(err, migrator.ErrNoChange) {
		require.NoError(t, err, "migrate to head for the round trips")
	}

	without := &record.Client{ClientIdentifier: "no-documents-" + fake.LetterN(6), DefaultAcrLevel: record.AcrLevel1}
	require.NoError(t, h.DB.CreateClient(ctx, nil, without))
	read, err := h.DB.GetClientById(ctx, nil, without.Id)
	require.NoError(t, err)
	require.NotNil(t, read)
	assert.Empty(t, read.PrivacyPolicyURL, "a client written without a privacy policy URL reads back none")
	assert.Empty(t, read.TermsOfServiceURL, "a client written without a terms of service URL reads back none")

	// 256 characters, the admin API's bound, some of them outside ASCII so a byte-counting column
	// would be caught short.
	privacy := "https://app.example.com/privacy/" + strings.Repeat("é", 256-len("https://app.example.com/privacy/"))
	terms := "https://app.example.com/terms?lang=pt-BR&v=2"
	with := &record.Client{
		ClientIdentifier:  "with-documents-" + fake.LetterN(6),
		DefaultAcrLevel:   record.AcrLevel1,
		PrivacyPolicyURL:  privacy,
		TermsOfServiceURL: terms,
	}
	require.NoError(t, h.DB.CreateClient(ctx, nil, with))
	read, err = h.DB.GetClientById(ctx, nil, with.Id)
	require.NoError(t, err)
	assert.Equal(t, privacy, read.PrivacyPolicyURL)
	assert.Equal(t, terms, read.TermsOfServiceURL)

	read.PrivacyPolicyURL = "https://app.example.com/privacy-v2"
	read.TermsOfServiceURL = ""
	require.NoError(t, h.DB.UpdateClient(ctx, nil, read))
	updated, err := h.DB.GetClientById(ctx, nil, with.Id)
	require.NoError(t, err)
	assert.Equal(t, "https://app.example.com/privacy-v2", updated.PrivacyPolicyURL, "UpdateClient writes the privacy policy URL")
	assert.Empty(t, updated.TermsOfServiceURL, "UpdateClient clears the terms of service URL")

	require.NoErrorf(t, h.Migrator.Migrate(ctx, beforeClientDocumentURLs000078), "roll back to 000077 on %s", dbType())
	assert.Equalf(t, before, dumpTable(t, h, "clients"),
		"000078's down must restore clients to the shape 000077 built on %s", dbType())

	require.NoErrorf(t, h.Migrator.Migrate(ctx, clientDocumentURLs000078), "re-apply 000078 on %s", dbType())
	assertClientDocumentURLsShape000078(t, h, before, "after a down/up round trip")
}

// assertClientDocumentURLsShape000078 holds clients to the shape 000077 built plus the two columns,
// and each column to website_url's shape on the same engine but for its default's name, which SQL
// Server names per column.
func assertClientDocumentURLsShape000078(t *testing.T, h *isolatedDB, before tableShape, phase string) {
	t.Helper()
	after := schemadump.TableShape(dumpTable(t, h, "clients"))

	sibling, ok := after.Column("website_url")
	require.Truef(t, ok, "[%s] clients.website_url must exist on %s", phase, dbType())

	for _, column := range columns000078 {
		added, ok := after.Column(column)
		require.Truef(t, ok, "[%s] clients.%s must exist on %s", phase, column, dbType())
		assert.Falsef(t, added.Nullable, "[%s] clients.%s must be NOT NULL on %s", phase, column, dbType())
		assert.Equalf(t, sibling.Type, added.Type, "[%s] clients.%s type on %s", phase, column, dbType())
		assert.Truef(t, added.HasDefault, "[%s] clients.%s must carry a default on %s", phase, column, dbType())
		assert.Equalf(t, sibling.Default, added.Default, "[%s] clients.%s must default to '' on %s", phase, column, dbType())
		assert.Equalf(t, sibling.Collation, added.Collation, "[%s] clients.%s collation on %s", phase, column, dbType())
		if dbType() == data.MSSQL {
			assert.Equalf(t, "df_clients_"+column, added.DefaultName,
				"[%s] clients.%s's default constraint is named, so the down can drop it", phase, column)
		}
	}

	withoutAdded := after
	withoutAdded.Columns = slices.DeleteFunc(slices.Clone(after.Columns),
		func(c schemadump.ColumnShape) bool { return slices.Contains(columns000078, c.Name) })
	assert.Equalf(t, schemadump.TableShape(before), withoutAdded,
		"[%s] 000078 must add the two columns and touch nothing else of clients on %s", phase, dbType())
}
