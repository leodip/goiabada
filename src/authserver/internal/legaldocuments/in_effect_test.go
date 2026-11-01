package legaldocuments

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var published = time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)

// documents answers five documents and their versions: 1 for all apps at version 2, 2 for selected
// apps listing client 7, 3 for selected apps listing nobody, 4 for all apps but never published, and
// 5 for all apps but retired.
func documents(database *datamocks.Database) {
	database.EXPECT().GetAllLegalDocuments(mock.Anything, (*sql.Tx)(nil)).Return([]record.LegalDocument{
		{Id: 1, ShortName: "privacy", AppliesToAllApps: true},
		{Id: 2, ShortName: "shop-terms"},
		{Id: 3, ShortName: "nobodys"},
		{Id: 4, ShortName: "unpublished", AppliesToAllApps: true},
		{Id: 5, ShortName: "retired", AppliesToAllApps: true, RetiredAt: sql.NullTime{Time: published, Valid: true}},
	}, nil)
	versions := map[int64][]record.LegalDocumentVersion{
		1: {{LegalDocumentId: 1, VersionNumber: 1, Title: "Privacy v1"}, {LegalDocumentId: 1, VersionNumber: 2, Title: "Privacy v2", PublishedAt: published}},
		2: {{LegalDocumentId: 2, VersionNumber: 1, Title: "Shop terms"}},
		3: {{LegalDocumentId: 3, VersionNumber: 1, Title: "Nobody's"}},
		4: {},
		5: {{LegalDocumentId: 5, VersionNumber: 1, Title: "Retired"}},
	}
	database.EXPECT().GetLegalDocumentVersionsByLegalDocumentId(mock.Anything, (*sql.Tx)(nil), mock.Anything).
		RunAndReturn(func(_ context.Context, _ *sql.Tx, id int64) ([]record.LegalDocumentVersion, error) {
			return versions[id], nil
		}).Maybe()
}

// titles answers each document's short name and current version's title.
func titles(inEffect []InEffect) map[string]string {
	out := map[string]string{}
	for _, d := range inEffect {
		out[d.Document.ShortName] = d.Current.Title
	}
	return out
}

func TestForAllApps_ThePublishedDocumentsNotRetiredForAllApps(t *testing.T) {
	database := datamocks.NewDatabase(t)
	documents(database)

	inEffect, err := NewReader(database).ForAllApps(context.Background())
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"privacy": "Privacy v2"}, titles(inEffect))
	assert.Equal(t, published, inEffect[0].Current.PublishedAt, "the latest version is the current one")
}

func TestForClient_TheAllAppsDocumentsAndTheClientsOwn(t *testing.T) {
	database := datamocks.NewDatabase(t)
	documents(database)
	database.EXPECT().GetClientByClientIdentifier(mock.Anything, (*sql.Tx)(nil), "shop").Return(&record.Client{Id: 7}, nil)
	database.EXPECT().GetLegalDocumentClientsByClientId(mock.Anything, (*sql.Tx)(nil), int64(7)).
		Return([]record.LegalDocumentClient{{LegalDocumentId: 2, ClientId: 7}}, nil)

	inEffect, err := NewReader(database).ForClient(context.Background(), "shop")
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"privacy": "Privacy v2", "shop-terms": "Shop terms"}, titles(inEffect))
	assert.Equal(t, "privacy", inEffect[0].Document.ShortName, "in id order")
}

func TestForClient_NoAppOrAnUnknownOneIsTheAllAppsDocuments(t *testing.T) {
	t.Run("no app", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		documents(database)
		inEffect, err := NewReader(database).ForClient(context.Background(), "")
		require.NoError(t, err)
		assert.Equal(t, map[string]string{"privacy": "Privacy v2"}, titles(inEffect))
	})
	t.Run("an unknown app", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		documents(database)
		database.EXPECT().GetClientByClientIdentifier(mock.Anything, (*sql.Tx)(nil), "gone").Return(nil, nil)
		inEffect, err := NewReader(database).ForClient(context.Background(), "gone")
		require.NoError(t, err)
		assert.Equal(t, map[string]string{"privacy": "Privacy v2"}, titles(inEffect))
	})
}

func TestForClient_AFailedReadIsAnError(t *testing.T) {
	failure := errors.New("database down")
	database := datamocks.NewDatabase(t)
	database.EXPECT().GetClientByClientIdentifier(mock.Anything, (*sql.Tx)(nil), "shop").Return(nil, failure)

	_, err := NewReader(database).ForClient(context.Background(), "shop")
	require.ErrorIs(t, err, failure)

	database = datamocks.NewDatabase(t)
	database.EXPECT().GetAllLegalDocuments(mock.Anything, (*sql.Tx)(nil)).Return(nil, failure)
	_, err = NewReader(database).ForAllApps(context.Background())
	require.ErrorIs(t, err, failure)
}
