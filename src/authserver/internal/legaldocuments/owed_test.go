package legaldocuments

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const (
	mustAccept     = record.LegalDocumentKindMustAccept
	forInformation = record.LegalDocumentKindForInformation
)

// mustAcceptDocuments answers seven documents and their versions, the version ids numbered by
// document and version (11 is document 1's version 1):
//
//	1 must accept, all apps, versions 11 and 12
//	2 must accept, selected apps listing client 7, version 21
//	3 for information, all apps, version 31
//	4 must accept, selected apps listing client 8 alone, version 41
//	5 must accept, all apps, retired, version 51
//	6 must accept, all apps, never published
//	7 must accept, all apps, version 71
func mustAcceptDocuments(database *datamocks.Database) {
	database.EXPECT().GetAllLegalDocuments(mock.Anything, (*sql.Tx)(nil)).Return([]record.LegalDocument{
		{Id: 1, ShortName: "terms", Kind: mustAccept, AppliesToAllApps: true},
		{Id: 2, ShortName: "shop-terms", Kind: mustAccept},
		{Id: 3, ShortName: "privacy", Kind: forInformation, AppliesToAllApps: true},
		{Id: 4, ShortName: "other-shop-terms", Kind: mustAccept},
		{Id: 5, ShortName: "retired", Kind: mustAccept, AppliesToAllApps: true, RetiredAt: sql.NullTime{Time: published, Valid: true}},
		{Id: 6, ShortName: "unpublished", Kind: mustAccept, AppliesToAllApps: true},
		{Id: 7, ShortName: "house-rules", Kind: mustAccept, AppliesToAllApps: true},
	}, nil)
	versions := map[int64][]record.LegalDocumentVersion{
		1: {{Id: 11, LegalDocumentId: 1, VersionNumber: 1, Title: "Terms v1"}, {Id: 12, LegalDocumentId: 1, VersionNumber: 2, Title: "Terms v2"}},
		2: {{Id: 21, LegalDocumentId: 2, VersionNumber: 1, Title: "Shop terms"}},
		3: {{Id: 31, LegalDocumentId: 3, VersionNumber: 1, Title: "Privacy"}},
		4: {{Id: 41, LegalDocumentId: 4, VersionNumber: 1, Title: "Other shop terms"}},
		5: {{Id: 51, LegalDocumentId: 5, VersionNumber: 1, Title: "Retired"}},
		6: {},
		7: {{Id: 71, LegalDocumentId: 7, VersionNumber: 1, Title: "House rules"}},
	}
	database.EXPECT().GetLegalDocumentVersionsByLegalDocumentId(mock.Anything, (*sql.Tx)(nil), mock.Anything).
		RunAndReturn(func(_ context.Context, _ *sql.Tx, id int64) ([]record.LegalDocumentVersion, error) {
			return versions[id], nil
		}).Maybe()
	database.EXPECT().GetLegalDocumentClientsByClientId(mock.Anything, (*sql.Tx)(nil), int64(7)).
		Return([]record.LegalDocumentClient{{LegalDocumentId: 2, ClientId: 7}}, nil).Maybe()
}

// acceptedVersions makes the user 42 hold acceptances of the versions given.
func acceptedVersions(database *datamocks.Database, versionIds ...int64) {
	acceptances := []record.LegalDocumentAcceptance{}
	for _, id := range versionIds {
		acceptances = append(acceptances, record.LegalDocumentAcceptance{UserId: 42, LegalDocumentVersionId: id})
	}
	database.EXPECT().GetLegalDocumentAcceptancesByUserId(mock.Anything, (*sql.Tx)(nil), int64(42)).Return(acceptances, nil)
}

// owedVersions answers each owed document's short name and the id of the version owed.
func owedVersions(owed []InEffect) map[string]int64 {
	out := map[string]int64{}
	for _, d := range owed {
		out[d.Document.ShortName] = d.Current.Id
	}
	return out
}

var shop = &record.Client{Id: 7, ClientIdentifier: "shop"}

func TestOwed_TheMustAcceptDocumentsForTheAppWhoseCurrentVersionTheUserHasNotAccepted(t *testing.T) {
	database := datamocks.NewDatabase(t)
	mustAcceptDocuments(database)
	// Version 1 of the terms, the shop's terms and the privacy notice's only version: the terms'
	// version 2 and the house rules are still owed.
	acceptedVersions(database, 11, 21, 31)

	owed, err := NewReader(database).Owed(context.Background(), shop, 42)
	require.NoError(t, err)
	assert.Equal(t, map[string]int64{"terms": 12, "house-rules": 71}, owedVersions(owed),
		"the current version of each must-accept document for all apps or for the shop, not yet accepted")
	assert.Equal(t, "terms", owed[0].Document.ShortName, "in id order")
}

func TestOwed_EveryCurrentVersionAcceptedOwesNothing(t *testing.T) {
	database := datamocks.NewDatabase(t)
	mustAcceptDocuments(database)
	acceptedVersions(database, 12, 21, 71)

	owed, err := NewReader(database).Owed(context.Background(), shop, 42)
	require.NoError(t, err)
	assert.Empty(t, owed)
}

func TestOwed_AnotherAppsDocumentIsNotOwed(t *testing.T) {
	database := datamocks.NewDatabase(t)
	mustAcceptDocuments(database)
	database.EXPECT().GetLegalDocumentClientsByClientId(mock.Anything, (*sql.Tx)(nil), int64(9)).
		Return([]record.LegalDocumentClient{}, nil)
	acceptedVersions(database)

	owed, err := NewReader(database).Owed(context.Background(), &record.Client{Id: 9, ClientIdentifier: "blog"}, 42)
	require.NoError(t, err)
	assert.Equal(t, map[string]int64{"terms": 12, "house-rules": 71}, owedVersions(owed),
		"the all-apps documents alone: the shop's terms and client 8's are not the blog's")
}

func TestOwed_TheAdminConsolesOwnClientOwesNothingAndReadsNothing(t *testing.T) {
	// Strict mocks with no expectation: any read fails the test.
	database := datamocks.NewDatabase(t)

	owed, err := NewReader(database).Owed(context.Background(),
		&record.Client{Id: 1, ClientIdentifier: builtin.AdminConsoleClientIdentifier}, 42)
	require.NoError(t, err)
	assert.Empty(t, owed)
}

func TestOwed_NoMustAcceptDocumentInEffectReadsNoAcceptance(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.EXPECT().GetAllLegalDocuments(mock.Anything, (*sql.Tx)(nil)).Return([]record.LegalDocument{
		{Id: 3, ShortName: "privacy", Kind: forInformation, AppliesToAllApps: true},
	}, nil)
	database.EXPECT().GetLegalDocumentVersionsByLegalDocumentId(mock.Anything, (*sql.Tx)(nil), int64(3)).
		Return([]record.LegalDocumentVersion{{Id: 31, LegalDocumentId: 3, VersionNumber: 1}}, nil)
	database.EXPECT().GetLegalDocumentClientsByClientId(mock.Anything, (*sql.Tx)(nil), int64(7)).
		Return([]record.LegalDocumentClient{}, nil)

	owed, err := NewReader(database).Owed(context.Background(), shop, 42)
	require.NoError(t, err)
	assert.Empty(t, owed, "a notice for information is never accepted")
}

func TestOwed_AFailedReadIsAnError(t *testing.T) {
	failure := errors.New("database down")

	database := datamocks.NewDatabase(t)
	database.EXPECT().GetLegalDocumentClientsByClientId(mock.Anything, (*sql.Tx)(nil), int64(7)).Return(nil, failure)
	_, err := NewReader(database).Owed(context.Background(), shop, 42)
	require.ErrorIs(t, err, failure)

	database = datamocks.NewDatabase(t)
	mustAcceptDocuments(database)
	database.EXPECT().GetLegalDocumentAcceptancesByUserId(mock.Anything, (*sql.Tx)(nil), int64(42)).Return(nil, failure)
	_, err = NewReader(database).Owed(context.Background(), shop, 42)
	require.ErrorIs(t, err, failure, "never read as nothing accepted, nor as everything")
}
