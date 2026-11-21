package datatests

import (
	"context"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A user's acceptances of legal document versions (#622, "What an acceptance records") on every
// engine: the user, the version and the time read back as written, a user accepts a version once,
// and the acceptances are the user's own.

// acceptLegalDocumentVersion records that the user accepted the version now.
func acceptLegalDocumentVersion(t *testing.T, userID, versionID int64) *record.LegalDocumentAcceptance {
	t.Helper()
	acceptance := &record.LegalDocumentAcceptance{
		AcceptedAt:             time.Now().UTC().Truncate(time.Microsecond),
		UserID:                 userID,
		LegalDocumentVersionID: versionID,
	}
	require.NoError(t, database.CreateLegalDocumentAcceptance(context.Background(), nil, acceptance))
	return acceptance
}

// acceptedVersionIDs answers the version ids the user has accepted, in the order they were read.
func acceptedVersionIDs(t *testing.T, userID int64) []int64 {
	t.Helper()
	acceptances, err := database.GetLegalDocumentAcceptancesByUserID(context.Background(), nil, userID)
	require.NoError(t, err)
	ids := []int64{}
	for _, acceptance := range acceptances {
		assert.Equal(t, userID, acceptance.UserID)
		ids = append(ids, acceptance.LegalDocumentVersionID)
	}
	return ids
}

func TestLegalDocumentAcceptance_CreateAndReadBack(t *testing.T) {
	ctx := context.Background()
	user := createTestUser(t)
	doc := createLegalDocument(t, record.LegalDocumentKindMustAccept)
	first := publishVersion(t, doc.ID, 1, "Terms of use", "Be nice.")
	second := publishVersion(t, doc.ID, 2, "Terms of use", "Be nicer.")

	acceptedAt := time.Date(2026, 10, 31, 15, 7, 34, 123456000, time.UTC)
	acceptance := &record.LegalDocumentAcceptance{
		AcceptedAt:             acceptedAt,
		UserID:                 user.ID,
		LegalDocumentVersionID: first.ID,
	}
	require.NoError(t, database.CreateLegalDocumentAcceptance(ctx, nil, acceptance))
	require.NotZero(t, acceptance.ID, "the id is read back")
	later := acceptLegalDocumentVersion(t, user.ID, second.ID)

	acceptances, err := database.GetLegalDocumentAcceptancesByUserID(ctx, nil, user.ID)
	require.NoError(t, err)
	require.Len(t, acceptances, 2)
	assert.Equal(t, record.LegalDocumentAcceptance{
		ID:                     acceptance.ID,
		AcceptedAt:             acceptedAt,
		UserID:                 user.ID,
		LegalDocumentVersionID: first.ID,
	}, normalizedAcceptance(acceptances[0]), "the first acceptance reads back as written, to the microsecond")
	assert.Equal(t, later.ID, acceptances[1].ID, "in id order")
	assert.Equal(t, second.ID, acceptances[1].LegalDocumentVersionID, "a newer version is an acceptance of its own")
}

// normalizedAcceptance puts the time in UTC, as each engine's driver answers it in its own zone.
func normalizedAcceptance(acceptance record.LegalDocumentAcceptance) record.LegalDocumentAcceptance {
	acceptance.AcceptedAt = acceptance.AcceptedAt.UTC()
	return acceptance
}

func TestLegalDocumentAcceptance_AUserAcceptsAVersionOnce(t *testing.T) {
	ctx := context.Background()
	user := createTestUser(t)
	doc := createLegalDocument(t, record.LegalDocumentKindMustAccept)
	version := publishVersion(t, doc.ID, 1, "Terms of use", "Be nice.")
	acceptLegalDocumentVersion(t, user.ID, version.ID)

	again := &record.LegalDocumentAcceptance{
		AcceptedAt:             time.Now().UTC(),
		UserID:                 user.ID,
		LegalDocumentVersionID: version.ID,
	}
	err := database.CreateLegalDocumentAcceptance(ctx, nil, again)
	require.Error(t, err)
	require.ErrorIs(t, err, data.ErrUniqueViolation, "a second acceptance of the version is the key's refusal")
	assert.Equal(t, []int64{version.ID}, acceptedVersionIDs(t, user.ID), "and writes nothing")

	other := createTestUser(t)
	acceptLegalDocumentVersion(t, other.ID, version.ID)
	assert.Equal(t, []int64{version.ID}, acceptedVersionIDs(t, other.ID), "another user accepts the same version")
}

func TestLegalDocumentAcceptance_AreTheUsersOwn(t *testing.T) {
	user := createTestUser(t)
	other := createTestUser(t)
	doc := createLegalDocument(t, record.LegalDocumentKindMustAccept)
	version := publishVersion(t, doc.ID, 1, "Terms of use", "Be nice.")
	acceptLegalDocumentVersion(t, other.ID, version.ID)

	assert.Empty(t, acceptedVersionIDs(t, user.ID), "a user who accepted nothing has no acceptance")
	assert.Equal(t, []int64{version.ID}, acceptedVersionIDs(t, other.ID))
}

func TestLegalDocumentAcceptance_NamesAUserAndAVersionThatExist(t *testing.T) {
	ctx := context.Background()
	user := createTestUser(t)
	doc := createLegalDocument(t, record.LegalDocumentKindMustAccept)
	version := publishVersion(t, doc.ID, 1, "Terms of use", "Be nice.")

	for name, acceptance := range map[string]*record.LegalDocumentAcceptance{
		"no user":            {AcceptedAt: time.Now().UTC(), LegalDocumentVersionID: version.ID},
		"no version":         {AcceptedAt: time.Now().UTC(), UserID: user.ID},
		"an unknown user":    {AcceptedAt: time.Now().UTC(), UserID: user.ID + 1_000_000, LegalDocumentVersionID: version.ID},
		"an unknown version": {AcceptedAt: time.Now().UTC(), UserID: user.ID, LegalDocumentVersionID: version.ID + 1_000_000},
	} {
		require.Errorf(t, database.CreateLegalDocumentAcceptance(ctx, nil, acceptance), "an acceptance naming %s is refused", name)
	}
	assert.Empty(t, acceptedVersionIDs(t, user.ID), "and nothing is written")
}

func TestLegalDocumentAcceptance_ADocumentAcceptedCannotBeDeleted(t *testing.T) {
	ctx := context.Background()
	user := createTestUser(t)
	doc := createLegalDocument(t, record.LegalDocumentKindMustAccept)
	version := publishVersion(t, doc.ID, 1, "Terms of use", "Be nice.")
	acceptLegalDocumentVersion(t, user.ID, version.ID)

	require.Error(t, database.DeleteLegalDocument(ctx, nil, doc.ID), "a published document is retired, never deleted")
	assert.Equal(t, []int64{version.ID}, acceptedVersionIDs(t, user.ID), "so what the user accepted stays")
}
