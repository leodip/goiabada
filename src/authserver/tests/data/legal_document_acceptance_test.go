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
func acceptLegalDocumentVersion(t *testing.T, userId, versionId int64) *record.LegalDocumentAcceptance {
	t.Helper()
	acceptance := &record.LegalDocumentAcceptance{
		AcceptedAt:             time.Now().UTC().Truncate(time.Microsecond),
		UserId:                 userId,
		LegalDocumentVersionId: versionId,
	}
	require.NoError(t, database.CreateLegalDocumentAcceptance(context.Background(), nil, acceptance))
	return acceptance
}

// acceptedVersionIds answers the version ids the user has accepted, in the order they were read.
func acceptedVersionIds(t *testing.T, userId int64) []int64 {
	t.Helper()
	acceptances, err := database.GetLegalDocumentAcceptancesByUserId(context.Background(), nil, userId)
	require.NoError(t, err)
	ids := []int64{}
	for _, acceptance := range acceptances {
		assert.Equal(t, userId, acceptance.UserId)
		ids = append(ids, acceptance.LegalDocumentVersionId)
	}
	return ids
}

func TestLegalDocumentAcceptance_CreateAndReadBack(t *testing.T) {
	ctx := context.Background()
	user := createTestUser(t)
	doc := createLegalDocument(t, record.LegalDocumentKindMustAccept)
	first := publishVersion(t, doc.Id, 1, "Terms of use", "Be nice.")
	second := publishVersion(t, doc.Id, 2, "Terms of use", "Be nicer.")

	acceptedAt := time.Date(2026, 10, 31, 15, 7, 34, 123456000, time.UTC)
	acceptance := &record.LegalDocumentAcceptance{
		AcceptedAt:             acceptedAt,
		UserId:                 user.Id,
		LegalDocumentVersionId: first.Id,
	}
	require.NoError(t, database.CreateLegalDocumentAcceptance(ctx, nil, acceptance))
	require.NotZero(t, acceptance.Id, "the id is read back")
	later := acceptLegalDocumentVersion(t, user.Id, second.Id)

	acceptances, err := database.GetLegalDocumentAcceptancesByUserId(ctx, nil, user.Id)
	require.NoError(t, err)
	require.Len(t, acceptances, 2)
	assert.Equal(t, record.LegalDocumentAcceptance{
		Id:                     acceptance.Id,
		AcceptedAt:             acceptedAt,
		UserId:                 user.Id,
		LegalDocumentVersionId: first.Id,
	}, normalizedAcceptance(acceptances[0]), "the first acceptance reads back as written, to the microsecond")
	assert.Equal(t, later.Id, acceptances[1].Id, "in id order")
	assert.Equal(t, second.Id, acceptances[1].LegalDocumentVersionId, "a newer version is an acceptance of its own")
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
	version := publishVersion(t, doc.Id, 1, "Terms of use", "Be nice.")
	acceptLegalDocumentVersion(t, user.Id, version.Id)

	again := &record.LegalDocumentAcceptance{
		AcceptedAt:             time.Now().UTC(),
		UserId:                 user.Id,
		LegalDocumentVersionId: version.Id,
	}
	err := database.CreateLegalDocumentAcceptance(ctx, nil, again)
	require.Error(t, err)
	require.ErrorIs(t, err, data.ErrUniqueViolation, "a second acceptance of the version is the key's refusal")
	assert.Equal(t, []int64{version.Id}, acceptedVersionIds(t, user.Id), "and writes nothing")

	other := createTestUser(t)
	acceptLegalDocumentVersion(t, other.Id, version.Id)
	assert.Equal(t, []int64{version.Id}, acceptedVersionIds(t, other.Id), "another user accepts the same version")
}

func TestLegalDocumentAcceptance_AreTheUsersOwn(t *testing.T) {
	user := createTestUser(t)
	other := createTestUser(t)
	doc := createLegalDocument(t, record.LegalDocumentKindMustAccept)
	version := publishVersion(t, doc.Id, 1, "Terms of use", "Be nice.")
	acceptLegalDocumentVersion(t, other.Id, version.Id)

	assert.Empty(t, acceptedVersionIds(t, user.Id), "a user who accepted nothing has no acceptance")
	assert.Equal(t, []int64{version.Id}, acceptedVersionIds(t, other.Id))
}

func TestLegalDocumentAcceptance_NamesAUserAndAVersionThatExist(t *testing.T) {
	ctx := context.Background()
	user := createTestUser(t)
	doc := createLegalDocument(t, record.LegalDocumentKindMustAccept)
	version := publishVersion(t, doc.Id, 1, "Terms of use", "Be nice.")

	for name, acceptance := range map[string]*record.LegalDocumentAcceptance{
		"no user":            {AcceptedAt: time.Now().UTC(), LegalDocumentVersionId: version.Id},
		"no version":         {AcceptedAt: time.Now().UTC(), UserId: user.Id},
		"an unknown user":    {AcceptedAt: time.Now().UTC(), UserId: user.Id + 1_000_000, LegalDocumentVersionId: version.Id},
		"an unknown version": {AcceptedAt: time.Now().UTC(), UserId: user.Id, LegalDocumentVersionId: version.Id + 1_000_000},
	} {
		require.Errorf(t, database.CreateLegalDocumentAcceptance(ctx, nil, acceptance), "an acceptance naming %s is refused", name)
	}
	assert.Empty(t, acceptedVersionIds(t, user.Id), "and nothing is written")
}

func TestLegalDocumentAcceptance_ADocumentAcceptedCannotBeDeleted(t *testing.T) {
	ctx := context.Background()
	user := createTestUser(t)
	doc := createLegalDocument(t, record.LegalDocumentKindMustAccept)
	version := publishVersion(t, doc.Id, 1, "Terms of use", "Be nice.")
	acceptLegalDocumentVersion(t, user.Id, version.Id)

	require.Error(t, database.DeleteLegalDocument(ctx, nil, doc.Id), "a published document is retired, never deleted")
	assert.Equal(t, []int64{version.Id}, acceptedVersionIds(t, user.Id), "so what the user accepted stays")
}
