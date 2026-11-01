package datatests

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Legal documents and their versions (#622 decisions 1, 2 and 5) on every engine: what is stored
// reads back unchanged, at the API's bounds; short names are unique; a version is never rewritten;
// and only a never-published document can be deleted.

func newLegalDocument(kind string) *record.LegalDocument {
	return &record.LegalDocument{
		ShortName:     "terms-" + strings.ToLower(fake.LetterN(10)),
		Kind:          kind,
		DraftTitle:    sql.NullString{String: "Terms of use", Valid: true},
		DraftMarkdown: sql.NullString{String: "# Terms\n\nBe nice.", Valid: true},
	}
}

func createLegalDocument(t *testing.T, kind string) *record.LegalDocument {
	t.Helper()
	doc := newLegalDocument(kind)
	require.NoError(t, database.CreateLegalDocument(context.Background(), nil, doc))
	return doc
}

// publishVersion stores version number n of the document, as Publish does.
func publishVersion(t *testing.T, documentId int64, n int, title, markdown string) *record.LegalDocumentVersion {
	t.Helper()
	version := &record.LegalDocumentVersion{
		PublishedAt:     time.Now().UTC().Truncate(time.Microsecond),
		LegalDocumentId: documentId,
		VersionNumber:   n,
		Title:           title,
		Markdown:        markdown,
	}
	require.NoError(t, database.CreateLegalDocumentVersion(context.Background(), nil, version))
	return version
}

func TestLegalDocument_CreateAndRead(t *testing.T) {
	ctx := context.Background()
	doc := newLegalDocument(record.LegalDocumentKindMustAccept)
	require.NoError(t, database.CreateLegalDocument(ctx, nil, doc))

	require.NotZero(t, doc.Id)
	require.True(t, doc.CreatedAt.Valid, "created_at is stamped")
	require.True(t, doc.UpdatedAt.Valid, "updated_at is stamped")

	got, err := database.GetLegalDocumentById(ctx, nil, doc.Id)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, doc.ShortName, got.ShortName)
	assert.Equal(t, "must_accept", got.Kind)
	assert.Equal(t, sql.NullString{String: "Terms of use", Valid: true}, got.DraftTitle)
	assert.Equal(t, sql.NullString{String: "# Terms\n\nBe nice.", Valid: true}, got.DraftMarkdown)
	assert.False(t, got.RetiredAt.Valid, "a new document is not retired")
	assert.True(t, got.HasDraft())

	byName, err := database.GetLegalDocumentByShortName(ctx, nil, doc.ShortName)
	require.NoError(t, err)
	require.NotNil(t, byName)
	assert.Equal(t, doc.Id, byName.Id)

	missing, err := database.GetLegalDocumentById(ctx, nil, doc.Id+1_000_000)
	require.NoError(t, err)
	assert.Nil(t, missing, "an id naming no document answers nil")

	other, err := database.GetLegalDocumentByShortName(ctx, nil, doc.ShortName+"-x")
	require.NoError(t, err)
	assert.Nil(t, other, "a short name naming no document answers nil")
	upper, err := database.GetLegalDocumentByShortName(ctx, nil, strings.ToUpper(doc.ShortName))
	require.NoError(t, err)
	assert.Nil(t, upper, "the lookup is exact, never folded")
	padded, err := database.GetLegalDocumentByShortName(ctx, nil, doc.ShortName+" ")
	require.NoError(t, err)
	assert.Nil(t, padded, "a trailing space is another name, though SQL Server pads for =")
}

func TestLegalDocument_ShortNameIsUnique(t *testing.T) {
	ctx := context.Background()
	first := createLegalDocument(t, record.LegalDocumentKindMustAccept)

	second := newLegalDocument(record.LegalDocumentKindForInformation)
	second.ShortName = first.ShortName
	err := database.CreateLegalDocument(ctx, nil, second)
	require.ErrorIs(t, err, data.ErrUniqueViolation, "a short name another document holds is refused")

	third := createLegalDocument(t, record.LegalDocumentKindForInformation)
	third.ShortName = first.ShortName
	err = database.UpdateLegalDocument(ctx, nil, third)
	require.ErrorIs(t, err, data.ErrUniqueViolation, "and so is renaming a document onto it")
}

func TestLegalDocument_UpdateWritesEverythingButTheKind(t *testing.T) {
	ctx := context.Background()
	doc := createLegalDocument(t, record.LegalDocumentKindForInformation)
	stored, err := database.GetLegalDocumentById(ctx, nil, doc.Id)
	require.NoError(t, err)
	createdAt := stored.CreatedAt

	time.Sleep(timestampTick)
	retiredAt := time.Now().UTC().Truncate(time.Microsecond)
	doc.ShortName += "-v2"
	doc.Kind = record.LegalDocumentKindMustAccept
	doc.DraftTitle = sql.NullString{}
	doc.DraftMarkdown = sql.NullString{}
	doc.RetiredAt = sql.NullTime{Time: retiredAt, Valid: true}
	require.NoError(t, database.UpdateLegalDocument(ctx, nil, doc))

	got, err := database.GetLegalDocumentById(ctx, nil, doc.Id)
	require.NoError(t, err)
	assert.Equal(t, doc.ShortName, got.ShortName)
	assert.Equal(t, "for_information", got.Kind, "a document's kind is fixed at creation")
	assert.False(t, got.DraftTitle.Valid, "the draft is cleared")
	assert.False(t, got.DraftMarkdown.Valid, "the draft is cleared")
	assert.False(t, got.HasDraft())
	require.True(t, got.RetiredAt.Valid)
	assert.True(t, retiredAt.Equal(got.RetiredAt.Time), "retired_at reads back to the microsecond: %v, %v", retiredAt, got.RetiredAt.Time)
	assert.True(t, got.IsRetired())
	assert.True(t, createdAt.Time.Equal(got.CreatedAt.Time), "created_at is never rewritten")
	assert.True(t, got.UpdatedAt.Time.After(createdAt.Time), "updated_at moves")
}

func TestLegalDocument_TextAtTheAPIBoundsReadsBack(t *testing.T) {
	ctx := context.Background()
	// 200 UTF-16 code units of title, half of them in astral characters, and 100,000 of Markdown
	// in two- and three-byte UTF-8: the bounds the API holds a document to, in the unit it counts.
	title := strings.Repeat("😀", 50) + strings.Repeat("é", 100)
	require.Len(t, []rune(title), 150)
	markdown := strings.Repeat("Données personnelles — ", 4000) + strings.Repeat("ü", 8000)

	doc := newLegalDocument(record.LegalDocumentKindMustAccept)
	doc.DraftTitle = sql.NullString{String: title, Valid: true}
	doc.DraftMarkdown = sql.NullString{String: markdown, Valid: true}
	require.NoError(t, database.CreateLegalDocument(ctx, nil, doc))
	got, err := database.GetLegalDocumentById(ctx, nil, doc.Id)
	require.NoError(t, err)
	assert.Equal(t, title, got.DraftTitle.String)
	assert.Equal(t, markdown, got.DraftMarkdown.String)

	publishVersion(t, doc.Id, 1, title, markdown)
	version, err := database.GetLegalDocumentVersion(ctx, nil, doc.Id, 1)
	require.NoError(t, err)
	require.NotNil(t, version)
	assert.Equal(t, title, version.Title)
	assert.Equal(t, markdown, version.Markdown)
}

func TestLegalDocument_VersionsAreNumberedOncePerDocument(t *testing.T) {
	ctx := context.Background()
	doc := createLegalDocument(t, record.LegalDocumentKindMustAccept)
	other := createLegalDocument(t, record.LegalDocumentKindMustAccept)

	none, err := database.GetLegalDocumentVersionsByLegalDocumentId(ctx, nil, doc.Id)
	require.NoError(t, err)
	assert.Empty(t, none, "a never-published document has no version")

	first := publishVersion(t, doc.Id, 1, "Terms", "First text.")
	require.NotZero(t, first.Id)
	second := publishVersion(t, doc.Id, 2, "Terms of use", "Second text.")
	publishVersion(t, other.Id, 1, "Other", "Another document's first version.")

	// The same number twice in one document is the engine's to refuse, so two publishes racing
	// for one number cannot both win.
	err = database.CreateLegalDocumentVersion(ctx, nil, &record.LegalDocumentVersion{
		PublishedAt: time.Now().UTC(), LegalDocumentId: doc.Id, VersionNumber: 2, Title: "Racing", Markdown: "Racing.",
	})
	require.ErrorIs(t, err, data.ErrUniqueViolation)

	versions, err := database.GetLegalDocumentVersionsByLegalDocumentId(ctx, nil, doc.Id)
	require.NoError(t, err)
	require.Len(t, versions, 2, "the document's two versions and not the other document's")
	assert.Equal(t, *first, versions[0], "the first version reads back exactly as it was published")
	assert.Equal(t, *second, versions[1])

	got, err := database.GetLegalDocumentVersion(ctx, nil, doc.Id, 1)
	require.NoError(t, err)
	assert.Equal(t, first, got)
	missing, err := database.GetLegalDocumentVersion(ctx, nil, doc.Id, 3)
	require.NoError(t, err)
	assert.Nil(t, missing, "a number never published answers nil")
}

func TestLegalDocument_PublishingANewVersionLeavesTheEarlierOnesAsTheyWere(t *testing.T) {
	ctx := context.Background()
	doc := createLegalDocument(t, record.LegalDocumentKindMustAccept)
	first := publishVersion(t, doc.Id, 1, "Terms", "What users accepted.")

	// The draft that follows is edited and published as version 2; nothing touches version 1.
	doc.DraftTitle = sql.NullString{String: "Terms, revised", Valid: true}
	doc.DraftMarkdown = sql.NullString{String: "What users will accept next.", Valid: true}
	require.NoError(t, database.UpdateLegalDocument(ctx, nil, doc))
	publishVersion(t, doc.Id, 2, "Terms, revised", "What users will accept next.")

	again, err := database.GetLegalDocumentVersion(ctx, nil, doc.Id, 1)
	require.NoError(t, err)
	assert.Equal(t, first, again)
}

func TestLegalDocument_OnlyANeverPublishedDocumentIsDeleted(t *testing.T) {
	ctx := context.Background()
	draftOnly := createLegalDocument(t, record.LegalDocumentKindForInformation)
	require.NoError(t, database.DeleteLegalDocument(ctx, nil, draftOnly.Id))
	gone, err := database.GetLegalDocumentById(ctx, nil, draftOnly.Id)
	require.NoError(t, err)
	assert.Nil(t, gone)

	published := createLegalDocument(t, record.LegalDocumentKindMustAccept)
	version := publishVersion(t, published.Id, 1, "Terms", "Accepted text.")
	require.Error(t, database.DeleteLegalDocument(ctx, nil, published.Id),
		"the engine refuses to delete a document with a published version")
	still, err := database.GetLegalDocumentById(ctx, nil, published.Id)
	require.NoError(t, err)
	assert.NotNil(t, still, "the document stays")
	kept, err := database.GetLegalDocumentVersion(ctx, nil, published.Id, 1)
	require.NoError(t, err)
	assert.Equal(t, version, kept, "and so does its version")

	require.Error(t, database.CreateLegalDocumentVersion(ctx, nil, &record.LegalDocumentVersion{
		PublishedAt: time.Now().UTC(), LegalDocumentId: draftOnly.Id, VersionNumber: 1, Title: "x", Markdown: "x",
	}), "a version naming no document is refused")
}

func TestLegalDocument_AllDocumentsInIdOrder(t *testing.T) {
	ctx := context.Background()
	a := createLegalDocument(t, record.LegalDocumentKindMustAccept)
	b := createLegalDocument(t, record.LegalDocumentKindForInformation)
	b.RetiredAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}
	require.NoError(t, database.UpdateLegalDocument(ctx, nil, b))

	all, err := database.GetAllLegalDocuments(ctx, nil)
	require.NoError(t, err)
	var ids []int64
	positions := map[int64]int{}
	for i, doc := range all {
		ids = append(ids, doc.Id)
		positions[doc.Id] = i
	}
	require.Contains(t, ids, a.Id)
	require.Contains(t, ids, b.Id, "a retired document is listed too")
	assert.Less(t, positions[a.Id], positions[b.Id])
	for i := 1; i < len(ids); i++ {
		assert.Less(t, ids[i-1], ids[i], "in id order")
	}
	assert.Equal(t, b.ShortName, all[positions[b.Id]].ShortName)
	assert.True(t, all[positions[b.Id]].IsRetired())
}
