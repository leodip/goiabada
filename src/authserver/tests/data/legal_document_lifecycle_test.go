package datatests

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/handlers/apihandlers"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A legal document's lifecycle writes on real engines, through the admin API's handlers (#622
// decisions 1, 2 and 5). Each write takes the document's row (AcquireLegalDocumentRow) and decides
// on the document read again under it, so two writes of one document are serialized: the second
// waits for the first and decides on what it committed. Each test parks one write inside its
// transaction, after it has taken the row and read what it decides on, sends a second write at
// the same document, requires the engine to show that second write waiting behind the first, then
// releases the first and checks that the outcome is the one the serial order gives. Without the
// row, the second write finishes while the first is parked, and the first then writes back what
// it read before: a publish clears a draft saved meanwhile, a save renames a document published
// meanwhile, a save undoes a retirement.

// The point inside a parked write's transaction where it waits.
const (
	pauseAfterVersionsRead   = "after its versions are read"
	pauseBeforeShortNameRead = "before the short name is checked"
	pauseBeforeDocumentWrite = "before the document is written"
)

// pausedLegalDocumentWrite parks a lifecycle write at one point inside its transaction. Reads with
// no transaction, as the answer's read-back after the commit, go straight through.
type pausedLegalDocumentWrite struct {
	data.Database
	b     *barrier
	pause string
}

func (d pausedLegalDocumentWrite) GetLegalDocumentVersionsByLegalDocumentId(ctx context.Context, tx *sql.Tx,
	legalDocumentId int64) ([]record.LegalDocumentVersion, error) {
	versions, err := d.Database.GetLegalDocumentVersionsByLegalDocumentId(ctx, tx, legalDocumentId)
	if tx != nil && d.pause == pauseAfterVersionsRead {
		d.b.arriveBefore(tx)
	}
	return versions, err
}

func (d pausedLegalDocumentWrite) GetLegalDocumentByShortName(ctx context.Context, tx *sql.Tx,
	shortName string) (*record.LegalDocument, error) {
	if tx != nil && d.pause == pauseBeforeShortNameRead {
		d.b.arriveBefore(tx)
	}
	return d.Database.GetLegalDocumentByShortName(ctx, tx, shortName)
}

func (d pausedLegalDocumentWrite) UpdateLegalDocument(ctx context.Context, tx *sql.Tx, doc *record.LegalDocument) error {
	if tx != nil && d.pause == pauseBeforeDocumentWrite {
		d.b.arriveBefore(tx)
	}
	return d.Database.UpdateLegalDocument(ctx, tx, doc)
}

// legalWriteOutcome is what a lifecycle write answered.
type legalWriteOutcome struct {
	status    int
	errorCode string
}

// legalWrite sends one lifecycle request at document id through a handler, with the draft as its
// body when there is one.
func legalWrite(handler http.HandlerFunc, method string, id int64, body *api.SaveLegalDocumentDraftRequest) legalWriteOutcome {
	reader := bytes.NewReader(nil)
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return legalWriteOutcome{errorCode: "the test's request did not encode: " + err.Error()}
		}
		reader = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, "/api/v1/admin/legal-documents/"+strconv.FormatInt(id, 10), reader)
	req.SetPathValue("id", strconv.FormatInt(id, 10))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	var answer struct {
		ErrorCode string `json:"error_code"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &answer)
	return legalWriteOutcome{status: rr.Code, errorCode: answer.ErrorCode}
}

// legalWrites are the lifecycle writes the tests send, each through the db it is handed.
func saveDraft(db data.Database, id int64, req *api.SaveLegalDocumentDraftRequest) legalWriteOutcome {
	return legalWrite(apihandlers.HandleLegalDocumentDraftPut(db, &countingAuditLogger{}), http.MethodPut, id, req)
}

func publish(db data.Database, id int64) legalWriteOutcome {
	return legalWrite(apihandlers.HandleLegalDocumentPublishPost(db, &countingAuditLogger{}), http.MethodPost, id, nil)
}

func retire(db data.Database, id int64) legalWriteOutcome {
	return legalWrite(apihandlers.HandleLegalDocumentRetirePost(db, &countingAuditLogger{}), http.MethodPost, id, nil)
}

// serialize parks first at pause, sends second at the same document, requires the engine to show
// second waiting behind first, then releases first, and answers both outcomes.
func serialize(t *testing.T, pause string,
	first func(db data.Database) legalWriteOutcome, second func() legalWriteOutcome) (legalWriteOutcome, legalWriteOutcome) {
	t.Helper()

	b := newBarrier(t, "the first write")
	firstDone := make(chan legalWriteOutcome, 1)
	go func() { firstDone <- first(pausedLegalDocumentWrite{Database: database, b: b, pause: pause}) }()
	tx := b.awaitParked(t)

	party := goBlocked(t, "the second write", tx, func(reached func()) legalWriteOutcome {
		reached()
		return second()
	})
	party.requireBlocked(t)
	party.requireStillWaiting(t)

	b.releaseParked()
	return awaitWorker(t, "the first write", firstDone), party.await(t)
}

func TestLegalDocumentLifecycle_PublishClearsOnlyTheDraftItFroze(t *testing.T) {
	ctx := context.Background()
	doc := createLegalDocument(t, record.LegalDocumentKindForInformation)
	original := doc.DraftMarkdown.String

	published, saved := serialize(t, pauseAfterVersionsRead,
		func(db data.Database) legalWriteOutcome { return publish(db, doc.Id) },
		func() legalWriteOutcome {
			return saveDraft(database, doc.Id, &api.SaveLegalDocumentDraftRequest{Title: "Later draft", Markdown: "Saved during the publish."})
		})

	require.Equal(t, http.StatusOK, published.status)
	require.Equal(t, http.StatusOK, saved.status)
	version, err := database.GetLegalDocumentVersion(ctx, nil, doc.Id, 1)
	require.NoError(t, err)
	require.NotNil(t, version)
	assert.Equal(t, original, version.Markdown, "the publish froze the draft it read")
	stored, err := database.GetLegalDocumentById(ctx, nil, doc.Id)
	require.NoError(t, err)
	assert.True(t, stored.HasDraft(), "the draft saved after the publish read the document is kept")
	assert.Equal(t, "Saved during the publish.", stored.DraftMarkdown.String)
}

func TestLegalDocumentLifecycle_ASaveWaitingOnTheFirstPublishCannotRenameIt(t *testing.T) {
	ctx := context.Background()
	doc := createLegalDocument(t, record.LegalDocumentKindForInformation)
	original := doc.ShortName

	published, saved := serialize(t, pauseAfterVersionsRead,
		func(db data.Database) legalWriteOutcome { return publish(db, doc.Id) },
		func() legalWriteOutcome {
			return saveDraft(database, doc.Id, &api.SaveLegalDocumentDraftRequest{
				ShortName: original + "-renamed", Title: "Next draft", Markdown: "Next draft."})
		})

	require.Equal(t, http.StatusOK, published.status)
	assert.Equal(t, http.StatusBadRequest, saved.status)
	assert.Equal(t, "handler.legal_document.short_name_fixed", saved.errorCode)
	stored, err := database.GetLegalDocumentById(ctx, nil, doc.Id)
	require.NoError(t, err)
	assert.Equal(t, original, stored.ShortName, "the published address is kept")
	assert.False(t, stored.HasDraft(), "the refused save wrote nothing")
}

func TestLegalDocumentLifecycle_ARenameCommittedFirstIsTheNamePublished(t *testing.T) {
	ctx := context.Background()
	doc := createLegalDocument(t, record.LegalDocumentKindForInformation)
	renamed := doc.ShortName + "-renamed"

	saved, published := serialize(t, pauseBeforeShortNameRead,
		func(db data.Database) legalWriteOutcome {
			return saveDraft(db, doc.Id, &api.SaveLegalDocumentDraftRequest{
				ShortName: renamed, Title: "Next draft", Markdown: "Next draft."})
		},
		func() legalWriteOutcome { return publish(database, doc.Id) })

	require.Equal(t, http.StatusOK, saved.status)
	require.Equal(t, http.StatusOK, published.status)
	stored, err := database.GetLegalDocumentById(ctx, nil, doc.Id)
	require.NoError(t, err)
	assert.Equal(t, renamed, stored.ShortName)
	version, err := database.GetLegalDocumentVersion(ctx, nil, doc.Id, 1)
	require.NoError(t, err)
	require.NotNil(t, version)
	assert.Equal(t, "Next draft.", version.Markdown,
		"the publish waited for the save, so the version it froze carries the name it was published under")
}

func TestLegalDocumentLifecycle_ASaveCannotUndoARetirement(t *testing.T) {
	ctx := context.Background()
	doc := createLegalDocument(t, record.LegalDocumentKindForInformation)
	publishVersion(t, doc.Id, 1, "Notice", "Text")

	saved, retired := serialize(t, pauseBeforeDocumentWrite,
		func(db data.Database) legalWriteOutcome {
			return saveDraft(db, doc.Id, &api.SaveLegalDocumentDraftRequest{Title: "Next draft", Markdown: "Next draft."})
		},
		func() legalWriteOutcome { return retire(database, doc.Id) })

	require.Equal(t, http.StatusOK, saved.status)
	require.Equal(t, http.StatusOK, retired.status)
	stored, err := database.GetLegalDocumentById(ctx, nil, doc.Id)
	require.NoError(t, err)
	assert.True(t, stored.IsRetired(), "the retirement that waited for the save is kept")
	assert.Equal(t, "Next draft.", stored.DraftMarkdown.String)
}

func TestLegalDocumentLifecycle_ASaveWaitingOnARetirementIsRefused(t *testing.T) {
	ctx := context.Background()
	doc := createLegalDocument(t, record.LegalDocumentKindForInformation)
	publishVersion(t, doc.Id, 1, "Notice", "Text")
	draft := doc.DraftMarkdown.String

	retired, saved := serialize(t, pauseBeforeDocumentWrite,
		func(db data.Database) legalWriteOutcome { return retire(db, doc.Id) },
		func() legalWriteOutcome {
			return saveDraft(database, doc.Id, &api.SaveLegalDocumentDraftRequest{Title: "Next draft", Markdown: "Next draft."})
		})

	require.Equal(t, http.StatusOK, retired.status)
	assert.Equal(t, http.StatusBadRequest, saved.status)
	assert.Equal(t, "handler.legal_document.retired", saved.errorCode)
	stored, err := database.GetLegalDocumentById(ctx, nil, doc.Id)
	require.NoError(t, err)
	assert.True(t, stored.IsRetired())
	assert.Equal(t, draft, stored.DraftMarkdown.String, "the refused save wrote nothing")
}
