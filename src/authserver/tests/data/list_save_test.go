package datatests

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/authserver/internal/constants"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/handlers/apihandlers"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/testutil/fake"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The list-save pattern of #428 on real engines, through the client redirect-URI save: one
// transaction per save, no row lock, the stored rows read on the transaction and the save refused
// when they differ from the list the caller loaded. The handler's unit tests prove each failure is
// handed to RunInTransaction and each plan is the one replaceSet returns; what only an engine
// shows is what that buys: a failure rolls the whole save back, two overlapping saves both finish
// and merge per item, and a save from a list that has since changed is refused with nothing
// written.

// countingAuditLogger stands in for the audit logger, counting the events a save emits.
type countingAuditLogger struct {
	mu     sync.Mutex
	events int
}

func (a *countingAuditLogger) Log(context.Context, string, map[string]interface{}) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events++
}

func (a *countingAuditLogger) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.events
}

// redirectURIInsertRefused passes every write through and refuses every redirect URI insert, so a
// save that deletes before it inserts has committed nothing only if the delete was rolled back.
type redirectURIInsertRefused struct {
	data.Database
}

func (d redirectURIInsertRefused) CreateRedirectURI(context.Context, *sql.Tx, *models.RedirectURI) error {
	return errs.New("the redirect URI insert was refused")
}

// pausedAfterRedirectURIRead parks the save after it has read the stored rows on its transaction,
// and so after it has decided that they are the list its caller loaded, and before it writes.
// The reload after the commit passes a nil transaction and goes straight through.
type pausedAfterRedirectURIRead struct {
	data.Database
	b *barrier
}

func (d pausedAfterRedirectURIRead) ClientLoadRedirectURIs(ctx context.Context, tx *sql.Tx, client *models.Client) error {
	err := d.Database.ClientLoadRedirectURIs(ctx, tx, client)
	if tx != nil {
		d.b.arriveBefore(tx)
	}
	return err
}

// createRedirectClient creates a client whose authorization code flow is enabled, which the save
// requires, holding the given redirect URIs.
func createRedirectClient(t *testing.T, uris ...string) *models.Client {
	t.Helper()
	client := &models.Client{
		ClientIdentifier:         "list_save_" + fake.LetterN(8),
		Description:              "List save client",
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
	}
	require.NoError(t, database.CreateClient(context.Background(), nil, client))
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.Id) })
	for _, uri := range uris {
		require.NoError(t, database.CreateRedirectURI(context.Background(), nil,
			&models.RedirectURI{ClientId: client.Id, URI: uri}))
	}
	return client
}

// saveRedirectURIs serves one save through the real handler against db, with no router.
func saveRedirectURIs(t *testing.T, db data.Database, auditLogger apihandlers.AuditLogger, clientId int64,
	wanted, expected []string) *httptest.ResponseRecorder {

	t.Helper()
	body, err := json.Marshal(api.UpdateClientRedirectURIsRequest{RedirectURIs: wanted, ExpectedRedirectURIs: expected})
	require.NoError(t, err)

	id := strconv.FormatInt(clientId, 10)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/clients/"+id+"/redirect-uris", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	ctx = context.WithValue(ctx, constants.ContextKeySettings, &models.Settings{Id: 1})

	rr := httptest.NewRecorder()
	apihandlers.HandleAPIClientRedirectURIsPut(db, auditLogger).ServeHTTP(rr, req.WithContext(ctx))
	return rr
}

// storedRedirectURIs reads the client's rows back, one entry per row, so a duplicate shows twice.
func storedRedirectURIs(t *testing.T, clientId int64) []string {
	t.Helper()
	rows, err := database.GetRedirectURIsByClientId(context.Background(), nil, clientId)
	require.NoError(t, err)
	uris := make([]string, 0, len(rows))
	for _, row := range rows {
		uris = append(uris, row.URI)
	}
	return uris
}

// A save that removes one URI and adds another, whose insert fails after its delete, leaves the
// stored list exactly as it was: the delete is rolled back with the insert. Written
// autocommitted, as the save was before #428, the removal stayed committed under the 500 (#264).
func TestRedirectURISave_AnInsertFailingAfterTheDeleteLeavesTheStoredListAsItWas(t *testing.T) {
	client := createRedirectClient(t, "https://a.example.com/cb", "https://b.example.com/cb")
	auditLogger := &countingAuditLogger{}

	rr := saveRedirectURIs(t, redirectURIInsertRefused{Database: database}, auditLogger, client.Id,
		[]string{"https://a.example.com/cb", "https://c.example.com/cb"},
		[]string{"https://a.example.com/cb", "https://b.example.com/cb"})

	assert.Equal(t, http.StatusInternalServerError, rr.Code, rr.Body.String())
	assert.ElementsMatch(t, []string{"https://a.example.com/cb", "https://b.example.com/cb"},
		storedRedirectURIs(t, client.Id), "the delete of b was rolled back with the refused insert of c")
	assert.Zero(t, auditLogger.count(), "a save that committed nothing audits nothing")
}

// Two saves of one client's redirect URIs, both loaded from the same list and overlapping on a real
// engine: the first is parked after its read while the second runs to its commit, then released.
// Without a row lock neither waits for the other, both answer 200, and the stored list is the
// per-item merge, holding the one URI both added twice. The next save, loaded from that list,
// collapses the duplicate, since replaceSet deletes every extra row of a wanted key. A save still
// carrying the list as it was before either is refused 409 CONCURRENT_UPDATE and writes nothing
// (#428 decisions 12 and 15).
//
// MySQL, PostgreSQL and SQL Server only: SQLite has one connection, so the second save would wait
// for the parked first one forever rather than overlap it.
func TestRedirectURISave_TwoOverlappingSavesMergePerItemAndAnOutdatedListIsRefused(t *testing.T) {
	skipIfSQLite(t)

	const (
		a = "https://a.example.com/cb"
		x = "https://x.example.com/cb"
		y = "https://y.example.com/cb"
		z = "https://z.example.com/cb"
	)
	client := createRedirectClient(t, a)
	loaded := []string{a}
	auditLogger := &countingAuditLogger{}

	b := newBarrier(t, "the first redirect URI save")
	first := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		first <- saveRedirectURIs(t, pausedAfterRedirectURIRead{Database: database, b: b}, auditLogger,
			client.Id, []string{a, x, z}, loaded)
	}()
	b.awaitParked(t)

	second := saveRedirectURIs(t, database, auditLogger, client.Id, []string{a, y, z}, loaded)
	require.Equal(t, http.StatusOK, second.Code, "the second save waited on nothing: %s", second.Body.String())

	b.releaseParked()
	firstRR := awaitWorker(t, "the first redirect URI save", first)
	require.Equal(t, http.StatusOK, firstRR.Code, firstRR.Body.String())

	merged := storedRedirectURIs(t, client.Id)
	assert.ElementsMatch(t, []string{a, x, y, z, z}, merged,
		"each save's own additions survive, and the URI both added is stored once per save")
	assert.Equal(t, 2, auditLogger.count(), "each committed save audits once")

	collapse := saveRedirectURIs(t, database, auditLogger, client.Id, []string{a, x, y, z}, merged)
	require.Equal(t, http.StatusOK, collapse.Code, collapse.Body.String())
	assert.ElementsMatch(t, []string{a, x, y, z}, storedRedirectURIs(t, client.Id),
		"the following save removed the duplicate row and kept one copy")

	outdated := saveRedirectURIs(t, database, auditLogger, client.Id, []string{a}, loaded)
	assert.Equal(t, http.StatusConflict, outdated.Code, outdated.Body.String())
	assert.Contains(t, outdated.Body.String(), "CONCURRENT_UPDATE")
	assert.ElementsMatch(t, []string{a, x, y, z}, storedRedirectURIs(t, client.Id),
		"the save from the outdated list removed nothing")
	assert.Equal(t, 3, auditLogger.count(), "the refused save audited nothing")
}
