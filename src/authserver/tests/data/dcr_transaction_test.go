package datatests

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	mocks_audit "github.com/leodip/goiabada/authserver/internal/audit/mocks"
	"github.com/leodip/goiabada/authserver/internal/constants"
	"github.com/leodip/goiabada/authserver/internal/data"
	mocks_handlerhelpers "github.com/leodip/goiabada/authserver/internal/handlerhelpers/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/core/errs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// dcrWriteRecorder passes every write through to the real database, remembers the client
// registration created, and refuses the redirect URI write numbered failAt (from 1; 0 refuses none).
// The handler's unit tests prove the failure is handed to RunInTransaction; this is where a real
// engine shows what that buys (#428).
type dcrWriteRecorder struct {
	data.Database
	failAt  int
	uris    int
	created *models.Client
}

func (d *dcrWriteRecorder) CreateClient(ctx context.Context, tx *sql.Tx, client *models.Client) error {
	d.created = client
	return d.Database.CreateClient(ctx, tx, client)
}

func (d *dcrWriteRecorder) CreateRedirectURI(ctx context.Context, tx *sql.Tx, redirectURI *models.RedirectURI) error {
	d.uris++
	if d.uris == d.failAt {
		return errs.New("the second redirect URI write was refused")
	}
	return d.Database.CreateRedirectURI(ctx, tx, redirectURI)
}

func registerThroughTheHandler(t *testing.T, db *dcrWriteRecorder, httpHelper *mocks_handlerhelpers.HttpHelper,
	auditLogger *mocks_audit.AuditLogger) *httptest.ResponseRecorder {

	t.Helper()
	body, err := json.Marshal(oidc.DynamicClientRegistrationRequest{
		ClientName:              "A Rolled Back Client",
		RedirectURIs:            []string{"https://client.example.com/one", "https://client.example.com/two"},
		TokenEndpointAuthMethod: "client_secret_post",
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/connect/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeySettings,
		&models.Settings{Id: 1, DynamicClientRegistrationEnabled: true}))

	rr := httptest.NewRecorder()
	handlers.HandleDynamicClientRegistrationPost(httpHelper, db, auditLogger).ServeHTTP(rr, req)
	return rr
}

// A registration whose second redirect URI write fails leaves no client row, and so no secret, and
// no redirect URI row, the first one included: the client and its URIs are one transaction. Before
// #428 the client was committed on its own and a compensating delete, whose error was discarded,
// was all that withdrew it.
func TestDCR_AFailedSecondRedirectURIWriteLeavesNoClientAndNoRedirectURI(t *testing.T) {
	db := &dcrWriteRecorder{Database: database, failAt: 2}

	// Strict mocks with no expectations: neither the audit event nor the 201 may happen.
	rr := registerThroughTheHandler(t, db, mocks_handlerhelpers.NewHttpHelper(t), mocks_audit.NewAuditLogger(t))

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	require.NotNil(t, db.created, "the client write was reached")
	require.Equal(t, 2, db.uris, "the first redirect URI was written before the second failed")

	client, err := database.GetClientByClientIdentifier(context.Background(), nil, db.created.ClientIdentifier)
	require.NoError(t, err)
	assert.Nil(t, client, "the client row was rolled back with the redirect URIs")

	uris, err := database.GetRedirectURIsByClientId(context.Background(), nil, db.created.Id)
	require.NoError(t, err)
	assert.Empty(t, uris, "the first redirect URI was rolled back with the client")
}

// The control: the same recorder refusing nothing commits the client and both URIs, so the case
// above is the failure's doing and not the recorder's.
func TestDCR_ARegistrationWithNoFailureCommitsTheClientAndItsRedirectURIs(t *testing.T) {
	db := &dcrWriteRecorder{Database: database}

	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	httpHelper.On("EncodeJson", mock.Anything, mock.Anything, mock.Anything).Return().Once()
	auditLogger := mocks_audit.NewAuditLogger(t)
	auditLogger.On("Log", mock.Anything, audit.AuditDynamicClientRegistration, mock.Anything).Return().Once()

	rr := registerThroughTheHandler(t, db, httpHelper, auditLogger)

	assert.Equal(t, http.StatusCreated, rr.Code)
	require.NotNil(t, db.created)

	client, err := database.GetClientByClientIdentifier(context.Background(), nil, db.created.ClientIdentifier)
	require.NoError(t, err)
	require.NotNil(t, client)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.Id) })
	assert.NotEmpty(t, client.ClientSecretEncrypted)

	uris, err := database.GetRedirectURIsByClientId(context.Background(), nil, client.Id)
	require.NoError(t, err)
	got := make([]string, 0, len(uris))
	for _, uri := range uris {
		got = append(got, uri.URI)
	}
	assert.ElementsMatch(t, []string{"https://client.example.com/one", "https://client.example.com/two"}, got)
}
