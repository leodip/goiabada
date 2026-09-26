package apihandlers

import (
	"database/sql"
	"net/http"
	"testing"

	mocks_audit "github.com/leodip/goiabada/authserver/internal/audit/mocks"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// The client permission save shares every case of grant_list_saves_test.go with the user and group
// saves. What is its own is the rule that a client's permissions are configurable only with the
// client credentials flow enabled, since they are what a client_credentials token is granted from.
// It is decided before the transaction opens, so the refusal reads nothing more and writes nothing
// (#428).
func TestHandleAPIClientPermissionsPut_ClientCredentialsOffIsRefusedBeforeTheTransaction(t *testing.T) {
	save := grantSaves[2]
	if save.name != "client permissions" {
		t.Fatalf("grantSaves[2] is %q, not the client permission save", save.name)
	}

	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)
	database.On("GetClientById", mock.Anything, (*sql.Tx)(nil), grantOwnerId).
		Return(&models.Client{Id: grantOwnerId, ClientIdentifier: "a-web-app", ClientCredentialsEnabled: false}, nil).Once()

	rr := save.serve(database, auditLogger, save.body(t, []int64{6}, []int64{}))

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	code, description := decodeErrorEnvelope(t, rr)
	assert.Equal(t, "VALIDATION_ERROR", code)
	assert.Contains(t, description, "only be configured when client credentials flow is enabled")
	database.AssertExpectations(t)
	assertNotAttemptedOnClientDatabase(t, database, "GetPermissionById", "RunInTransaction")
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}
