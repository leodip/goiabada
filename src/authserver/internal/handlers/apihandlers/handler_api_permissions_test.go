package apihandlers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	mocks_audit "github.com/leodip/goiabada/authserver/internal/audit/mocks"
	"github.com/leodip/goiabada/authserver/internal/data"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/validators"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestHandleAPIResourcePermissionsPut_BuiltInPermissionMissingFromDB verifies that when
// a built-in permission is missing from the system resource's database rows, the handler
// returns HTTP 500 with an appropriate integrity error message.
// This is a unit test because simulating a missing built-in permission in integration tests
// would cascade FK deletions that can't be rolled back.
func TestHandleAPIResourcePermissionsPut_BuiltInPermissionMissingFromDB(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)
	identifierValidator := validators.NewIdentifierValidator()

	handler := HandleAPIResourcePermissionsPut(database, identifierValidator, auditLogger)

	// System-level resource (authserver)
	resource := &models.Resource{
		Id:                 1,
		ResourceIdentifier: constants.AuthServerResourceIdentifier,
	}

	// Return existing permissions that are MISSING the "manage" built-in permission
	existingPerms := []models.Permission{
		{Id: 10, PermissionIdentifier: constants.UserinfoPermissionIdentifier, ResourceId: 1, Description: "Userinfo"},
		{Id: 11, PermissionIdentifier: constants.ManageAccountPermissionIdentifier, ResourceId: 1, Description: "Manage account"},
		// "manage" is intentionally missing
		{Id: 13, PermissionIdentifier: constants.AdminReadPermissionIdentifier, ResourceId: 1, Description: "Admin read"},
		{Id: 14, PermissionIdentifier: constants.ManageUsersPermissionIdentifier, ResourceId: 1, Description: "Manage users"},
		{Id: 15, PermissionIdentifier: constants.ManageClientsPermissionIdentifier, ResourceId: 1, Description: "Manage clients"},
		{Id: 16, PermissionIdentifier: constants.ManageSettingsPermissionIdentifier, ResourceId: 1, Description: "Manage settings"},
	}

	database.On("GetResourceById", mock.Anything, (*sql.Tx)(nil), int64(1)).Return(resource, nil)
	database.On("GetPermissionsByResourceId", mock.Anything, (*sql.Tx)(nil), int64(1)).Return(existingPerms, nil)

	// Build a valid request body that includes all the permissions we have
	var permUpserts []api.ResourcePermissionUpsert
	for _, p := range existingPerms {
		permUpserts = append(permUpserts, api.ResourcePermissionUpsert{
			Id:                   p.Id,
			PermissionIdentifier: p.PermissionIdentifier,
			Description:          p.Description,
		})
	}
	reqBody := api.UpdateResourcePermissionsRequest{Permissions: permUpserts, ExpectedPermissions: permUpserts}
	body, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("PUT", "/api/v1/admin/resources/1/permissions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = setChiURLParam(req, "resourceId", "1")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)

	// The detail is in the log, not on the wire: every 500 on this surface answers the one
	// code and the one sentence, and the identifier that is missing goes to the operator as a
	// structured attribute (#279 decision 7).
	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "INTERNAL_SERVER_ERROR", response["error_code"])
	assert.Contains(t, response["error_description"], "An unexpected server error has occurred")

	database.AssertExpectations(t)
	assertNotAttemptedOnClientDatabase(t, database, "RunInTransaction")
}

// Seam 6 for PUT /resources/{id}/permissions, the one list save that keeps its own comparison:
// entries are renamed and re-described as well as added and dropped, so it plans with the rows'
// ids rather than replaceSet, inside the same three steps as the other six saves (#406, #428).

// resourcePermsTx is the transaction the stub hands the save's body. Not nil: a write expected on
// it cannot be matched by one made outside the transaction.
var resourcePermsTx = &sql.Tx{}

const resourcePermsId = int64(7)

// resourcePermsStored is the resource's stored permissions in the cases below: read, write, admin.
func resourcePermsStored() []models.Permission {
	return []models.Permission{
		{Id: 31, ResourceId: resourcePermsId, PermissionIdentifier: "read", Description: "Read"},
		{Id: 32, ResourceId: resourcePermsId, PermissionIdentifier: "write", Description: "Write"},
		{Id: 33, ResourceId: resourcePermsId, PermissionIdentifier: "admin", Description: "Admin"},
	}
}

// loadedEntries is permissions as a caller that read them sends them back as its loaded list.
func loadedEntries(permissions []models.Permission) []api.ResourcePermissionUpsert {
	out := make([]api.ResourcePermissionUpsert, 0, len(permissions))
	for _, p := range permissions {
		out = append(out, api.ResourcePermissionUpsert{Id: p.Id, PermissionIdentifier: p.PermissionIdentifier, Description: p.Description})
	}
	return out
}

// resourcePermsEdit is the save most cases send against resourcePermsStored: read re-described,
// write kept as it is, admin dropped, audit created.
func resourcePermsEdit() []api.ResourcePermissionUpsert {
	return []api.ResourcePermissionUpsert{
		{Id: 31, PermissionIdentifier: "read", Description: "Read everything"},
		{Id: 32, PermissionIdentifier: "write", Description: "Write"},
		{PermissionIdentifier: "audit", Description: "Audit"},
	}
}

func resourcePermsBody(t *testing.T, permissions, expected []api.ResourcePermissionUpsert) string {
	t.Helper()
	body, err := json.Marshal(api.UpdateResourcePermissionsRequest{Permissions: permissions, ExpectedPermissions: expected})
	require.NoError(t, err)
	return string(body)
}

// serveResourcePerms runs the save on a PUT carrying body.
func serveResourcePerms(database *mocks_data.Database, auditLogger *mocks_audit.AuditLogger, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPut, "/api/v1/admin/resources/7/permissions", strings.NewReader(body))
	r = setChiURLParam(r, "resourceId", "7")
	rr := httptest.NewRecorder()
	HandleAPIResourcePermissionsPut(database, validators.NewIdentifierValidator(), auditLogger).ServeHTTP(rr, r)
	return rr
}

// expectResourcePermsResource registers the resource read the save makes first.
func expectResourcePermsResource(database *mocks_data.Database, resourceIdentifier string) {
	database.On("GetResourceById", mock.Anything, (*sql.Tx)(nil), resourcePermsId).
		Return(&models.Resource{Id: resourcePermsId, ResourceIdentifier: resourceIdentifier}, nil).Once()
}

// expectResourcePermsChecked registers the read of the stored rows step 1 refuses against,
// outside the transaction.
func expectResourcePermsChecked(database *mocks_data.Database, stored []models.Permission) {
	database.On("GetPermissionsByResourceId", mock.Anything, (*sql.Tx)(nil), resourcePermsId).Return(stored, nil).Once()
}

// expectResourcePermsRead registers the read of the stored rows on the save's transaction.
func expectResourcePermsRead(database *mocks_data.Database, stored []models.Permission) {
	database.On("GetPermissionsByResourceId", mock.Anything, resourcePermsTx, resourcePermsId).Return(stored, nil).Once()
}

// expectResourcePermsAudit accepts the one consolidated event and counts it.
func expectResourcePermsAudit(t *testing.T, auditLogger *mocks_audit.AuditLogger, order *[]string) *int {
	count := new(int)
	auditLogger.On("Log", mock.Anything, audit.AuditUpdatedResourcePermissions, mock.Anything).
		Run(func(args mock.Arguments) {
			details := args.Get(2).(map[string]interface{})
			assert.Equal(t, resourcePermsId, details["resourceId"])
			assert.Contains(t, details, "loggedInUser")
			*count++
			if order != nil {
				*order = append(*order, "audit")
			}
		}).Return()
	return count
}

// The save is one transaction: the stored rows are read on the transaction the writes use,
// compared with the list the caller loaded, and changed by exactly the plan, on that transaction:
// the dropped row deleted, the re-described row updated, the unchanged row left alone, the new
// entry created. The one audit event follows the commit (#406, #428).
func TestHandleAPIResourcePermissionsPut_SavesTheExactPlanInOneTransaction(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	expectResourcePermsResource(database, "a-resource")
	expectResourcePermsChecked(database, resourcePermsStored())
	var order []string
	stub := mocks_data.ExpectRunInTransaction(database, resourcePermsTx, func(edge string) { order = append(order, edge) })
	expectResourcePermsRead(database, resourcePermsStored())
	database.On("DeletePermission", mock.Anything, resourcePermsTx, int64(33)).
		Run(func(mock.Arguments) { order = append(order, "delete") }).Return(nil).Once()
	var updated []models.Permission
	database.On("UpdatePermission", mock.Anything, resourcePermsTx, mock.Anything).
		Run(func(args mock.Arguments) {
			updated = append(updated, *args.Get(2).(*models.Permission))
			order = append(order, "update")
		}).Return(nil).Once()
	var created []models.Permission
	database.On("CreatePermission", mock.Anything, resourcePermsTx, mock.Anything).
		Run(func(args mock.Arguments) {
			created = append(created, *args.Get(2).(*models.Permission))
			order = append(order, "create")
		}).Return(nil).Once()
	audits := expectResourcePermsAudit(t, auditLogger, &order)

	rr := serveResourcePerms(database, auditLogger, resourcePermsBody(t, resourcePermsEdit(), loadedEntries(resourcePermsStored())))

	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.NoError(t, stub.BodyErr)
	require.Len(t, updated, 1, "the re-described row, and not the unchanged one")
	assert.Equal(t, int64(31), updated[0].Id)
	assert.Equal(t, "read", updated[0].PermissionIdentifier)
	assert.Equal(t, "Read everything", updated[0].Description)
	require.Len(t, created, 1)
	assert.Equal(t, models.Permission{ResourceId: resourcePermsId, PermissionIdentifier: "audit", Description: "Audit"}, created[0])
	assert.Equal(t, 1, *audits)
	assert.Equal(t, []string{"begin", "delete", "update", "create", "commit", "audit"}, order)
	database.AssertExpectations(t)
}

// A rename is an update of the named row, on the transaction, and nothing else.
func TestHandleAPIResourcePermissionsPut_ARenameUpdatesTheNamedRow(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	stored := resourcePermsStored()
	expectResourcePermsResource(database, "a-resource")
	expectResourcePermsChecked(database, stored)
	mocks_data.ExpectRunInTransaction(database, resourcePermsTx)
	expectResourcePermsRead(database, stored)
	database.On("UpdatePermission", mock.Anything, resourcePermsTx, mock.MatchedBy(func(p *models.Permission) bool {
		return p.Id == 33 && p.PermissionIdentifier == "manage" && p.Description == "Admin"
	})).Return(nil).Once()
	expectResourcePermsAudit(t, auditLogger, nil)

	wanted := loadedEntries(stored)
	wanted[2].PermissionIdentifier = "manage"
	rr := serveResourcePerms(database, auditLogger, resourcePermsBody(t, wanted, loadedEntries(stored)))

	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	database.AssertExpectations(t)
	assertNotAttemptedOnClientDatabase(t, database, "CreatePermission", "DeletePermission")
}

// A failure part way through commits nothing: the body hands the driver's error to the helper,
// which is when the real one rolls back, and the answer is one 500 with nothing audited. Written
// autocommitted, as this save was, the updates before the failure stayed committed under the 500
// (#406, #428).
func TestHandleAPIResourcePermissionsPut_AFailedWriteCommitsNothing(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	expectResourcePermsResource(database, "a-resource")
	expectResourcePermsChecked(database, resourcePermsStored())
	stub := mocks_data.ExpectRunInTransaction(database, resourcePermsTx)
	expectResourcePermsRead(database, resourcePermsStored())
	database.On("DeletePermission", mock.Anything, resourcePermsTx, int64(33)).Return(nil).Once()
	database.On("UpdatePermission", mock.Anything, resourcePermsTx, mock.Anything).Return(nil).Once()
	diskFull := errors.New("the disk is full")
	database.On("CreatePermission", mock.Anything, resourcePermsTx, mock.Anything).Return(diskFull).Once()

	rr := serveResourcePerms(database, auditLogger, resourcePermsBody(t, resourcePermsEdit(), loadedEntries(resourcePermsStored())))

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Equal(t, 1, strings.Count(rr.Body.String(), "INTERNAL_SERVER_ERROR"), "exactly one error response")
	require.ErrorIs(t, stub.BodyErr, diskFull, "the body hands the driver's error to the helper, which rolls back")
	assert.Contains(t, stub.BodyErr.Error(), "database error creating permission audit")
	database.AssertExpectations(t)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}

// A new permission the engine refuses on the unique index is another save adding the same
// identifier at the same moment: 409 CONCURRENT_UPDATE, the whole save rolled back and nothing
// audited, where the autocommitted writes answered it 500 with the earlier writes kept (#428).
func TestHandleAPIResourcePermissionsPut_AUniqueKeyRaceAnswersConflict(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	expectResourcePermsResource(database, "a-resource")
	expectResourcePermsChecked(database, resourcePermsStored())
	stub := mocks_data.ExpectRunInTransaction(database, resourcePermsTx)
	expectResourcePermsRead(database, resourcePermsStored())
	database.On("DeletePermission", mock.Anything, resourcePermsTx, int64(33)).Return(nil).Once()
	database.On("UpdatePermission", mock.Anything, resourcePermsTx, mock.Anything).Return(nil).Once()
	refused := errs.Errorf("%w: %w", data.ErrUniqueViolation, errs.New("duplicate key value violates unique constraint \"idx_permissions_permission_identifier_resource\""))
	database.On("CreatePermission", mock.Anything, resourcePermsTx, mock.Anything).Return(refused).Once()

	rr := serveResourcePerms(database, auditLogger, resourcePermsBody(t, resourcePermsEdit(), loadedEntries(resourcePermsStored())))

	assert.Equal(t, http.StatusConflict, rr.Code)
	code, _ := decodeErrorEnvelope(t, rr)
	assert.Equal(t, "CONCURRENT_UPDATE", code)
	assert.ErrorIs(t, stub.BodyErr, data.ErrUniqueViolation, "the body hands the refusal to the helper, which rolls back")
	database.AssertExpectations(t)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}

// The stored rows failing to read inside the transaction is one 500 under its own message, with no
// write and no audit: with the read's error ignored, a save dropping every permission would find
// nothing to delete and answer 200 with them all still stored, and with both lists empty it would
// answer 200 over a read that never happened (#428).
func TestHandleAPIResourcePermissionsPut_AFailedLoadIsAnsweredAsALoadFailure(t *testing.T) {
	variants := []struct {
		name     string
		checked  []models.Permission
		expected []api.ResourcePermissionUpsert
	}{
		{name: "a save dropping every stored permission", checked: resourcePermsStored(), expected: loadedEntries(resourcePermsStored())},
		{name: "the loaded list and the wanted list are both empty", checked: nil, expected: []api.ResourcePermissionUpsert{}},
	}

	for _, variant := range variants {
		t.Run(variant.name, func(t *testing.T) {
			database := mocks_data.NewDatabase(t)
			auditLogger := mocks_audit.NewAuditLogger(t)

			expectResourcePermsResource(database, "a-resource")
			expectResourcePermsChecked(database, variant.checked)
			stub := mocks_data.ExpectRunInTransaction(database, resourcePermsTx)
			loadErr := errors.New("the read failed")
			database.On("GetPermissionsByResourceId", mock.Anything, resourcePermsTx, resourcePermsId).Return(nil, loadErr).Once()

			rr := serveResourcePerms(database, auditLogger, resourcePermsBody(t, []api.ResourcePermissionUpsert{}, variant.expected))

			assert.Equal(t, http.StatusInternalServerError, rr.Code, rr.Body.String())
			assert.Equal(t, 1, strings.Count(rr.Body.String(), "INTERNAL_SERVER_ERROR"), "exactly one error response")
			require.ErrorIs(t, stub.BodyErr, loadErr)
			assert.Contains(t, stub.BodyErr.Error(), "resource permissions before update")
			database.AssertExpectations(t)
			assertNotAttemptedOnClientDatabase(t, database, "CreatePermission", "UpdatePermission", "DeletePermission")
			auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// A body aborted as a deadlock victim on its first attempt and rerun by the helper answers once
// and audits once: the plan is recomputed from a fresh read on each attempt, and the event is
// emitted after the attempt that committed (#301, #428).
func TestHandleAPIResourcePermissionsPut_ARerunAttemptAnswersAndAuditsOnce(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	expectResourcePermsResource(database, "a-resource")
	expectResourcePermsChecked(database, resourcePermsStored())

	deadlock := errors.New("Error 1213: Deadlock found when trying to get lock")
	attempts := 0
	database.EXPECT().RunInTransaction(mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, fn func(tx *sql.Tx) error) error {
		for {
			attempts++
			err := fn(resourcePermsTx)
			if err == nil {
				return nil
			}
			require.ErrorIs(t, err, deadlock,
				"the body must hand the driver's error back in the chain, or the helper cannot tell a deadlock from a fault")
			require.Less(t, attempts, 3, "the second attempt was scripted to succeed")
		}
	}).Once()

	database.On("GetPermissionsByResourceId", mock.Anything, resourcePermsTx, resourcePermsId).Return(resourcePermsStored(), nil).Twice()
	database.On("DeletePermission", mock.Anything, resourcePermsTx, int64(33)).Return(nil).Twice()
	database.On("UpdatePermission", mock.Anything, resourcePermsTx, mock.Anything).Return(nil).Twice()
	// The first create is the deadlock victim; the second lands.
	database.On("CreatePermission", mock.Anything, resourcePermsTx, mock.Anything).Return(deadlock).Once()
	database.On("CreatePermission", mock.Anything, resourcePermsTx, mock.Anything).Return(nil).Once()
	audits := expectResourcePermsAudit(t, auditLogger, nil)

	rr := serveResourcePerms(database, auditLogger, resourcePermsBody(t, resourcePermsEdit(), loadedEntries(resourcePermsStored())))

	assert.Equal(t, 2, attempts)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.NotContains(t, rr.Body.String(), "INTERNAL_SERVER_ERROR")
	assert.Equal(t, 1, *audits, "the event of one committed save, not one per attempt")
	database.AssertExpectations(t)
}

// The helper giving up, a deadlock on every attempt, is one 500 and no audit event.
func TestHandleAPIResourcePermissionsPut_AnExhaustedRetryIsOneFiveHundred(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	expectResourcePermsResource(database, "a-resource")
	expectResourcePermsChecked(database, resourcePermsStored())
	mocks_data.ExpectRunInTransactionRefused(database, errors.New("transaction aborted as a deadlock victim on all 3 attempts"))

	rr := serveResourcePerms(database, auditLogger, resourcePermsBody(t, resourcePermsEdit(), loadedEntries(resourcePermsStored())))

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Equal(t, 1, strings.Count(rr.Body.String(), "INTERNAL_SERVER_ERROR"), "exactly one error response")
	database.AssertExpectations(t)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}

// A loaded list that differs from the rows read on the transaction is a save from an outdated
// page: 409 CONCURRENT_UPDATE, nothing written and nothing audited. Each entry is compared whole,
// so a description another save changed makes the list as outdated as a permission it added or
// dropped, and applying this save's whole list would silently undo that change (#428).
func TestHandleAPIResourcePermissionsPut_AnOutdatedLoadedListIsRefused(t *testing.T) {
	variants := []struct {
		name   string
		stored func() []models.Permission
	}{
		{name: "another save added a permission", stored: func() []models.Permission {
			return append(resourcePermsStored(), models.Permission{Id: 34, ResourceId: resourcePermsId, PermissionIdentifier: "export", Description: "Export"})
		}},
		{name: "another save dropped a permission", stored: func() []models.Permission {
			return resourcePermsStored()[:2]
		}},
		{name: "another save changed a description", stored: func() []models.Permission {
			stored := resourcePermsStored()
			stored[1].Description = "Write anything"
			return stored
		}},
		{name: "another save renamed a permission", stored: func() []models.Permission {
			stored := resourcePermsStored()
			stored[1].PermissionIdentifier = "edit"
			return stored
		}},
	}

	for _, variant := range variants {
		t.Run(variant.name, func(t *testing.T) {
			database := mocks_data.NewDatabase(t)
			auditLogger := mocks_audit.NewAuditLogger(t)

			expectResourcePermsResource(database, "a-resource")
			expectResourcePermsChecked(database, resourcePermsStored())
			stub := mocks_data.ExpectRunInTransaction(database, resourcePermsTx)
			expectResourcePermsRead(database, variant.stored())

			rr := serveResourcePerms(database, auditLogger, resourcePermsBody(t, resourcePermsEdit(), loadedEntries(resourcePermsStored())))

			assert.Equal(t, http.StatusConflict, rr.Code)
			code, _ := decodeErrorEnvelope(t, rr)
			assert.Equal(t, "CONCURRENT_UPDATE", code)
			assert.ErrorIs(t, stub.BodyErr, errListChanged, "the body refuses, so the helper rolls back")
			database.AssertExpectations(t)
			assertNotAttemptedOnClientDatabase(t, database, "CreatePermission", "UpdatePermission", "DeletePermission")
			auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// A loaded list equal to the stored rows as a set proceeds: in another order and with a repeat,
// and [] against no stored permissions, which is a page that loaded none and not a missing field
// (#428).
func TestHandleAPIResourcePermissionsPut_ALoadedListEqualAsASetProceeds(t *testing.T) {
	reordered := loadedEntries(resourcePermsStored())
	reordered = []api.ResourcePermissionUpsert{reordered[2], reordered[0], reordered[1], reordered[0]}

	variants := []struct {
		name     string
		stored   []models.Permission
		expected []api.ResourcePermissionUpsert
		wanted   []api.ResourcePermissionUpsert
	}{
		{name: "another order and a repeat", stored: resourcePermsStored(), expected: reordered, wanted: loadedEntries(resourcePermsStored())},
		{name: "an empty loaded list against no stored permissions", stored: nil, expected: []api.ResourcePermissionUpsert{}, wanted: []api.ResourcePermissionUpsert{}},
	}

	for _, variant := range variants {
		t.Run(variant.name, func(t *testing.T) {
			database := mocks_data.NewDatabase(t)
			auditLogger := mocks_audit.NewAuditLogger(t)

			expectResourcePermsResource(database, "a-resource")
			expectResourcePermsChecked(database, variant.stored)
			mocks_data.ExpectRunInTransaction(database, resourcePermsTx)
			expectResourcePermsRead(database, variant.stored)
			audits := expectResourcePermsAudit(t, auditLogger, nil)

			rr := serveResourcePerms(database, auditLogger, resourcePermsBody(t, variant.wanted, variant.expected))

			assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
			assert.Equal(t, 1, *audits)
			database.AssertExpectations(t)
			assertNotAttemptedOnClientDatabase(t, database, "CreatePermission", "UpdatePermission", "DeletePermission")
		})
	}
}

// Every refusal is decided before the transaction opens, so a refused save writes nothing: the
// strict mock carries the reads each refusal needs and nothing else, and reaching RunInTransaction
// fails the case. The loaded list is required (#428); the identifier rule is the one the update
// and create loops applied, stated against the rows read here; and the system resource keeps its
// built-in protection, userinfo included (decision 18 of #428 leaves that page's save as it is).
func TestHandleAPIResourcePermissionsPut_ARefusedSaveNeverOpensTheTransaction(t *testing.T) {
	stored := resourcePermsStored()
	loaded := loadedEntries(stored)
	withEntry := func(i int, identifier string) []api.ResourcePermissionUpsert {
		wanted := loadedEntries(stored)
		wanted[i].PermissionIdentifier = identifier
		return wanted
	}

	builtIns := make([]models.Permission, 0, len(constants.BuiltInAuthServerPermissionIdentifiers))
	for i, identifier := range constants.BuiltInAuthServerPermissionIdentifiers {
		builtIns = append(builtIns, models.Permission{Id: int64(40 + i), ResourceId: resourcePermsId, PermissionIdentifier: identifier, Description: identifier})
	}
	withoutUserinfo := make([]api.ResourcePermissionUpsert, 0, len(builtIns))
	for _, p := range loadedEntries(builtIns) {
		if p.PermissionIdentifier != constants.UserinfoPermissionIdentifier {
			withoutUserinfo = append(withoutUserinfo, p)
		}
	}

	variants := []struct {
		name               string
		resourceIdentifier string
		stored             []models.Permission
		body               string
		wantStatus         int
		wantCode           string
		wantDescription    string
	}{
		{
			name:            "the loaded list is absent",
			body:            `{"permissions":[]}`,
			wantStatus:      http.StatusBadRequest,
			wantCode:        "VALIDATION_ERROR",
			wantDescription: "expectedPermissions is required",
		},
		{
			name:            "the loaded list is null",
			body:            `{"permissions":[],"expectedPermissions":null}`,
			wantStatus:      http.StatusBadRequest,
			wantCode:        "VALIDATION_ERROR",
			wantDescription: "expectedPermissions is required",
		},
		{
			name:            "an id that is not one of the resource's permissions",
			stored:          stored,
			body:            resourcePermsBody(t, append(loadedEntries(stored), api.ResourcePermissionUpsert{Id: 99, PermissionIdentifier: "other", Description: "x"}), loaded),
			wantStatus:      http.StatusNotFound,
			wantCode:        "NOT_FOUND",
			wantDescription: "Permission not found",
		},
		{
			name:            "a rename onto another stored permission's identifier",
			stored:          stored,
			body:            resourcePermsBody(t, withEntry(0, "admin")[:1], loaded),
			wantStatus:      http.StatusBadRequest,
			wantCode:        "VALIDATION_ERROR",
			wantDescription: "Permission identifier admin is already in use.",
		},
		{
			name:   "a swap of two stored identifiers",
			stored: stored,
			body: resourcePermsBody(t, []api.ResourcePermissionUpsert{
				{Id: 31, PermissionIdentifier: "write", Description: "Read"},
				{Id: 32, PermissionIdentifier: "read", Description: "Write"},
			}, loaded),
			wantStatus:      http.StatusBadRequest,
			wantCode:        "VALIDATION_ERROR",
			wantDescription: "Permission identifier write is already in use.",
		},
		{
			name:            "a new permission reusing a stored identifier",
			stored:          stored,
			body:            resourcePermsBody(t, []api.ResourcePermissionUpsert{{PermissionIdentifier: "read", Description: "Read again"}}, loaded),
			wantStatus:      http.StatusBadRequest,
			wantCode:        "VALIDATION_ERROR",
			wantDescription: "Permission identifier read is already in use.",
		},
		{
			name:               "the system resource's list without userinfo",
			resourceIdentifier: constants.AuthServerResourceIdentifier,
			stored:             builtIns,
			body:               resourcePermsBody(t, withoutUserinfo, loadedEntries(builtIns)),
			wantStatus:         http.StatusBadRequest,
			wantCode:           "VALIDATION_ERROR",
			wantDescription:    "Built-in permission 'userinfo' cannot be deleted.",
		},
	}

	for _, variant := range variants {
		t.Run(variant.name, func(t *testing.T) {
			database := mocks_data.NewDatabase(t)
			auditLogger := mocks_audit.NewAuditLogger(t)

			resourceIdentifier := variant.resourceIdentifier
			if resourceIdentifier == "" {
				resourceIdentifier = "a-resource"
			}
			expectResourcePermsResource(database, resourceIdentifier)
			if variant.stored != nil {
				expectResourcePermsChecked(database, variant.stored)
			}

			rr := serveResourcePerms(database, auditLogger, variant.body)

			assert.Equal(t, variant.wantStatus, rr.Code)
			code, description := decodeErrorEnvelope(t, rr)
			assert.Equal(t, variant.wantCode, code)
			assert.Contains(t, description, variant.wantDescription)
			database.AssertExpectations(t)
			assertNotAttemptedOnClientDatabase(t, database, "RunInTransaction")
			auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// A named row that the step 1 read carried and the transaction's read does not, with the loaded
// list still equal to the transaction's read, is a list that changed and changed back between the
// two reads: refused 409 with nothing written, rather than an update of a row that is gone (#428).
func TestHandleAPIResourcePermissionsPut_ANamedRowGoneByTheTransactionIsRefused(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	stored := resourcePermsStored()
	expectResourcePermsResource(database, "a-resource")
	expectResourcePermsChecked(database, stored)
	stub := mocks_data.ExpectRunInTransaction(database, resourcePermsTx)
	expectResourcePermsRead(database, stored[:2])

	rr := serveResourcePerms(database, auditLogger, resourcePermsBody(t, loadedEntries(stored), loadedEntries(stored[:2])))

	assert.Equal(t, http.StatusConflict, rr.Code)
	assert.ErrorIs(t, stub.BodyErr, errListChanged)
	database.AssertExpectations(t)
	assertNotAttemptedOnClientDatabase(t, database, "CreatePermission", "UpdatePermission", "DeletePermission")
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}
