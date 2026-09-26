package apihandlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	mocks_audit "github.com/leodip/goiabada/authserver/internal/audit/mocks"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Seam 6 for the two saves that replace a set of permission grants and audit each grant and
// revocation: PUT /users/{id}/permissions and PUT /groups/{id}/permissions. They are the same
// three steps over two tables, so each case below runs once per save (#406, #428).

// grantsTx is the transaction the stub hands the save's body. Not nil: a write expected on it
// cannot be matched by one made outside the transaction.
var grantsTx = &sql.Tx{}

// grantRow is a stored grant row, whichever table it is read from.
type grantRow struct {
	id           int64
	permissionId int64
}

// grantSave describes one of the two saves to the shared cases.
type grantSave struct {
	name         string
	path         string
	ownerRead    string
	owner        any
	readMethod   string
	storedRows   func(rows []grantRow) any
	createMethod string
	deleteMethod string
	// created is the owner id and permission id of the row the save handed its create method.
	created      func(arg any) (ownerId int64, permissionId int64)
	addedEvent   string
	deletedEvent string
	ownerKey     string
	handler      func(database *mocks_data.Database, auditLogger *mocks_audit.AuditLogger) http.HandlerFunc
	body         func(t *testing.T, wanted, expected []int64) string
}

const grantOwnerId = int64(5)

var grantSaves = []grantSave{
	{
		name:       "user permissions",
		path:       "/api/v1/admin/users/5/permissions",
		ownerRead:  "GetUserById",
		owner:      &models.User{Id: grantOwnerId},
		readMethod: "GetUserPermissionsByUserId",
		storedRows: func(rows []grantRow) any {
			out := make([]models.UserPermission, 0, len(rows))
			for _, r := range rows {
				out = append(out, models.UserPermission{Id: r.id, UserId: grantOwnerId, PermissionId: r.permissionId})
			}
			return out
		},
		createMethod: "CreateUserPermission",
		deleteMethod: "DeleteUserPermission",
		created: func(arg any) (int64, int64) {
			up := arg.(*models.UserPermission)
			return up.UserId, up.PermissionId
		},
		addedEvent:   audit.AuditAddedUserPermission,
		deletedEvent: audit.AuditDeletedUserPermission,
		ownerKey:     "userId",
		handler: func(database *mocks_data.Database, auditLogger *mocks_audit.AuditLogger) http.HandlerFunc {
			return HandleAPIUserPermissionsPut(database, auditLogger)
		},
		body: func(t *testing.T, wanted, expected []int64) string {
			t.Helper()
			body, err := json.Marshal(map[string]any{"permissionIds": wanted, "expectedPermissionIds": expected})
			require.NoError(t, err)
			return string(body)
		},
	},
	{
		name:       "group permissions",
		path:       "/api/v1/admin/groups/5/permissions",
		ownerRead:  "GetGroupById",
		owner:      &models.Group{Id: grantOwnerId, GroupIdentifier: "admins"},
		readMethod: "GetGroupPermissionsByGroupId",
		storedRows: func(rows []grantRow) any {
			out := make([]models.GroupPermission, 0, len(rows))
			for _, r := range rows {
				out = append(out, models.GroupPermission{Id: r.id, GroupId: grantOwnerId, PermissionId: r.permissionId})
			}
			return out
		},
		createMethod: "CreateGroupPermission",
		deleteMethod: "DeleteGroupPermission",
		created: func(arg any) (int64, int64) {
			gp := arg.(*models.GroupPermission)
			return gp.GroupId, gp.PermissionId
		},
		addedEvent:   audit.AuditAddedGroupPermission,
		deletedEvent: audit.AuditDeletedGroupPermission,
		ownerKey:     "groupId",
		handler: func(database *mocks_data.Database, auditLogger *mocks_audit.AuditLogger) http.HandlerFunc {
			return HandleAPIGroupPermissionsPut(database, auditLogger)
		},
		body: func(t *testing.T, wanted, expected []int64) string {
			t.Helper()
			body, err := json.Marshal(map[string]any{"permissionIds": wanted, "expectedPermissionIds": expected})
			require.NoError(t, err)
			return string(body)
		},
	},
}

// serve runs the save on a PUT carrying body.
func (s grantSave) serve(database *mocks_data.Database, auditLogger *mocks_audit.AuditLogger, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPut, s.path, strings.NewReader(body))
	r = setChiURLParam(r, "id", "5")
	rr := httptest.NewRecorder()
	s.handler(database, auditLogger).ServeHTTP(rr, r)
	return rr
}

// expectOwner registers the owner read the save makes before it validates.
func (s grantSave) expectOwner(database *mocks_data.Database) {
	database.On(s.ownerRead, mock.Anything, (*sql.Tx)(nil), grantOwnerId).Return(s.owner, nil).Once()
}

// expectPermissionsExist registers the validation read of each wanted permission, outside the
// transaction.
func expectPermissionsExist(database *mocks_data.Database, permissionIds ...int64) {
	for _, id := range permissionIds {
		database.On("GetPermissionById", mock.Anything, (*sql.Tx)(nil), id).
			Return(&models.Permission{Id: id, PermissionIdentifier: "p"}, nil).Once()
	}
}

// expectStored registers the read of the stored grants on the save's transaction.
func (s grantSave) expectStored(database *mocks_data.Database, rows ...grantRow) {
	database.On(s.readMethod, mock.Anything, grantsTx, grantOwnerId).Return(s.storedRows(rows), nil).Once()
}

// auditRecord is one audit event as a case reads it, the event and the permission it names, in the
// form audited writes it.
type auditRecord string

// audited is the record of one event naming one permission.
func audited(event string, permissionId int64) auditRecord {
	return auditRecord(fmt.Sprintf("%s %d", event, permissionId))
}

// recordAudits accepts every Log call and collects them, checking each names the owner and the
// caller, in order.
func (s grantSave) recordAudits(t *testing.T, auditLogger *mocks_audit.AuditLogger, order *[]string) *[]auditRecord {
	records := &[]auditRecord{}
	auditLogger.On("Log", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			details := args.Get(2).(map[string]interface{})
			assert.Equal(t, grantOwnerId, details[s.ownerKey])
			assert.Contains(t, details, "loggedInUser")
			*records = append(*records, audited(args.String(1), details["permissionId"].(int64)))
			if order != nil {
				*order = append(*order, "audit")
			}
		}).Return()
	return records
}

// The save is one transaction: the stored grants are read on the transaction the writes use,
// compared with the set the caller loaded, and replaced by exactly replaceSet's plan, deletes then
// inserts, on that transaction. One audit event per grant made and per grant withdrawn follows the
// commit, never inside it, since an attempt inside can be rolled back and rerun (#406, #428).
func TestGrantListSaves_SaveTheExactPlanInOneTransaction(t *testing.T) {
	for _, save := range grantSaves {
		t.Run(save.name, func(t *testing.T) {
			database := mocks_data.NewDatabase(t)
			auditLogger := mocks_audit.NewAuditLogger(t)

			save.expectOwner(database)
			expectPermissionsExist(database, 4, 6)
			var order []string
			stub := mocks_data.ExpectRunInTransaction(database, grantsTx, func(edge string) { order = append(order, edge) })
			save.expectStored(database, grantRow{id: 21, permissionId: 3}, grantRow{id: 22, permissionId: 4})
			var deleted []int64
			database.On(save.deleteMethod, mock.Anything, grantsTx, mock.Anything).
				Run(func(args mock.Arguments) {
					deleted = append(deleted, args.Get(2).(int64))
					order = append(order, "delete")
				}).Return(nil).Once()
			var granted []int64
			database.On(save.createMethod, mock.Anything, grantsTx, mock.Anything).
				Run(func(args mock.Arguments) {
					ownerId, permissionId := save.created(args.Get(2))
					assert.Equal(t, grantOwnerId, ownerId)
					granted = append(granted, permissionId)
					order = append(order, "insert")
				}).Return(nil).Once()
			records := save.recordAudits(t, auditLogger, &order)

			rr := save.serve(database, auditLogger, save.body(t, []int64{4, 6}, []int64{3, 4}))

			assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
			assert.NoError(t, stub.BodyErr)
			assert.Equal(t, []int64{21}, deleted, "the revoked grant's row, and nothing kept")
			assert.Equal(t, []int64{6}, granted, "the new grant, and nothing already stored")
			assert.Equal(t, []auditRecord{audited(save.addedEvent, 6), audited(save.deletedEvent, 3)}, *records)
			assert.Equal(t, []string{"begin", "delete", "insert", "commit", "audit", "audit"}, order)
			database.AssertExpectations(t)
		})
	}
}

// A permission stored twice is what an earlier save left behind: the user save stored a repeated
// id as two rows, and two overlapping saves that both grant one permission do the same. Revoking it
// deletes both copies, where the lookup this replaced deleted one and left the permission granted,
// and audits one revocation. An extra copy of a permission that stays granted is deleted too, as a
// repair, and audited as nothing, since nothing was withdrawn (#406, #428).
func TestGrantListSaves_AStoredDuplicateIsRemovedWithItsOriginal(t *testing.T) {
	for _, save := range grantSaves {
		t.Run(save.name, func(t *testing.T) {
			database := mocks_data.NewDatabase(t)
			auditLogger := mocks_audit.NewAuditLogger(t)

			save.expectOwner(database)
			expectPermissionsExist(database, 4)
			mocks_data.ExpectRunInTransaction(database, grantsTx)
			save.expectStored(database,
				grantRow{id: 21, permissionId: 3}, grantRow{id: 22, permissionId: 3},
				grantRow{id: 23, permissionId: 4}, grantRow{id: 24, permissionId: 4},
			)
			var deleted []int64
			database.On(save.deleteMethod, mock.Anything, grantsTx, mock.Anything).
				Run(func(args mock.Arguments) { deleted = append(deleted, args.Get(2).(int64)) }).
				Return(nil).Times(3)
			records := save.recordAudits(t, auditLogger, nil)

			rr := save.serve(database, auditLogger, save.body(t, []int64{4}, []int64{3, 4}))

			assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
			assert.Equal(t, []int64{21, 22, 24}, deleted, "both copies of the revoked grant, and the extra copy of the kept one")
			assert.Equal(t, []auditRecord{audited(save.deletedEvent, 3)}, *records, "one revocation, and nothing for the repair")
			database.AssertExpectations(t)
			assertNotAttemptedOnClientDatabase(t, database, save.createMethod)
		})
	}
}

// A failure part way through commits nothing: the body hands the driver's error to the helper,
// which is when the real one rolls back, and the answer is one 500 with nothing audited. Written
// autocommitted, as these saves were, the grant made before the failure stayed committed under the
// 500 (#406, #428).
func TestGrantListSaves_AFailedWriteCommitsNothing(t *testing.T) {
	for _, save := range grantSaves {
		t.Run(save.name, func(t *testing.T) {
			database := mocks_data.NewDatabase(t)
			auditLogger := mocks_audit.NewAuditLogger(t)

			save.expectOwner(database)
			expectPermissionsExist(database, 6)
			stub := mocks_data.ExpectRunInTransaction(database, grantsTx)
			save.expectStored(database, grantRow{id: 21, permissionId: 3})
			database.On(save.deleteMethod, mock.Anything, grantsTx, int64(21)).Return(nil).Once()
			diskFull := errors.New("the disk is full")
			database.On(save.createMethod, mock.Anything, grantsTx, mock.Anything).Return(diskFull).Once()

			rr := save.serve(database, auditLogger, save.body(t, []int64{6}, []int64{3}))

			assert.Equal(t, http.StatusInternalServerError, rr.Code)
			assert.Equal(t, 1, strings.Count(rr.Body.String(), "INTERNAL_SERVER_ERROR"), "exactly one error response")
			require.ErrorIs(t, stub.BodyErr, diskFull, "the body hands the driver's error to the helper, which rolls back")
			assert.Contains(t, stub.BodyErr.Error(), "database error granting permission 6")
			database.AssertExpectations(t)
			auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// The stored grants failing to read inside the transaction is one 500 under its own message, with
// no write and no audit. Here it guards a revocation: a save withdrawing the one stored grant, with
// the read's error ignored, would find nothing to delete and answer 200 with the grant still in
// force; and with both lists empty it would answer 200 over a read that never happened (#428).
func TestGrantListSaves_AFailedLoadIsAnsweredAsALoadFailure(t *testing.T) {
	variants := []struct {
		name     string
		wanted   []int64
		expected []int64
	}{
		{name: "a save revoking the one stored grant", wanted: []int64{}, expected: []int64{3}},
		{name: "the loaded list and the wanted list are both empty", wanted: []int64{}, expected: []int64{}},
	}

	for _, save := range grantSaves {
		for _, variant := range variants {
			t.Run(save.name+"/"+variant.name, func(t *testing.T) {
				database := mocks_data.NewDatabase(t)
				auditLogger := mocks_audit.NewAuditLogger(t)

				save.expectOwner(database)
				stub := mocks_data.ExpectRunInTransaction(database, grantsTx)
				loadErr := errors.New("the read failed")
				database.On(save.readMethod, mock.Anything, grantsTx, grantOwnerId).Return(nil, loadErr).Once()

				rr := save.serve(database, auditLogger, save.body(t, variant.wanted, variant.expected))

				assert.Equal(t, http.StatusInternalServerError, rr.Code, rr.Body.String())
				assert.Equal(t, 1, strings.Count(rr.Body.String(), "INTERNAL_SERVER_ERROR"), "exactly one error response")
				require.ErrorIs(t, stub.BodyErr, loadErr)
				assert.Contains(t, stub.BodyErr.Error(), "permissions before update")
				database.AssertExpectations(t)
				assertNotAttemptedOnClientDatabase(t, database, save.createMethod, save.deleteMethod)
				auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
			})
		}
	}
}

// A body aborted as a deadlock victim on its first attempt and rerun by the helper answers once
// and audits once: the plan is recomputed from a fresh read on each attempt, and the events are
// emitted from the attempt that committed, after it did (#301, #428).
func TestGrantListSaves_ARerunAttemptAnswersAndAuditsOnce(t *testing.T) {
	for _, save := range grantSaves {
		t.Run(save.name, func(t *testing.T) {
			database := mocks_data.NewDatabase(t)
			auditLogger := mocks_audit.NewAuditLogger(t)

			save.expectOwner(database)
			expectPermissionsExist(database, 6)

			deadlock := errors.New("Error 1213: Deadlock found when trying to get lock")
			attempts := 0
			database.EXPECT().RunInTransaction(mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, fn func(tx *sql.Tx) error) error {
				for {
					attempts++
					err := fn(grantsTx)
					if err == nil {
						return nil
					}
					require.ErrorIs(t, err, deadlock,
						"the body must hand the driver's error back in the chain, or the helper cannot tell a deadlock from a fault")
					require.Less(t, attempts, 3, "the second attempt was scripted to succeed")
				}
			}).Once()

			// Both attempts read the grants afresh and withdraw permission 3.
			database.On(save.readMethod, mock.Anything, grantsTx, grantOwnerId).
				Return(save.storedRows([]grantRow{{id: 21, permissionId: 3}}), nil).Twice()
			database.On(save.deleteMethod, mock.Anything, grantsTx, int64(21)).Return(nil).Twice()
			// The first insert is the deadlock victim; the second lands.
			database.On(save.createMethod, mock.Anything, grantsTx, mock.Anything).Return(deadlock).Once()
			database.On(save.createMethod, mock.Anything, grantsTx, mock.Anything).Return(nil).Once()
			records := save.recordAudits(t, auditLogger, nil)

			rr := save.serve(database, auditLogger, save.body(t, []int64{6}, []int64{3}))

			assert.Equal(t, 2, attempts)
			assert.Equal(t, http.StatusOK, rr.Code)
			assert.NotContains(t, rr.Body.String(), "INTERNAL_SERVER_ERROR")
			assert.Equal(t, []auditRecord{audited(save.addedEvent, 6), audited(save.deletedEvent, 3)}, *records, "one event per change, not one per attempt")
			database.AssertExpectations(t)
		})
	}
}

// The helper giving up, a deadlock on every attempt, is one 500 and no audit event.
func TestGrantListSaves_AnExhaustedRetryIsOneFiveHundred(t *testing.T) {
	for _, save := range grantSaves {
		t.Run(save.name, func(t *testing.T) {
			database := mocks_data.NewDatabase(t)
			auditLogger := mocks_audit.NewAuditLogger(t)

			save.expectOwner(database)
			expectPermissionsExist(database, 6)
			mocks_data.ExpectRunInTransactionRefused(database, errors.New("transaction aborted as a deadlock victim on all 3 attempts"))

			rr := save.serve(database, auditLogger, save.body(t, []int64{6}, []int64{}))

			assert.Equal(t, http.StatusInternalServerError, rr.Code)
			assert.Equal(t, 1, strings.Count(rr.Body.String(), "INTERNAL_SERVER_ERROR"), "exactly one error response")
			database.AssertExpectations(t)
			auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// A loaded set that differs from the grants read on the transaction is a save from an outdated
// page: 409 CONCURRENT_UPDATE, nothing written and nothing audited, where applying the whole set
// would silently re-grant a permission another administrator had just revoked (#428).
func TestGrantListSaves_AnOutdatedLoadedListIsRefused(t *testing.T) {
	for _, save := range grantSaves {
		t.Run(save.name, func(t *testing.T) {
			database := mocks_data.NewDatabase(t)
			auditLogger := mocks_audit.NewAuditLogger(t)

			save.expectOwner(database)
			expectPermissionsExist(database, 3, 4, 6)
			stub := mocks_data.ExpectRunInTransaction(database, grantsTx)
			// Permission 3 was revoked by another save after this caller loaded {3, 4}.
			save.expectStored(database, grantRow{id: 22, permissionId: 4})

			rr := save.serve(database, auditLogger, save.body(t, []int64{3, 4, 6}, []int64{3, 4}))

			assert.Equal(t, http.StatusConflict, rr.Code)
			code, _ := decodeErrorEnvelope(t, rr)
			assert.Equal(t, "CONCURRENT_UPDATE", code)
			assert.ErrorIs(t, stub.BodyErr, errListChanged, "the body refuses, so the helper rolls back")
			database.AssertExpectations(t)
			assertNotAttemptedOnClientDatabase(t, database, save.createMethod, save.deleteMethod)
			auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// A loaded set equal to the stored grants as a set proceeds: in another order and with a repeat,
// and [] against no stored grants, which is a page that loaded none and not a missing field (#428).
func TestGrantListSaves_ALoadedListEqualAsASetProceeds(t *testing.T) {
	variants := []struct {
		name     string
		stored   []grantRow
		expected []int64
	}{
		{name: "another order and a repeat", stored: []grantRow{{id: 21, permissionId: 3}, {id: 22, permissionId: 4}}, expected: []int64{4, 3, 4}},
		{name: "an empty loaded list against no stored grants", stored: nil, expected: []int64{}},
	}

	for _, save := range grantSaves {
		for _, variant := range variants {
			t.Run(save.name+"/"+variant.name, func(t *testing.T) {
				database := mocks_data.NewDatabase(t)
				auditLogger := mocks_audit.NewAuditLogger(t)

				save.expectOwner(database)
				expectPermissionsExist(database, 6)
				mocks_data.ExpectRunInTransaction(database, grantsTx)
				save.expectStored(database, variant.stored...)
				for _, row := range variant.stored {
					database.On(save.deleteMethod, mock.Anything, grantsTx, row.id).Return(nil).Once()
				}
				database.On(save.createMethod, mock.Anything, grantsTx, mock.Anything).Return(nil).Once()
				save.recordAudits(t, auditLogger, nil)

				rr := save.serve(database, auditLogger, save.body(t, []int64{6}, variant.expected))

				assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
				database.AssertExpectations(t)
			})
		}
	}
}

// Every refusal is decided before the transaction opens, so a refused save writes nothing: the
// strict mock carries the reads each refusal needs and nothing else, and reaching RunInTransaction
// fails the case. The loaded set is required (#428); a permission that does not exist is #406's
// 404, as before.
func TestGrantListSaves_ARefusedSaveNeverOpensTheTransaction(t *testing.T) {
	variants := []struct {
		name            string
		body            string
		missing         int64
		wantStatus      int
		wantCode        string
		wantDescription string
	}{
		{
			name:            "the loaded list is absent",
			body:            `{"permissionIds":[6]}`,
			wantStatus:      http.StatusBadRequest,
			wantCode:        "VALIDATION_ERROR",
			wantDescription: "expectedPermissionIds is required",
		},
		{
			name:            "the loaded list is null",
			body:            `{"permissionIds":[6],"expectedPermissionIds":null}`,
			wantStatus:      http.StatusBadRequest,
			wantCode:        "VALIDATION_ERROR",
			wantDescription: "expectedPermissionIds is required",
		},
		{
			name:            "a permission that does not exist",
			body:            `{"permissionIds":[6],"expectedPermissionIds":[]}`,
			missing:         6,
			wantStatus:      http.StatusNotFound,
			wantCode:        "NOT_FOUND",
			wantDescription: "Permission not found",
		},
	}

	for _, save := range grantSaves {
		for _, variant := range variants {
			t.Run(save.name+"/"+variant.name, func(t *testing.T) {
				database := mocks_data.NewDatabase(t)
				auditLogger := mocks_audit.NewAuditLogger(t)

				save.expectOwner(database)
				if variant.missing != 0 {
					database.On("GetPermissionById", mock.Anything, (*sql.Tx)(nil), variant.missing).
						Return((*models.Permission)(nil), nil).Once()
				}

				rr := save.serve(database, auditLogger, variant.body)

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
}

// A repeated id in the request is validated once, granted once and audited once. The group save
// always deduplicated; the user save did not, and stored the repeat as two grant rows, one of which
// a later revocation left in force (#406).
func TestGrantListSaves_ARepeatedIdIsGrantedOnce(t *testing.T) {
	for _, save := range grantSaves {
		t.Run(save.name, func(t *testing.T) {
			database := mocks_data.NewDatabase(t)
			auditLogger := mocks_audit.NewAuditLogger(t)

			save.expectOwner(database)
			expectPermissionsExist(database, 6)
			mocks_data.ExpectRunInTransaction(database, grantsTx)
			save.expectStored(database)
			database.On(save.createMethod, mock.Anything, grantsTx, mock.Anything).Return(nil).Once()
			records := save.recordAudits(t, auditLogger, nil)

			rr := save.serve(database, auditLogger, save.body(t, []int64{6, 6}, []int64{}))

			assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
			assert.Equal(t, []auditRecord{audited(save.addedEvent, 6)}, *records)
			database.AssertExpectations(t)
		})
	}
}
