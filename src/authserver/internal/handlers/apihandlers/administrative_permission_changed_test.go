package apihandlers

import (
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Every change to who is an administrator is alertable: a committed grant or revocation of an
// administrative permission, on a user, a group or a client, and a user joining or leaving a group
// that holds one, writes one administrative_permission_changed record beside the records the write
// already made, never instead of them. The client permission save's own record names what it
// granted and revoked. Deleting an administrative group keeps its own record alone (#402 decision
// 6).

// eventNames is the events of the records, in the order they were written.
func eventNames(records []loggedEvent) []string {
	names := make([]string, 0, len(records))
	for _, r := range records {
		names = append(names, r.event)
	}
	return names
}

// administrativeChanges is the administrative_permission_changed records among records, details
// only, in the order they were written.
func administrativeChanges(records []loggedEvent) []map[string]interface{} {
	var changes []map[string]interface{}
	for _, r := range records {
		if r.event == "administrative_permission_changed" {
			changes = append(changes, r.details)
		}
	}
	return changes
}

// existingEvents is the records a committed permission save made before this change, for the
// grants and revocations it commits: one per permission, or the client save's one record.
func (s grantSave) existingEvents(granted, revoked int) []string {
	if s.consolidatedEvent != "" {
		return []string{s.consolidatedEvent}
	}
	var events []string
	for range granted {
		events = append(events, s.addedEvent)
	}
	for range revoked {
		events = append(events, s.deletedEvent)
	}
	return events
}

func TestAdministrativePermissionChanged_APermissionSaveRecordsWhatItGrantsAndRevokes(t *testing.T) {
	for _, save := range grantSaves {
		t.Run(save.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)

			save.expectOwner(database)
			expectPermissionsExist(database, permManage, permAdminRead, 6, 4)
			expectAuthServerPermissions(database)
			datamocks.ExpectRunInTransaction(database, grantsTx)
			save.expectStored(database, grantRow{id: 21, permissionId: permManageUsers}, grantRow{id: 22, permissionId: 4})
			database.On(save.deleteMethod, mock.Anything, grantsTx, int64(21)).Return(nil).Once()
			database.On(save.createMethod, mock.Anything, grantsTx, mock.Anything).Return(nil).Times(3)
			records := recordLoggedEvents(auditLogger)

			// Grants manage, admin-read and an ordinary permission, keeps another, and revokes
			// manage-users.
			rr := save.serveWithScope(database, auditLogger,
				save.body(t, []int64{permManage, permAdminRead, 6, 4}, []int64{permManageUsers, 4}), "authserver:manage")

			require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
			database.AssertExpectations(t)
			want := append(save.existingEvents(3, 1), "administrative_permission_changed", "administrative_permission_changed")
			assert.Equal(t, want, eventNames(*records), "beside the save's own records, after them, one per direction")
			assert.Equal(t, []map[string]interface{}{
				{
					"change":                 "granted",
					"target_kind":            save.kind,
					"target_id":              grantOwnerId,
					"permission_identifiers": []string{"authserver:manage", "authserver:admin-read"},
					"logged_in_user":         grantCaller,
				},
				{
					"change":                 "revoked",
					"target_kind":            save.kind,
					"target_id":              grantOwnerId,
					"permission_identifiers": []string{"authserver:manage-users"},
					"logged_in_user":         grantCaller,
				},
			}, administrativeChanges(*records))
		})
	}
}

// Granting or revoking only permissions that are not administrative, manage-account, an
// operator's custom authserver permission and another resource's, writes the save's own records
// and nothing beside them.
func TestAdministrativePermissionChanged_AnOrdinaryChangeIsNotRecorded(t *testing.T) {
	for _, save := range grantSaves {
		t.Run(save.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)

			save.expectOwner(database)
			expectPermissionsExist(database, permManageAccount, permCustomOnAuthServer)
			expectAuthServerPermissions(database)
			datamocks.ExpectRunInTransaction(database, grantsTx)
			save.expectStored(database, grantRow{id: 21, permissionId: 4})
			database.On(save.deleteMethod, mock.Anything, grantsTx, int64(21)).Return(nil).Once()
			database.On(save.createMethod, mock.Anything, grantsTx, mock.Anything).Return(nil).Twice()
			records := recordLoggedEvents(auditLogger)

			rr := save.serveWithScope(database, auditLogger,
				save.body(t, []int64{permManageAccount, permCustomOnAuthServer}, []int64{4}), "authserver:manage")

			require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
			database.AssertExpectations(t)
			assert.Equal(t, save.existingEvents(2, 1), eventNames(*records))
		})
	}
}

// The client permission save's one record names the permissions it granted and those it revoked,
// so a grant of authserver:manage to a client says which permission it was. Both are lists, empty
// when the save changed nothing in that direction.
func TestAdministrativePermissionChanged_TheClientRecordNamesWhatTheSaveChanged(t *testing.T) {
	save := grantSaves[2]
	require.Equal(t, "client permissions", save.name)

	clientRecord := func(t *testing.T, records []loggedEvent) map[string]interface{} {
		t.Helper()
		for _, r := range records {
			if r.event == audit.EventUpdatedClientPermissions {
				return r.details
			}
		}
		t.Fatalf("no %s record among %v", audit.EventUpdatedClientPermissions, eventNames(records))
		return nil
	}

	t.Run("a grant and a revocation", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		auditLogger := handlersmocks.NewAuditLogger(t)

		save.expectOwner(database)
		expectPermissionsExist(database, permManage, 6)
		expectAuthServerPermissions(database)
		datamocks.ExpectRunInTransaction(database, grantsTx)
		save.expectStored(database, grantRow{id: 21, permissionId: 3}, grantRow{id: 22, permissionId: 6})
		database.On(save.deleteMethod, mock.Anything, grantsTx, int64(21)).Return(nil).Once()
		database.On(save.createMethod, mock.Anything, grantsTx, mock.Anything).Return(nil).Once()
		records := recordLoggedEvents(auditLogger)

		rr := save.serveWithScope(database, auditLogger, save.body(t, []int64{permManage, 6}, []int64{3, 6}), "authserver:manage")

		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		assert.Equal(t, map[string]interface{}{
			"client_id":              grantOwnerId,
			"granted_permission_ids": []int64{permManage},
			"revoked_permission_ids": []int64{3},
			"logged_in_user":         grantCaller,
		}, clientRecord(t, *records))
	})

	t.Run("nothing changed", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		auditLogger := handlersmocks.NewAuditLogger(t)

		save.expectOwner(database)
		expectPermissionsExist(database, 6)
		datamocks.ExpectRunInTransaction(database, grantsTx)
		save.expectStored(database, grantRow{id: 22, permissionId: 6})
		records := recordLoggedEvents(auditLogger)

		rr := save.serveWithScope(database, auditLogger, save.body(t, []int64{6}, []int64{6}), "authserver:manage")

		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		assert.Equal(t, []string{audit.EventUpdatedClientPermissions}, eventNames(*records))
		details := clientRecord(t, *records)
		assert.Equal(t, []int64{}, details["granted_permission_ids"])
		assert.Equal(t, []int64{}, details["revoked_permission_ids"])
		assertNotAttemptedOnClientDatabase(t, database, "GetResourceByResourceIdentifier", "GetPermissionsByResourceId")
	})
}

// An authserver:manage save that changes anything reads the administrative set before its
// transaction, to know which records it owes. That read failing is one 500 with no transaction
// opened and nothing recorded, so a change is never committed without the record it owes.
func TestAdministrativePermissionChanged_AFailedReadOfTheAdministrativeSetIsOneFiveHundred(t *testing.T) {
	for _, save := range grantSaves {
		t.Run(save.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)

			save.expectOwner(database)
			expectPermissionsExist(database, permManage)
			database.On("GetResourceByResourceIdentifier", mock.Anything, (*sql.Tx)(nil), "authserver").
				Return(nil, errors.New("the read failed")).Once()

			rr := save.serveWithScope(database, auditLogger, save.body(t, []int64{permManage}, []int64{}), "authserver:manage")

			assert.Equal(t, http.StatusInternalServerError, rr.Code)
			assert.Equal(t, 1, strings.Count(rr.Body.String(), "INTERNAL_SERVER_ERROR"), "exactly one error response")
			database.AssertExpectations(t)
			assertNotAttemptedOnClientDatabase(t, database, "RunInTransaction")
			auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// authserver:manage moves a user into and out of an administrative group by every membership
// route, and each move writes the route's own record and then one administrative_permission_changed
// naming the user, the group, and the administrative permissions the group holds, not its other
// one.
func TestAdministrativePermissionChanged_MovingAUserThroughAnAdministrativeGroupIsRecorded(t *testing.T) {
	for _, change := range membershipChanges {
		if change.change == "" {
			continue
		}
		t.Run(change.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)

			change.expectReads(database, administrativeGroupId, false)
			if change.expectAlertReads != nil {
				change.expectAlertReads(database, administrativeGroupId)
			}
			change.expectWrite(t, database, auditLogger, administrativeGroupId)
			var changes []map[string]interface{}
			auditLogger.On("Log", mock.Anything, "administrative_permission_changed", mock.Anything).
				Run(func(args mock.Arguments) { changes = append(changes, args.Get(2).(map[string]interface{})) }).
				Return().Once()

			rr := change.serve(database, auditLogger, administrativeGroupId, "authserver:manage-users authserver:manage")

			require.Less(t, rr.Code, 300, rr.Body.String())
			database.AssertExpectations(t)
			auditLogger.AssertExpectations(t)
			assert.Equal(t, []map[string]interface{}{{
				"change":                 change.change,
				"target_kind":            "user",
				"target_id":              ceilingMemberId,
				"group_id":               administrativeGroupId,
				"permission_identifiers": []string{"authserver:manage"},
				"logged_in_user":         grantCaller,
			}}, changes)
			assert.Equal(t, "administrative_permission_changed", auditLogger.Calls[len(auditLogger.Calls)-1].Arguments.String(1),
				"written after the route's own record")
		})
	}
}

// Deleting an administrative group keeps its own deleted_group record, and is not doubled by an
// administrative_permission_changed one; an authserver:manage deletion reads nothing for the policy.
func TestAdministrativePermissionChanged_DeletingAnAdministrativeGroupKeepsItsOwnRecordAlone(t *testing.T) {
	var deletion membershipChange
	for _, change := range membershipChanges {
		if change.targetKind == targetKindGroup {
			deletion = change
		}
	}
	require.NotNil(t, deletion.serve)

	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	deletion.expectReads(database, administrativeGroupId, false)
	deletion.expectWrite(t, database, auditLogger, administrativeGroupId)

	rr := deletion.serve(database, auditLogger, administrativeGroupId, "authserver:manage")

	require.Less(t, rr.Code, 300, rr.Body.String())
	database.AssertExpectations(t)
	auditLogger.AssertExpectations(t)
	assertNoPolicyRead(t, database)
}

// A save of a user's groups that joins an ordinary and an administrative group and leaves another
// administrative one writes its own record for each membership, then one
// administrative_permission_changed for the administrative group joined and one for the one left.
// What the groups hold is read on the save's transaction, so it is what the committed attempt saw.
func TestAdministrativePermissionChanged_AUserGroupsSaveRecordsEachAdministrativeGroupItChanges(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	expectMember(database)
	database.On("GetGroupsByIds", mock.Anything, (*sql.Tx)(nil), []int64{ordinaryGroupId, administrativeGroupId}).
		Return([]record.Group{{Id: ordinaryGroupId}, {Id: administrativeGroupId}}, nil).Once()
	datamocks.ExpectRunInTransaction(database, userGroupsTx)
	expectAdministratorsLock(database, userGroupsTx)
	expectStoredMemberships(database, membershipRow{id: ceilingMembershipRowId, groupId: adminReadGroupId})
	expectGuardOfGroup(database, userGroupsTx, adminReadGroupId)
	database.On("DeleteUserGroup", mock.Anything, userGroupsTx, ceilingMembershipRowId).Return(nil).Once()
	database.On("CreateUserGroup", mock.Anything, userGroupsTx, mock.Anything).Return(nil).Twice()
	expectGroupPermissionsOn(database, userGroupsTx, ordinaryGroupId, administrativeGroupId, adminReadGroupId)
	expectAuthServerPermissionsOn(database, userGroupsTx)
	expectReload(database, nil)
	records := recordLoggedEvents(auditLogger)

	body := `{"groupIds":[8,7],"expectedGroupIds":[9]}`
	r := membershipRequest(http.MethodPut, "/api/v1/admin/users/42/groups", body, "authserver:manage", map[string]string{"id": "42"})
	rr := httptest.NewRecorder()
	HandleUserGroupsPut(database, auditLogger).ServeHTTP(rr, r)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	database.AssertExpectations(t)
	assert.Equal(t, []string{
		audit.EventUserAddedToGroup, audit.EventUserAddedToGroup, audit.EventUserRemovedFromGroup,
		"administrative_permission_changed", "administrative_permission_changed",
	}, eventNames(*records))
	assert.Equal(t, []map[string]interface{}{
		{
			"change":                 "granted",
			"target_kind":            "user",
			"target_id":              ceilingMemberId,
			"group_id":               administrativeGroupId,
			"permission_identifiers": []string{"authserver:manage"},
			"logged_in_user":         grantCaller,
		},
		{
			"change":                 "revoked",
			"target_kind":            "user",
			"target_id":              ceilingMemberId,
			"group_id":               adminReadGroupId,
			"permission_identifiers": []string{"authserver:admin-read"},
			"logged_in_user":         grantCaller,
		},
	}, administrativeChanges(*records))
}

// What the changed groups hold failing to read on the save's transaction undoes the save: one 500,
// nothing recorded, so a membership is never committed without the record it owes.
func TestAdministrativePermissionChanged_AFailedReadInTheUserGroupsSaveCommitsNothing(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	expectMember(database)
	database.On("GetGroupsByIds", mock.Anything, (*sql.Tx)(nil), []int64{administrativeGroupId}).
		Return([]record.Group{{Id: administrativeGroupId}}, nil).Once()
	stub := datamocks.ExpectRunInTransaction(database, userGroupsTx)
	expectAdministratorsLock(database, userGroupsTx)
	expectStoredMemberships(database)
	database.On("CreateUserGroup", mock.Anything, userGroupsTx, mock.Anything).Return(nil).Once()
	readErr := errors.New("the read failed")
	database.On("GetGroupPermissionsByGroupIds", mock.Anything, userGroupsTx, []int64{administrativeGroupId}).Return(nil, readErr).Once()

	body := `{"groupIds":[7],"expectedGroupIds":[]}`
	r := membershipRequest(http.MethodPut, "/api/v1/admin/users/42/groups", body, "authserver:manage", map[string]string{"id": "42"})
	rr := httptest.NewRecorder()
	HandleUserGroupsPut(database, auditLogger).ServeHTTP(rr, r)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Equal(t, 1, strings.Count(rr.Body.String(), "INTERNAL_SERVER_ERROR"), "exactly one error response")
	require.ErrorIs(t, stub.BodyErr, readErr, "the body hands the error to the helper, which rolls back")
	database.AssertExpectations(t)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}
