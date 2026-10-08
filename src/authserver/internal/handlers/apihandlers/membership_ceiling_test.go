package apihandlers

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The grant ceiling on group membership and group deletion: joining or leaving a group that holds
// an administrative permission grants or revokes it, so only an authserver:manage token moves a
// user into or out of such a group, by either membership route, or deletes one. A granular token
// is refused 403 MANAGE_SCOPE_REQUIRED before any write, with one administrator_change_refused
// record, and keeps full control of every other group (#402 decisions 1, 2, 4 and 5).

// The groups the cases move a user into and out of. The administrative group holds manage beside a
// permission of another resource; the ordinary one holds manage-account and an operator's custom
// authserver permission, neither of them administrative. A third administrative group holds
// admin-read alone.
const (
	ceilingMemberId        = int64(42)
	administrativeGroupId  = int64(7)
	ordinaryGroupId        = int64(8)
	adminReadGroupId       = int64(9)
	ceilingMembershipRowId = int64(31)
)

// groupPermissionRows is what each case group holds.
var groupPermissionRows = map[int64][]int64{
	administrativeGroupId: {6, permManage},
	ordinaryGroupId:       {permManageAccount, permCustomOnAuthServer},
	adminReadGroupId:      {permAdminRead},
}

// expectGroupPermissions registers the policy's one read of what the groups it judges hold,
// outside any transaction.
func expectGroupPermissions(database *datamocks.Database, groupIds ...int64) {
	expectGroupPermissionsOn(database, nil, groupIds...)
}

// expectGroupPermissionsOn registers the same read on tx.
func expectGroupPermissionsOn(database *datamocks.Database, tx *sql.Tx, groupIds ...int64) {
	var rows []record.GroupPermission
	for _, groupId := range groupIds {
		for _, permissionId := range groupPermissionRows[groupId] {
			rows = append(rows, record.GroupPermission{GroupId: groupId, PermissionId: permissionId})
		}
	}
	database.On("GetGroupPermissionsByGroupIds", mock.Anything, tx, groupIds).Return(rows, nil).Once()
}

// membershipRequest builds a request for one of the routes, with chi's URL parameters set and a
// validated token carrying scope, or none when scope is empty.
func membershipRequest(method, target, body string, scope string, params map[string]string) *http.Request {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	routeContext := chi.NewRouteContext()
	for key, value := range params {
		routeContext.URLParams.Add(key, value)
	}
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, routeContext))
	if scope != "" {
		r = setTokenContextWithClaims(r, map[string]interface{}{"scope": scope, "sub": grantCaller})
	}
	return r
}

// membershipChange is one of the five writes the ceiling guards, against a given group.
type membershipChange struct {
	name string
	// serve runs the write against group, as a caller holding scope.
	serve func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, group int64, scope string) *httptest.ResponseRecorder
	// expectReads registers the reads the write makes before the ceiling judges it. granular says
	// whether the caller is held to the ceiling, which reads what it needs to judge.
	expectReads func(database *datamocks.Database, group int64, granular bool)
	// writes is every write the route makes, none of which a refusal may reach.
	writes []string
	// expectWrite registers the write and its audit record for a write that proceeds.
	expectWrite func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, group int64)
	// targetKind is the target a refusal names: the user whose memberships change, or the group.
	targetKind string
	// namesGroups says whether a refusal names the groups that caused it beside its target.
	namesGroups bool
	// change is what the write does to the permissions the group holds, as an
	// administrative_permission_changed record names it: granted for joining, revoked for leaving,
	// and empty for a deletion, which keeps its own record alone.
	change string
	// expectAlertReads registers what an authserver:manage caller's write reads, outside its
	// write, to know whether the group is administrative. A save of the user's groups reads it on
	// its transaction, as part of expectWrite.
	expectAlertReads func(database *datamocks.Database, group int64)
}

// expectAlertReadsOutsideTheWrite registers the read of what the group holds and of the
// administrative set, outside any transaction.
func expectAlertReadsOutsideTheWrite(database *datamocks.Database, group int64) {
	expectGroupPermissions(database, group)
	expectAuthServerPermissions(database)
}

func (c membershipChange) targetId(group int64) int64 {
	if c.targetKind == targetKindGroup {
		return group
	}
	return ceilingMemberId
}

// expectMember registers the member read every membership route makes before the ceiling.
func expectMember(database *datamocks.Database) {
	database.On("GetUserById", mock.Anything, (*sql.Tx)(nil), ceilingMemberId).
		Return(&record.User{Id: ceilingMemberId, Subject: "sub-42"}, nil).Once()
}

func expectGroup(database *datamocks.Database, group int64) {
	database.On("GetGroupById", mock.Anything, (*sql.Tx)(nil), group).
		Return(&record.Group{Id: group, GroupIdentifier: "g"}, nil).Once()
}

func expectAudit(auditLogger *handlersmocks.AuditLogger, event string) {
	auditLogger.On("Log", mock.Anything, event, mock.Anything).Return().Once()
}

var membershipChanges = []membershipChange{
	{
		name: "PUT /users/{id}/groups joining",
		serve: func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, group int64, scope string) *httptest.ResponseRecorder {
			body := `{"groupIds":[` + itoa(group) + `],"expectedGroupIds":[]}`
			r := membershipRequest(http.MethodPut, "/api/v1/admin/users/42/groups", body, scope, map[string]string{"id": "42"})
			rr := httptest.NewRecorder()
			HandleUserGroupsPut(database, auditLogger).ServeHTTP(rr, r)
			return rr
		},
		expectReads: func(database *datamocks.Database, group int64, _ bool) {
			expectMember(database)
			database.On("GetGroupsByIds", mock.Anything, (*sql.Tx)(nil), []int64{group}).
				Return([]record.Group{{Id: group, GroupIdentifier: "g"}}, nil).Once()
		},
		writes: []string{"RunInTransaction", "CreateUserGroup", "DeleteUserGroup"},
		expectWrite: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, group int64) {
			datamocks.ExpectRunInTransaction(database, userGroupsTx)
			expectAdministratorsLock(database, userGroupsTx)
			expectStoredMemberships(database)
			database.On("CreateUserGroup", mock.Anything, userGroupsTx, mock.MatchedBy(func(ug *record.UserGroup) bool {
				return ug.UserId == ceilingMemberId && ug.GroupId == group
			})).Return(nil).Once()
			expectGroupPermissionsOn(database, userGroupsTx, group)
			expectAuthServerPermissionsOn(database, userGroupsTx)
			expectAudit(auditLogger, audit.EventUserAddedToGroup)
			expectReload(database, nil)
		},
		targetKind:  targetKindUser,
		namesGroups: true,
		change:      "granted",
	},
	{
		name: "PUT /users/{id}/groups leaving",
		serve: func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, group int64, scope string) *httptest.ResponseRecorder {
			body := `{"groupIds":[],"expectedGroupIds":[` + itoa(group) + `]}`
			r := membershipRequest(http.MethodPut, "/api/v1/admin/users/42/groups", body, scope, map[string]string{"id": "42"})
			rr := httptest.NewRecorder()
			HandleUserGroupsPut(database, auditLogger).ServeHTTP(rr, r)
			return rr
		},
		expectReads: func(database *datamocks.Database, group int64, granular bool) {
			expectMember(database)
			if granular {
				// What the user belongs to, read to judge only the memberships the save can remove.
				database.On("GetUserGroupsByUserId", mock.Anything, (*sql.Tx)(nil), ceilingMemberId).
					Return([]record.UserGroup{{Id: ceilingMembershipRowId, UserId: ceilingMemberId, GroupId: group}}, nil).Once()
			}
		},
		writes: []string{"RunInTransaction", "CreateUserGroup", "DeleteUserGroup"},
		expectWrite: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, group int64) {
			datamocks.ExpectRunInTransaction(database, userGroupsTx)
			expectAdministratorsLock(database, userGroupsTx)
			expectStoredMemberships(database, membershipRow{id: ceilingMembershipRowId, groupId: group})
			expectGuardOfGroup(database, userGroupsTx, group)
			database.On("DeleteUserGroup", mock.Anything, userGroupsTx, ceilingMembershipRowId).Return(nil).Once()
			expectGroupPermissionsOn(database, userGroupsTx, group)
			expectAuthServerPermissionsOn(database, userGroupsTx)
			expectAudit(auditLogger, audit.EventUserRemovedFromGroup)
			expectReload(database, nil)
		},
		targetKind:  targetKindUser,
		namesGroups: true,
		change:      "revoked",
	},
	{
		name: "POST /groups/{id}/members",
		serve: func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, group int64, scope string) *httptest.ResponseRecorder {
			r := membershipRequest(http.MethodPost, "/api/v1/admin/groups/"+itoa(group)+"/members", `{"userId":42}`, scope,
				map[string]string{"id": itoa(group)})
			rr := httptest.NewRecorder()
			HandleGroupMemberAddPost(database, auditLogger).ServeHTTP(rr, r)
			return rr
		},
		expectReads: func(database *datamocks.Database, group int64, _ bool) {
			expectGroup(database, group)
			expectMember(database)
			database.On("GetUserGroupByUserIdAndGroupId", mock.Anything, (*sql.Tx)(nil), ceilingMemberId, group).
				Return((*record.UserGroup)(nil), nil).Once()
		},
		writes: []string{"CreateUserGroup"},
		expectWrite: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, group int64) {
			database.On("CreateUserGroup", mock.Anything, (*sql.Tx)(nil), mock.MatchedBy(func(ug *record.UserGroup) bool {
				return ug.UserId == ceilingMemberId && ug.GroupId == group
			})).Return(nil).Once()
			expectAudit(auditLogger, audit.EventUserAddedToGroup)
		},
		targetKind:       targetKindUser,
		namesGroups:      true,
		change:           "granted",
		expectAlertReads: expectAlertReadsOutsideTheWrite,
	},
	{
		name: "DELETE /groups/{id}/members/{userId}",
		serve: func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, group int64, scope string) *httptest.ResponseRecorder {
			r := membershipRequest(http.MethodDelete, "/api/v1/admin/groups/"+itoa(group)+"/members/42", "", scope,
				map[string]string{"id": itoa(group), "userId": "42"})
			rr := httptest.NewRecorder()
			HandleGroupMemberDelete(database, auditLogger).ServeHTTP(rr, r)
			return rr
		},
		expectReads: func(database *datamocks.Database, group int64, _ bool) {
			expectGroup(database, group)
			expectMember(database)
			database.On("GetUserGroupByUserIdAndGroupId", mock.Anything, (*sql.Tx)(nil), ceilingMemberId, group).
				Return(&record.UserGroup{Id: ceilingMembershipRowId, UserId: ceilingMemberId, GroupId: group}, nil).Once()
		},
		writes: []string{"RunInTransaction", "DeleteUserGroup"},
		expectWrite: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, group int64) {
			datamocks.ExpectRunInTransaction(database, guardTx)
			expectAdministratorsLock(database, guardTx)
			expectGuardOfGroup(database, guardTx, group)
			database.On("DeleteUserGroup", mock.Anything, guardTx, ceilingMembershipRowId).Return(nil).Once()
			expectAudit(auditLogger, audit.EventUserRemovedFromGroup)
		},
		targetKind:       targetKindUser,
		namesGroups:      true,
		change:           "revoked",
		expectAlertReads: expectAlertReadsOutsideTheWrite,
	},
	{
		name: "DELETE /groups/{id}",
		serve: func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, group int64, scope string) *httptest.ResponseRecorder {
			r := membershipRequest(http.MethodDelete, "/api/v1/admin/groups/"+itoa(group), "", scope, map[string]string{"id": itoa(group)})
			rr := httptest.NewRecorder()
			HandleGroupDelete(database, auditLogger).ServeHTTP(rr, r)
			return rr
		},
		expectReads: func(database *datamocks.Database, group int64, _ bool) {
			expectGroup(database, group)
		},
		writes: []string{"RunInTransaction", "DeleteGroup"},
		expectWrite: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, group int64) {
			datamocks.ExpectRunInTransaction(database, guardTx)
			expectAdministratorsLock(database, guardTx)
			expectGuardOfGroup(database, guardTx, group)
			database.On("DeleteGroup", mock.Anything, guardTx, group).Return(nil).Once()
			expectAudit(auditLogger, audit.EventDeletedGroup)
		},
		targetKind: targetKindGroup,
	},
}

func itoa(id int64) string {
	return strconv.FormatInt(id, 10)
}

// assertNoPolicyRead holds a path to reading nothing for the policy: neither the groups' grants nor
// the administrative set, nor the user's memberships outside the save's transaction.
func assertNoPolicyRead(t *testing.T, database *datamocks.Database) {
	t.Helper()
	assertNotAttemptedOnClientDatabase(t, database, "GetResourceByResourceIdentifier", "GetPermissionsByResourceId")
	for _, call := range database.Calls {
		// What a group holds is read on a write's transaction by the last-administrator guard,
		// which is no read for the policy (#402 decision 11); outside any transaction it is.
		if call.Method == "GetGroupPermissionsByGroupIds" && call.Arguments.Get(1) == (*sql.Tx)(nil) {
			t.Errorf("what the groups hold was read outside any transaction for the policy")
		}
		if call.Method == "GetUserGroupsByUserId" && call.Arguments.Get(1) == (*sql.Tx)(nil) {
			t.Errorf("the user's memberships were read outside the save's transaction for the policy")
		}
	}
}

func TestMembershipCeiling_AGranularTokenMovingAUserThroughAnAdministrativeGroupIsRefused(t *testing.T) {
	for _, change := range membershipChanges {
		t.Run(change.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)

			change.expectReads(database, administrativeGroupId, true)
			expectGroupPermissions(database, administrativeGroupId)
			expectAuthServerPermissions(database)
			records := recordLoggedEvents(auditLogger)

			rr := change.serve(database, auditLogger, administrativeGroupId, "authserver:manage-users")

			status := rr.Code
			code, description := decodeErrorEnvelope(t, rr)
			assertManageScopeRequired(t, rr, status, code, description)
			database.AssertExpectations(t)
			assertNotAttemptedOnClientDatabase(t, database, change.writes...)

			require.Len(t, *records, 1, "one record per refused request")
			refusal := (*records)[0]
			assert.Equal(t, "administrator_change_refused", refusal.event)
			assert.Equal(t, grantCaller, refusal.details["logged_in_user"])
			assert.Contains(t, refusal.details, "method")
			assert.Contains(t, refusal.details, "route")
			assert.Equal(t, "grant", refusal.details["ceiling"])
			assert.Equal(t, change.targetKind, refusal.details["target_kind"])
			assert.Equal(t, change.targetId(administrativeGroupId), refusal.details["target_id"])
			assert.Equal(t, []int64{permManage}, refusal.details["permission_ids"], "the administrative permission the group holds, and not its other one")
			if change.namesGroups {
				assert.Equal(t, []int64{administrativeGroupId}, refusal.details["group_ids"])
			} else {
				assert.NotContains(t, refusal.details, "group_ids")
			}
		})
	}
}

// Every token below authserver:manage is held to the ceiling, and so is a request that reached the
// handler with no validated token at all: the policy fails closed.
func TestMembershipCeiling_EveryOtherCallerIsHeldToIt(t *testing.T) {
	callers := []struct {
		name  string
		scope string
	}{
		{name: "admin-read", scope: "authserver:admin-read"},
		{name: "two granular scopes", scope: "authserver:manage-users authserver:manage-clients"},
		{name: "no validated token", scope: ""},
	}

	for _, change := range membershipChanges {
		for _, caller := range callers {
			t.Run(change.name+"/"+caller.name, func(t *testing.T) {
				database := datamocks.NewDatabase(t)
				auditLogger := handlersmocks.NewAuditLogger(t)

				change.expectReads(database, adminReadGroupId, true)
				expectGroupPermissions(database, adminReadGroupId)
				expectAuthServerPermissions(database)
				records := recordLoggedEvents(auditLogger)

				rr := change.serve(database, auditLogger, adminReadGroupId, caller.scope)

				status := rr.Code
				code, description := decodeErrorEnvelope(t, rr)
				assertManageScopeRequired(t, rr, status, code, description)
				assertNotAttemptedOnClientDatabase(t, database, change.writes...)
				require.Len(t, *records, 1)
				assert.Equal(t, "administrator_change_refused", (*records)[0].event)
				assert.Equal(t, []int64{permAdminRead}, (*records)[0].details["permission_ids"])
			})
		}
	}
}

// A granular token keeps moving users into and out of every group that holds no administrative
// permission, and deleting it: manage-account and a custom authserver permission are not
// administrative. The write and its record are as before.
func TestMembershipCeiling_AGranularTokenChangingAnOrdinaryGroupProceeds(t *testing.T) {
	for _, change := range membershipChanges {
		t.Run(change.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)

			change.expectReads(database, ordinaryGroupId, true)
			expectGroupPermissions(database, ordinaryGroupId)
			expectAuthServerPermissions(database)
			if change.targetKind == targetKindUser {
				// The target ceiling's reads of the user moved, who holds nothing of their own.
				expectHoldsNothing(database, ceilingMemberId)
			}
			change.expectWrite(t, database, auditLogger, ordinaryGroupId)

			rr := change.serve(database, auditLogger, ordinaryGroupId, "authserver:manage-users")

			assert.Less(t, rr.Code, 300, rr.Body.String())
			assert.Empty(t, rr.Header().Get("WWW-Authenticate"))
			database.AssertExpectations(t)
			auditLogger.AssertNotCalled(t, "Log", mock.Anything, audit.EventAdministratorChangeRefused, mock.Anything)
		})
	}
}

// The policy failing to read what it judges is one 500, with no write and no record: a change the
// policy could not judge is not let through.
func TestMembershipCeiling_AFailedPolicyReadIsOneFiveHundred(t *testing.T) {
	for _, change := range membershipChanges {
		t.Run(change.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)

			change.expectReads(database, administrativeGroupId, true)
			database.On("GetGroupPermissionsByGroupIds", mock.Anything, (*sql.Tx)(nil), []int64{administrativeGroupId}).
				Return(nil, errors.New("the read failed")).Once()

			rr := change.serve(database, auditLogger, administrativeGroupId, "authserver:manage-users")

			assert.Equal(t, http.StatusInternalServerError, rr.Code)
			assert.Equal(t, 1, strings.Count(rr.Body.String(), "INTERNAL_SERVER_ERROR"), "exactly one error response")
			database.AssertExpectations(t)
			assertNotAttemptedOnClientDatabase(t, database, change.writes...)
			auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// The refusal comes after the request's 400 answers: adding a member who is already in the group,
// or removing one who is not, is answered as before, with nothing read for the policy and nothing
// audited.
func TestMembershipCeiling_TheMembershipRoutesAnswerTheirOwnFourHundredFirst(t *testing.T) {
	t.Run("adding a member already in the group", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		expectGroup(database, administrativeGroupId)
		expectMember(database)
		database.On("GetUserGroupByUserIdAndGroupId", mock.Anything, (*sql.Tx)(nil), ceilingMemberId, administrativeGroupId).
			Return(&record.UserGroup{Id: ceilingMembershipRowId}, nil).Once()

		r := membershipRequest(http.MethodPost, "/api/v1/admin/groups/7/members", `{"userId":42}`, "authserver:manage-users", map[string]string{"id": "7"})
		rr := httptest.NewRecorder()
		HandleGroupMemberAddPost(database, auditLogger).ServeHTTP(rr, r)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		database.AssertExpectations(t)
		assertNoPolicyRead(t, database)
		auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("removing a member not in the group", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		expectGroup(database, administrativeGroupId)
		expectMember(database)
		database.On("GetUserGroupByUserIdAndGroupId", mock.Anything, (*sql.Tx)(nil), ceilingMemberId, administrativeGroupId).
			Return((*record.UserGroup)(nil), nil).Once()

		r := membershipRequest(http.MethodDelete, "/api/v1/admin/groups/7/members/42", "", "authserver:manage-users",
			map[string]string{"id": "7", "userId": "42"})
		rr := httptest.NewRecorder()
		HandleGroupMemberDelete(database, auditLogger).ServeHTTP(rr, r)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		database.AssertExpectations(t)
		assertNoPolicyRead(t, database)
		auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
	})
}

// A save of a user's groups is judged on what it changes: the groups it adds, and the groups it
// removes from those the user belongs to. Joining an ordinary group beside an administrative one,
// and leaving an administrative one, is refused naming the two administrative groups and what they
// hold.
func TestMembershipCeiling_AUserGroupsSaveIsJudgedOnEveryGroupItChanges(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	expectMember(database)
	database.On("GetGroupsByIds", mock.Anything, (*sql.Tx)(nil), []int64{ordinaryGroupId, administrativeGroupId}).
		Return([]record.Group{{Id: ordinaryGroupId}, {Id: administrativeGroupId}}, nil).Once()
	database.On("GetUserGroupsByUserId", mock.Anything, (*sql.Tx)(nil), ceilingMemberId).
		Return([]record.UserGroup{{Id: ceilingMembershipRowId, UserId: ceilingMemberId, GroupId: adminReadGroupId}}, nil).Once()
	expectGroupPermissions(database, ordinaryGroupId, administrativeGroupId, adminReadGroupId)
	expectAuthServerPermissions(database)
	records := recordLoggedEvents(auditLogger)

	body := `{"groupIds":[8,7],"expectedGroupIds":[9]}`
	r := membershipRequest(http.MethodPut, "/api/v1/admin/users/42/groups", body, "authserver:manage-users", map[string]string{"id": "42"})
	rr := httptest.NewRecorder()
	HandleUserGroupsPut(database, auditLogger).ServeHTTP(rr, r)

	assert.Equal(t, http.StatusForbidden, rr.Code)
	database.AssertExpectations(t)
	assertNotAttemptedOnClientDatabase(t, database, "RunInTransaction", "CreateUserGroup", "DeleteUserGroup")
	require.Len(t, *records, 1)
	assert.Equal(t, []int64{administrativeGroupId, adminReadGroupId}, (*records)[0].details["group_ids"])
	assert.Equal(t, []int64{permManage, permAdminRead}, (*records)[0].details["permission_ids"])
}

// A removal the user's stored memberships do not hold removes nothing if the save commits, since
// the save's transaction refuses unless the stored memberships are the loaded list. It is not read
// for the policy, so a loaded list of any length costs the policy nothing, and the save meets its
// 409 as before.
func TestMembershipCeiling_ARemovalTheUserDoesNotHoldIsLeftToTheSavesConflict(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	expectMember(database)
	database.On("GetUserGroupsByUserId", mock.Anything, (*sql.Tx)(nil), ceilingMemberId).Return([]record.UserGroup{}, nil).Once()
	expectHoldsNothing(database, ceilingMemberId)
	datamocks.ExpectRunInTransaction(database, userGroupsTx)
	expectAdministratorsLock(database, userGroupsTx)
	expectStoredMemberships(database)

	body := `{"groupIds":[],"expectedGroupIds":[7]}`
	r := membershipRequest(http.MethodPut, "/api/v1/admin/users/42/groups", body, "authserver:manage-users", map[string]string{"id": "42"})
	rr := httptest.NewRecorder()
	HandleUserGroupsPut(database, auditLogger).ServeHTTP(rr, r)

	assert.Equal(t, http.StatusConflict, rr.Code)
	code, _ := decodeErrorEnvelope(t, rr)
	assert.Equal(t, "CONCURRENT_UPDATE", code)
	database.AssertExpectations(t)
	assertNotAttemptedOnClientDatabase(t, database, "GetGroupPermissionsByGroupIds", "DeleteUserGroup", "CreateUserGroup")
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}
