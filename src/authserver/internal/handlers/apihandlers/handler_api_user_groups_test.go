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
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Seam 4 of #425 for the user's groups: both endpoints swallowed a failed count and published 0.
// requireCountFailureAnswered500 is handler_api_groups_test.go's.

// loadGroupsOnto answers UserLoadGroups by setting the user's groups, as commondb does.
func loadGroupsOnto(groups ...models.Group) func(mock.Arguments) {
	return func(args mock.Arguments) {
		args.Get(2).(*models.User).Groups = groups
	}
}

// usergroups/get-count.
func TestHandleAPIUserGroupsGet_AFailedCountAnswers500(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	database.On("GetUserById", mock.Anything, mock.Anything, int64(42)).
		Return(&models.User{Id: 42, Subject: "sub-42"}, nil).Once()
	database.On("UserLoadGroups", mock.Anything, mock.Anything, mock.Anything).
		Run(loadGroupsOnto(models.Group{Id: 5, GroupIdentifier: "admins"})).Return(nil).Once()
	database.On("CountGroupMembers", mock.Anything, mock.Anything, int64(5)).Return(0, errCountFailed).Once()

	capture := testutil.CaptureSlog(t)
	rr := httptest.NewRecorder()
	HandleAPIUserGroupsGet(database).ServeHTTP(rr, apiIdRequest("/api/v1/admin/users/42/groups", "42"))

	requireCountFailureAnswered500(t, rr, capture, 5)
	require.Equal(t, int64(42), capture.Records()[0].Attrs["user_id"])
}

// usergroups/put-count: the membership is committed and audited before the response is counted,
// so the 500 answers a request whose effect stands. What the case pins is that the response does
// not then claim the group has no members.
func TestHandleAPIUserGroupsPut_AFailedCountAnswers500(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	database.On("GetUserById", mock.Anything, mock.Anything, int64(42)).
		Return(&models.User{Id: 42, Subject: "sub-42"}, nil).Once()
	database.On("GetGroupsByIds", mock.Anything, mock.Anything, []int64{5}).
		Return([]models.Group{{Id: 5, GroupIdentifier: "admins"}}, nil).Once()
	// The user holds no group before the request and the one it names after it.
	mocks_data.ExpectRunInTransaction(database, userGroupsTx)
	database.On("GetUserGroupsByUserId", mock.Anything, userGroupsTx, int64(42)).Return([]models.UserGroup{}, nil).Once()
	database.On("CreateUserGroup", mock.Anything, userGroupsTx, mock.Anything).Return(nil).Once()
	auditLogger.On("Log", mock.Anything, audit.AuditUserAddedToGroup, mock.Anything).Return().Once()
	database.On("UserLoadGroups", mock.Anything, mock.Anything, mock.Anything).
		Run(loadGroupsOnto(models.Group{Id: 5, GroupIdentifier: "admins"})).Return(nil).Once()
	database.On("CountGroupMembers", mock.Anything, mock.Anything, int64(5)).Return(0, errCountFailed).Once()

	body, err := json.Marshal(api.UpdateUserGroupsRequest{GroupIds: []int64{5}, ExpectedGroupIds: []int64{}})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/users/42/groups", bytes.NewReader(body))
	req = setChiURLParam(req, "id", "42")

	capture := testutil.CaptureSlog(t)
	rr := httptest.NewRecorder()
	HandleAPIUserGroupsPut(database, auditLogger).ServeHTTP(rr, req)

	requireCountFailureAnswered500(t, rr, capture, 5)
	require.Equal(t, int64(42), capture.Records()[0].Attrs["user_id"])
}

// Seam 6 for PUT /users/{id}/groups, the one list save no issue named: validate, one transaction,
// answer, as the three permission saves in grant_list_saves_test.go, over users_groups and with
// one audit event per membership added and removed (#428).

// userGroupsTx is the transaction the stub hands the save's body. Not nil: a write expected on it
// cannot be matched by one made outside the transaction.
var userGroupsTx = &sql.Tx{}

const userGroupsOwnerId = int64(42)

// membershipRow is a stored users_groups row.
type membershipRow struct {
	id      int64
	groupId int64
}

// serveUserGroupsSave runs the save on a PUT carrying the wanted and loaded group ids.
func serveUserGroupsSave(t *testing.T, database *mocks_data.Database, auditLogger *mocks_audit.AuditLogger, wanted, expected []int64) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]any{"groupIds": wanted, "expectedGroupIds": expected})
	require.NoError(t, err)
	return serveUserGroupsBody(database, auditLogger, string(body))
}

// serveUserGroupsBody runs the save on a PUT carrying body as written.
func serveUserGroupsBody(database *mocks_data.Database, auditLogger *mocks_audit.AuditLogger, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/users/42/groups", strings.NewReader(body))
	req = setChiURLParam(req, "id", "42")
	rr := httptest.NewRecorder()
	HandleAPIUserGroupsPut(database, auditLogger).ServeHTTP(rr, req)
	return rr
}

// expectUserAndGroups registers the reads the save makes before the transaction: the user, and the
// one lookup of the wanted groups, which every one of them answers.
func expectUserAndGroups(database *mocks_data.Database, wanted ...int64) {
	database.On("GetUserById", mock.Anything, (*sql.Tx)(nil), userGroupsOwnerId).
		Return(&models.User{Id: userGroupsOwnerId, Subject: "sub-42"}, nil).Once()
	if len(wanted) == 0 {
		return
	}
	groups := make([]models.Group, 0, len(wanted))
	for _, id := range wanted {
		groups = append(groups, models.Group{Id: id, GroupIdentifier: "g"})
	}
	database.On("GetGroupsByIds", mock.Anything, (*sql.Tx)(nil), wanted).Return(groups, nil).Once()
}

// expectStoredMemberships registers the read of the stored memberships on the save's transaction.
func expectStoredMemberships(database *mocks_data.Database, rows ...membershipRow) {
	stored := make([]models.UserGroup, 0, len(rows))
	for _, r := range rows {
		stored = append(stored, models.UserGroup{Id: r.id, UserId: userGroupsOwnerId, GroupId: r.groupId})
	}
	database.On("GetUserGroupsByUserId", mock.Anything, userGroupsTx, userGroupsOwnerId).Return(stored, nil).Once()
}

// expectReload registers the reload the answer is built from, after the commit. It finds no groups,
// so no member count follows.
func expectReload(database *mocks_data.Database, order *[]string) {
	database.On("UserLoadGroups", mock.Anything, (*sql.Tx)(nil), mock.Anything).
		Run(func(args mock.Arguments) {
			loadGroupsOnto()(args)
			if order != nil {
				*order = append(*order, "reload")
			}
		}).Return(nil).Once()
}

// recordMembershipAudits accepts every Log call and collects them as event and group id, checking
// each names the user and the caller.
func recordMembershipAudits(t *testing.T, auditLogger *mocks_audit.AuditLogger, order *[]string) *[]auditRecord {
	records := &[]auditRecord{}
	auditLogger.On("Log", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			details := args.Get(2).(map[string]interface{})
			assert.Equal(t, userGroupsOwnerId, details["userId"])
			assert.Contains(t, details, "loggedInUser")
			*records = append(*records, audited(args.String(1), details["groupId"].(int64)))
			if order != nil {
				*order = append(*order, "audit")
			}
		}).Return()
	return records
}

// The save is one transaction: the stored memberships are read on the transaction the writes use,
// compared with the set the caller loaded, and replaced by exactly replaceSet's plan, deletes then
// inserts, on that transaction. One audit event per membership added and removed follows the
// commit, and the answer's reload follows those (#428).
func TestHandleAPIUserGroupsPut_SavesTheExactPlanInOneTransaction(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	expectUserAndGroups(database, 4, 6)
	var order []string
	stub := mocks_data.ExpectRunInTransaction(database, userGroupsTx, func(edge string) { order = append(order, edge) })
	expectStoredMemberships(database, membershipRow{id: 21, groupId: 3}, membershipRow{id: 22, groupId: 4})
	var deleted []int64
	database.On("DeleteUserGroup", mock.Anything, userGroupsTx, mock.Anything).
		Run(func(args mock.Arguments) {
			deleted = append(deleted, args.Get(2).(int64))
			order = append(order, "delete")
		}).Return(nil).Once()
	var added []int64
	database.On("CreateUserGroup", mock.Anything, userGroupsTx, mock.Anything).
		Run(func(args mock.Arguments) {
			ug := args.Get(2).(*models.UserGroup)
			assert.Equal(t, userGroupsOwnerId, ug.UserId)
			added = append(added, ug.GroupId)
			order = append(order, "insert")
		}).Return(nil).Once()
	records := recordMembershipAudits(t, auditLogger, &order)
	expectReload(database, &order)

	rr := serveUserGroupsSave(t, database, auditLogger, []int64{4, 6}, []int64{3, 4})

	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.NoError(t, stub.BodyErr)
	assert.Equal(t, []int64{21}, deleted, "the removed membership's row, and nothing kept")
	assert.Equal(t, []int64{6}, added, "the new membership, and nothing already stored")
	assert.Equal(t, []auditRecord{audited(audit.AuditUserAddedToGroup, 6), audited(audit.AuditUserRemovedFromGroup, 3)}, *records)
	assert.Equal(t, []string{"begin", "delete", "insert", "commit", "audit", "audit", "reload"}, order)
	database.AssertExpectations(t)
}

// A membership stored twice, which two overlapping saves that both add it leave behind, is deleted
// in both copies when it is removed, and audited as one removal. An extra copy of a membership that
// is kept is deleted as a repair and audited as nothing (#428).
func TestHandleAPIUserGroupsPut_AStoredDuplicateIsRemovedWithItsOriginal(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	expectUserAndGroups(database, 4)
	mocks_data.ExpectRunInTransaction(database, userGroupsTx)
	expectStoredMemberships(database,
		membershipRow{id: 21, groupId: 3}, membershipRow{id: 22, groupId: 3},
		membershipRow{id: 23, groupId: 4}, membershipRow{id: 24, groupId: 4},
	)
	var deleted []int64
	database.On("DeleteUserGroup", mock.Anything, userGroupsTx, mock.Anything).
		Run(func(args mock.Arguments) { deleted = append(deleted, args.Get(2).(int64)) }).
		Return(nil).Times(3)
	records := recordMembershipAudits(t, auditLogger, nil)
	expectReload(database, nil)

	rr := serveUserGroupsSave(t, database, auditLogger, []int64{4}, []int64{3, 4})

	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Equal(t, []int64{21, 22, 24}, deleted, "both copies of the removed membership, and the extra copy of the kept one")
	assert.Equal(t, []auditRecord{audited(audit.AuditUserRemovedFromGroup, 3)}, *records, "one removal, and nothing for the repair")
	database.AssertExpectations(t)
	assertNotAttemptedOnClientDatabase(t, database, "CreateUserGroup")
}

// A failure part way through commits nothing: the body hands the driver's error to the helper,
// which is when the real one rolls back, and the answer is one 500 with nothing audited and no
// reload. Written autocommitted, as this save was, the membership removed before the failure
// stayed removed, and audited, under the 500 (#428).
func TestHandleAPIUserGroupsPut_AFailedWriteCommitsNothing(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	expectUserAndGroups(database, 6)
	stub := mocks_data.ExpectRunInTransaction(database, userGroupsTx)
	expectStoredMemberships(database, membershipRow{id: 21, groupId: 3})
	database.On("DeleteUserGroup", mock.Anything, userGroupsTx, int64(21)).Return(nil).Once()
	diskFull := errors.New("the disk is full")
	database.On("CreateUserGroup", mock.Anything, userGroupsTx, mock.Anything).Return(diskFull).Once()

	rr := serveUserGroupsSave(t, database, auditLogger, []int64{6}, []int64{3})

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Equal(t, 1, strings.Count(rr.Body.String(), "INTERNAL_SERVER_ERROR"), "exactly one error response")
	require.ErrorIs(t, stub.BodyErr, diskFull, "the body hands the driver's error to the helper, which rolls back")
	assert.Contains(t, stub.BodyErr.Error(), "database error adding the user to group 6")
	database.AssertExpectations(t)
	assertNotAttemptedOnClientDatabase(t, database, "UserLoadGroups")
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}

// The stored memberships failing to read inside the transaction is one 500 under its own message,
// with no write and no audit. A save removing the one stored membership, with the read's error
// ignored, would find nothing to delete and answer 200 with the user still in the group; and with
// both lists empty it would answer 200 over a read that never happened (#428).
func TestHandleAPIUserGroupsPut_AFailedLoadIsAnsweredAsALoadFailure(t *testing.T) {
	variants := []struct {
		name     string
		expected []int64
	}{
		{name: "a save removing the one stored membership", expected: []int64{3}},
		{name: "the loaded list and the wanted list are both empty", expected: []int64{}},
	}

	for _, variant := range variants {
		t.Run(variant.name, func(t *testing.T) {
			database := mocks_data.NewDatabase(t)
			auditLogger := mocks_audit.NewAuditLogger(t)

			expectUserAndGroups(database)
			stub := mocks_data.ExpectRunInTransaction(database, userGroupsTx)
			loadErr := errors.New("the read failed")
			database.On("GetUserGroupsByUserId", mock.Anything, userGroupsTx, userGroupsOwnerId).Return(nil, loadErr).Once()

			rr := serveUserGroupsSave(t, database, auditLogger, []int64{}, variant.expected)

			assert.Equal(t, http.StatusInternalServerError, rr.Code, rr.Body.String())
			assert.Equal(t, 1, strings.Count(rr.Body.String(), "INTERNAL_SERVER_ERROR"), "exactly one error response")
			require.ErrorIs(t, stub.BodyErr, loadErr)
			assert.Contains(t, stub.BodyErr.Error(), "user groups before update")
			database.AssertExpectations(t)
			assertNotAttemptedOnClientDatabase(t, database, "CreateUserGroup", "DeleteUserGroup", "UserLoadGroups")
			auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// A body aborted as a deadlock victim on its first attempt and rerun by the helper answers once
// and audits once: the plan is recomputed from a fresh read on each attempt, and the events are
// emitted from the attempt that committed, after it did (#301, #428).
func TestHandleAPIUserGroupsPut_ARerunAttemptAnswersAndAuditsOnce(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	expectUserAndGroups(database, 6)

	deadlock := errors.New("Error 1213: Deadlock found when trying to get lock")
	attempts := 0
	database.EXPECT().RunInTransaction(mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, fn func(tx *sql.Tx) error) error {
		for {
			attempts++
			err := fn(userGroupsTx)
			if err == nil {
				return nil
			}
			require.ErrorIs(t, err, deadlock,
				"the body must hand the driver's error back in the chain, or the helper cannot tell a deadlock from a fault")
			require.Less(t, attempts, 3, "the second attempt was scripted to succeed")
		}
	}).Once()

	// Both attempts read the memberships afresh and remove group 3.
	database.On("GetUserGroupsByUserId", mock.Anything, userGroupsTx, userGroupsOwnerId).
		Return([]models.UserGroup{{Id: 21, UserId: userGroupsOwnerId, GroupId: 3}}, nil).Twice()
	database.On("DeleteUserGroup", mock.Anything, userGroupsTx, int64(21)).Return(nil).Twice()
	// The first insert is the deadlock victim; the second lands.
	database.On("CreateUserGroup", mock.Anything, userGroupsTx, mock.Anything).Return(deadlock).Once()
	database.On("CreateUserGroup", mock.Anything, userGroupsTx, mock.Anything).Return(nil).Once()
	records := recordMembershipAudits(t, auditLogger, nil)
	expectReload(database, nil)

	rr := serveUserGroupsSave(t, database, auditLogger, []int64{6}, []int64{3})

	assert.Equal(t, 2, attempts)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.NotContains(t, rr.Body.String(), "INTERNAL_SERVER_ERROR")
	assert.Equal(t, []auditRecord{audited(audit.AuditUserAddedToGroup, 6), audited(audit.AuditUserRemovedFromGroup, 3)}, *records, "one event per change, not one per attempt")
	database.AssertExpectations(t)
}

// The helper giving up, a deadlock on every attempt, is one 500 and no audit event.
func TestHandleAPIUserGroupsPut_AnExhaustedRetryIsOneFiveHundred(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	expectUserAndGroups(database, 6)
	mocks_data.ExpectRunInTransactionRefused(database, errors.New("transaction aborted as a deadlock victim on all 3 attempts"))

	rr := serveUserGroupsSave(t, database, auditLogger, []int64{6}, []int64{})

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Equal(t, 1, strings.Count(rr.Body.String(), "INTERNAL_SERVER_ERROR"), "exactly one error response")
	database.AssertExpectations(t)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}

// A loaded set that differs from the memberships read on the transaction is a save from an
// outdated page: 409 CONCURRENT_UPDATE, nothing written and nothing audited, where applying the
// whole set would silently put the user back into a group another administrator had just removed
// them from (#428).
func TestHandleAPIUserGroupsPut_AnOutdatedLoadedListIsRefused(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	expectUserAndGroups(database, 3, 4, 6)
	stub := mocks_data.ExpectRunInTransaction(database, userGroupsTx)
	// Group 3 was removed by another save after this caller loaded {3, 4}.
	expectStoredMemberships(database, membershipRow{id: 22, groupId: 4})

	rr := serveUserGroupsSave(t, database, auditLogger, []int64{3, 4, 6}, []int64{3, 4})

	assert.Equal(t, http.StatusConflict, rr.Code)
	code, _ := decodeErrorEnvelope(t, rr)
	assert.Equal(t, "CONCURRENT_UPDATE", code)
	assert.ErrorIs(t, stub.BodyErr, errListChanged, "the body refuses, so the helper rolls back")
	database.AssertExpectations(t)
	assertNotAttemptedOnClientDatabase(t, database, "CreateUserGroup", "DeleteUserGroup", "UserLoadGroups")
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}

// A loaded set equal to the stored memberships as a set proceeds: in another order and with a
// repeat, and [] against no stored memberships, which is a page that loaded none and not a missing
// field (#428).
func TestHandleAPIUserGroupsPut_ALoadedListEqualAsASetProceeds(t *testing.T) {
	variants := []struct {
		name     string
		stored   []membershipRow
		expected []int64
	}{
		{name: "another order and a repeat", stored: []membershipRow{{id: 21, groupId: 3}, {id: 22, groupId: 4}}, expected: []int64{4, 3, 4}},
		{name: "an empty loaded list against no stored memberships", stored: nil, expected: []int64{}},
	}

	for _, variant := range variants {
		t.Run(variant.name, func(t *testing.T) {
			database := mocks_data.NewDatabase(t)
			auditLogger := mocks_audit.NewAuditLogger(t)

			expectUserAndGroups(database, 6)
			mocks_data.ExpectRunInTransaction(database, userGroupsTx)
			expectStoredMemberships(database, variant.stored...)
			for _, row := range variant.stored {
				database.On("DeleteUserGroup", mock.Anything, userGroupsTx, row.id).Return(nil).Once()
			}
			database.On("CreateUserGroup", mock.Anything, userGroupsTx, mock.Anything).Return(nil).Once()
			recordMembershipAudits(t, auditLogger, nil)
			expectReload(database, nil)

			rr := serveUserGroupsSave(t, database, auditLogger, []int64{6}, variant.expected)

			assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
			database.AssertExpectations(t)
		})
	}
}

// Every refusal is decided before the transaction opens, so a refused save writes nothing: the
// strict mock carries the reads each refusal needs and nothing else, and reaching RunInTransaction
// fails the case. The loaded set is required and read from the body before any query (#428); the
// array bound is #373's; a group that does not exist is refused as before.
func TestHandleAPIUserGroupsPut_ARefusedSaveNeverOpensTheTransaction(t *testing.T) {
	tooMany := make([]int64, maxGroupIdsPerRequest+1)
	for i := range tooMany {
		tooMany[i] = int64(i + 1)
	}
	tooManyBody, err := json.Marshal(map[string]any{"groupIds": tooMany, "expectedGroupIds": []int64{}})
	require.NoError(t, err)

	variants := []struct {
		name            string
		body            string
		readsUser       bool
		missing         bool
		wantCode        string
		wantDescription string
	}{
		{
			name:            "the loaded list is absent",
			body:            `{"groupIds":[6]}`,
			wantCode:        "VALIDATION_ERROR",
			wantDescription: "expectedGroupIds is required",
		},
		{
			name:            "the loaded list is null",
			body:            `{"groupIds":[6],"expectedGroupIds":null}`,
			wantCode:        "VALIDATION_ERROR",
			wantDescription: "expectedGroupIds is required",
		},
		{
			name:            "more group ids than one request may name",
			body:            string(tooManyBody),
			wantCode:        "VALIDATION_ERROR",
			wantDescription: "Too many group ids",
		},
		{
			name:      "a group that does not exist",
			body:      `{"groupIds":[6],"expectedGroupIds":[]}`,
			readsUser: true,
			missing:   true,
			wantCode:  i18n.ErrCodeUserGroupsNotFound,
		},
	}

	for _, variant := range variants {
		t.Run(variant.name, func(t *testing.T) {
			database := mocks_data.NewDatabase(t)
			auditLogger := mocks_audit.NewAuditLogger(t)

			if variant.readsUser {
				database.On("GetUserById", mock.Anything, (*sql.Tx)(nil), userGroupsOwnerId).
					Return(&models.User{Id: userGroupsOwnerId}, nil).Once()
			}
			if variant.missing {
				database.On("GetGroupsByIds", mock.Anything, (*sql.Tx)(nil), []int64{6}).Return([]models.Group{}, nil).Once()
			}

			rr := serveUserGroupsBody(database, auditLogger, variant.body)

			assert.Equal(t, http.StatusBadRequest, rr.Code)
			code, description := decodeErrorEnvelope(t, rr)
			assert.Equal(t, variant.wantCode, code)
			assert.Contains(t, description, variant.wantDescription)
			database.AssertExpectations(t)
			assertNotAttemptedOnClientDatabase(t, database, "RunInTransaction")
			auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// A repeated id in the request is looked up once, added once and audited once, like the three
// permission saves. The lookup answers each group once, so the repeat used to be refused as a
// group that does not exist (#428).
func TestHandleAPIUserGroupsPut_ARepeatedIdIsAddedOnce(t *testing.T) {
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	expectUserAndGroups(database, 6)
	mocks_data.ExpectRunInTransaction(database, userGroupsTx)
	expectStoredMemberships(database)
	database.On("CreateUserGroup", mock.Anything, userGroupsTx, mock.Anything).Return(nil).Once()
	records := recordMembershipAudits(t, auditLogger, nil)
	expectReload(database, nil)

	rr := serveUserGroupsSave(t, database, auditLogger, []int64{6, 6}, []int64{})

	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Equal(t, []auditRecord{audited(audit.AuditUserAddedToGroup, 6)}, *records)
	database.AssertExpectations(t)
}
