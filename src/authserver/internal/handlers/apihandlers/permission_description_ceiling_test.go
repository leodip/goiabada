package apihandlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/inputvalidation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The target ceiling on a save of the authserver resource's permissions: the description of an
// administrative permission is what an operator reads before granting it, so only an
// authserver:manage token changes one. A caller below manage is refused 403 MANAGE_SCOPE_REQUIRED,
// before the transaction opens, with one administrator_change_refused record naming the resource
// and the permissions; every other description, and every other resource, saves as before (#402
// decisions 1 and 3).

// descriptionCeilingStored is the authserver resource's seven built-in permissions, each described
// by its identifier, and one custom permission beside them.
func descriptionCeilingStored() []record.Permission {
	stored := make([]record.Permission, 0, len(builtin.AuthServerPermissionIdentifiers())+1)
	for i, identifier := range builtin.AuthServerPermissionIdentifiers() {
		stored = append(stored, record.Permission{Id: int64(40 + i), ResourceId: resourcePermsId, PermissionIdentifier: identifier, Description: identifier})
	}
	return append(stored, record.Permission{Id: 60, ResourceId: resourcePermsId, PermissionIdentifier: "reports", Description: "Reports"})
}

// descriptionCeilingIdOf is the stored id of the permission identified so.
func descriptionCeilingIdOf(t *testing.T, stored []record.Permission, identifier string) int64 {
	t.Helper()
	for _, p := range stored {
		if p.PermissionIdentifier == identifier {
			return p.Id
		}
	}
	t.Fatalf("no stored permission %q", identifier)
	return 0
}

// redescribed is the stored permissions as entries, the one identified so re-described.
func redescribed(stored []record.Permission, identifier, description string) []api.ResourcePermissionUpsert {
	entries := loadedEntries(stored)
	for i := range entries {
		if entries[i].PermissionIdentifier == identifier {
			entries[i].Description = description
		}
	}
	return entries
}

// serveResourcePermsWithScope runs the save on a PUT carrying body, as a caller whose validated
// token carries scope, or with no validated token at all when scope is empty.
func serveResourcePermsWithScope(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, body, scope string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPut, "/api/v1/admin/resources/7/permissions", strings.NewReader(body))
	r = setChiURLParam(r, "resourceId", "7")
	if scope != "" {
		r = setTokenContextWithClaims(r, map[string]interface{}{"scope": scope, "sub": grantCaller})
	}
	rr := httptest.NewRecorder()
	HandleResourcePermissionsPut(database, inputvalidation.NewIdentifierValidator(), auditLogger).ServeHTTP(rr, r)
	return rr
}

func TestPermissionDescriptionCeiling_EveryCallerBelowManageIsRefused(t *testing.T) {
	callers := []struct {
		name  string
		scope string
	}{
		{name: "manage-settings", scope: "authserver:manage-settings"},
		{name: "every granular scope", scope: "authserver:admin-read authserver:manage-users authserver:manage-clients authserver:manage-settings authserver:browser-sessions"},
		{name: "a scope that only resembles manage", scope: "authserver:manage-account other:manage"},
		{name: "no validated token", scope: ""},
	}
	stored := descriptionCeilingStored()

	for identifier := range administrativePermissionIdentifiers {
		for _, caller := range callers {
			t.Run(identifier+"/"+caller.name, func(t *testing.T) {
				database := datamocks.NewDatabase(t)
				auditLogger := handlersmocks.NewAuditLogger(t)
				expectResourcePermsResource(database, builtin.AuthServerResourceIdentifier)
				expectResourcePermsChecked(database, stored)
				records := recordLoggedEvents(auditLogger)

				body := resourcePermsBody(t, redescribed(stored, identifier, "Read-only reporting"), loadedEntries(stored))
				rr := serveResourcePermsWithScope(database, auditLogger, body, caller.scope)

				status := rr.Code
				code, description := decodeErrorEnvelope(t, rr)
				assertManageScopeRequired(t, rr, status, code, description)
				database.AssertExpectations(t)
				assertNotAttemptedOnClientDatabase(t, database, "RunInTransaction")

				require.Len(t, *records, 1, "one record per refused request, and not the save's own")
				refusal := (*records)[0]
				assert.Equal(t, "administrator_change_refused", refusal.event)
				assert.Equal(t, http.MethodPut, refusal.details["method"])
				assert.Equal(t, "target", refusal.details["ceiling"])
				assert.Equal(t, "resource", refusal.details["targetKind"])
				assert.Equal(t, resourcePermsId, refusal.details["targetId"])
				assert.Equal(t, []int64{descriptionCeilingIdOf(t, stored, identifier)}, refusal.details["permissionIds"])
				if caller.scope != "" {
					assert.Equal(t, grantCaller, refusal.details["loggedInUser"])
				}
			})
		}
	}
}

// The change is judged against the list the caller loaded, which is what the save commits or
// nothing. An administrative row the loaded list leaves out counts as changed, whatever the stored
// text: the save would otherwise answer 409, and a caller below manage is told the one answer no
// retry changes.
func TestPermissionDescriptionCeiling_AnAdministrativeRowTheLoadedListLeavesOutIsAChange(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	stored := descriptionCeilingStored()
	expectResourcePermsResource(database, builtin.AuthServerResourceIdentifier)
	expectResourcePermsChecked(database, stored)
	records := recordLoggedEvents(auditLogger)

	manageId := descriptionCeilingIdOf(t, stored, builtin.ManagePermissionIdentifier)
	loaded := make([]api.ResourcePermissionUpsert, 0, len(stored))
	for _, entry := range loadedEntries(stored) {
		if entry.Id != manageId {
			loaded = append(loaded, entry)
		}
	}
	rr := serveResourcePermsWithScope(database, auditLogger, resourcePermsBody(t, loadedEntries(stored), loaded), "authserver:manage-settings")

	status := rr.Code
	code, description := decodeErrorEnvelope(t, rr)
	assertManageScopeRequired(t, rr, status, code, description)
	assertNotAttemptedOnClientDatabase(t, database, "RunInTransaction")
	require.Len(t, *records, 1)
	assert.Equal(t, []int64{manageId}, (*records)[0].details["permissionIds"])
}

// The refusal comes after the save's own answers: a built-in renamed or a row that is not the
// resource's is answered as before, though the same save re-describes an administrative permission,
// and nothing is audited.
func TestPermissionDescriptionCeiling_TheSavesOwnAnswersComeFirst(t *testing.T) {
	stored := descriptionCeilingStored()
	renamedAndRedescribed := redescribed(stored, builtin.ManagePermissionIdentifier, "Read-only reporting")
	for i := range renamedAndRedescribed {
		if renamedAndRedescribed[i].PermissionIdentifier == builtin.AdminReadPermissionIdentifier {
			renamedAndRedescribed[i].PermissionIdentifier = "reader"
		}
	}

	cases := []struct {
		name       string
		wanted     []api.ResourcePermissionUpsert
		wantStatus int
	}{
		{name: "a built-in renamed", wanted: renamedAndRedescribed, wantStatus: http.StatusBadRequest},
		{name: "a row that is not the resource's",
			wanted: append(redescribed(stored, builtin.ManagePermissionIdentifier, "Read-only reporting"),
				api.ResourcePermissionUpsert{Id: 99, PermissionIdentifier: "other", Description: "x"}),
			wantStatus: http.StatusNotFound},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			expectResourcePermsResource(database, builtin.AuthServerResourceIdentifier)
			expectResourcePermsChecked(database, stored)

			rr := serveResourcePermsWithScope(database, auditLogger, resourcePermsBody(t, c.wanted, loadedEntries(stored)), "authserver:manage-settings")

			assert.Equal(t, c.wantStatus, rr.Code, rr.Body.String())
			assert.Empty(t, rr.Header().Get("WWW-Authenticate"))
			assertNotAttemptedOnClientDatabase(t, database, "RunInTransaction")
			auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// What the ceiling does not reach saves as before: manage-settings re-describes manage-account and
// a custom permission on the authserver resource, and authserver:manage re-describes an
// administrative one. Each is one update on the save's transaction and the save's own record.
func TestPermissionDescriptionCeiling_WhatItDoesNotReachSaves(t *testing.T) {
	cases := []struct {
		name       string
		identifier string
		scope      string
	}{
		{name: "manage-settings, manage-account", identifier: builtin.ManageAccountPermissionIdentifier, scope: "authserver:manage-settings"},
		{name: "manage-settings, a custom permission", identifier: "reports", scope: "authserver:manage-settings"},
		{name: "manage, manage", identifier: builtin.ManagePermissionIdentifier, scope: "authserver:manage"},
		{name: "manage, manage-users", identifier: builtin.ManageUsersPermissionIdentifier, scope: "authserver:manage"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			stored := descriptionCeilingStored()
			expectResourcePermsResource(database, builtin.AuthServerResourceIdentifier)
			expectResourcePermsChecked(database, stored)
			stub := datamocks.ExpectRunInTransaction(database, resourcePermsTx)
			expectResourcePermsRead(database, stored)
			var updated []record.Permission
			database.On("UpdatePermission", mock.Anything, resourcePermsTx, mock.Anything).
				Run(func(args mock.Arguments) { updated = append(updated, *args.Get(2).(*record.Permission)) }).
				Return(nil).Once()
			records := recordLoggedEvents(auditLogger)

			body := resourcePermsBody(t, redescribed(stored, c.identifier, "Re-described"), loadedEntries(stored))
			rr := serveResourcePermsWithScope(database, auditLogger, body, c.scope)

			assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
			assert.NoError(t, stub.BodyErr)
			require.Len(t, updated, 1)
			assert.Equal(t, descriptionCeilingIdOf(t, stored, c.identifier), updated[0].Id)
			assert.Equal(t, "Re-described", updated[0].Description)
			require.Len(t, *records, 1)
			assert.Equal(t, "updated_resource_permissions", (*records)[0].event)
		})
	}
}
