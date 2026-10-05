package apihandlers

import (
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The grant ceiling on the three permission saves: only an authserver:manage token grants or
// revokes one of the six administrative permissions. A granular token doing either is refused 403
// MANAGE_SCOPE_REQUIRED with an insufficient_scope challenge naming authserver:manage, before any
// transaction opens, and leaves one administrator_change_refused record. It keeps granting and
// revoking every other permission (#402 decisions 1, 2, 4 and 5).

// The authserver resource as the cases' policy reads it: the six administrative permissions, the
// self-service one and a custom permission an operator added, which is not administrative.
const (
	ceilingResourceId      = int64(1)
	permManageAccount      = int64(10)
	permManage             = int64(11)
	permAdminRead          = int64(12)
	permManageUsers        = int64(13)
	permManageClients      = int64(14)
	permManageSettings     = int64(15)
	permBrowserSessions    = int64(16)
	permCustomOnAuthServer = int64(17)
)

// expectAuthServerPermissions registers the policy's read of the authserver resource and its
// permissions, outside any transaction.
func expectAuthServerPermissions(database *datamocks.Database) {
	expectAuthServerPermissionsOn(database, nil)
}

// expectAuthServerPermissionsOn registers the same read on tx.
func expectAuthServerPermissionsOn(database *datamocks.Database, tx *sql.Tx) {
	database.On("GetResourceByResourceIdentifier", mock.Anything, tx, "authserver").
		Return(&record.Resource{Id: ceilingResourceId, ResourceIdentifier: "authserver"}, nil).Once()
	database.On("GetPermissionsByResourceId", mock.Anything, tx, ceilingResourceId).
		Return([]record.Permission{
			{Id: permManageAccount, PermissionIdentifier: "manage-account", ResourceId: ceilingResourceId},
			{Id: permManage, PermissionIdentifier: "manage", ResourceId: ceilingResourceId},
			{Id: permAdminRead, PermissionIdentifier: "admin-read", ResourceId: ceilingResourceId},
			{Id: permManageUsers, PermissionIdentifier: "manage-users", ResourceId: ceilingResourceId},
			{Id: permManageClients, PermissionIdentifier: "manage-clients", ResourceId: ceilingResourceId},
			{Id: permManageSettings, PermissionIdentifier: "manage-settings", ResourceId: ceilingResourceId},
			{Id: permBrowserSessions, PermissionIdentifier: "browser-sessions", ResourceId: ceilingResourceId},
			{Id: permCustomOnAuthServer, PermissionIdentifier: "reports", ResourceId: ceilingResourceId},
		}, nil).Once()
}

// granularScopeOf is the granular write scope the route of each save admits.
func granularScopeOf(save grantSave) string {
	if save.kind == "client" {
		return "authserver:manage-clients"
	}
	return "authserver:manage-users"
}

// assertManageScopeRequired holds a response to the refusal decision 4 describes.
func assertManageScopeRequired(t *testing.T, rr interface {
	Header() http.Header
}, status int, code, description string) {
	t.Helper()
	assert.Equal(t, http.StatusForbidden, status)
	assert.Equal(t, "MANAGE_SCOPE_REQUIRED", code)
	assert.Contains(t, description, "authserver:manage")
	challenge := rr.Header().Get("WWW-Authenticate")
	assert.True(t, strings.HasPrefix(challenge, `Bearer realm="`), "a Bearer challenge with its realm: %q", challenge)
	assert.Contains(t, challenge, `, error="insufficient_scope"`)
	assert.Contains(t, challenge, `, error_description="`)
	assert.True(t, strings.HasSuffix(challenge, `, scope="authserver:manage"`), "the challenge names the scope that would do: %q", challenge)
}

// loggedEvent is one Log call as the cases read it, the event and its details.
type loggedEvent struct {
	event   string
	details map[string]interface{}
}

func recordLoggedEvents(auditLogger *handlersmocks.AuditLogger) *[]loggedEvent {
	records := &[]loggedEvent{}
	auditLogger.On("Log", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			*records = append(*records, loggedEvent{event: args.String(1), details: args.Get(2).(map[string]interface{})})
		}).Return()
	return records
}

func TestGrantCeiling_AGranularTokenChangingAnAdministrativePermissionIsRefused(t *testing.T) {
	variants := []struct {
		name     string
		wanted   []int64
		expected []int64
		// causes is the administrative permissions the refusal names: those granted, in the order
		// requested, then those revoked, in the order loaded.
		causes []int64
	}{
		{name: "granting manage", wanted: []int64{permManage}, expected: []int64{}, causes: []int64{permManage}},
		{name: "revoking manage-users", wanted: []int64{}, expected: []int64{permManageUsers}, causes: []int64{permManageUsers}},
		{name: "granting browser-sessions beside an ordinary permission", wanted: []int64{6, permBrowserSessions}, expected: []int64{}, causes: []int64{permBrowserSessions}},
		{name: "replacing admin-read with manage-settings", wanted: []int64{permManageSettings, permManageAccount}, expected: []int64{permAdminRead, permManageAccount}, causes: []int64{permManageSettings, permAdminRead}},
		{name: "granting manage-clients", wanted: []int64{permManageClients}, expected: []int64{}, causes: []int64{permManageClients}},
	}

	for _, save := range grantSaves {
		for _, variant := range variants {
			t.Run(save.name+"/"+variant.name, func(t *testing.T) {
				database := datamocks.NewDatabase(t)
				auditLogger := handlersmocks.NewAuditLogger(t)

				save.expectOwner(database)
				expectPermissionsExist(database, variant.wanted...)
				expectAuthServerPermissions(database)
				records := recordLoggedEvents(auditLogger)

				rr := save.serveWithScope(database, auditLogger, save.body(t, variant.wanted, variant.expected), granularScopeOf(save))

				status := rr.Code
				code, description := decodeErrorEnvelope(t, rr)
				assertManageScopeRequired(t, rr, status, code, description)
				database.AssertExpectations(t)
				assertNotAttemptedOnClientDatabase(t, database, "RunInTransaction", save.readMethod, save.createMethod, save.deleteMethod)

				require.Len(t, *records, 1, "one record per refused request")
				record := (*records)[0]
				assert.Equal(t, "administrator_change_refused", record.event)
				assert.Equal(t, grantCaller, record.details["loggedInUser"])
				assert.Equal(t, http.MethodPut, record.details["method"])
				assert.Contains(t, record.details, "route")
				assert.Equal(t, "grant", record.details["ceiling"])
				assert.Equal(t, save.kind, record.details["targetKind"])
				assert.Equal(t, grantOwnerId, record.details["targetId"])
				assert.Equal(t, variant.causes, record.details["permissionIds"])
			})
		}
	}
}

// Every token below authserver:manage is held to the ceiling, and so is a request that reached the
// handler with no validated token at all: the policy fails closed.
func TestGrantCeiling_EveryOtherCallerIsHeldToIt(t *testing.T) {
	callers := []struct {
		name  string
		scope string
	}{
		{name: "admin-read", scope: "authserver:admin-read"},
		{name: "manage-settings", scope: "authserver:manage-settings"},
		{name: "two granular scopes", scope: "authserver:manage-users authserver:manage-clients"},
		{name: "a scope that only resembles manage", scope: "authserver:manage-account other:manage"},
		{name: "no validated token", scope: ""},
	}

	for _, save := range grantSaves {
		for _, caller := range callers {
			t.Run(save.name+"/"+caller.name, func(t *testing.T) {
				database := datamocks.NewDatabase(t)
				auditLogger := handlersmocks.NewAuditLogger(t)

				save.expectOwner(database)
				expectPermissionsExist(database, permManage)
				expectAuthServerPermissions(database)
				records := recordLoggedEvents(auditLogger)

				rr := save.serveWithScope(database, auditLogger, save.body(t, []int64{permManage}, []int64{}), caller.scope)

				status := rr.Code
				code, description := decodeErrorEnvelope(t, rr)
				assertManageScopeRequired(t, rr, status, code, description)
				assertNotAttemptedOnClientDatabase(t, database, "RunInTransaction")
				require.Len(t, *records, 1)
				assert.Equal(t, "administrator_change_refused", (*records)[0].event)
			})
		}
	}
}

// A granular token keeps granting and revoking every permission that is not administrative:
// manage-account, a custom permission on the authserver resource, and permissions on other
// resources. The save runs as before and audits as before.
func TestGrantCeiling_AGranularTokenChangingOrdinaryPermissionsProceeds(t *testing.T) {
	for _, save := range grantSaves {
		t.Run(save.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)

			save.expectOwner(database)
			expectPermissionsExist(database, permManageAccount, permCustomOnAuthServer, 6)
			expectAuthServerPermissions(database)
			datamocks.ExpectRunInTransaction(database, grantsTx)
			save.expectStored(database, grantRow{id: 21, permissionId: 4})
			database.On(save.deleteMethod, mock.Anything, grantsTx, int64(21)).Return(nil).Once()
			database.On(save.createMethod, mock.Anything, grantsTx, mock.Anything).Return(nil).Times(3)
			records := save.recordAudits(t, auditLogger, nil)

			rr := save.serveWithScope(database, auditLogger,
				save.body(t, []int64{permManageAccount, permCustomOnAuthServer, 6}, []int64{4}), granularScopeOf(save))

			assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
			assert.Empty(t, rr.Header().Get("WWW-Authenticate"))
			assert.Equal(t, save.wantAudits([]int64{permManageAccount, permCustomOnAuthServer, 6}, []int64{4}), *records)
			database.AssertExpectations(t)
		})
	}
}

// A save that changes nothing grants and revokes nothing, so the grant ceiling has nothing to judge
// and reads nothing for it.
func TestGrantCeiling_ASaveThatChangesNothingReadsNothingForThePolicy(t *testing.T) {
	for _, save := range grantSaves {
		t.Run(save.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)

			save.expectOwner(database)
			expectPermissionsExist(database, 4)
			datamocks.ExpectRunInTransaction(database, grantsTx)
			save.expectStored(database, grantRow{id: 21, permissionId: 4})
			if save.consolidatedEvent != "" {
				save.recordAudits(t, auditLogger, nil)
			}

			rr := save.serveWithScope(database, auditLogger, save.body(t, []int64{4}, []int64{4}), granularScopeOf(save))

			assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
			database.AssertExpectations(t)
			assertNotAttemptedOnClientDatabase(t, database, "GetResourceByResourceIdentifier", "GetPermissionsByResourceId")
		})
	}
}

// The refusal comes after the request's 404: the named permissions are read to decide, so one that
// does not exist is answered as before, and nothing is audited.
func TestGrantCeiling_AMissingPermissionIsAnsweredFirst(t *testing.T) {
	for _, save := range grantSaves {
		t.Run(save.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)

			save.expectOwner(database)
			expectPermissionsExist(database, permManage)
			database.On("GetPermissionById", mock.Anything, (*sql.Tx)(nil), int64(99)).
				Return((*record.Permission)(nil), nil).Once()

			rr := save.serveWithScope(database, auditLogger, save.body(t, []int64{permManage, 99}, []int64{}), granularScopeOf(save))

			assert.Equal(t, http.StatusNotFound, rr.Code)
			database.AssertExpectations(t)
			assertNotAttemptedOnClientDatabase(t, database, "RunInTransaction")
			auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// The policy failing to read the administrative set is one 500, with no transaction and no record:
// a save the policy could not judge is not let through.
func TestGrantCeiling_AFailedPolicyReadIsOneFiveHundred(t *testing.T) {
	for _, save := range grantSaves {
		t.Run(save.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)

			save.expectOwner(database)
			expectPermissionsExist(database, 6)
			database.On("GetResourceByResourceIdentifier", mock.Anything, (*sql.Tx)(nil), "authserver").
				Return(nil, errors.New("the read failed")).Once()

			rr := save.serveWithScope(database, auditLogger, save.body(t, []int64{6}, []int64{}), granularScopeOf(save))

			assert.Equal(t, http.StatusInternalServerError, rr.Code)
			assert.Equal(t, 1, strings.Count(rr.Body.String(), "INTERNAL_SERVER_ERROR"), "exactly one error response")
			database.AssertExpectations(t)
			assertNotAttemptedOnClientDatabase(t, database, "RunInTransaction")
			auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}
