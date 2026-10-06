package apihandlers

import (
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/accountvalidation"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/inputvalidation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The target ceiling on users and groups: a user holding an administrative permission, directly or
// through any of its groups, and a group holding one, are administrators, and only an
// authserver:manage token writes to one in any way. A granular token is refused 403
// MANAGE_SCOPE_REQUIRED after the write's own 400 and 404 answers and before any write, with one
// administrator_change_refused record under ceiling "target" naming the target, and keeps full
// control of every user and group that is not an administrator (#402 decisions 1, 2, 4 and 5).
//
// Deleting a group and changing its members are the grant ceiling's, which refuses exactly the
// administrative groups (membership_ceiling_test.go); a change of membership is here for its user.

// The targets the cases write to, and the rows that point at them.
const (
	targetUserId        = int64(52)
	targetGroupId       = int64(57)
	targetAttributeId   = int64(90)
	targetSessionId     = int64(91)
	targetConsentId     = int64(92)
	targetMembershipId  = int64(93)
	heldAdminGroupId    = int64(70)
	heldOrdinaryGroupId = int64(71)
)

// targetHolding is what a target holds, as the policy reads it: for a user, its direct grants and
// its groups with what each holds; for a group, its grants.
type targetHolding struct {
	name   string
	direct []int64
	groups []heldGroup
	// administrator is what the holding makes the target, written out rather than derived.
	administrator bool
}

type heldGroup struct {
	id            int64
	permissionIds []int64
}

// The users the cases write to: an administrator directly, one through a group, and an ordinary
// user who holds manage-account and belongs to a group holding a custom authserver permission.
var (
	userAdministratorDirectly = targetHolding{
		name:          "an administrator directly",
		direct:        []int64{permManageAccount, permManageUsers},
		administrator: true,
	}
	userAdministratorThroughAGroup = targetHolding{
		name:   "an administrator through a group",
		direct: []int64{permManageAccount},
		groups: []heldGroup{
			{id: heldOrdinaryGroupId, permissionIds: []int64{permCustomOnAuthServer}},
			{id: heldAdminGroupId, permissionIds: []int64{6, permBrowserSessions}},
		},
		administrator: true,
	}
	ordinaryUser = targetHolding{
		name:   "an ordinary user",
		direct: []int64{permManageAccount},
		groups: []heldGroup{{id: heldOrdinaryGroupId, permissionIds: []int64{permCustomOnAuthServer}}},
	}
)

// The groups the cases write to: one holding manage-settings beside a permission of another
// resource, and one holding manage-account and a custom authserver permission.
var (
	administrativeTargetGroup = targetHolding{name: "an administrative group", direct: []int64{6, permManageSettings}, administrator: true}
	ordinaryTargetGroup       = targetHolding{name: "an ordinary group", direct: []int64{permManageAccount, permCustomOnAuthServer}}
)

// expectUserHolding registers the policy's reads of what targetUserId holds, outside any
// transaction: its grants, its groups, what those hold, and the administrative set.
func expectUserHolding(database *datamocks.Database, holding targetHolding) {
	var grants []record.UserPermission
	for _, permissionId := range holding.direct {
		grants = append(grants, record.UserPermission{UserId: targetUserId, PermissionId: permissionId})
	}
	database.On("GetUserPermissionsByUserId", mock.Anything, (*sql.Tx)(nil), targetUserId).Return(grants, nil).Once()

	var memberships []record.UserGroup
	var groupIds []int64
	var groupGrants []record.GroupPermission
	for _, group := range holding.groups {
		memberships = append(memberships, record.UserGroup{UserId: targetUserId, GroupId: group.id})
		groupIds = append(groupIds, group.id)
		for _, permissionId := range group.permissionIds {
			groupGrants = append(groupGrants, record.GroupPermission{GroupId: group.id, PermissionId: permissionId})
		}
	}
	database.On("GetUserGroupsByUserId", mock.Anything, (*sql.Tx)(nil), targetUserId).Return(memberships, nil).Once()
	if len(groupIds) > 0 {
		database.On("GetGroupPermissionsByGroupIds", mock.Anything, (*sql.Tx)(nil), groupIds).Return(groupGrants, nil).Once()
	}
	expectAuthServerPermissions(database)
}

// expectGroupHolding registers the policy's reads of what targetGroupId holds, outside any
// transaction.
func expectGroupHolding(database *datamocks.Database, holding targetHolding) {
	var grants []record.GroupPermission
	for _, permissionId := range holding.direct {
		grants = append(grants, record.GroupPermission{GroupId: targetGroupId, PermissionId: permissionId})
	}
	database.On("GetGroupPermissionsByGroupIds", mock.Anything, (*sql.Tx)(nil), []int64{targetGroupId}).Return(grants, nil).Once()
	expectAuthServerPermissions(database)
}

// targetWrite is one of the writes the target ceiling guards.
type targetWrite struct {
	name string
	// kind is the target's kind, user or group.
	kind string
	// serve runs the write against its target, as a caller holding scope, or no validated token
	// when scope is empty.
	serve func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, scope string) *httptest.ResponseRecorder
	// expectReads registers the reads the write makes before the target ceiling judges it,
	// including what the grant ceiling reads ahead of it on a write it also judges. granular says
	// whether the caller is held to the ceilings.
	expectReads func(database *datamocks.Database, granular bool)
	// writes is every write the route makes, none of which a refusal may reach.
	writes []string
	// expectFirstWrite registers the write's first write past the ceiling, failing, so a write the
	// ceiling lets through ends in one 500 there.
	expectFirstWrite func(database *datamocks.Database)
}

var errFirstWriteFails = errors.New("the first write past the ceiling fails")

// targetRequest builds a request for one of the routes, with chi's URL parameters set.
func targetRequest(method, target, body, scope string, params map[string]string) *http.Request {
	return membershipRequest(method, target, body, scope, params)
}

// withPasswordSettings puts the settings the password write validates against on the request.
func withPasswordSettings(r *http.Request) *http.Request {
	return r.WithContext(reqctx.WithSettings(r.Context(), &record.Settings{PasswordPolicy: record.PasswordPolicyLow}))
}

func expectTargetUser(database *datamocks.Database, user *record.User) {
	if user == nil {
		user = &record.User{Id: targetUserId, Subject: "sub-52", Email: "target@example.com", Enabled: true}
	}
	database.On("GetUserById", mock.Anything, (*sql.Tx)(nil), targetUserId).Return(user, nil).Once()
}

func expectTargetGroup(database *datamocks.Database) {
	database.On("GetGroupById", mock.Anything, (*sql.Tx)(nil), targetGroupId).
		Return(&record.Group{Id: targetGroupId, GroupIdentifier: "target-group"}, nil).Once()
}

func failingWrite(method string, arguments ...interface{}) func(database *datamocks.Database) {
	return func(database *datamocks.Database) {
		database.On(method, arguments...).Return(errFirstWriteFails).Once()
	}
}

var userTargetWrites = []targetWrite{
	{
		name: "PUT /users/{id}/enabled disabling",
		kind: targetKindUser,
		serve: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, scope string) *httptest.ResponseRecorder {
			r := targetRequest(http.MethodPut, "/api/v1/admin/users/52/enabled", `{"enabled":false}`, scope, map[string]string{"id": "52"})
			rr := httptest.NewRecorder()
			HandleUserEnabledPut(database, auditLogger).ServeHTTP(rr, r)
			return rr
		},
		expectReads:      func(database *datamocks.Database, _ bool) { expectTargetUser(database, nil) },
		writes:           []string{"RunInTransaction", "TrySetUserEnabled"},
		expectFirstWrite: failingWrite("RunInTransaction", mock.Anything, mock.Anything),
	},
	{
		name: "PUT /users/{id}/enabled enabling",
		kind: targetKindUser,
		serve: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, scope string) *httptest.ResponseRecorder {
			r := targetRequest(http.MethodPut, "/api/v1/admin/users/52/enabled", `{"enabled":true}`, scope, map[string]string{"id": "52"})
			rr := httptest.NewRecorder()
			HandleUserEnabledPut(database, auditLogger).ServeHTTP(rr, r)
			return rr
		},
		expectReads: func(database *datamocks.Database, _ bool) { expectTargetUser(database, nil) },
		writes:      []string{"RunInTransaction", "TrySetUserEnabled"},
		expectFirstWrite: func(database *datamocks.Database) {
			database.On("TrySetUserEnabled", mock.Anything, (*sql.Tx)(nil), targetUserId, false, true).Return(false, errFirstWriteFails).Once()
		},
	},
	{
		name: "PUT /users/{id}/profile",
		kind: targetKindUser,
		serve: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, scope string) *httptest.ResponseRecorder {
			r := targetRequest(http.MethodPut, "/api/v1/admin/users/52/profile", `{"givenName":"Ann"}`, scope, map[string]string{"id": "52"})
			rr := httptest.NewRecorder()
			HandleUserProfilePut(database, accountvalidation.NewProfileValidator(database), auditLogger).ServeHTTP(rr, r)
			return rr
		},
		expectReads:      func(database *datamocks.Database, _ bool) { expectTargetUser(database, nil) },
		writes:           []string{"SetUserProfile"},
		expectFirstWrite: failingWrite("SetUserProfile", mock.Anything, (*sql.Tx)(nil), mock.Anything),
	},
	{
		name: "PUT /users/{id}/address",
		kind: targetKindUser,
		serve: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, scope string) *httptest.ResponseRecorder {
			r := targetRequest(http.MethodPut, "/api/v1/admin/users/52/address", `{"addressLine1":"1 Long Road"}`, scope, map[string]string{"id": "52"})
			rr := httptest.NewRecorder()
			HandleUserAddressPut(database, accountvalidation.NewAddressValidator(), auditLogger).ServeHTTP(rr, r)
			return rr
		},
		expectReads:      func(database *datamocks.Database, _ bool) { expectTargetUser(database, nil) },
		writes:           []string{"SetUserAddress"},
		expectFirstWrite: failingWrite("SetUserAddress", mock.Anything, (*sql.Tx)(nil), mock.Anything),
	},
	{
		name: "PUT /users/{id}/email",
		kind: targetKindUser,
		serve: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, scope string) *httptest.ResponseRecorder {
			r := targetRequest(http.MethodPut, "/api/v1/admin/users/52/email", `{"email":"taken-over@example.com","emailVerified":true}`, scope,
				map[string]string{"id": "52"})
			rr := httptest.NewRecorder()
			HandleUserEmailPut(database, accountvalidation.NewEmailValidator(database), auditLogger).ServeHTTP(rr, r)
			return rr
		},
		expectReads: func(database *datamocks.Database, _ bool) {
			expectTargetUser(database, nil)
			database.On("GetUserBySubject", mock.Anything, mock.Anything, "sub-52").
				Return(&record.User{Id: targetUserId, Subject: "sub-52"}, nil).Once()
			database.On("GetUserByEmail", mock.Anything, mock.Anything, "taken-over@example.com").Return(nil, nil).Once()
		},
		writes:           []string{"UpdateUser"},
		expectFirstWrite: failingWrite("UpdateUser", mock.Anything, (*sql.Tx)(nil), mock.Anything),
	},
	{
		name: "POST /users/{id}/email/verification-code",
		kind: targetKindUser,
		serve: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, scope string) *httptest.ResponseRecorder {
			r := targetRequest(http.MethodPost, "/api/v1/admin/users/52/email/verification-code", "", scope, map[string]string{"id": "52"})
			rr := httptest.NewRecorder()
			HandleUserEmailVerificationCodePost(database, auditLogger, testDataCipher).ServeHTTP(rr, r)
			return rr
		},
		expectReads:      func(database *datamocks.Database, _ bool) { expectTargetUser(database, nil) },
		writes:           []string{"UpdateUser"},
		expectFirstWrite: failingWrite("UpdateUser", mock.Anything, (*sql.Tx)(nil), mock.Anything),
	},
	{
		name: "PUT /users/{id}/phone",
		kind: targetKindUser,
		serve: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, scope string) *httptest.ResponseRecorder {
			r := targetRequest(http.MethodPut, "/api/v1/admin/users/52/phone", `{"phoneCountryUniqueId":"","phoneNumber":""}`, scope,
				map[string]string{"id": "52"})
			rr := httptest.NewRecorder()
			HandleUserPhonePut(database, accountvalidation.NewPhoneValidator(), auditLogger).ServeHTTP(rr, r)
			return rr
		},
		expectReads:      func(database *datamocks.Database, _ bool) { expectTargetUser(database, nil) },
		writes:           []string{"SetUserPhone"},
		expectFirstWrite: failingWrite("SetUserPhone", mock.Anything, (*sql.Tx)(nil), mock.Anything),
	},
	{
		name: "PUT /users/{id}/password",
		kind: targetKindUser,
		serve: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, scope string) *httptest.ResponseRecorder {
			r := targetRequest(http.MethodPut, "/api/v1/admin/users/52/password", `{"newPassword":"a new password to sign in with"}`, scope,
				map[string]string{"id": "52"})
			rr := httptest.NewRecorder()
			HandleUserPasswordPut(database, accountvalidation.NewPasswordValidator(), auditLogger).ServeHTTP(rr, withPasswordSettings(r))
			return rr
		},
		expectReads:      func(database *datamocks.Database, _ bool) { expectTargetUser(database, nil) },
		writes:           []string{"RunInTransaction", "SetUserPasswordHash"},
		expectFirstWrite: failingWrite("RunInTransaction", mock.Anything, mock.Anything),
	},
	{
		name: "PUT /users/{id}/otp",
		kind: targetKindUser,
		serve: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, scope string) *httptest.ResponseRecorder {
			r := targetRequest(http.MethodPut, "/api/v1/admin/users/52/otp", `{"enabled":false}`, scope, map[string]string{"id": "52"})
			rr := httptest.NewRecorder()
			HandleUserOTPPut(database, auditLogger).ServeHTTP(rr, r)
			return rr
		},
		expectReads: func(database *datamocks.Database, _ bool) {
			expectTargetUser(database, &record.User{Id: targetUserId, Subject: "sub-52", OTPEnabled: true})
		},
		writes:           []string{"RunInTransaction"},
		expectFirstWrite: failingWrite("RunInTransaction", mock.Anything, mock.Anything),
	},
	{
		name: "POST /users/{id}/profile-picture",
		kind: targetKindUser,
		serve: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, scope string) *httptest.ResponseRecorder {
			r, err := createMultipartRequest(http.MethodPost, "/api/v1/admin/users/52/profile-picture", "picture", createTestPNG(100, 100))
			require.NoError(t, err)
			r = setChiURLParam(r, "id", "52")
			if scope != "" {
				r = setTokenContextWithClaims(r, map[string]interface{}{"scope": scope, "sub": grantCaller})
			}
			rr := httptest.NewRecorder()
			HandleUserProfilePicturePost(database, auditLogger, testBaseURL, testMaxUploadBytes).ServeHTTP(rr, r)
			return rr
		},
		expectReads: func(database *datamocks.Database, _ bool) { expectTargetUser(database, nil) },
		writes:      []string{"CreateUserProfilePicture", "UpdateUserProfilePicture"},
		expectFirstWrite: func(database *datamocks.Database) {
			database.On("GetUserProfilePictureByUserId", mock.Anything, (*sql.Tx)(nil), targetUserId).Return(nil, nil).Once()
			database.On("CreateUserProfilePicture", mock.Anything, (*sql.Tx)(nil), mock.Anything).Return(errFirstWriteFails).Once()
		},
	},
	{
		name: "DELETE /users/{id}/profile-picture",
		kind: targetKindUser,
		serve: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, scope string) *httptest.ResponseRecorder {
			r := targetRequest(http.MethodDelete, "/api/v1/admin/users/52/profile-picture", "", scope, map[string]string{"id": "52"})
			rr := httptest.NewRecorder()
			HandleUserProfilePictureDelete(database, auditLogger).ServeHTTP(rr, r)
			return rr
		},
		expectReads:      func(database *datamocks.Database, _ bool) { expectTargetUser(database, nil) },
		writes:           []string{"DeleteUserProfilePicture"},
		expectFirstWrite: failingWrite("DeleteUserProfilePicture", mock.Anything, (*sql.Tx)(nil), targetUserId),
	},
	{
		name: "DELETE /users/{id}",
		kind: targetKindUser,
		serve: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, scope string) *httptest.ResponseRecorder {
			r := targetRequest(http.MethodDelete, "/api/v1/admin/users/52", "", scope, map[string]string{"id": "52"})
			rr := httptest.NewRecorder()
			HandleUserDelete(database, auditLogger).ServeHTTP(rr, r)
			return rr
		},
		expectReads:      func(database *datamocks.Database, _ bool) { expectTargetUser(database, nil) },
		writes:           []string{"RunInTransaction", "DeleteUser"},
		expectFirstWrite: failingWrite("RunInTransaction", mock.Anything, mock.Anything),
	},
	{
		name: "POST /user-attributes",
		kind: targetKindUser,
		serve: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, scope string) *httptest.ResponseRecorder {
			r := targetRequest(http.MethodPost, "/api/v1/admin/user-attributes", `{"userId":52,"key":"tier","value":"gold"}`, scope, nil)
			rr := httptest.NewRecorder()
			HandleUserAttributeCreatePost(database, inputvalidation.NewIdentifierValidator(), auditLogger).ServeHTTP(rr, r)
			return rr
		},
		expectReads:      func(database *datamocks.Database, _ bool) { expectTargetUser(database, nil) },
		writes:           []string{"CreateUserAttribute"},
		expectFirstWrite: failingWrite("CreateUserAttribute", mock.Anything, (*sql.Tx)(nil), mock.Anything),
	},
	{
		name: "PUT /user-attributes/{id}",
		kind: targetKindUser,
		serve: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, scope string) *httptest.ResponseRecorder {
			r := targetRequest(http.MethodPut, "/api/v1/admin/user-attributes/90", `{"key":"tier","value":"platinum"}`, scope, map[string]string{"id": "90"})
			rr := httptest.NewRecorder()
			HandleUserAttributeUpdatePut(database, inputvalidation.NewIdentifierValidator(), auditLogger).ServeHTTP(rr, r)
			return rr
		},
		expectReads: func(database *datamocks.Database, _ bool) {
			database.On("GetUserAttributeById", mock.Anything, (*sql.Tx)(nil), targetAttributeId).
				Return(&record.UserAttribute{Id: targetAttributeId, UserId: targetUserId, Key: "tier", Value: "gold"}, nil).Once()
		},
		writes:           []string{"UpdateUserAttribute"},
		expectFirstWrite: failingWrite("UpdateUserAttribute", mock.Anything, (*sql.Tx)(nil), mock.Anything),
	},
	{
		name: "DELETE /user-attributes/{id}",
		kind: targetKindUser,
		serve: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, scope string) *httptest.ResponseRecorder {
			r := targetRequest(http.MethodDelete, "/api/v1/admin/user-attributes/90", "", scope, map[string]string{"id": "90"})
			rr := httptest.NewRecorder()
			HandleUserAttributeDelete(database, auditLogger).ServeHTTP(rr, r)
			return rr
		},
		expectReads: func(database *datamocks.Database, _ bool) {
			database.On("GetUserAttributeById", mock.Anything, (*sql.Tx)(nil), targetAttributeId).
				Return(&record.UserAttribute{Id: targetAttributeId, UserId: targetUserId, Key: "tier"}, nil).Once()
		},
		writes:           []string{"DeleteUserAttribute"},
		expectFirstWrite: failingWrite("DeleteUserAttribute", mock.Anything, (*sql.Tx)(nil), targetAttributeId),
	},
	{
		name: "DELETE /user-sessions/{id}",
		kind: targetKindUser,
		serve: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, scope string) *httptest.ResponseRecorder {
			r := targetRequest(http.MethodDelete, "/api/v1/admin/user-sessions/91", "", scope, map[string]string{"id": "91"})
			rr := httptest.NewRecorder()
			HandleUserSessionDelete(database, auditLogger).ServeHTTP(rr, r)
			return rr
		},
		expectReads: func(database *datamocks.Database, _ bool) {
			database.On("GetUserSessionById", mock.Anything, (*sql.Tx)(nil), targetSessionId).
				Return(&record.UserSession{Id: targetSessionId, UserId: targetUserId, SessionIdentifier: "sid-91"}, nil).Once()
		},
		writes:           []string{"RunInTransaction", "DeleteUserSession"},
		expectFirstWrite: failingWrite("RunInTransaction", mock.Anything, mock.Anything),
	},
	{
		name: "DELETE /user-consents/{id}",
		kind: targetKindUser,
		serve: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, scope string) *httptest.ResponseRecorder {
			r := targetRequest(http.MethodDelete, "/api/v1/admin/user-consents/92", "", scope, map[string]string{"id": "92"})
			rr := httptest.NewRecorder()
			HandleUserConsentDelete(database, auditLogger).ServeHTTP(rr, r)
			return rr
		},
		expectReads: func(database *datamocks.Database, _ bool) {
			database.On("GetUserConsentById", mock.Anything, (*sql.Tx)(nil), targetConsentId).
				Return(&record.UserConsent{Id: targetConsentId, UserId: targetUserId, ClientId: 3}, nil).Once()
		},
		writes:           []string{"DeleteUserConsent"},
		expectFirstWrite: failingWrite("DeleteUserConsent", mock.Anything, (*sql.Tx)(nil), targetConsentId),
	},
	{
		// A save that changes nothing gives the grant ceiling nothing to judge; the target is what
		// is refused.
		name: "PUT /users/{id}/groups",
		kind: targetKindUser,
		serve: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, scope string) *httptest.ResponseRecorder {
			r := targetRequest(http.MethodPut, "/api/v1/admin/users/52/groups", `{"groupIds":[],"expectedGroupIds":[]}`, scope, map[string]string{"id": "52"})
			rr := httptest.NewRecorder()
			HandleUserGroupsPut(database, auditLogger).ServeHTTP(rr, r)
			return rr
		},
		expectReads:      func(database *datamocks.Database, _ bool) { expectTargetUser(database, nil) },
		writes:           []string{"RunInTransaction", "CreateUserGroup", "DeleteUserGroup"},
		expectFirstWrite: failingWrite("RunInTransaction", mock.Anything, mock.Anything),
	},
	{
		name: "PUT /users/{id}/permissions",
		kind: targetKindUser,
		serve: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, scope string) *httptest.ResponseRecorder {
			r := targetRequest(http.MethodPut, "/api/v1/admin/users/52/permissions", `{"permissionIds":[],"expectedPermissionIds":[]}`, scope,
				map[string]string{"id": "52"})
			rr := httptest.NewRecorder()
			HandleUserPermissionsPut(database, auditLogger).ServeHTTP(rr, r)
			return rr
		},
		expectReads:      func(database *datamocks.Database, _ bool) { expectTargetUser(database, nil) },
		writes:           []string{"RunInTransaction", "CreateUserPermission", "DeleteUserPermission"},
		expectFirstWrite: failingWrite("RunInTransaction", mock.Anything, mock.Anything),
	},
	{
		// Granting an administrator an ordinary permission changes no administrative one, so the
		// grant ceiling lets it through and the target ceiling refuses it.
		name: "PUT /users/{id}/permissions granting an ordinary permission",
		kind: targetKindUser,
		serve: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, scope string) *httptest.ResponseRecorder {
			r := targetRequest(http.MethodPut, "/api/v1/admin/users/52/permissions", `{"permissionIds":[6],"expectedPermissionIds":[]}`, scope,
				map[string]string{"id": "52"})
			rr := httptest.NewRecorder()
			HandleUserPermissionsPut(database, auditLogger).ServeHTTP(rr, r)
			return rr
		},
		expectReads: func(database *datamocks.Database, _ bool) {
			expectTargetUser(database, nil)
			expectPermissionsExist(database, 6)
			// The grant ceiling's read of the administrative set, which an authserver:manage caller
			// makes too, for the save's records.
			expectAuthServerPermissions(database)
		},
		writes:           []string{"RunInTransaction", "CreateUserPermission", "DeleteUserPermission"},
		expectFirstWrite: failingWrite("RunInTransaction", mock.Anything, mock.Anything),
	},
	{
		// Moving an administrator into an ordinary group grants nothing administrative, so the grant
		// ceiling lets it through and the target ceiling refuses it.
		name: "POST /groups/{id}/members of an ordinary group",
		kind: targetKindUser,
		serve: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, scope string) *httptest.ResponseRecorder {
			r := targetRequest(http.MethodPost, "/api/v1/admin/groups/8/members", `{"userId":52}`, scope, map[string]string{"id": "8"})
			rr := httptest.NewRecorder()
			HandleGroupMemberAddPost(database, auditLogger).ServeHTTP(rr, r)
			return rr
		},
		expectReads: func(database *datamocks.Database, _ bool) {
			expectGroup(database, ordinaryGroupId)
			expectTargetUser(database, nil)
			database.On("GetUserGroupByUserIdAndGroupId", mock.Anything, (*sql.Tx)(nil), targetUserId, ordinaryGroupId).
				Return((*record.UserGroup)(nil), nil).Once()
			// The grant ceiling's read of what the group holds, which an authserver:manage caller
			// makes too, for the change's records.
			expectGroupPermissions(database, ordinaryGroupId)
			expectAuthServerPermissions(database)
		},
		writes:           []string{"CreateUserGroup"},
		expectFirstWrite: failingWrite("CreateUserGroup", mock.Anything, (*sql.Tx)(nil), mock.Anything),
	},
	{
		name: "DELETE /groups/{id}/members/{userId} of an ordinary group",
		kind: targetKindUser,
		serve: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, scope string) *httptest.ResponseRecorder {
			r := targetRequest(http.MethodDelete, "/api/v1/admin/groups/8/members/52", "", scope, map[string]string{"id": "8", "userId": "52"})
			rr := httptest.NewRecorder()
			HandleGroupMemberDelete(database, auditLogger).ServeHTTP(rr, r)
			return rr
		},
		expectReads: func(database *datamocks.Database, _ bool) {
			expectGroup(database, ordinaryGroupId)
			expectTargetUser(database, nil)
			database.On("GetUserGroupByUserIdAndGroupId", mock.Anything, (*sql.Tx)(nil), targetUserId, ordinaryGroupId).
				Return(&record.UserGroup{Id: targetMembershipId, UserId: targetUserId, GroupId: ordinaryGroupId}, nil).Once()
			expectGroupPermissions(database, ordinaryGroupId)
			expectAuthServerPermissions(database)
		},
		writes:           []string{"RunInTransaction", "DeleteUserGroup"},
		expectFirstWrite: failingWrite("RunInTransaction", mock.Anything, mock.Anything),
	},
}

var groupTargetWrites = []targetWrite{
	{
		name: "PUT /groups/{id}",
		kind: targetKindGroup,
		serve: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, scope string) *httptest.ResponseRecorder {
			r := targetRequest(http.MethodPut, "/api/v1/admin/groups/57", `{"groupIdentifier":"renamed-group","description":"Renamed"}`, scope,
				map[string]string{"id": "57"})
			rr := httptest.NewRecorder()
			HandleGroupUpdatePut(database, inputvalidation.NewIdentifierValidator(), auditLogger).ServeHTTP(rr, r)
			return rr
		},
		expectReads: func(database *datamocks.Database, _ bool) {
			expectTargetGroup(database)
			database.On("GetGroupByGroupIdentifier", mock.Anything, (*sql.Tx)(nil), "renamed-group").Return(nil, nil).Once()
		},
		writes:           []string{"UpdateGroup"},
		expectFirstWrite: failingWrite("UpdateGroup", mock.Anything, (*sql.Tx)(nil), mock.Anything),
	},
	{
		name: "POST /group-attributes",
		kind: targetKindGroup,
		serve: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, scope string) *httptest.ResponseRecorder {
			r := targetRequest(http.MethodPost, "/api/v1/admin/group-attributes", `{"groupId":57,"key":"tier","value":"gold"}`, scope, nil)
			rr := httptest.NewRecorder()
			HandleGroupAttributeCreatePost(database, inputvalidation.NewIdentifierValidator(), auditLogger).ServeHTTP(rr, r)
			return rr
		},
		expectReads:      func(database *datamocks.Database, _ bool) { expectTargetGroup(database) },
		writes:           []string{"CreateGroupAttribute"},
		expectFirstWrite: failingWrite("CreateGroupAttribute", mock.Anything, (*sql.Tx)(nil), mock.Anything),
	},
	{
		name: "PUT /group-attributes/{id}",
		kind: targetKindGroup,
		serve: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, scope string) *httptest.ResponseRecorder {
			r := targetRequest(http.MethodPut, "/api/v1/admin/group-attributes/90", `{"key":"tier","value":"platinum"}`, scope, map[string]string{"id": "90"})
			rr := httptest.NewRecorder()
			HandleGroupAttributeUpdatePut(database, inputvalidation.NewIdentifierValidator(), auditLogger).ServeHTTP(rr, r)
			return rr
		},
		expectReads: func(database *datamocks.Database, _ bool) {
			database.On("GetGroupAttributeById", mock.Anything, (*sql.Tx)(nil), targetAttributeId).
				Return(&record.GroupAttribute{Id: targetAttributeId, GroupId: targetGroupId, Key: "tier", Value: "gold"}, nil).Once()
		},
		writes: []string{"UpdateGroupAttribute"},
		expectFirstWrite: func(database *datamocks.Database) {
			// The group, read for the record after the ceiling.
			expectTargetGroup(database)
			failingWrite("UpdateGroupAttribute", mock.Anything, (*sql.Tx)(nil), mock.Anything)(database)
		},
	},
	{
		name: "DELETE /group-attributes/{id}",
		kind: targetKindGroup,
		serve: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, scope string) *httptest.ResponseRecorder {
			r := targetRequest(http.MethodDelete, "/api/v1/admin/group-attributes/90", "", scope, map[string]string{"id": "90"})
			rr := httptest.NewRecorder()
			HandleGroupAttributeDelete(database, auditLogger).ServeHTTP(rr, r)
			return rr
		},
		expectReads: func(database *datamocks.Database, _ bool) {
			database.On("GetGroupAttributeById", mock.Anything, (*sql.Tx)(nil), targetAttributeId).
				Return(&record.GroupAttribute{Id: targetAttributeId, GroupId: targetGroupId, Key: "tier"}, nil).Once()
		},
		writes: []string{"DeleteGroupAttribute"},
		expectFirstWrite: func(database *datamocks.Database) {
			// The group, read for the record after the ceiling.
			expectTargetGroup(database)
			failingWrite("DeleteGroupAttribute", mock.Anything, (*sql.Tx)(nil), targetAttributeId)(database)
		},
	},
	{
		name: "PUT /groups/{id}/permissions",
		kind: targetKindGroup,
		serve: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, scope string) *httptest.ResponseRecorder {
			r := targetRequest(http.MethodPut, "/api/v1/admin/groups/57/permissions", `{"permissionIds":[],"expectedPermissionIds":[]}`, scope,
				map[string]string{"id": "57"})
			rr := httptest.NewRecorder()
			HandleGroupPermissionsPut(database, auditLogger).ServeHTTP(rr, r)
			return rr
		},
		expectReads:      func(database *datamocks.Database, _ bool) { expectTargetGroup(database) },
		writes:           []string{"RunInTransaction", "CreateGroupPermission", "DeleteGroupPermission"},
		expectFirstWrite: failingWrite("RunInTransaction", mock.Anything, mock.Anything),
	},
	{
		name: "PUT /groups/{id}/permissions granting an ordinary permission",
		kind: targetKindGroup,
		serve: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, scope string) *httptest.ResponseRecorder {
			r := targetRequest(http.MethodPut, "/api/v1/admin/groups/57/permissions", `{"permissionIds":[5],"expectedPermissionIds":[]}`, scope,
				map[string]string{"id": "57"})
			rr := httptest.NewRecorder()
			HandleGroupPermissionsPut(database, auditLogger).ServeHTTP(rr, r)
			return rr
		},
		expectReads: func(database *datamocks.Database, _ bool) {
			expectTargetGroup(database)
			expectPermissionsExist(database, 5)
			expectAuthServerPermissions(database)
		},
		writes:           []string{"RunInTransaction", "CreateGroupPermission", "DeleteGroupPermission"},
		expectFirstWrite: failingWrite("RunInTransaction", mock.Anything, mock.Anything),
	},
}

// targetCase is one write against one holding of its target.
type targetCase struct {
	write   targetWrite
	holding targetHolding
}

func (c targetCase) name() string { return c.write.name + "/" + c.holding.name }

func (c targetCase) targetId() int64 {
	if c.write.kind == targetKindGroup {
		return targetGroupId
	}
	return targetUserId
}

func (c targetCase) expectHolding(database *datamocks.Database) {
	if c.write.kind == targetKindGroup {
		expectGroupHolding(database, c.holding)
	} else {
		expectUserHolding(database, c.holding)
	}
}

// administratorTargets is every write against each administrator holding of its target's kind.
func administratorTargets() []targetCase {
	var cases []targetCase
	for _, write := range userTargetWrites {
		cases = append(cases, targetCase{write, userAdministratorDirectly}, targetCase{write, userAdministratorThroughAGroup})
	}
	for _, write := range groupTargetWrites {
		cases = append(cases, targetCase{write, administrativeTargetGroup})
	}
	return cases
}

// ordinaryTargets is every write against an ordinary target of its kind.
func ordinaryTargets() []targetCase {
	var cases []targetCase
	for _, write := range userTargetWrites {
		cases = append(cases, targetCase{write, ordinaryUser})
	}
	for _, write := range groupTargetWrites {
		cases = append(cases, targetCase{write, ordinaryTargetGroup})
	}
	return cases
}

// granularScopeOfTarget is the granular write scope every user and group write admits.
const granularScopeOfTarget = "authserver:manage-users"

func TestTargetCeiling_AGranularTokenWritingToAnAdministratorIsRefused(t *testing.T) {
	for _, c := range administratorTargets() {
		t.Run(c.name(), func(t *testing.T) {
			require.True(t, c.holding.administrator)
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)

			c.write.expectReads(database, true)
			c.expectHolding(database)
			records := recordLoggedEvents(auditLogger)

			rr := c.write.serve(t, database, auditLogger, granularScopeOfTarget)

			status := rr.Code
			code, description := decodeErrorEnvelope(t, rr)
			assertManageScopeRequired(t, rr, status, code, description)
			database.AssertExpectations(t)
			assertNotAttemptedOnClientDatabase(t, database, c.write.writes...)

			require.Len(t, *records, 1, "one record per refused request")
			refusal := (*records)[0]
			assert.Equal(t, audit.EventAdministratorChangeRefused, refusal.event)
			assert.Equal(t, grantCaller, refusal.details["loggedInUser"])
			assert.Contains(t, refusal.details, "method")
			assert.Contains(t, refusal.details, "route")
			assert.Equal(t, "target", refusal.details["ceiling"])
			assert.Equal(t, c.write.kind, refusal.details["targetKind"])
			assert.Equal(t, c.targetId(), refusal.details["targetId"])
			assert.NotContains(t, refusal.details, "permissionIds", "a target refusal names the target, not permissions")
			assert.NotContains(t, refusal.details, "groupIds")
		})
	}
}

// Every token below authserver:manage is held to the ceiling, and so is a request that reached the
// handler with no validated token at all: the policy fails closed.
func TestTargetCeiling_EveryOtherCallerIsHeldToIt(t *testing.T) {
	callers := []struct {
		name  string
		scope string
	}{
		{name: "admin-read", scope: "authserver:admin-read"},
		{name: "two granular scopes", scope: "authserver:manage-users authserver:manage-clients authserver:manage-settings"},
		{name: "a scope that only resembles manage", scope: "authserver:manage-account other:manage"},
		{name: "no validated token", scope: ""},
	}

	for _, c := range administratorTargets() {
		for _, caller := range callers {
			t.Run(c.name()+"/"+caller.name, func(t *testing.T) {
				database := datamocks.NewDatabase(t)
				auditLogger := handlersmocks.NewAuditLogger(t)

				c.write.expectReads(database, true)
				c.expectHolding(database)
				records := recordLoggedEvents(auditLogger)

				rr := c.write.serve(t, database, auditLogger, caller.scope)

				status := rr.Code
				code, description := decodeErrorEnvelope(t, rr)
				assertManageScopeRequired(t, rr, status, code, description)
				assertNotAttemptedOnClientDatabase(t, database, c.write.writes...)
				require.Len(t, *records, 1)
				assert.Equal(t, audit.EventAdministratorChangeRefused, (*records)[0].event)
				assert.Equal(t, "target", (*records)[0].details["ceiling"])
			})
		}
	}
}

// A granular token keeps writing to every user and group that is not an administrator: holding
// manage-account, belonging to a group that holds a custom authserver permission, and holding one
// itself make nobody an administrator. The write goes on past the ceiling.
func TestTargetCeiling_AGranularTokenWritingToAnOrdinaryTargetProceeds(t *testing.T) {
	for _, c := range ordinaryTargets() {
		t.Run(c.name(), func(t *testing.T) {
			require.False(t, c.holding.administrator)
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)

			c.write.expectReads(database, true)
			c.expectHolding(database)
			c.write.expectFirstWrite(database)

			rr := c.write.serve(t, database, auditLogger, granularScopeOfTarget)

			assert.Equal(t, http.StatusInternalServerError, rr.Code, "the write past the ceiling was reached: %s", rr.Body.String())
			assert.Empty(t, rr.Header().Get("WWW-Authenticate"))
			database.AssertExpectations(t)
			auditLogger.AssertNotCalled(t, "Log", mock.Anything, audit.EventAdministratorChangeRefused, mock.Anything)
		})
	}
}

// An authserver:manage caller writes to administrators, and reads nothing for the target ceiling:
// whatever the target holds, its token already carries every authority.
func TestTargetCeiling_AManageTokenWritesToAdministratorsAndReadsNothingForIt(t *testing.T) {
	for _, write := range append(append([]targetWrite{}, userTargetWrites...), groupTargetWrites...) {
		t.Run(write.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)

			write.expectReads(database, false)
			write.expectFirstWrite(database)

			rr := write.serve(t, database, auditLogger, "authserver:manage")

			assert.Equal(t, http.StatusInternalServerError, rr.Code, "the write past the ceiling was reached: %s", rr.Body.String())
			database.AssertExpectations(t)
			for _, call := range database.Calls {
				if call.Arguments.Get(1) != (*sql.Tx)(nil) {
					continue
				}
				switch call.Method {
				case "GetUserPermissionsByUserId", "GetUserGroupsByUserId":
					t.Errorf("%s was read for the target ceiling", call.Method)
				case "GetGroupPermissionsByGroupIds":
					if ids, ok := call.Arguments.Get(2).([]int64); ok && len(ids) == 1 && ids[0] == targetGroupId {
						t.Errorf("the target group's permissions were read for the target ceiling")
					}
				}
			}
			auditLogger.AssertNotCalled(t, "Log", mock.Anything, audit.EventAdministratorChangeRefused, mock.Anything)
		})
	}
}

// The policy failing to read what the target holds is one 500, with no write and no record: a write
// the policy could not judge is not let through.
func TestTargetCeiling_AFailedPolicyReadIsOneFiveHundred(t *testing.T) {
	for _, write := range append(append([]targetWrite{}, userTargetWrites...), groupTargetWrites...) {
		t.Run(write.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)

			write.expectReads(database, true)
			if write.kind == targetKindGroup {
				database.On("GetGroupPermissionsByGroupIds", mock.Anything, (*sql.Tx)(nil), []int64{targetGroupId}).
					Return(nil, errors.New("the read failed")).Once()
			} else {
				database.On("GetUserPermissionsByUserId", mock.Anything, (*sql.Tx)(nil), targetUserId).
					Return(nil, errors.New("the read failed")).Once()
			}

			rr := write.serve(t, database, auditLogger, granularScopeOfTarget)

			assert.Equal(t, http.StatusInternalServerError, rr.Code)
			assert.Equal(t, 1, strings.Count(rr.Body.String(), "INTERNAL_SERVER_ERROR"), "exactly one error response")
			database.AssertExpectations(t)
			assertNotAttemptedOnClientDatabase(t, database, write.writes...)
			auditLogger.AssertNotCalled(t, "Log", mock.Anything, audit.EventAdministratorChangeRefused, mock.Anything)
		})
	}
}

// The refusal comes after the request's 404 and 400 answers: a target that does not exist and a
// body the write refuses are answered as before, with nothing read for the policy and nothing
// audited.
func TestTargetCeiling_TheWritesAnswerTheirOwnFourHundredsFirst(t *testing.T) {
	assertNoTargetPolicyRead := func(t *testing.T, database *datamocks.Database) {
		t.Helper()
		assertNotAttemptedOnClientDatabase(t, database, "GetUserPermissionsByUserId", "GetUserGroupsByUserId",
			"GetGroupPermissionsByGroupIds", "GetResourceByResourceIdentifier", "GetPermissionsByResourceId")
	}

	t.Run("a user that does not exist", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		database.On("GetUserById", mock.Anything, (*sql.Tx)(nil), targetUserId).Return(nil, nil).Once()

		r := targetRequest(http.MethodDelete, "/api/v1/admin/users/52", "", granularScopeOfTarget, map[string]string{"id": "52"})
		rr := httptest.NewRecorder()
		HandleUserDelete(database, auditLogger).ServeHTTP(rr, r)

		assert.Equal(t, http.StatusNotFound, rr.Code)
		assertNoTargetPolicyRead(t, database)
		auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("a user attribute that does not exist", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		database.On("GetUserAttributeById", mock.Anything, (*sql.Tx)(nil), targetAttributeId).Return(nil, nil).Once()

		r := targetRequest(http.MethodDelete, "/api/v1/admin/user-attributes/90", "", granularScopeOfTarget, map[string]string{"id": "90"})
		rr := httptest.NewRecorder()
		HandleUserAttributeDelete(database, auditLogger).ServeHTTP(rr, r)

		assert.Equal(t, http.StatusNotFound, rr.Code)
		assertNoTargetPolicyRead(t, database)
		auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("a password the policy refuses", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		expectTargetUser(database, nil)

		r := targetRequest(http.MethodPut, "/api/v1/admin/users/52/password", `{"newPassword":"x"}`, granularScopeOfTarget, map[string]string{"id": "52"})
		rr := httptest.NewRecorder()
		HandleUserPasswordPut(database, accountvalidation.NewPasswordValidator(), auditLogger).ServeHTTP(rr, withPasswordSettings(r))

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assertNoTargetPolicyRead(t, database)
		auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("a group identifier another group holds", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		expectTargetGroup(database)
		database.On("GetGroupByGroupIdentifier", mock.Anything, (*sql.Tx)(nil), "renamed-group").
			Return(&record.Group{Id: 99, GroupIdentifier: "renamed-group"}, nil).Once()

		r := targetRequest(http.MethodPut, "/api/v1/admin/groups/57", `{"groupIdentifier":"renamed-group"}`, granularScopeOfTarget,
			map[string]string{"id": "57"})
		rr := httptest.NewRecorder()
		HandleGroupUpdatePut(database, inputvalidation.NewIdentifierValidator(), auditLogger).ServeHTTP(rr, r)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assertNoTargetPolicyRead(t, database)
		auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
	})
}

// expectHoldsNothing registers the target ceiling's reads of a user who holds no grant, directly or
// through a group, for a caller without authserver:manage: an ordinary user, whose write goes on.
func expectHoldsNothing(database *datamocks.Database, userId int64) {
	database.On("GetUserPermissionsByUserId", mock.Anything, (*sql.Tx)(nil), userId).Return([]record.UserPermission{}, nil).Once()
	database.On("GetUserGroupsByUserId", mock.Anything, (*sql.Tx)(nil), userId).Return([]record.UserGroup{}, nil).Once()
}
