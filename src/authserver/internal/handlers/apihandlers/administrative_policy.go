package apihandlers

import (
	"context"
	"database/sql"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/middleware"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/errs"
)

// The administrative policy, the one rule behind the admin API's route gate: only an
// authserver:manage token creates an administrator, changes one, or changes what reaches one. The
// route gate asks whether a token may call a route; this asks whether it may do what the request
// does, to whom it does it. A granular scope keeps full control of everyone and everything else
// (#402 decision 1).
//
// The caller's authority is the access token's scope, as at the route gate, and a request that
// reached a handler with no validated token holds no authority here: the policy fails closed.
// A refusal is decided before anything is written and before any transaction opens, after the
// request's own 400 and 404 answers, against the rows as read then (#402 decision 4).

// administrativePermissionIdentifiers is the named administrative set: the permissions on the
// authserver resource that confer power in this server. A user, group or client holding any of them
// is an administrator. manage-account, which every user receives at creation, and the custom
// permissions an operator adds to the resource confer none and are not in it (#402 decision 2).
var administrativePermissionIdentifiers = map[string]bool{
	builtin.ManagePermissionIdentifier:          true,
	builtin.AdminReadPermissionIdentifier:       true,
	builtin.ManageUsersPermissionIdentifier:     true,
	builtin.ManageClientsPermissionIdentifier:   true,
	builtin.ManageSettingsPermissionIdentifier:  true,
	builtin.BrowserSessionsPermissionIdentifier: true,
}

// manageScope is the one scope the policy admits.
const manageScope = builtin.AuthServerResourceIdentifier + ":" + builtin.ManagePermissionIdentifier

// manageScopeRequiredDescription is the refusal's sentence, in the body and in the challenge.
const manageScopeRequiredDescription = "Only a token with the authserver:manage scope may act on administrators or administrative permissions."

// The ceiling a refusal names. The grant ceiling is granting or revoking an administrative
// permission, directly or by moving a user into or out of a group that holds one, and deleting such
// a group (#402 decisions 1 and 5).
const ceilingGrant = "grant"

// The kind of target a refusal names.
const (
	targetKindUser   = "user"
	targetKindGroup  = "group"
	targetKindClient = "client"
)

// administrativePolicyDatabase is what the policy reads to resolve the administrative set to rows.
// Every handler a ceiling guards names it in its own port.
type administrativePolicyDatabase interface {
	GetPermissionsByResourceId(ctx context.Context, tx *sql.Tx, resourceId int64) ([]record.Permission, error)
	GetResourceByResourceIdentifier(ctx context.Context, tx *sql.Tx, resourceIdentifier string) (*record.Resource, error)
}

// administrativeGroupPolicyDatabase is what the policy reads to judge a change of group membership
// or a group's deletion: the administrative set, and what the groups hold.
type administrativeGroupPolicyDatabase interface {
	administrativePolicyDatabase
	GetGroupPermissionsByGroupIds(ctx context.Context, tx *sql.Tx, groupIds []int64) ([]record.GroupPermission, error)
}

// userGroupsPolicyDatabase is what the policy reads to judge a save of a user's groups: beside
// what the groups hold, the memberships the user has.
type userGroupsPolicyDatabase interface {
	administrativeGroupPolicyDatabase
	GetUserGroupsByUserId(ctx context.Context, tx *sql.Tx, userId int64) ([]record.UserGroup, error)
}

// callerHoldsManage reports whether the request's validated token carries authserver:manage.
func callerHoldsManage(r *http.Request) bool {
	token, ok := reqctx.ValidatedTokenFrom(r.Context())
	return ok && token.HasScope(manageScope)
}

// administrativePermissionIds is the ids of the administrative set's rows: the permissions on the
// authserver resource whose identifiers it names. Read outside any transaction.
func administrativePermissionIds(ctx context.Context, database administrativePolicyDatabase) (map[int64]bool, error) {
	resource, err := database.GetResourceByResourceIdentifier(ctx, nil, builtin.AuthServerResourceIdentifier)
	if err != nil {
		return nil, errs.Wrap(err, "unable to read the authserver resource for the administrative policy")
	}
	if resource == nil {
		return nil, errs.New("the authserver resource does not exist")
	}
	permissions, err := database.GetPermissionsByResourceId(ctx, nil, resource.Id)
	if err != nil {
		return nil, errs.Wrap(err, "unable to read the authserver permissions for the administrative policy")
	}
	ids := make(map[int64]bool, len(administrativePermissionIdentifiers))
	for _, permission := range permissions {
		if administrativePermissionIdentifiers[permission.PermissionIdentifier] {
			ids[permission.Id] = true
		}
	}
	return ids, nil
}

// administratorChangeRefusal is what one refusal records beside the caller and the route.
type administratorChangeRefusal struct {
	ceiling    string
	targetKind string
	targetId   int64
	// permissionIds is the administrative permissions whose change caused a grant refusal.
	permissionIds []int64
	// groupIds is the administrative groups whose membership change caused a grant refusal, when
	// the target is the user moved into or out of them.
	groupIds []int64
}

// refuseAdministratorChange answers a request the policy refused: one administrator_change_refused
// record, then 403 MANAGE_SCOPE_REQUIRED with an insufficient_scope challenge naming
// authserver:manage. RFC 6750 section 3 requires the challenge whenever the token "does not
// enable access to the protected resource", and section 3.1 defines insufficient_scope as "the
// request requires higher privileges than provided by the access token", answered 403, which MAY
// carry the scope. The code is not the route gate's INSUFFICIENT_SCOPE because the remedy differs:
// there the integration requests the route's scope, here no granular scope will ever do (#402
// decisions 4 and 5).
func refuseAdministratorChange(w http.ResponseWriter, r *http.Request, auditLogger AuditLogger, refusal administratorChangeRefusal) {
	details := map[string]interface{}{
		"loggedInUser": callerSubject(r),
		"method":       r.Method,
		"route":        routePattern(r),
		"ceiling":      refusal.ceiling,
		"targetKind":   refusal.targetKind,
		"targetId":     refusal.targetId,
	}
	if refusal.permissionIds != nil {
		details["permissionIds"] = refusal.permissionIds
	}
	if refusal.groupIds != nil {
		details["groupIds"] = refusal.groupIds
	}
	auditLogger.Log(r.Context(), audit.EventAdministratorChangeRefused, details)

	w.Header().Set("WWW-Authenticate", middleware.InsufficientScopeChallenge(manageScopeRequiredDescription, manageScope))
	writeJSONError(w, manageScopeRequiredDescription, "MANAGE_SCOPE_REQUIRED", http.StatusForbidden)
}

// routePattern is the pattern of the route chi matched, such as /api/v1/admin/users/{id}/permissions,
// never the path: the path carries ids and a pattern is what an operator filters on.
func routePattern(r *http.Request) string {
	routeContext := chi.RouteContext(r.Context())
	if routeContext == nil {
		return ""
	}
	return routeContext.RoutePattern()
}

// grantCeilingAllows applies the grant ceiling to a save replacing a target's permission grants:
// it reports whether the save may go on, and when it may not it has answered the request.
//
// The save is judged on what it changes, the permissions in wanted and not in expected and those
// in expected and not in wanted. That is exactly what the save commits or nothing: the save's
// transaction refuses with 409 unless the stored grants are expected as a set, and repairing a
// stored duplicate grants and revokes nothing. A save changing nothing reads nothing here, and
// neither does an authserver:manage caller, whose token already carries every authority a grant
// confers.
func grantCeilingAllows(w http.ResponseWriter, r *http.Request, database administrativePolicyDatabase, auditLogger AuditLogger,
	targetKind string, targetId int64, wanted, expected []int64) bool {
	changed := grantChange(wanted, expected)
	if len(changed) == 0 || callerHoldsManage(r) {
		return true
	}

	administrative, err := administrativePermissionIds(r.Context(), database)
	if err != nil {
		writeInternalServerError(w, r, err, "target_kind", targetKind, "target_id", targetId)
		return false
	}
	var causes []int64
	for _, permissionId := range changed {
		if administrative[permissionId] {
			causes = append(causes, permissionId)
		}
	}
	if len(causes) == 0 {
		return true
	}

	refuseAdministratorChange(w, r, auditLogger, administratorChangeRefusal{
		ceiling:       ceilingGrant,
		targetKind:    targetKind,
		targetId:      targetId,
		permissionIds: causes,
	})
	return false
}

// grantChange is the permissions a save of wanted over expected grants, in wanted's order, then
// those it revokes, in expected's order, each once.
func grantChange(wanted, expected []int64) []int64 {
	granted, revoked := grantedAndRevoked(wanted, expected)
	return append(granted, revoked...)
}

// grantedAndRevoked is the keys a save of wanted over expected adds, in wanted's order, and those
// it removes, in expected's order, each once.
func grantedAndRevoked(wanted, expected []int64) (granted, revoked []int64) {
	inExpected := make(map[int64]bool, len(expected))
	for _, id := range expected {
		inExpected[id] = true
	}
	inWanted := make(map[int64]bool, len(wanted))
	for _, id := range wanted {
		inWanted[id] = true
	}

	for _, id := range firstOccurrences(wanted) {
		if !inExpected[id] {
			granted = append(granted, id)
		}
	}
	for _, id := range firstOccurrences(expected) {
		if !inWanted[id] {
			revoked = append(revoked, id)
		}
	}
	return granted, revoked
}

// administrativeGroups is which of groupIds hold an administrative permission, in groupIds' order,
// and the administrative permissions they hold, each once, group by group. Read outside any
// transaction; a set of groups holding no grant at all reads nothing more.
func administrativeGroups(ctx context.Context, database administrativeGroupPolicyDatabase, groupIds []int64) (groups, permissions []int64, err error) {
	grants, err := database.GetGroupPermissionsByGroupIds(ctx, nil, groupIds)
	if err != nil {
		return nil, nil, errs.Wrap(err, "unable to read the groups' permissions for the administrative policy")
	}
	if len(grants) == 0 {
		return nil, nil, nil
	}
	administrative, err := administrativePermissionIds(ctx, database)
	if err != nil {
		return nil, nil, err
	}

	held := make(map[int64][]int64)
	for _, grant := range grants {
		if administrative[grant.PermissionId] {
			held[grant.GroupId] = append(held[grant.GroupId], grant.PermissionId)
		}
	}
	named := make(map[int64]bool)
	for _, groupId := range groupIds {
		if len(held[groupId]) == 0 {
			continue
		}
		groups = append(groups, groupId)
		for _, permissionId := range held[groupId] {
			if !named[permissionId] {
				named[permissionId] = true
				permissions = append(permissions, permissionId)
			}
		}
	}
	return groups, permissions, nil
}

// membershipCeilingAllows applies the grant ceiling to moving a user into or out of groups: joining
// a group that holds an administrative permission grants it, and leaving one revokes it. groupIds
// is the groups the request joins or leaves. It reports whether the change may go on, and when it
// may not it has answered the request. An authserver:manage caller reads nothing here.
func membershipCeilingAllows(w http.ResponseWriter, r *http.Request, database administrativeGroupPolicyDatabase, auditLogger AuditLogger,
	userId int64, groupIds []int64) bool {
	if len(groupIds) == 0 || callerHoldsManage(r) {
		return true
	}

	groups, causes, err := administrativeGroups(r.Context(), database, groupIds)
	if err != nil {
		writeInternalServerError(w, r, err, "user_id", userId, "group_ids", groupIds)
		return false
	}
	if len(groups) == 0 {
		return true
	}

	refuseAdministratorChange(w, r, auditLogger, administratorChangeRefusal{
		ceiling:       ceilingGrant,
		targetKind:    targetKindUser,
		targetId:      userId,
		permissionIds: causes,
		groupIds:      groups,
	})
	return false
}

// userGroupsCeilingAllows applies the grant ceiling to a save replacing a user's groups with wanted
// over the loaded expected. Like a permission save it is judged on what it changes: the groups it
// joins, wanted and not expected, which is exactly what it adds if it commits, and the groups it
// leaves, expected and not wanted. The save's transaction refuses with 409 unless the stored
// memberships are expected as a set, so a group the user does not belong to is left by nothing
// that commits. Only the groups left that the user belongs to are judged, which bounds what the
// policy reads by the user's memberships rather than by the length of the loaded list.
func userGroupsCeilingAllows(w http.ResponseWriter, r *http.Request, database userGroupsPolicyDatabase, auditLogger AuditLogger,
	userId int64, wanted, expected []int64) bool {
	if callerHoldsManage(r) {
		return true
	}

	judged, left := grantedAndRevoked(wanted, expected)
	if len(left) > 0 {
		stored, err := database.GetUserGroupsByUserId(r.Context(), nil, userId)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "unable to read the user's groups for the administrative policy"), "user_id", userId)
			return false
		}
		belongs := make(map[int64]bool, len(stored))
		for _, membership := range stored {
			belongs[membership.GroupId] = true
		}
		for _, groupId := range left {
			if belongs[groupId] {
				judged = append(judged, groupId)
			}
		}
	}

	return membershipCeilingAllows(w, r, database, auditLogger, userId, judged)
}

// groupDeletionCeilingAllows applies the grant ceiling to deleting a group: deleting a group that
// holds an administrative permission revokes it from every member at once. It reports whether the
// deletion may go on, and when it may not it has answered the request. An authserver:manage caller
// reads nothing here.
func groupDeletionCeilingAllows(w http.ResponseWriter, r *http.Request, database administrativeGroupPolicyDatabase, auditLogger AuditLogger,
	groupId int64) bool {
	if callerHoldsManage(r) {
		return true
	}

	groups, causes, err := administrativeGroups(r.Context(), database, []int64{groupId})
	if err != nil {
		writeInternalServerError(w, r, err, "group_id", groupId)
		return false
	}
	if len(groups) == 0 {
		return true
	}

	refuseAdministratorChange(w, r, auditLogger, administratorChangeRefusal{
		ceiling:       ceilingGrant,
		targetKind:    targetKindGroup,
		targetId:      groupId,
		permissionIds: causes,
	})
	return false
}
