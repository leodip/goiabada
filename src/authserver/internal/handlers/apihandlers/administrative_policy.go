package apihandlers

import (
	"context"
	"database/sql"
	"net/http"
	"slices"

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
// a group; the target ceiling is any other write on an administrator; the settings ceiling is
// changing the email or the audit-log settings (#402 decisions 1, 5 and 7).
const (
	ceilingGrant    = "grant"
	ceilingTarget   = "target"
	ceilingSettings = "settings"
)

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

// userTargetPolicyDatabase is what the policy reads to judge a write on a user: the administrative
// set, the permissions the user holds directly, and those its groups hold.
type userTargetPolicyDatabase interface {
	administrativeGroupPolicyDatabase
	GetUserGroupsByUserId(ctx context.Context, tx *sql.Tx, userId int64) ([]record.UserGroup, error)
	GetUserPermissionsByUserId(ctx context.Context, tx *sql.Tx, userId int64) ([]record.UserPermission, error)
}

// callerHoldsManage reports whether the request's validated token carries authserver:manage.
func callerHoldsManage(r *http.Request) bool {
	token, ok := reqctx.ValidatedTokenFrom(r.Context())
	return ok && token.HasScope(manageScope)
}

// administrativePermissions is the administrative set's rows: the permissions on the authserver
// resource whose identifiers it names, each id mapped to its identifier as resource:permission,
// authserver:manage, the form an administrative_permission_changed record names it in. Read on tx,
// or outside any transaction when tx is nil.
func administrativePermissions(ctx context.Context, database administrativePolicyDatabase, tx *sql.Tx) (map[int64]string, error) {
	resource, err := database.GetResourceByResourceIdentifier(ctx, tx, builtin.AuthServerResourceIdentifier)
	if err != nil {
		return nil, errs.Wrap(err, "unable to read the authserver resource for the administrative policy")
	}
	if resource == nil {
		return nil, errs.New("the authserver resource does not exist")
	}
	permissions, err := database.GetPermissionsByResourceId(ctx, tx, resource.Id)
	if err != nil {
		return nil, errs.Wrap(err, "unable to read the authserver permissions for the administrative policy")
	}
	administrative := make(map[int64]string, len(administrativePermissionIdentifiers))
	for _, permission := range permissions {
		if administrativePermissionIdentifiers[permission.PermissionIdentifier] {
			administrative[permission.Id] = resource.ResourceIdentifier + ":" + permission.PermissionIdentifier
		}
	}
	return administrative, nil
}

// administratorChangeRefusal is what one refusal records beside the caller and the route.
type administratorChangeRefusal struct {
	ceiling string
	// targetKind and targetId name the user, group or client the request acts on. A request with
	// no target, a settings write, leaves targetKind empty and the record names neither.
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
	}
	if refusal.targetKind != "" {
		details["targetKind"] = refusal.targetKind
		details["targetId"] = refusal.targetId
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
// it reports whether the save may go on, and when it may not it has answered the request. When it
// may, it hands back the administrative set, which the save's administrative_permission_changed
// records are written from once it commits, or nil for a save that changes nothing.
//
// The save is judged on what it changes, the permissions in wanted and not in expected and those
// in expected and not in wanted. That is exactly what the save commits or nothing: the save's
// transaction refuses with 409 unless the stored grants are expected as a set, and repairing a
// stored duplicate grants and revokes nothing. A save changing nothing reads nothing here. An
// authserver:manage caller, whose token already carries every authority a grant confers, is never
// refused, but the set is read for it too, before the transaction, so that a change is never
// committed without knowing which records it owes (#402 decision 6).
func grantCeilingAllows(w http.ResponseWriter, r *http.Request, database administrativePolicyDatabase, auditLogger AuditLogger,
	targetKind string, targetId int64, wanted, expected []int64) (map[int64]string, bool) {
	changed := grantChange(wanted, expected)
	if len(changed) == 0 {
		return nil, true
	}

	administrative, err := administrativePermissions(r.Context(), database, nil)
	if err != nil {
		writeInternalServerError(w, r, err, "target_kind", targetKind, "target_id", targetId)
		return nil, false
	}
	if callerHoldsManage(r) {
		return administrative, true
	}
	var causes []int64
	for _, permissionId := range changed {
		if administrative[permissionId] != "" {
			causes = append(causes, permissionId)
		}
	}
	if len(causes) == 0 {
		return administrative, true
	}

	refuseAdministratorChange(w, r, auditLogger, administratorChangeRefusal{
		ceiling:       ceilingGrant,
		targetKind:    targetKind,
		targetId:      targetId,
		permissionIds: causes,
	})
	return nil, false
}

// The change an administrative_permission_changed record names.
const (
	changeGranted = "granted"
	changeRevoked = "revoked"
)

// recordAdministrativePermissionChanges writes, after a committed permission save and after its own
// records, one administrative_permission_changed record for the administrative permissions it
// granted and one for those it revoked, each only when there are any. administrative is the set
// grantCeilingAllows handed back.
func recordAdministrativePermissionChanges(r *http.Request, auditLogger AuditLogger, administrative map[int64]string,
	targetKind string, targetId int64, granted, revoked []int64) {
	for _, direction := range []struct {
		change        string
		permissionIds []int64
	}{{changeGranted, granted}, {changeRevoked, revoked}} {
		var identifiers []string
		for _, permissionId := range direction.permissionIds {
			if identifier := administrative[permissionId]; identifier != "" {
				identifiers = append(identifiers, identifier)
			}
		}
		if len(identifiers) == 0 {
			continue
		}
		auditLogger.Log(r.Context(), audit.EventAdministrativePermissionChanged, map[string]interface{}{
			"change":                direction.change,
			"targetKind":            targetKind,
			"targetId":              targetId,
			"permissionIdentifiers": identifiers,
			"loggedInUser":          callerSubject(r),
		})
	}
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

// administrativeGroup is a group holding at least one administrative permission, and the
// administrative permissions it holds, each once, by id and by identifier.
type administrativeGroup struct {
	id            int64
	permissionIds []int64
	identifiers   []string
}

// administrativeGroups is which of groupIds hold an administrative permission, in groupIds' order,
// each with what it holds of the administrative set. Read on tx, or outside any transaction when tx
// is nil; a set of groups holding no grant at all reads nothing more.
func administrativeGroups(ctx context.Context, database administrativeGroupPolicyDatabase, tx *sql.Tx, groupIds []int64) ([]administrativeGroup, error) {
	grants, err := database.GetGroupPermissionsByGroupIds(ctx, tx, groupIds)
	if err != nil {
		return nil, errs.Wrap(err, "unable to read the groups' permissions for the administrative policy")
	}
	if len(grants) == 0 {
		return nil, nil
	}
	administrative, err := administrativePermissions(ctx, database, tx)
	if err != nil {
		return nil, err
	}

	held := make(map[int64]*administrativeGroup)
	for _, grant := range grants {
		identifier := administrative[grant.PermissionId]
		if identifier == "" {
			continue
		}
		group := held[grant.GroupId]
		if group == nil {
			group = &administrativeGroup{id: grant.GroupId}
			held[grant.GroupId] = group
		}
		if !slices.Contains(group.permissionIds, grant.PermissionId) {
			group.permissionIds = append(group.permissionIds, grant.PermissionId)
			group.identifiers = append(group.identifiers, identifier)
		}
	}
	var groups []administrativeGroup
	for _, groupId := range firstOccurrences(groupIds) {
		if group := held[groupId]; group != nil {
			groups = append(groups, *group)
		}
	}
	return groups, nil
}

// refusalCauses is the ids of groups and the administrative permissions they hold, each once, group
// by group, as a grant refusal names them.
func refusalCauses(groups []administrativeGroup) (groupIds, permissionIds []int64) {
	for _, group := range groups {
		groupIds = append(groupIds, group.id)
		for _, permissionId := range group.permissionIds {
			if !slices.Contains(permissionIds, permissionId) {
				permissionIds = append(permissionIds, permissionId)
			}
		}
	}
	return groupIds, permissionIds
}

// recordMembershipChanges writes, after a committed change of a user's memberships and after its
// own records, one administrative_permission_changed record per administrative group the user
// joined (change granted) or left (change revoked), naming what the group holds of the set.
func recordMembershipChanges(r *http.Request, auditLogger AuditLogger, userId int64, change string, groups []administrativeGroup) {
	for _, group := range groups {
		auditLogger.Log(r.Context(), audit.EventAdministrativePermissionChanged, map[string]interface{}{
			"change":                change,
			"targetKind":            targetKindUser,
			"targetId":              userId,
			"groupId":               group.id,
			"permissionIdentifiers": group.identifiers,
			"loggedInUser":          callerSubject(r),
		})
	}
}

// membershipCeilingAllows applies the grant ceiling to moving a user into or out of groups: joining
// a group that holds an administrative permission grants it, and leaving one revokes it. groupIds
// is the groups the request joins or leaves. It reports whether the change may go on, and when it
// may not it has answered the request. When it may, it hands back which of groupIds are
// administrative, which the change's administrative_permission_changed records are written from:
// an authserver:manage caller is never refused, but what the groups hold is read for it too, before
// the write, so that a change is never made without knowing which records it owes (#402 decision 6).
func membershipCeilingAllows(w http.ResponseWriter, r *http.Request, database administrativeGroupPolicyDatabase, auditLogger AuditLogger,
	userId int64, groupIds []int64) ([]administrativeGroup, bool) {
	if len(groupIds) == 0 {
		return nil, true
	}

	groups, err := administrativeGroups(r.Context(), database, nil, groupIds)
	if err != nil {
		writeInternalServerError(w, r, err, "user_id", userId, "group_ids", groupIds)
		return nil, false
	}
	if len(groups) == 0 || callerHoldsManage(r) {
		return groups, true
	}

	causeGroups, causes := refusalCauses(groups)
	refuseAdministratorChange(w, r, auditLogger, administratorChangeRefusal{
		ceiling:       ceilingGrant,
		targetKind:    targetKindUser,
		targetId:      userId,
		permissionIds: causes,
		groupIds:      causeGroups,
	})
	return nil, false
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

	_, allowed := membershipCeilingAllows(w, r, database, auditLogger, userId, judged)
	return allowed
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

	groups, err := administrativeGroups(r.Context(), database, nil, []int64{groupId})
	if err != nil {
		writeInternalServerError(w, r, err, "group_id", groupId)
		return false
	}
	if len(groups) == 0 {
		return true
	}

	_, causes := refusalCauses(groups)
	refuseAdministratorChange(w, r, auditLogger, administratorChangeRefusal{
		ceiling:       ceilingGrant,
		targetKind:    targetKindGroup,
		targetId:      groupId,
		permissionIds: causes,
	})
	return false
}

// settingsCeilingAllows applies the settings ceiling to a write of the email or the audit-log
// settings. The email settings decide where every reset link and verification code goes, so a
// token that may point SMTP at a server it controls may sign in as any administrator; the audit-log
// settings can switch off the record every other refusal rests on, for every token and not only the
// caller's. Both are reserved to authserver:manage. It reports whether the write may go on, and when
// it may not it has answered the request. The ceiling reads nothing: the route is the whole of what
// it judges (#402 decision 7).
func settingsCeilingAllows(w http.ResponseWriter, r *http.Request, auditLogger AuditLogger) bool {
	if callerHoldsManage(r) {
		return true
	}
	refuseAdministratorChange(w, r, auditLogger, administratorChangeRefusal{ceiling: ceilingSettings})
	return false
}

// userIsAdministrator reports whether the user holds an administrative permission, directly or
// through any of its groups. Read on tx, or outside any transaction when tx is nil; a user holding
// no grant at all, directly or through a group, reads nothing more.
func userIsAdministrator(ctx context.Context, database userTargetPolicyDatabase, tx *sql.Tx, userId int64) (bool, error) {
	direct, err := database.GetUserPermissionsByUserId(ctx, tx, userId)
	if err != nil {
		return false, errs.Wrap(err, "unable to read the user's permissions for the administrative policy")
	}
	memberships, err := database.GetUserGroupsByUserId(ctx, tx, userId)
	if err != nil {
		return false, errs.Wrap(err, "unable to read the user's groups for the administrative policy")
	}
	held := make([]int64, 0, len(direct))
	for _, grant := range direct {
		held = append(held, grant.PermissionId)
	}
	if len(memberships) > 0 {
		groupIds := make([]int64, 0, len(memberships))
		for _, membership := range memberships {
			groupIds = append(groupIds, membership.GroupId)
		}
		grants, groupErr := database.GetGroupPermissionsByGroupIds(ctx, tx, groupIds)
		if groupErr != nil {
			return false, errs.Wrap(groupErr, "unable to read the user's groups' permissions for the administrative policy")
		}
		for _, grant := range grants {
			held = append(held, grant.PermissionId)
		}
	}
	if len(held) == 0 {
		return false, nil
	}

	administrative, err := administrativePermissions(ctx, database, tx)
	if err != nil {
		return false, err
	}
	for _, permissionId := range held {
		if administrative[permissionId] != "" {
			return true, nil
		}
	}
	return false, nil
}

// userTargetCeilingAllows applies the target ceiling to a write on a user: a user holding an
// administrative permission, directly or through any of its groups, is an administrator, and only
// an authserver:manage token writes to one in any way, its profile, credentials, sessions,
// consents, attributes, memberships or permissions alike. Setting an administrator's password,
// switching off their OTP or changing their email is signing in as them. It reports whether the
// write may go on, and when it may not it has answered the request. An authserver:manage caller
// reads nothing here (#402 decision 1).
//
// A write the grant ceiling also judges, a save of the user's permissions or groups and a change of
// one membership, meets the grant ceiling first, whose refusal names the permissions and groups
// that caused it; this refuses what the grant ceiling lets through, such as granting an
// administrator an ordinary permission or moving one into an ordinary group.
func userTargetCeilingAllows(w http.ResponseWriter, r *http.Request, database userTargetPolicyDatabase, auditLogger AuditLogger,
	userId int64) bool {
	if callerHoldsManage(r) {
		return true
	}

	administrator, err := userIsAdministrator(r.Context(), database, nil, userId)
	if err != nil {
		writeInternalServerError(w, r, err, "user_id", userId)
		return false
	}
	if !administrator {
		return true
	}

	refuseAdministratorChange(w, r, auditLogger, administratorChangeRefusal{
		ceiling:    ceilingTarget,
		targetKind: targetKindUser,
		targetId:   userId,
	})
	return false
}

// groupTargetCeilingAllows applies the target ceiling to a write on a group: a group holding an
// administrative permission is an administrator, and so is every member it gives one, so only an
// authserver:manage token renames it, changes its attributes or changes its permissions, ordinary
// ones included. It reports whether the write may go on, and when it may not it has answered the
// request. An authserver:manage caller reads nothing here (#402 decision 1).
//
// A save of the group's permissions meets the grant ceiling first. Deleting the group and changing
// its members are the grant ceiling's alone, which refuses exactly the groups this would.
func groupTargetCeilingAllows(w http.ResponseWriter, r *http.Request, database administrativeGroupPolicyDatabase, auditLogger AuditLogger,
	groupId int64) bool {
	if callerHoldsManage(r) {
		return true
	}

	groups, err := administrativeGroups(r.Context(), database, nil, []int64{groupId})
	if err != nil {
		writeInternalServerError(w, r, err, "group_id", groupId)
		return false
	}
	if len(groups) == 0 {
		return true
	}

	refuseAdministratorChange(w, r, auditLogger, administratorChangeRefusal{
		ceiling:    ceilingTarget,
		targetKind: targetKindGroup,
		targetId:   groupId,
	})
	return false
}

// clientTargetPolicyDatabase is what the policy reads to judge a write on a client: the
// administrative set and the permissions the client holds.
type clientTargetPolicyDatabase interface {
	administrativePolicyDatabase
	GetClientPermissionsByClientId(ctx context.Context, tx *sql.Tx, clientId int64) ([]record.ClientPermission, error)
}

// clientIsAdministrator reports whether the client is an administrator: the admin console's own
// client, whatever it holds, or a client holding an administrative permission. The admin console's
// client is one by what it is, the client every administrator signs in through, so that editing its
// redirect URIs, its flows or its secret stays authserver:manage's however its grants are changed.
// Read outside any transaction; the admin console's client and a client holding no grant read
// nothing more.
func clientIsAdministrator(ctx context.Context, database clientTargetPolicyDatabase, client *record.Client) (bool, error) {
	if client.IsSystemLevelClient() {
		return true, nil
	}
	grants, err := database.GetClientPermissionsByClientId(ctx, nil, client.Id)
	if err != nil {
		return false, errs.Wrap(err, "unable to read the client's permissions for the administrative policy")
	}
	if len(grants) == 0 {
		return false, nil
	}

	administrative, err := administrativePermissions(ctx, database, nil)
	if err != nil {
		return false, err
	}
	for _, grant := range grants {
		if administrative[grant.PermissionId] != "" {
			return true, nil
		}
	}
	return false, nil
}

// clientTargetCeilingAllows applies the target ceiling to a write on a client, or to reading its
// secret: only an authserver:manage token writes to an administrator client in any way, its
// settings, authentication, flows, redirect URIs, web origins, token settings, permissions, logo or
// its deletion, or reads its secret. A client holding manage is obtained on a plain
// client_credentials request by whoever holds its secret, so replacing or reading that secret, or
// redirecting the admin console's codes, is taking the client over. It reports whether the request
// may go on, and when it may not it has answered the request. An authserver:manage caller reads
// nothing here (#402 decisions 1 and 8).
//
// A save of the client's permissions meets the grant ceiling first; this refuses what the grant
// ceiling lets through, such as granting an administrator client an ordinary permission.
func clientTargetCeilingAllows(w http.ResponseWriter, r *http.Request, database clientTargetPolicyDatabase, auditLogger AuditLogger,
	client *record.Client) bool {
	if callerHoldsManage(r) {
		return true
	}

	administrator, err := clientIsAdministrator(r.Context(), database, client)
	if err != nil {
		writeInternalServerError(w, r, err, "client_id", client.Id)
		return false
	}
	if !administrator {
		return true
	}

	refuseAdministratorChange(w, r, auditLogger, administratorChangeRefusal{
		ceiling:    ceilingTarget,
		targetKind: targetKindClient,
		targetId:   client.Id,
	})
	return false
}
