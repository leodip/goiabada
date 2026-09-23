// Package permissions decides what a resource:permission scope means and who holds it: ResolveScope
// turns a scope into the permission row it names, and PermissionChecker answers whether a user
// holds that row directly or through a group, one scope at a time or over a whole requested scope
// string. The protocol validators and the authorization handlers ask it; none of them resolves a
// scope or walks a user's grants on its own (#425).
package permissions

import (
	"context"
	"database/sql"
	"strings"

	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/core/errs"
)

// ScopeOutcome is what resolving a single resource:permission scope against the database can
// conclude. Every value other than ScopeOK is a rejection the caller words itself: the validator
// call sites answer the same conclusion with deliberately different text, so returning an error
// here would either flatten that wording or force the resolver to know which site called it (#124).
type ScopeOutcome int

const (
	ScopeOK ScopeOutcome = iota
	ScopeMalformed
	ScopeResourceUnknown
	ScopePermissionUnknown
)

// ScopeResolution carries the split parts back to the caller as well as the outcome, because every
// rejection message quotes the resource identifier, the permission identifier, or both, and
// re-splitting the scope at the call site is how the two copies drift apart.
type ScopeResolution struct {
	Outcome              ScopeOutcome
	ResourceIdentifier   string             // parts[0], empty when Outcome is ScopeMalformed
	PermissionIdentifier string             // parts[1], empty when Outcome is ScopeMalformed
	Permission           *models.Permission // the resolved row, set only when Outcome is ScopeOK
}

// ScopeResolverDatabase is what resolving one `resource:permission` scope needs: the resource, and
// the permissions declared on it.
//
// Its own port rather than the checker's, because the protocol validators call ResolveScope too
// and embed this in ports of their own. Handing them the checker's six to reach these two is the
// shape #386 decision 3 rejected when it chose a port per file over a port per package.
type ScopeResolverDatabase interface {
	GetResourceByResourceIdentifier(ctx context.Context, tx *sql.Tx, resourceIdentifier string) (*models.Resource, error)
	GetPermissionsByResourceId(ctx context.Context, tx *sql.Tx, resourceId int64) ([]models.Permission, error)
}

// IsResourceScope reports whether a scope has the resource:permission shape, which is exactly one
// ':'. It says nothing about whether the resource or the permission exists; ResolveScope answers
// that. It is the one statement of the shape: ResolveScope answers anything else as ScopeMalformed,
// and the refresh arm uses it to tell a stored value this server does not issue from a resource
// scope it must re-check (#425).
func IsResourceScope(scope string) bool {
	return strings.Count(scope, ":") == 1
}

// ResolveScope resolves one resource:permission scope against the database: split on ':', look the
// resource up, look the permission up on that resource. It is the one copy of that sequence: the
// three protocol validators each carried their own until #124, and this package carried a fourth
// until #425, whose unknown-resource and unknown-permission branches returned a nil err by accident
// rather than by rule. Only a resolved row answers the #104 question, which compares permission ids
// rather than bare identifiers. Keep it that way: a caller that re-resolves the permission itself is
// free to compare the identifier again and re-open #104.
//
// A returned error is a genuine database failure and nothing else; it is propagated unwrapped,
// since every caller hands it to a 500. A rejection is an Outcome, never an error.
//
// It lives here rather than beside the validators because what a scope names is this package's
// rule, and protocolvalidation already depends on this package's checker; moving it the other way
// would put a domain rule under a protocol validator (#425 decision 9).
func ResolveScope(ctx context.Context, db ScopeResolverDatabase, scopeStr string) (ScopeResolution, error) {
	if !IsResourceScope(scopeStr) {
		return ScopeResolution{Outcome: ScopeMalformed}, nil
	}
	parts := strings.Split(scopeStr, ":")

	resolution := ScopeResolution{
		ResourceIdentifier:   parts[0],
		PermissionIdentifier: parts[1],
	}

	res, err := db.GetResourceByResourceIdentifier(ctx, nil, resolution.ResourceIdentifier)
	if err != nil {
		return ScopeResolution{}, err
	}
	if res == nil {
		resolution.Outcome = ScopeResourceUnknown
		return resolution, nil
	}

	permissions, err := db.GetPermissionsByResourceId(ctx, nil, res.Id)
	if err != nil {
		return ScopeResolution{}, err
	}

	// Resolve the requested permission ON THIS RESOURCE. permissions is already narrowed to
	// resolution.ResourceIdentifier by the query above, and (permission_identifier, resource_id) is
	// unique on every supported engine via idx_permission_identifier_resource, so at most one row
	// here can match.
	for i := range permissions {
		if permissions[i].PermissionIdentifier == resolution.PermissionIdentifier {
			resolution.Outcome = ScopeOK
			resolution.Permission = &permissions[i]
			return resolution, nil
		}
	}

	resolution.Outcome = ScopePermissionUnknown
	return resolution, nil
}

// permissionCheckerDatabase is what the permission check needs: the user's own grants and the
// ones their groups carry, and the scope resolver's two reads.
type permissionCheckerDatabase interface {
	ScopeResolverDatabase

	GetUserById(ctx context.Context, tx *sql.Tx, userId int64) (*models.User, error)
	GroupsLoadPermissions(ctx context.Context, tx *sql.Tx, groups []models.Group) error
	UserLoadGroups(ctx context.Context, tx *sql.Tx, user *models.User) error
	UserLoadPermissions(ctx context.Context, tx *sql.Tx, user *models.User) error
}

type PermissionChecker struct {
	database permissionCheckerDatabase
}

func NewPermissionChecker(database permissionCheckerDatabase) *PermissionChecker {
	return &PermissionChecker{
		database: database,
	}
}

// loadGrantHolder reads the user afresh and loads their own permissions, their groups and the
// groups' permissions onto that row. A nil user and a nil error mean the row is gone, which every
// caller answers as holding nothing.
//
// The fresh row is the point: the caller's *models.User is never loaded onto, so a check cannot
// mutate a struct its caller goes on to use, and a user deleted since the caller read it holds
// nothing rather than whatever the caller's copy still says.
func (pc *PermissionChecker) loadGrantHolder(ctx context.Context, userId int64) (*models.User, error) {
	user, err := pc.database.GetUserById(ctx, nil, userId)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, nil
	}

	err = pc.database.UserLoadPermissions(ctx, nil, user)
	if err != nil {
		return nil, err
	}

	err = pc.database.UserLoadGroups(ctx, nil, user)
	if err != nil {
		return nil, err
	}

	err = pc.database.GroupsLoadPermissions(ctx, nil, user.Groups)
	if err != nil {
		return nil, err
	}

	return user, nil
}

// holdsPermission reports whether the loaded user holds the permission row, directly or through
// any of their groups. It compares row ids, never identifiers, because a permission identifier is
// only unique within its resource (#104).
func holdsPermission(user *models.User, permissionId int64) bool {
	for _, userPerm := range user.Permissions {
		if userPerm.Id == permissionId {
			return true
		}
	}

	for _, group := range user.Groups {
		for _, groupPerm := range group.Permissions {
			if groupPerm.Id == permissionId {
				return true
			}
		}
	}

	return false
}

func (pc *PermissionChecker) UserHasScopePermission(ctx context.Context, userId int64, scope string) (bool, error) {
	user, err := pc.loadGrantHolder(ctx, userId)
	if err != nil {
		return false, err
	}
	if user == nil {
		return false, nil
	}

	resolution, err := ResolveScope(ctx, pc.database, scope)
	if err != nil {
		return false, err
	}

	switch resolution.Outcome {
	case ScopeMalformed:
		return false, errs.New("invalid scope format: " + scope + ". expected format: resource_identifier:permission_identifier")
	case ScopeOK:
		return holdsPermission(user, resolution.Permission.Id), nil
	default:
		// An unknown resource or an unknown permission on it: nobody holds it.
		return false, nil
	}
}

// FilterOutScopesWhereUserIsNotAuthorized keeps the claim scopes, offline_access and every
// resource scope the user holds, and strips the rest.
//
// Each resource scope is resolved before the user is touched, so a malformed element is an error
// with no read of the user at all, and a scope naming nothing is stripped at the cost of its own
// lookup alone. The user and their grants are then loaded once, at the first scope that resolves,
// and every later scope is answered from that one load: it used to reload them per scope, four of
// the six reads each resource scope cost (#425).
func (pc *PermissionChecker) FilterOutScopesWhereUserIsNotAuthorized(ctx context.Context, scope string, user *models.User) (string, error) {

	if user == nil {
		return "", errs.New("user is nil")
	}

	newScope := ""

	var holder *models.User
	holderLoaded := false

	// filter
	scopes := strings.Split(scope, " ")
	for _, scopeStr := range scopes {

		if scopeStr == "" {
			continue
		}

		if oidc.IsClaimScope(scopeStr) || oidc.IsOfflineAccessScope(scopeStr) {
			newScope += scopeStr + " "
			continue
		}

		resolution, err := ResolveScope(ctx, pc.database, scopeStr)
		if err != nil {
			return "", err
		}

		switch resolution.Outcome {
		case ScopeMalformed:
			return "", errs.New("invalid scope format: " + scopeStr)
		case ScopeResourceUnknown, ScopePermissionUnknown:
			continue
		}

		if !holderLoaded {
			holder, err = pc.loadGrantHolder(ctx, user.Id)
			if err != nil {
				return "", err
			}
			holderLoaded = true
		}

		// A nil holder is a user deleted since the caller read them: every resource scope goes.
		if holder != nil && holdsPermission(holder, resolution.Permission.Id) {
			newScope += scopeStr + " "
		}
	}

	return strings.TrimSpace(newScope), nil
}
