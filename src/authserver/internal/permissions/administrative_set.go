package permissions

import (
	"context"
	"database/sql"
	"strings"

	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/errs"
)

// administrativePermissionIdentifiers is the named administrative set: the permissions on the
// authserver resource that confer power in this server. A user, group or client holding any of them
// is an administrator, and a token carrying any of them as a scope holds administrative authority at
// the Admin API. manage-account, which every user receives at creation, and the custom permissions
// an operator adds to the resource confer none and are not in it (#402 decision 2). It is the one
// definition of "administrative": the Admin API's administrative policy reads it, and so do the
// authorization and token endpoints asking whether a requested scope is one (#499 decision 2).
var administrativePermissionIdentifiers = map[string]bool{
	builtin.ManagePermissionIdentifier:          true,
	builtin.AdminReadPermissionIdentifier:       true,
	builtin.ManageUsersPermissionIdentifier:     true,
	builtin.ManageClientsPermissionIdentifier:   true,
	builtin.ManageSettingsPermissionIdentifier:  true,
	builtin.BrowserSessionsPermissionIdentifier: true,
}

// IsAdministrativeScope reports whether scope is one of the administrative set's permissions on the
// authserver resource, spelled resource:permission as a request and a token carry it, such as
// authserver:manage. It compares exactly: one scope, no surrounding space, no other case.
func IsAdministrativeScope(scope string) bool {
	if !IsResourceScope(scope) {
		return false
	}
	resourceIdentifier, permissionIdentifier, _ := strings.Cut(scope, ":")
	return resourceIdentifier == builtin.AuthServerResourceIdentifier && administrativePermissionIdentifiers[permissionIdentifier]
}

// AdministrativePermissions is the administrative set's rows: the permissions on the authserver
// resource whose identifiers it names, each id mapped to its identifier as resource:permission,
// authserver:manage, the form an administrative_permission_changed record names it in. Read on tx,
// or outside any transaction when tx is nil. A missing authserver resource is an error, since the
// seed writes it and nothing deletes it.
func AdministrativePermissions(ctx context.Context, database ScopeResolverDatabase, tx *sql.Tx) (map[int64]string, error) {
	resource, err := database.GetResourceByResourceIdentifier(ctx, tx, builtin.AuthServerResourceIdentifier)
	if err != nil {
		return nil, errs.Wrap(err, "unable to read the authserver resource for the administrative set")
	}
	if resource == nil {
		return nil, errs.New("the authserver resource does not exist")
	}
	permissions, err := database.GetPermissionsByResourceId(ctx, tx, resource.Id)
	if err != nil {
		return nil, errs.Wrap(err, "unable to read the authserver permissions for the administrative set")
	}
	administrative := make(map[int64]string, len(administrativePermissionIdentifiers))
	for _, permission := range permissions {
		if administrativePermissionIdentifiers[permission.PermissionIdentifier] {
			administrative[permission.Id] = resource.ResourceIdentifier + ":" + permission.PermissionIdentifier
		}
	}
	return administrative, nil
}
