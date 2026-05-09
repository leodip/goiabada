package i18n

import "context"

// System entity kinds — supplied to SystemEntityDisplay / SystemEntityDescription
// as the kind argument.
const (
	SystemEntityKindClient     = "client"
	SystemEntityKindResource   = "resource"
	SystemEntityKindPermission = "permission"
)

// systemEntityRegistry holds the set of built-in entity identifiers whose
// display names and descriptions are catalog-backed. Entities not in the
// registry render their DB-stored values verbatim — admin-authored content
// is never localized.
//
// Keys are formatted as "<kind>:<identifier>" (e.g.
// "client:adminconsole-client"). The set is populated alongside the
// templates that consume SystemEntityDisplay / SystemEntityDescription.
var systemEntityRegistry = map[string]struct{}{}

// SystemEntityDisplay returns the localized display name for a built-in
// entity identified by (kind, identifier). For user-created entities (not
// in the registry) it returns dbFallback verbatim. If the entity is in
// the registry but the catalog key is missing, also returns dbFallback —
// dev/CI catches the missing key separately.
func SystemEntityDisplay(ctx context.Context, kind, identifier, dbFallback string) string {
	if !isSystemEntity(kind, identifier) {
		return dbFallback
	}
	key := "system." + kind + "." + identifier + ".display_name"
	out := T(ctx, key)
	if out == key {
		return dbFallback
	}
	return out
}

// SystemEntityDescription is the description equivalent of SystemEntityDisplay.
func SystemEntityDescription(ctx context.Context, kind, identifier, dbFallback string) string {
	if !isSystemEntity(kind, identifier) {
		return dbFallback
	}
	key := "system." + kind + "." + identifier + ".description"
	out := T(ctx, key)
	if out == key {
		return dbFallback
	}
	return out
}

func isSystemEntity(kind, identifier string) bool {
	if identifier == "" {
		return false
	}
	_, ok := systemEntityRegistry[kind+":"+identifier]
	return ok
}
