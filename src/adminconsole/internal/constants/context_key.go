package constants

// The admin console's own context keys.
//
// A context key never leaves the process that set it, so there is nothing for the two
// binaries to agree on here. The ones core still declares are the ones a kernel package
// reads (#351).
type ctxKey string

// ContextKeySettings is declared once per process rather than shared, because the two
// processes store different types under it: this one holds an *api.PublicSettingsResponse
// read over HTTP, and the auth server's holds a *models.Settings read from the database.
// Either process's type assertion panics on the other's value, so one declaration would
// document a contract that does not exist (#351).
const ContextKeySettings ctxKey = "Settings"
