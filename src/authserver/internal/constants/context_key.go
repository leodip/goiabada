package constants

// The auth server's own context keys.
//
// A context key never leaves the process that set it, so there is nothing for the two
// binaries to agree on here and no reason for either to compile the other's keys. The
// ones core still declares are the ones a kernel package reads: core/middleware and
// core/handlerhelpers run inside both processes and have to name the same key both
// processes write (#351).
type ctxKey string

// ContextKeySettings is declared once per process rather than shared, because the two
// processes store different types under it: this one holds a *models.Settings read from
// the database, and the admin console's holds an *api.PublicSettingsResponse read over
// HTTP. Either process's type assertion panics on the other's value, so one declaration
// would document a contract that does not exist (#351).
const ContextKeySettings ctxKey = "Settings"

const ContextKeySessionIdentifier ctxKey = "SessionIdentifier"
const ContextKeyValidatedToken ctxKey = "ValidatedToken"
