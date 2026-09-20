package constants

// The auth server's own context keys.
//
// A context key never leaves the process that set it, so there is nothing for the two
// binaries to agree on here and no reason for either to compile the other's keys. The
// ones core still declares are the ones a kernel package reads: core/handlerhelpers runs
// inside both processes and has to name the same key the admin console writes (#351).
type ctxKey string

// ContextKeySettings is declared once per process rather than shared, because the two
// processes store different types under it: this one holds a *models.Settings read from
// the database, and the admin console's holds an *api.PublicSettingsResponse read over
// HTTP. Either process's type assertion panics on the other's value, so one declaration
// would document a contract that does not exist (#351).
const ContextKeySettings ctxKey = "Settings"

const ContextKeySessionIdentifier ctxKey = "SessionIdentifier"
const ContextKeyValidatedToken ctxKey = "ValidatedToken"

// ContextKeyBearerToken carries the token JwtAuthorizationHeaderToContext validated off
// the request, and the three guards in api_auth.go read it. Declared here rather than in
// core since #385 moved that middleware into this module: the auth server is the only
// process that installs it, so no other binary can observe the key.
//
// The string value is the one core declared. A context key is compared by the (type,
// value) pair of the key itself and never crosses a process boundary, so the value is
// not a contract with anything -- but it is the value every record and test in this
// module was written against, and changing it here would be a rename dressed as a move.
const ContextKeyBearerToken ctxKey = "BearerToken"
