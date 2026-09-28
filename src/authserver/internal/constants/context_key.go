package constants

// The auth server's settings context key, the one still declared here: the session identifier
// and both bearer tokens are written and read through internal/reqctx, and this one follows
// once the services that read it take their settings as a parameter (#433).
type ctxKey string

// ContextKeySettings is declared once per process rather than shared, because the two
// processes store different types under it: this one holds a *models.Settings read from
// the database, and the admin console's holds an *api.PublicSettingsResponse read over
// HTTP. Either process's type assertion panics on the other's value, so one declaration
// would document a contract that does not exist (#351).
const ContextKeySettings ctxKey = "Settings"
