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

// ContextKeyJwtInfo carries the browser session's token set, written by this module's JWT session
// middleware and read by its renderer and its handlers.
//
// It was core/constants' last context key, kernel on the strength of one reader:
// core/handlerhelpers/http_helper.go, which bound loggedInUser and isAdmin into every page's
// template data. That renderer was this console's alone and #385 moved it here, so nothing outside
// this module names the key any more and core declares no context key at all. The auth server
// never wrote it: its chain installs the bearer-token middleware, which is why every audit row
// read through it named nobody until #385 (#351, #385).
const ContextKeyJwtInfo ctxKey = "JwtInfo"
