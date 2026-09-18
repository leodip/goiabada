package constants

// The context keys a kernel package reads, and therefore the only ones core declares.
//
// core/middleware and core/handlerhelpers are compiled into both binaries and both write
// and read these, so they cannot move to either process without taking a kernel package
// with them. Everything else a context carries is process-local: a key never leaves the
// process that set it, so each binary declares its own (#351).
type ctxKey string

const ContextKeyJwtInfo ctxKey = "JwtInfo"
const ContextKeyBearerToken ctxKey = "BearerToken"
