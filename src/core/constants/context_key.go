package constants

// The context keys a kernel package reads, and therefore the only ones core declares.
//
// core/handlerhelpers is compiled into both binaries and reads the one key below, so it
// cannot move to the process that writes it without taking a kernel package with it.
// Everything else a context carries is process-local: a key never leaves the process that
// set it, so each binary declares its own (#351).
//
// ContextKeyBearerToken was the second. It left with the bearer-token middleware that
// writes it, to authserver/internal/constants, once no core package named it (#385).
type ctxKey string

const ContextKeyJwtInfo ctxKey = "JwtInfo"
