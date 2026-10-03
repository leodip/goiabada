// Package server composes the admin console: Server holds what main built, mounts the middleware
// chain, registers every route with the handler and the values it uses, and Start serves the HTTP
// and, when configured, HTTPS listeners until its context ends, then drains the requests in flight.
//
// It is composition and nothing else. A handler is handed the configuration it reads when the route
// table builds it, so nothing reads the configuration at request time (#441); every root Use comes
// before the static and application branches are split, because chi refuses a Use after a route;
// and Start logs none of its errors and ends nothing, leaving the one record and the exit to main
// (#426).
package server
