// Package server composes the auth server: Server holds what main built, the whole Database among
// it, mounts the middleware chain, registers every route on the branch of the format its handler
// answers in, and Start serves the HTTP and, when configured, HTTPS listeners until its context
// ends. It then drains the requests in flight, waits for the work they handed off and stops the
// cleanup worker.
//
// It is composition and nothing else. Every constructor routes.go calls narrows the Database to a
// port of its own and is handed the configuration it reads, so nothing reads the configuration at
// request time (#386, #434). A route's answering format is chosen by the branch it is registered
// on, never read off the request path, so a client parsing a protocol endpoint or an API as JSON
// gets JSON for the settings, session and panic faults too (#435). Start logs none of its errors
// and ends nothing, leaving the one record and the exit to main (#426).
package server
