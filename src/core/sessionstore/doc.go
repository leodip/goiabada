// Package sessionstore is the server-side browser session store both servers build.
//
// The browser carries one cookie holding a sealed, opaque identifier and nothing else; the
// session's contents live behind a Backend, which holds ciphertext it has no key for. The one
// exception is a short-lived state a browser carries itself rather than a row it names, sealed
// under a key of its own by SealCookieValues: the admin console's sign-in handshake, from the
// authorize redirect to the callback, which no longer costs the auth server a row for every
// anonymous request (#620). The
// auth server's backend writes rows, the admin console's calls the auth server's session
// endpoint, and the same ServerSideStore seals, opens, rotates and expires over either
// (#266, #270).
//
// A store is configured only through NewServerSideStore: backend, authenticated key, the
// Secure attribute, the cookie's lifetime and the key pairs. It has no exported field, so
// what a binary chose is what it passed there (#431). The auth server then wraps its store with
// NewConditionalStore, over a ConditionalBackend, for the writes that apply only their own change
// to a fresh read; the admin console's store has no such writes (#579).
//
// Handlers take the narrow Store interface; the in-memory Backend tests drive the real
// store over is in sessiontest, a package of its own so no binary links it.
package sessionstore
