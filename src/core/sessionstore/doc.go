// Package sessionstore is the server-side browser session store both servers build.
//
// The browser carries one cookie holding a sealed, opaque identifier and nothing else; the
// session's contents live behind a Backend, which holds ciphertext it has no key for. The
// auth server's backend writes rows, the admin console's calls the auth server's session
// endpoint, and the same ServerSideStore seals, opens, rotates and expires over either
// (#266, #270).
//
// A store is configured only through NewServerSideStore: backend, authenticated key, the
// Secure attribute, the cookie's lifetime and the key pairs. It has no exported field, so
// what a binary chose is what it passed there (#431).
//
// Handlers take the narrow Store interface; the in-memory Backend tests drive the real
// store over is in sessiontest, a package of its own so no binary links it.
package sessionstore
