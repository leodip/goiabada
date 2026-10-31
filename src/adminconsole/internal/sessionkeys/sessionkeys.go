// Package sessionkeys names the keys of the admin console's browser session and of its sealed
// sign-in handshake. Every value here is stored data. Request-scoped values are not session keys
// and live in reqctx (#440).
//
// Three name entries in the admin console's own browser session, written and read by this process
// alone: the authenticated-session key with the access token's recorded expiry beside it, and the
// signed-in user's page language. A live session carries these spellings, so renaming one of the
// first two signs every administrator out at deploy, and renaming the third puts every signed-in
// user on Automatic until they sign in again or open their profile. The
// auth server stores that session server-side but never opens it, so there is nothing for the two
// binaries to agree on beyond the session's name, which core/builtin declares (#385).
//
// The other six name the values the OAuth ceremony carries between the authorize redirect and the
// callback. Since #620 they ride in the sealed handshake cookie rather than the session, so
// renaming one fails only the sign-ins in flight at the deploy. They stay declared here because
// they key the sealed map, and because the callback deletes the stale copies a session written
// before #620 can still hold.
package sessionkeys

// JWT is the authenticated-session key. Its string value, like every one here, is the
// one core declared, byte for byte: a session written before #385 moved them and read after it
// must still resolve, since the admin console's sessions outlive a deployment.
const JWT string = "Jwt"

// JWTExpiresAt is the Unix second the stored access token lapses at, computed from
// the token response's expires_in when it arrives, or 0 when the response gave none and the
// expiry is unknown. It is written beside JWT at sign-in and at every refresh and
// deleted wherever JWT is, because the console never decodes its access token to
// read an expiry out of it (#427).
const JWTExpiresAt string = "JwtExpiresAt"

// PageLanguage is the console's copy of the signed-in user's page language: the tag of the catalog
// they chose for Goiabada's own pages, or empty for Automatic. It is read from the Account API at
// sign-in and again whenever the profile page fetches the profile, and written when the user saves
// it there; every signed-in page reads it, so a save shows on the user's next page without an auth
// server round trip per page (#631 decision 7).
const PageLanguage string = "PageLanguage"

const State string = "State"
const Nonce string = "Nonce"
const RedirectURI string = "RedirectURI"
const CodeVerifier string = "CodeVerifier"
const RedirectBack string = "RedirectBack"

// RequestedScope is the scope the authorize request asked for. The callback takes the
// grant to equal it when the token response carries no scope parameter, which RFC 6749 section
// 3.3 allows only when the two are identical (#427).
const RequestedScope string = "RequestedScope"
