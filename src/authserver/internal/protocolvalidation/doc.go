// Package protocolvalidation decides whether an authorization request or a token request is one the
// auth server will answer, per RFC 6749, RFC 7636 and OpenID Connect Core 1.0. AuthorizeValidator
// checks the client, the redirect URI and the request's parameters; TokenValidator authenticates
// the client and hands each grant to its own method, which returns a TokenGrant carrying what that
// grant proved; ParseResponseType, the space-delimited grammar, the parameter bounds and the
// repeated-parameter rule are the pieces both share.
//
// It reads and never writes: a validated grant is not yet claimed, and the claim that makes a code
// or a refresh token single-use is the issuer's (#77, #437). Every refusal is, or wraps, an
// *oauth.ErrorDetail, the error response of RFC 6749 section 5.2, so a handler answers it as it
// stands. A refusal the handler has to act on as well, a reused code or a disabled user, is a type
// of its own that errors.As finds, because the description the client is answered with does not
// say which condition it was (#137).
package protocolvalidation
