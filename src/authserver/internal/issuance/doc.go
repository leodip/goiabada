// Package issuance mints what the provider hands a client: CodeIssuer stores the authorization
// code a finished ceremony redeems, and TokenIssuer signs the access, ID and refresh tokens for
// every grant the token endpoint and the implicit flow serve. The settings a token is issued under
// are a parameter of each TokenIssuer method rather than read from the request context, and
// TokenType spells every typ value the tokens and refresh_tokens rows carry (#433).
package issuance
