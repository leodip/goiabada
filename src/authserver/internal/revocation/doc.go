// Package revocation invalidates what the auth server issued: RevokeUserAuthState, which advances a
// user's authentication generation and sweeps the sessions, codes and refresh tokens it authorized,
// at every credential change; TerminateUserSession, which ends one session and the grants issued
// under it; RevokeOnAuthCodeReuse, the answer to a redeemed code presented again;
// RevokeClientGrants, for a client that no longer has to authenticate; and RevokeRefreshTokens
// beneath them. Each has a *Tx form that opens its transaction through RunInTransaction, and the
// Reason* constants are the reasons a revocation records (#106, #129, #245, #387).
//
// Each operation reports what it actually did, the sessions it ended and only the tokens it moved
// from live to revoked, and on an error reports nothing, so a caller cannot audit a partial or
// rolled-back revocation. The audit event is the caller's, written through the Log* helpers after
// the commit, because an audit record takes no transaction and one written before a rollback would
// be false.
package revocation
