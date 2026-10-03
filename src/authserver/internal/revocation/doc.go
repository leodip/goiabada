// Package revocation invalidates what the auth server issued. Callers enter through four *Tx
// operations, each of which opens its own transaction through RunInTransaction:
// RevokeUserAuthStateTx, which advances a user's authentication generation and sweeps the
// sessions, codes and refresh tokens it authorized, at every credential change;
// TerminateUserSessionTx, which ends one session and the grants issued under it;
// RevokeOnAuthCodeReuseTx, the answer to a redeemed code presented again; and
// RevokeClientGrantsTx, for a client that no longer has to authenticate. RevokeUserAuthState,
// RevokeOnAuthCodeReuse and RevokeClientGrants are the same operations on a transaction the caller
// owns, which they require, and RevokeRefreshTokens, beneath them, runs on the caller's transaction
// or, given nil, on none. The Reason* constants are the reasons a revocation records (#106, #129,
// #245, #387).
//
// Each operation reports what it actually did, the sessions it ended and only the tokens it moved
// from live to revoked. On an error each *Tx operation reports nothing, the zero result, so a
// caller cannot audit a partial or rolled-back revocation; an operation on the caller's
// transaction may return a partly filled result beside its error, which the caller discards with
// the transaction. The audit event is the caller's, written through the Log* helpers after the
// commit, because an audit record takes no transaction and one written before a rollback would be
// false.
package revocation
