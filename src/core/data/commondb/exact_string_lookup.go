package commondb

// engineFoldedTheMatch reports that a row an engine returned for an exact string lookup
// does not actually carry the value the lookup asked for, which can only mean the ENGINE
// decided the two strings were the same string. The caller answers nothing when it does.
//
// It exists because two of those folds survive every collation, so pinning
// utf8mb4_0900_as_cs and Latin1_General_100_CS_AS_KS_WS_SC_UTF8 does not reach them:
//
//   - SQL Server pads for `=`. 'myapp' = 'myapp ' is true under every collation it has,
//     Latin1_General_100_BIN2_UTF8 included, while DATALENGTH shows the two strings differ.
//     No collation turns that off.
//   - SQL Server and MySQL compare an accented character spelled NFC equal to the same
//     character spelled as a base letter plus a combining mark. SQLite and PostgreSQL
//     compare them unequal.
//
// Neither is reachable through a WRITE: ValidateIdentifier admits no space and no
// non-ASCII, and every email write path is trimmed and lowercased in Go. Neither validator
// runs on a READ. ValidateTokenRequest and ValidateClientAndRedirectURI check only that
// client_id is non-empty before handing it to GetClientByClientIdentifier, so a token
// request naming client_id with a trailing space resolved the client registered without
// one on SQL Server, and resolved nothing on the other three engines. That was measured
// against a live SQL Server through this package's own method (#283).
//
// So the data layer decides identity and the engine does not. Delete this and those two
// folds are reachable again on the two engines that have them: a lookup by client
// identifier, group identifier, resource identifier, email or subject starts answering two
// different ways depending on which database the deployment happens to run, which is the
// divergence the collation change exists to close. RFC 6749 section 1.9 makes exact
// comparison of client_id a conformance requirement, section 3.3 does the same for scope,
// and OpenID Connect Core section 2 for sub.
//
// It compares what the CALLER asked for against what the ROW holds, and normalises
// neither. Trimming or case-folding either side here would let the padded value back in
// through the other door, which is the whole of what this closes.
//
// A future lookup that writes its own `=` over a string needs the same guard; the collation
// cannot supply it.
func engineFoldedTheMatch(got, want string) bool {
	return got != want
}
