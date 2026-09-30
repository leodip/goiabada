package models

// The three bounds below are the widths of the columns an authorization request's free-form values
// are stored in, on MySQL, PostgreSQL and SQL Server; SQLite stores TEXT. RFC 6749 gives a state
// and a scope no maximum length and OpenID Connect Core gives a nonce none, so the bound is
// storage's, and it is set where no realistic client meets it: a framework that packs its own
// properties into state, as ASP.NET Core's OpenID Connect handler does, sends well over the 512
// the columns used to hold.
//
// Every writer compares a value with len, which counts bytes: MySQL and PostgreSQL count a width in
// code points and SQL Server in UTF-16 units, and a string is never fewer bytes than either, so a
// value a bound admits fits the column, where a bound in characters would still overflow SQL
// Server on characters outside the Basic Multilingual Plane. 2048 keeps SQL Server on nvarchar(n),
// whose ceiling is 4000, and keeps each table's declared VARCHAR total inside InnoDB's 65535-byte
// row limit (codes 37480 bytes, refresh_tokens 9280, user_consents 8192). Raising one needs its
// columns widened first, or a value between the two bounds is admitted and then refused by three
// engines as a 500 after the user has signed in (#437).

// StateMaxBytes is the width of codes.state.
const StateMaxBytes = 2048

// NonceMaxBytes is the width of codes.nonce.
const NonceMaxBytes = 2048

// ScopeMaxBytes is the width of codes.scope, refresh_tokens.scope and user_consents.scope. They move
// together because one scope is stored in all three: the consent the user gave, the code issued
// under it and the refresh token descended from that code. The token endpoint's refresh only
// narrows a stored scope and client credentials stores none, so the authorization endpoint and the
// password grant are the two doors a scope enters through.
const ScopeMaxBytes = 2048
