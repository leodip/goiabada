package models

import "database/sql"

// RedirectURIMaxBytes is the width of redirect_uris.uri, and of codes.redirect_uri, which issuance
// copies the registered URI into verbatim, on MySQL, PostgreSQL and SQL Server; SQLite stores TEXT.
// Every writer compares it with len, which counts bytes: MySQL and PostgreSQL count a width in code
// points and SQL Server in UTF-16 units, and a string is never fewer bytes than either, so a value
// this admits fits all three columns, where a bound in runes would still overflow SQL Server on
// characters outside the Basic Multilingual Plane. 2048 fits every realistic callback, keeps a
// percent-encoded worst case to about 6 KiB of the authorize request line, and keeps SQL Server on
// nvarchar(n), whose ceiling is 4000. Raising it needs the columns widened first, or a URI between
// the two bounds is admitted and then refused by three engines as a 500 (#428).
const RedirectURIMaxBytes = 2048

// RedirectURIsMaxPerClient is how many redirect URIs one client may hold, the same number at dynamic
// client registration and at the admin API, because it is a property of the data rather than of the
// door. It bounds what an anonymous registration can make the server store, and an administrator's
// client spanning several environments does not meet it (#428).
const RedirectURIsMaxPerClient = 60

type RedirectURI struct {
	Id        int64        `db:"id" fieldtag:"pk"`
	CreatedAt sql.NullTime `db:"created_at" fieldtag:"dont-update"`
	URI       string       `db:"uri"`
	ClientId  int64        `db:"client_id"`
}
