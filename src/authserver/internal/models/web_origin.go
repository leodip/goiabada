package models

import "database/sql"

// WebOriginMaxBytes is the width of the web_origins.origin column on MySQL, PostgreSQL and SQL
// Server; SQLite stores TEXT. It is the longest standards-valid origin: "https://" plus a
// 253-character host, the longest DNS name, plus ":65535" is 267. urlutil.CanonicalOrigin admits
// only ASCII, so bytes and characters agree, but it does not bound a host's length, so a longer
// value it returns is refused at the endpoint rather than becoming a 500 on three engines out of
// four, which no SQLite tier can see. The bound lives on the record rather than in
// urlutil.CanonicalOrigin because it is a fact about storage rather than about what an origin is
// (#250, #428).
const WebOriginMaxBytes = 267

type WebOrigin struct {
	Id        int64        `db:"id" fieldtag:"pk"`
	CreatedAt sql.NullTime `db:"created_at" fieldtag:"dont-update"`
	Origin    string       `db:"origin"`
	ClientId  int64        `db:"client_id"`
}
