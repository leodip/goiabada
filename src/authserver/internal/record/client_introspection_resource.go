package record

import "database/sql"

// ClientIntrospectionResource lists one resource whose tokens a confidential client may introspect
// (#676 decision 5). A client lists a resource once, and the row goes with either side. It is
// created and deleted, never rewritten.
type ClientIntrospectionResource struct {
	Id         int64        `db:"id" fieldtag:"pk"`
	CreatedAt  sql.NullTime `db:"created_at" fieldtag:"dont-update"`
	ClientId   int64        `db:"client_id"`
	ResourceId int64        `db:"resource_id"`
}
