package record

import "time"

// DeletedClient is the record that a client with this identifier was deleted, and when (#676
// decision 6). A new client may take a deleted client's identifier, and an access token names its
// client only by that identifier, so the access-token liveness check reads this for a token issued
// in its client's creation second, the one second whose tokens its iat cannot place before or after
// the creation.
//
// There is no id: the identifier is the key, and a later deletion of the same identifier replaces
// the row.
type DeletedClient struct {
	ClientIdentifier string    `db:"client_identifier"`
	DeletedAt        time.Time `db:"deleted_at"`
}
