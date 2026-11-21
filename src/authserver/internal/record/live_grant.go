package record

// LiveGrant is one live refresh token a user holds, as the list of the user's connected clients
// reads it: the token's id, the client it reaches through either linkage shape (its code's client
// for an authorization-code token, its own for a password grant) and the scope it records (#135
// decision 4). A projection rather than a table, like EmailCaseRow: nothing writes a LiveGrant
// back.
type LiveGrant struct {
	RefreshTokenID int64
	ClientID       int64
	Scope          string
}
