package api

import (
	"time"
)

type UserSessionResponse struct {
	Id                int64      `json:"id"`
	CreatedAt         *time.Time `json:"createdAt"`
	UpdatedAt         *time.Time `json:"updatedAt"`
	SessionIdentifier string     `json:"sessionIdentifier"`
	Started           *time.Time `json:"started"`
	LastAccessed      *time.Time `json:"lastAccessed"`
	AuthMethods       string     `json:"authMethods"`
	AcrLevel          string     `json:"acrLevel"`
	AuthTime          *time.Time `json:"authTime"`
	IpAddress         string     `json:"ipAddress"`
	DeviceName        string     `json:"deviceName"`
	DeviceType        string     `json:"deviceType"`
	DeviceOS          string     `json:"deviceOS"`
	// UserAgent is the request's User-Agent header as the browser sent it, repaired and
	// bounded at the writer. No omitempty: a session created before the column existed
	// carries an empty string, and that is an answer rather than an absence (#281).
	UserAgent string `json:"userAgent"`
	UserId    int64  `json:"userId"`
}

type GetUserSessionResponse struct {
	Session UserSessionResponse `json:"session"`
}

// UserSessionDetailResponse is a session plus the two things a caller cannot work out for
// itself: the clients it authorized, which is a join, and whether it is the caller's own,
// which needs a claim from a token an API caller may not be able to read (RFC 6749 1.4).
// Everything else a page shows about a session is derived from the embedded timestamps by
// whoever is rendering it.
//
// It carried four pre-rendered strings and a constant true isValid until #373. The strings
// were an English RFC1123 date and a Go duration, computed at the server from instants that
// were already in the same payload, so they were stale before the page drew them and no
// locale could reach them; isValid was a field every producer set to true after skipping
// every session for which it would have been false.
type UserSessionDetailResponse struct {
	UserSessionResponse
	IsCurrent         bool     `json:"isCurrent"`
	ClientIdentifiers []string `json:"clientIdentifiers"`
}

type GetUserSessionsResponse struct {
	Sessions []UserSessionDetailResponse `json:"sessions"`
}

// SessionOwnerResponse is who a listed session belongs to, in the two things a session page
// shows: the name parts and the email. Deliberately not UserResponse, because this shape is
// only ever returned by the client-sessions endpoint, which is reached with the clients scopes
// alone -- admin-read, manage-clients or manage -- and the documented scope split does not put
// a person's profile inside the clients domain. Widening it back would let a manage-clients
// token read the subject, birth date, phone number, postal address and otpEnabled of everyone
// holding a live session on a client it manages (#373).
type SessionOwnerResponse struct {
	Id         int64  `json:"id"`
	Email      string `json:"email"`
	GivenName  string `json:"givenName"`
	MiddleName string `json:"middleName"`
	FamilyName string `json:"familyName"`
}

// GetClientSessionsResponse carries the owners of the sessions it lists, because that endpoint
// is the only one listing sessions across users and the console read them back one at a time,
// up to one HTTP round trip per row. Normalized: a user holding several sessions appears once,
// and every session's userId is a key into this array (#373).
//
// Both arrays are required and neither is nullable, so a producer answering an empty page emits
// [] rather than null; a nil slice would marshal as null against a schema that promises an array.
type GetClientSessionsResponse struct {
	Sessions []UserSessionDetailResponse `json:"sessions"`
	Users    []SessionOwnerResponse      `json:"users"`
}

// The browser session endpoint's request and response bodies (#266).
//
// The admin console keeps no database connection, so it reaches its own browser sessions
// through the auth server. These are the wire form of sessionstore.Backend, method for
// method, and there is deliberately no `owner` field anywhere: the handler names the
// owner itself, so no request can reach an auth server session.
//
// The identifier travels in the body and never in the request line. A handle in a path
// lands in the auth server's access log, in every proxy in front of it, and in anything
// that reports slow requests, which is one of the reasons a capability-style endpoint was
// rejected in the first place.
//
// `data` is a string because it is a string in the column: it is the session store's
// sealed envelope, which is base64 text, and it is ciphertext the auth server holds no
// key for.

// SessionLoadRequest names the session to read or remove.
type SessionLoadRequest struct {
	Id string `json:"id"`
}

// SessionLoadResponse is one stored session.
//
// lastAccessed is here because the caller decides whether to touch, and it makes that
// decision against a threshold rather than on every read: without the timestamp the hop
// would have to happen twice or the laziness would have to move to the server, and it
// belongs with the store that owns the threshold.
type SessionLoadResponse struct {
	Data         string    `json:"data"`
	LastAccessed time.Time `json:"lastAccessed"`
	ExpiresAt    time.Time `json:"expiresAt"`
}

// SessionWriteRequest carries a session's contents.
//
// `authenticated` is a fact about the container and not about its contents: it says
// whether the calling module considers this session signed in, which is what decides
// which of the two lifetimes applies to it. Only the caller can answer it, because only
// the caller can see inside the blob, and only the auth server can turn it into a
// timestamp, because only the auth server can read the deployment's session settings.
type SessionWriteRequest struct {
	Id            string `json:"id"`
	Data          string `json:"data"`
	Authenticated bool   `json:"authenticated"`
}

// SessionWriteResponse is the deadline the auth server chose for a session it just
// wrote. The caller sets its cookie's own expiry from it, so the browser never holds a
// handle that outlives what it names.
type SessionWriteResponse struct {
	ExpiresAt time.Time `json:"expiresAt"`
}

// SessionTouchRequest records that a live session was used.
type SessionTouchRequest struct {
	Id            string `json:"id"`
	Authenticated bool   `json:"authenticated"`
}
