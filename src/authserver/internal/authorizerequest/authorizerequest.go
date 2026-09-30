// Package authorizerequest holds an authorization request between the POST that received it and
// the GET it is answered with: two operations, Park, which a POST to /auth/authorize calls, and
// Consume, which the GET carrying ?request_handle=<handle> calls (#246, #437).
//
// A POST arrives cross-site without the browser's SameSite=Lax session cookie, so a response that
// began the ceremony would set a new cookie over the one the browser holds and lose the pointer to
// a session already signed in. The POST therefore parks the request here, touching nothing of the
// browser's own session, and answers with a redirect to a GET. That GET is a top-level safe
// navigation and does carry the cookie, so it consumes the request and runs the ceremony from
// what it held, and SSO and prompt=none work over POST as they do over GET.
//
// It is an application service in the shape #387 gave the others: it takes no http.ResponseWriter,
// *http.Request, template data or status code, and it imports no handler package. Which
// parameters are parked, and what a refused handle looks like on the page, are the handler's.
package authorizerequest

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"log/slog"
	"net/url"
	"time"

	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/hashutil"
)

const (
	// HandleParameter is the query parameter the redirect to the GET carries the handle in.
	HandleParameter = "request_handle"

	// Lifetime is how long a parked request can be consumed. It is what a person takes to follow a
	// redirect their browser made for them, with room for a slow connection, and no longer: a row
	// that outlives its use is a row that can be consumed by anyone holding the handle.
	Lifetime = 5 * time.Minute

	// handleBytes is the handle's entropy: 256 bits from crypto/rand, so a handle cannot be guessed
	// and a digest of it is enough to look the row up by.
	handleBytes = 32
)

// Parking is what parking a request needs: the one INSERT.
//
// Exported, unlike the per-file ports #386 left in the handler packages, because it is this
// package's own port and the authorization handlers' ports embed it to hand the capability on
// (#387).
type Parking interface {
	CreateAuthorizeRequest(ctx context.Context, tx *sql.Tx, authorizeRequest *models.AuthorizeRequest) error
}

// Consuming is what consuming a request needs: the read, the claim, and the transaction the pair
// runs in. Apart from Parking because the POST that parks a request never consumes one and the GET
// that consumes it never parks.
type Consuming interface {
	GetAuthorizeRequestByHandleHash(ctx context.Context, tx *sql.Tx, handleHash string, now time.Time) (*models.AuthorizeRequest, error)
	ClaimAuthorizeRequest(ctx context.Context, tx *sql.Tx, authorizeRequestId int64) (bool, error)
	RunInTransaction(ctx context.Context, fn func(tx *sql.Tx) error) error
}

// IsWellFormedHandle reports whether handle has the shape Park issues: handleBytes of randomness
// in the URL-safe base64 alphabet, unpadded. Consume refuses anything else without reading a row,
// so a handle a person mistyped, a truncated link, or an oversized value costs the database
// nothing.
func IsWellFormedHandle(handle string) bool {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(handle)
	return err == nil && len(decoded) == handleBytes
}

// Park stores form under a new one-time handle and returns the handle. Only the handle's digest
// is stored, so a reader of the table cannot consume a request.
//
// The row is one INSERT, atomic on its own, so no transaction is opened.
func Park(ctx context.Context, db Parking, form url.Values) (string, error) {
	raw := make([]byte, handleBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", errs.Wrap(err, "unable to generate an authorize request handle")
	}
	handle := base64.RawURLEncoding.EncodeToString(raw)

	err := db.CreateAuthorizeRequest(ctx, nil, &models.AuthorizeRequest{
		HandleHash:  hashutil.HashString(handle),
		RequestForm: form.Encode(),
		ExpiresAt:   time.Now().UTC().Add(Lifetime),
	})
	if err != nil {
		return "", errs.Wrap(err, "unable to park the authorize request")
	}
	return handle, nil
}

// Consume takes the request parked under handle and returns what it held, or reports false when
// there is none to take: the handle is malformed, unknown, expired, or already consumed. The
// caller answers all four the same way, so the answer says nothing about which it was.
//
// It is a one-winner claim. The row is read, compared with the handle's digest in Go, and then
// deleted by id, and only the call whose DELETE removed the row returns what it held; a second
// consumer that read the row before the first deleted it finds nothing to delete and reports
// false. Without that, two overlapping GETs of one link could both run the ceremony.
//
// The read and the delete run in one RunInTransaction, so a deadlock victim's body is rerun from
// the read and starts from what the database holds now.
func Consume(ctx context.Context, db Consuming, handle string) (url.Values, bool, error) {
	if !IsWellFormedHandle(handle) {
		return nil, false, nil
	}
	handleHash := hashutil.HashString(handle)

	var parked *models.AuthorizeRequest
	err := db.RunInTransaction(ctx, func(tx *sql.Tx) error {
		// Cleared on entry: the body is rerun after a deadlock, and what a first attempt found
		// never committed.
		parked = nil

		found, err := db.GetAuthorizeRequestByHandleHash(ctx, tx, handleHash, time.Now().UTC())
		if err != nil {
			return errs.Wrap(err, "unable to read the authorize request")
		}
		if found == nil {
			return nil
		}

		claimed, err := db.ClaimAuthorizeRequest(ctx, tx, found.Id)
		if err != nil {
			return errs.Wrap(err, "unable to claim the authorize request")
		}
		if claimed {
			parked = found
		}
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	if parked == nil {
		return nil, false, nil
	}

	form, err := url.ParseQuery(parked.RequestForm)
	if err != nil {
		// Park wrote what Encode produced, which ParseQuery reads back, so a row that does not parse
		// was changed outside this package. It is consumed already and is refused like any handle
		// with nothing behind it, rather than answered with a 500 the browser would repeat.
		slog.WarnContext(ctx, "unable to parse a parked authorize request, refusing its handle", "error", err)
		return nil, false, nil
	}
	return form, true, nil
}
