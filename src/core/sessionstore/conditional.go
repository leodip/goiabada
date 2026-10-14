package sessionstore

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/leodip/goiabada/core/errs"
)

// conditionalAttempts bounds how many times a conditional write reads, applies its change and
// writes before it gives up: the bound RunInTransaction puts on a deadlock victim, and for the
// same reason, since each loss means another request of this browser wrote in between and a
// browser that keeps doing so is better answered with the failure than retried forever (#579).
const conditionalAttempts = 3

// ErrChanged is "the stored session is not the one that was read": a conditional write or
// delete found no live row holding the expected contents, because another request wrote the
// session since, or the row is gone. The backend cannot tell those two apart in the one
// statement it runs, so the store reads again to find out which (#579).
//
// A sentinel on stdlib errors.New for the reason ErrNotFound states.
var ErrChanged = errors.New("session changed since it was read")

// ConditionalBackend is a Backend that can write on condition that a session is still what a
// read returned. Its own interface rather than two more methods on Backend: the admin console's
// backend, which speaks to the session endpoint, has no such operation and keeps none, and a
// store that needs one is built with this type, so a store without it does not compile where it
// is needed rather than being asserted at run time (#431, #579).
//
// The condition is the stored ciphertext. Every content write seals with a fresh random nonce,
// so any write in between changes it, while a touch moves only the timestamps and never makes a
// conditional write lose.
type ConditionalBackend interface {
	Backend
	// UpdateIfUnchanged replaces a live session's contents, as Update does, only while its
	// stored contents are expected. ErrChanged when they are not, or the session is gone.
	UpdateIfUnchanged(ctx context.Context, id string, expected, data []byte, authenticated bool) (time.Time, error)
	// DeleteIfUnchanged removes a live session only while its stored contents are expected.
	// ErrChanged when they are not, or the session is gone.
	DeleteIfUnchanged(ctx context.Context, id string, expected []byte) error
}

// ConditionalStore is a ServerSideStore over a ConditionalBackend, which adds the two writes
// that apply only the caller's change, ChangeAndSave and ChangeAndRegenerate. The auth server
// builds its store as one; the admin console's is a plain ServerSideStore (#579).
//
// The change each takes is the caller's own, applied to the session's values as a fresh read
// found them. An error from it refuses the write: nothing is written and the error is returned
// as it is, so the caller can match its own sentinel.
type ConditionalStore struct {
	*ServerSideStore
	conditional ConditionalBackend
}

// NewConditionalStore adds the conditional writes to store, over backend, which must be the
// backend store was built over: the conditional writes and the store's own then read and write
// the same rows. Passing the capability here, typed, rather than asserting it of the store's
// backend, is what makes a store without it fail to compile where it is needed (#431).
func NewConditionalStore(store *ServerSideStore, backend ConditionalBackend) (*ConditionalStore, error) {
	if store.backend != Backend(backend) {
		return nil, errs.New("the conditional writes must be over the backend the session store was built over")
	}
	return &ConditionalStore{ServerSideStore: store, conditional: backend}, nil
}

// ChangeAndSave applies change to the session as it is stored now and writes the result, on
// condition nothing wrote the session in between. It is what a write that must not put back
// the copy its request read uses instead of Save (#579):
//
//  1. read the session afresh, bypassing the request's cache, which holds the copy the request
//     began with
//  2. apply change to the values that read found, so only this caller's change is written
//  3. write on condition the stored contents are still the ones read, and on losing to another
//     write go back to 1, at most conditionalAttempts times in all, then read once more and fail
//     as that read answers (see outOfAttempts)
//  4. update the request's session with what was stored, and name it with a cookie as Save does
//
// A session the request loaded that is gone by the fresh read is not put back: the answer is
// ErrNotFound and nothing is written, for the reason Update never inserts. A session never
// stored, which no other request can have written, starts from empty values and is created.
// A refusal from change is returned as it is, with nothing written and the session untouched.
func (s *ConditionalStore) ChangeAndSave(r *http.Request, w http.ResponseWriter, session *Session, change func(values map[string]any) error) error {
	if session.ID == "" {
		values := make(map[string]any)
		if err := change(values); err != nil {
			return err
		}
		return s.create(r, w, session, values)
	}

	ctx := requestContext(r)
	for attempt := 1; attempt <= conditionalAttempts; attempt++ {
		record, values, err := s.freshRead(ctx, session)
		if err != nil {
			return err
		}
		if changeErr := change(values); changeErr != nil {
			return changeErr
		}

		encoded, err := s.sealValues(session.Name(), values)
		if err != nil {
			return err
		}

		expiresAt, err := s.conditional.UpdateIfUnchanged(ctx, session.ID, record.Data, []byte(encoded),
			s.valuesAreAuthenticated(values))
		if err != nil {
			if lostTheRace(err) {
				continue
			}
			return errs.Wrap(err, "unable to update the browser session")
		}

		session.Values = values
		return s.setCookie(w, session, session.ID, expiresAt)
	}

	return s.outOfAttempts(ctx, session, change, "update")
}

// ChangeAndRegenerate applies change to the session as it is stored now and writes the result
// under a fresh identifier: Regenerate for a rotation that must not put back the copy its
// request read (#579). Each attempt reads afresh and applies change as ChangeAndSave does,
// writes the new row, and removes the old one on condition it is still what was read. When
// another write landed in between the old row is kept, the new row removed, and the attempt
// repeated, at most conditionalAttempts times in all, and then answered as outOfAttempts reads it.
//
// The order is Regenerate's and for its reason: new row, old row gone, then the cookie, and every
// failure before the cookie emits no header. A session the request loaded that is gone by the
// fresh read is not re-created under a new name: the answer is ErrNotFound, since putting the
// request's session back after another request rotated it away is what this exists to stop.
func (s *ConditionalStore) ChangeAndRegenerate(w http.ResponseWriter, r *http.Request, session *Session, change func(values map[string]any) error) error {
	if session.ID == "" {
		values := make(map[string]any)
		if err := change(values); err != nil {
			return err
		}
		return s.create(r, w, session, values)
	}

	ctx := requestContext(r)
	for attempt := 1; attempt <= conditionalAttempts; attempt++ {
		record, values, err := s.freshRead(ctx, session)
		if err != nil {
			return err
		}
		if changeErr := change(values); changeErr != nil {
			return changeErr
		}

		encoded, err := s.sealValues(session.Name(), values)
		if err != nil {
			return err
		}
		newId, err := s.newSessionId()
		if err != nil {
			return err
		}

		expiresAt, err := s.conditional.Create(ctx, newId, []byte(encoded), s.valuesAreAuthenticated(values))
		if err != nil {
			return errs.Wrap(err, "unable to create the rotated browser session")
		}

		if err := s.conditional.DeleteIfUnchanged(ctx, session.ID, record.Data); err != nil {
			if !lostTheRace(err) {
				return errs.Wrap(err, "unable to delete the browser session being rotated away")
			}
			// The new row holds a copy of contents that are no longer the session's. No cookie
			// names it yet, so removing it is all it takes for it never to have existed.
			if err := s.conditional.Delete(ctx, newId); err != nil {
				return errs.Wrap(err, "unable to delete the rotated browser session after losing to another write")
			}
			continue
		}

		session.ID = newId
		session.IsNew = false
		session.Values = values
		return s.setCookie(w, session, newId, expiresAt)
	}

	return s.outOfAttempts(ctx, session, change, "rotate")
}

// outOfAttempts is the answer once every attempt has lost. The write that won the last comparison
// may have been the one the caller's change refuses, another ceremony or none, or the row's removal,
// and that answer must not depend on which attempt it landed at: so the session is read once more
// and change applied to what the read found, writing nothing, and a gone row is ErrNotFound and a
// refusal returned as it is, as on any attempt. ErrChanged is left for a session still there whose
// change still applies, the bounded loss to unrelated writes (#579).
func (s *ConditionalStore) outOfAttempts(ctx context.Context, session *Session, change func(values map[string]any) error, verb string) error {
	_, values, err := s.freshRead(ctx, session)
	if err != nil {
		return err
	}
	if changeErr := change(values); changeErr != nil {
		return changeErr
	}
	return errs.Wrapf(ErrChanged, "unable to %s the browser session after %d attempts", verb, conditionalAttempts)
}

// freshRead loads the stored row the session names, bypassing the request's cache, and opens
// it. A row gone is ErrNotFound. A row that does not open is an error rather than a fresh
// session as at New: the request opened this session when it began, so failing to now is a
// fault, not a browser presenting something this deployment cannot read.
func (s *ConditionalStore) freshRead(ctx context.Context, session *Session) (*Record, map[string]any, error) {
	record, err := s.conditional.Load(ctx, session.ID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, nil, errs.Wrap(err, "the browser session is gone")
		}
		return nil, nil, errs.Wrap(err, "unable to read the browser session afresh")
	}

	values, err := s.openSessionData(session.Name(), record.Data)
	if err != nil {
		return nil, nil, errs.Wrap(err, "unable to open the browser session read afresh")
	}
	return record, values, nil
}

// create writes a session never stored, which has no row another request could have written:
// a new identifier, the values, and the cookie.
func (s *ConditionalStore) create(r *http.Request, w http.ResponseWriter, session *Session, values map[string]any) error {
	encoded, err := s.sealValues(session.Name(), values)
	if err != nil {
		return err
	}
	id, err := s.newSessionId()
	if err != nil {
		return err
	}

	expiresAt, err := s.conditional.Create(requestContext(r), id, []byte(encoded), s.valuesAreAuthenticated(values))
	if err != nil {
		return errs.Wrap(err, "unable to create the browser session")
	}

	session.ID = id
	session.IsNew = false
	session.Values = values
	return s.setCookie(w, session, id, expiresAt)
}

// lostTheRace is whether a conditional operation found the row not as it was read: changed, or
// gone since, which ErrNotFound reports when a backend found that out before its statement ran.
// The next attempt's fresh read tells which.
func lostTheRace(err error) bool {
	return errors.Is(err, ErrChanged) || errors.Is(err, ErrNotFound)
}
