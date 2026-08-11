package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gorilla/sessions"
	"github.com/pkg/errors"

	"github.com/leodip/goiabada/core/constants"
)

// linkMarkerLifetime bounds how long a validated emailed link stays usable after the
// link itself was followed.
//
// Its own constant rather than a second use of forgotPasswordCodeLifetime. The two
// are equal today, but they measure different things: the code's lifetime runs from
// when the code was issued, and the marker gets a fresh window from when the link was
// validated, so a user clicking at 4:59 still has time to type a password. Tying the
// marker to the code's remaining lifetime would drop that user mid-form (#112).
const linkMarkerLifetime = 5 * time.Minute

// LinkMarkerFlow names which of the two emailed-link flows a marker belongs to.
type LinkMarkerFlow string

const (
	LinkMarkerFlowResetPassword   LinkMarkerFlow = "reset_password"
	LinkMarkerFlowAccountActivate LinkMarkerFlow = "account_activate"
)

// LinkMarkerRejection names why a marker was refused. The values are audit reason
// strings: the handler records what this helper decided rather than re-deriving it,
// so the audit vocabulary and the actual control flow cannot drift (#112).
type LinkMarkerRejection string

const (
	// LinkMarkerMissing is no marker at all: a bookmarked clean URL, a session that
	// has since been replaced, or a request that never followed a link.
	LinkMarkerMissing LinkMarkerRejection = "marker_missing"
	// LinkMarkerWrongFlow is a marker for the other flow. Reachable benignly, since
	// both flows share one session key and the later one replaces the earlier.
	LinkMarkerWrongFlow LinkMarkerRejection = "marker_wrong_flow"
	// LinkMarkerExpired is a marker past linkMarkerLifetime.
	LinkMarkerExpired LinkMarkerRejection = "marker_expired"
	// LinkMarkerContinuationInFlight is a second, different link of the same flow
	// followed while the first one is still live. Refused rather than allowed to
	// replace, which is what SaveLinkMarker exists to enforce.
	LinkMarkerContinuationInFlight LinkMarkerRejection = "continuation_in_flight"
)

// LinkMarker records that an emailed link was followed and its code was valid, so
// every later step of the flow can run on a URL with no credential in it (#112).
//
// It lives in the session, which is a client-side encrypted cookie
// (sessionstore.NewChunkedCookieStore). That is what CodeHash is for: clearing the
// marker replaces the browser's copy and cannot invalidate one an attacker kept, so a
// marker naming only a durable id would outlive the password write, a newly issued
// code and every other password change. Naming the code hash makes the marker durable
// only for as long as that hash is still the outstanding one, and re-resolving it is
// the consuming handler's job on every clean request.
type LinkMarker struct {
	Flow LinkMarkerFlow `json:"flow"`
	// Id is the userId for a reset and the pre-registration id for an activation.
	Id        int64     `json:"id"`
	CodeHash  string    `json:"codeHash"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// expired reports whether the marker is past its window. A marker whose ExpiresAt is
// exactly now is still live, matching isForgotPasswordCodeExpired.
func (m *LinkMarker) expired(now time.Time) bool {
	return m.ExpiresAt.Before(now)
}

// SaveLinkMarker records a validated link in the session.
//
// One continuation at a time, first writer wins: a live marker of the same flow naming
// a different code hash is NOT replaced. The caller is handed
// LinkMarkerContinuationInFlight and refuses this link instead, leaving the first
// continuation intact (#112).
//
// That rule is the per-tab binding the redirect took away, and without it this flow is
// worse than the one it replaces. One session holds one marker, the reset form names
// nothing about the marker that rendered it, and every reset form in a browser posts to
// the identical clean URL, so a second reset link followed between a form rendering and
// its submit retargets that submit: the password typed for one account is written into
// the other, revoking its sessions, while the first account keeps its old password.
// SameSite=Lax sends the session cookie on a top-level GET navigation, so one steered
// click reaches it. Before this change each tab was bound to its own credential by the
// query string it was served from.
//
// Three replacements stay allowed, and each is deliberate:
//   - the same code hash, which is one link followed twice, and refreshes its window;
//   - an expired marker, so a refusal can never outlast linkMarkerLifetime;
//   - a marker from the OTHER flow, which is already fail-closed, since every consuming
//     step refuses a wrong-flow marker rather than acting on it.
//
// Cost accepted: a genuinely wanted second, different link is refused for up to
// linkMarkerLifetime, and someone who can steer one navigation can pin a session with a
// marker of their own and deny a reset for that window. A bounded availability loss in
// place of a wrong-account credential write.
func SaveLinkMarker(httpSession sessions.Store, w http.ResponseWriter, r *http.Request,
	flow LinkMarkerFlow, id int64, codeHash string) (LinkMarkerRejection, error) {

	sess, err := httpSession.Get(r, constants.AuthServerSessionName)
	if err != nil {
		return "", err
	}

	now := time.Now().UTC()

	live, _, err := readLinkMarker(sess, flow, now)
	if err != nil {
		return "", err
	}
	if live != nil && live.CodeHash != codeHash {
		return LinkMarkerContinuationInFlight, nil
	}

	jsonData, err := json.Marshal(&LinkMarker{
		Flow:      flow,
		Id:        id,
		CodeHash:  codeHash,
		ExpiresAt: now.Add(linkMarkerLifetime),
	})
	if err != nil {
		return "", errors.Wrap(err, "unable to marshal link marker")
	}

	sess.Values[constants.SessionKeyLinkMarker] = string(jsonData)
	return "", httpSession.Save(r, w, sess)
}

// GetLinkMarker returns the session's marker if it belongs to the wanted flow and is
// still live.
//
// Exactly one of the three results is set. A rejection is an ordinary outcome the
// caller audits and renders indistinguishably; an error is a genuine server fault,
// which keeps its stack trace and keeps alerting rather than being answered as a bad
// link. A value that will not unmarshal is a fault, not a miss: the session cookie is
// encrypted and signed, so nobody outside this process can put one there.
func GetLinkMarker(httpSession sessions.Store, r *http.Request,
	want LinkMarkerFlow) (*LinkMarker, LinkMarkerRejection, error) {

	sess, err := httpSession.Get(r, constants.AuthServerSessionName)
	if err != nil {
		return nil, "", err
	}

	return readLinkMarker(sess, want, time.Now().UTC())
}

// readLinkMarker decodes the session's marker and applies the flow and expiry checks.
//
// Shared so that "is there a live marker of this flow" is one question with one answer:
// GetLinkMarker asks it of the marker a request presents, and SaveLinkMarker asks it of
// the marker already held before deciding whether it may be replaced. Two copies of this
// could drift, and a saver that read expiry differently from the consumer would either
// refuse a link nothing can use or replace one still in play.
func readLinkMarker(sess *sessions.Session, want LinkMarkerFlow,
	now time.Time) (*LinkMarker, LinkMarkerRejection, error) {

	jsonData, ok := sess.Values[constants.SessionKeyLinkMarker].(string)
	if !ok {
		return nil, LinkMarkerMissing, nil
	}

	var marker LinkMarker
	if err := json.Unmarshal([]byte(jsonData), &marker); err != nil {
		return nil, "", errors.Wrap(err, "unable to unmarshal link marker")
	}

	// Flow before expiry, so a marker left by the other flow reports the structural
	// mismatch rather than its age.
	if marker.Flow != want {
		return nil, LinkMarkerWrongFlow, nil
	}

	if marker.expired(now) {
		return nil, LinkMarkerExpired, nil
	}

	return &marker, "", nil
}

// ClearLinkMarker removes the marker from the session.
//
// Hygiene rather than a security boundary: the session is a client-side cookie, so
// this replaces the browser's copy and cannot invalidate one that was captured
// beforehand. What actually refuses a replayed marker is re-resolving its CodeHash,
// which the consuming handlers do on every clean request.
func ClearLinkMarker(httpSession sessions.Store, w http.ResponseWriter, r *http.Request) error {
	sess, err := httpSession.Get(r, constants.AuthServerSessionName)
	if err != nil {
		return err
	}

	delete(sess.Values, constants.SessionKeyLinkMarker)
	return httpSession.Save(r, w, sess)
}
