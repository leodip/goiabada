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

// SaveLinkMarker records a validated link in the session, replacing any marker
// already there including one from the other flow.
func SaveLinkMarker(httpSession sessions.Store, w http.ResponseWriter, r *http.Request,
	flow LinkMarkerFlow, id int64, codeHash string) error {

	sess, err := httpSession.Get(r, constants.AuthServerSessionName)
	if err != nil {
		return err
	}

	jsonData, err := json.Marshal(&LinkMarker{
		Flow:      flow,
		Id:        id,
		CodeHash:  codeHash,
		ExpiresAt: time.Now().UTC().Add(linkMarkerLifetime),
	})
	if err != nil {
		return errors.Wrap(err, "unable to marshal link marker")
	}

	sess.Values[constants.SessionKeyLinkMarker] = string(jsonData)
	return httpSession.Save(r, w, sess)
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

	if marker.expired(time.Now().UTC()) {
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
