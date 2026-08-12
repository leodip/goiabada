package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gorilla/sessions"
	"github.com/pkg/errors"

	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/stringutil"
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
	// LinkMarkerWrongFlow is a marker for the other flow. Both flows share one session
	// key, so this is what a request of one flow sees when the slot holds the other's:
	// a clean URL reached without following that flow's link, or a marker the other
	// flow wrote once the first had expired or been cleared.
	LinkMarkerWrongFlow LinkMarkerRejection = "marker_wrong_flow"
	// LinkMarkerExpired is a marker past linkMarkerLifetime.
	LinkMarkerExpired LinkMarkerRejection = "marker_expired"
	// LinkMarkerContinuationInFlight is a second, different link followed while the
	// first one is still live, of either flow. Refused rather than allowed to replace,
	// which is what SaveLinkMarker exists to enforce.
	LinkMarkerContinuationInFlight LinkMarkerRejection = "continuation_in_flight"
)

// continuationIdLength matches the length of the codes both flows email
// (GenerateSecurityRandomString(32)), which over that 65-character alphabet is far
// more entropy than this value needs. It is not guessed at: nobody outside the
// session ever sees it, and it authorizes nothing on its own.
const continuationIdLength = 32

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
	// ContinuationId names this continuation, so a page rendered from this marker can
	// say which marker rendered it and be refused once the slot holds another one.
	//
	// No rule about WRITING the slot can do that job, because the retarget happens to a
	// page that is already rendered: the marker can be replaced legitimately once it
	// expires, and the reset form otherwise carries nothing identifying it while every
	// reset form in a browser posts to the identical clean URL. The reset POST is what
	// checks it. Activation carries no id anywhere, because its continuation is the
	// browser following a 303 with no page in between (#112).
	ContinuationId string `json:"continuationId"`
}

// expired reports whether the marker is past its window. A marker whose ExpiresAt is
// exactly now is still live, matching isForgotPasswordCodeExpired.
func (m *LinkMarker) expired(now time.Time) bool {
	return m.ExpiresAt.Before(now)
}

// SaveLinkMarker records a validated link in the session.
//
// One continuation at a time, first writer wins: a live marker naming a different code
// hash is NOT replaced, whichever flow it belongs to. The caller is handed
// LinkMarkerContinuationInFlight and refuses this link instead, leaving the first
// continuation intact (#112).
//
// One session holds one marker, so without that rule a second link followed while a
// first continuation is in flight takes the slot over. Every reset form in a browser
// posts to the identical clean URL, so the password typed for one account is written
// into the other, revoking its sessions, while the first account keeps its old password.
// SameSite=Lax sends the session cookie on a top-level GET navigation, so one steered
// click reaches it. Before this change each tab was bound to its own credential by the
// query string it was served from.
//
// The rule spans both flows because scoping it to one leaves a two-step bridge: a
// wrong-flow marker is refused by every consuming step, but replacing an activation
// marker over a live reset one and then a reset marker over that puts the slot back into
// the reset flow, which is the same retarget in three navigations rather than one.
//
// Two replacements stay allowed, and each is deliberate:
//   - the same code hash, which is one link followed twice, and refreshes its window
//     while KEEPING its continuation id, since a form that link already rendered is the
//     same continuation and must not be refused;
//   - an expired marker, so a refusal can never outlast linkMarkerLifetime.
//
// The expired case is why this rule is not the whole answer, and why LinkMarker carries
// a continuation id: a reset form rendered at t=0 is still on screen at t=5min and posts
// to the same clean URL, so a link followed after the expiry would otherwise retarget it.
// No rule about writes can bind a page that is already rendered.
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

	held, err := decodeLinkMarker(sess)
	if err != nil {
		return "", err
	}

	live := held != nil && !held.expired(now)
	if live && held.CodeHash != codeHash {
		return LinkMarkerContinuationInFlight, nil
	}

	// A live marker with this code hash is this same continuation, so it keeps its id.
	// Rotating here would refuse the form that link had already rendered, which is the
	// legitimate sequence "the user clicked the emailed link again".
	continuationId := ""
	if live {
		continuationId = held.ContinuationId
	}
	if continuationId == "" {
		continuationId = stringutil.GenerateSecurityRandomString(continuationIdLength)
		// GenerateSecurityRandomString answers "" when the system CSPRNG is unavailable.
		// Writing that would put an empty id in the marker, which the POST refuses
		// outright, so failing here is the same outcome with a stack trace attached.
		if continuationId == "" {
			return "", errors.WithStack(errors.New("unable to generate a link marker continuation id"))
		}
	}

	jsonData, err := json.Marshal(&LinkMarker{
		Flow:           flow,
		Id:             id,
		CodeHash:       codeHash,
		ExpiresAt:      now.Add(linkMarkerLifetime),
		ContinuationId: continuationId,
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

// decodeLinkMarker returns whatever marker the session holds, of either flow and
// whether or not it is still live, or nil when the slot is empty.
//
// Separate from readLinkMarker because the two callers ask different questions of the
// same value. A consuming step wants "is there a live marker of MY flow", and answering
// anything else there would let one flow act on the other's marker. SaveLinkMarker wants
// "is this slot occupied at all", because the thing it must not do is overwrite another
// continuation, and another continuation of the other flow is still another continuation.
//
// A value that will not unmarshal is a fault rather than an empty slot: the session
// cookie is encrypted and signed, so nobody outside this process can put one there.
func decodeLinkMarker(sess *sessions.Session) (*LinkMarker, error) {
	jsonData, ok := sess.Values[constants.SessionKeyLinkMarker].(string)
	if !ok {
		return nil, nil
	}

	var marker LinkMarker
	if err := json.Unmarshal([]byte(jsonData), &marker); err != nil {
		return nil, errors.Wrap(err, "unable to unmarshal link marker")
	}

	return &marker, nil
}

// readLinkMarker applies the flow and expiry checks a consuming step needs, so that "is
// there a live marker of this flow" is one question with one answer wherever it is asked.
func readLinkMarker(sess *sessions.Session, want LinkMarkerFlow,
	now time.Time) (*LinkMarker, LinkMarkerRejection, error) {

	marker, err := decodeLinkMarker(sess)
	if err != nil {
		return nil, "", err
	}
	if marker == nil {
		return nil, LinkMarkerMissing, nil
	}

	// Flow before expiry, so a marker left by the other flow reports the structural
	// mismatch rather than its age.
	if marker.Flow != want {
		return nil, LinkMarkerWrongFlow, nil
	}

	if marker.expired(now) {
		return nil, LinkMarkerExpired, nil
	}

	return marker, "", nil
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
