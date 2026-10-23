package ceremony

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/sessionkeys"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/sessionstore"
)

// authSessionStore is what Store calls on the browser session store. A rotation is in it, so a
// store that cannot rotate does not compile here, where it used to make RegenerateSession a silent
// no-op (#431). It is ChangeAndRegenerate, the conditional rotation, beside ChangeAndSave, the
// conditional write every step's save is made with, both of which only
// sessionstore.ConditionalStore has (#579).
type authSessionStore interface {
	Get(r *http.Request, name string) (*sessionstore.Session, error)
	Save(r *http.Request, w http.ResponseWriter, session *sessionstore.Session) error
	ChangeAndSave(r *http.Request, w http.ResponseWriter, session *sessionstore.Session,
		change func(values map[string]any) error) error
	ChangeAndRegenerate(w http.ResponseWriter, r *http.Request, session *sessionstore.Session,
		change func(values map[string]any) error) error
}

// Store keeps a browser's AuthContext in the server-side session, under
// sessionkeys.AuthContext, between the hops of one authorization ceremony. Every reader reads the
// ceremony the request names (GetAuthContext, UILocales), and every write names the ceremony it
// writes. It was
// handlerhelpers.AuthHelper until #435 moved it beside the type it persists; the handlers reach it
// through their CeremonyStore port, and server.go's locale middleware through UILocales.
type Store struct {
	sessionStore authSessionStore
	sessionName  string
}

func NewStore(sessionStore authSessionStore, sessionName string) *Store {
	return &Store{
		sessionStore: sessionStore,
		sessionName:  sessionName,
	}
}

// GetAuthContext reads the ceremony the request names, through the one rule for which that is
// (RequestedId): the URL's parameter on a GET, the form's field on a POST. The step boundary loads
// every step's ceremony through it, and the one-time-code rate limit the user whose budget a
// submission spends, so the two always read the same ceremony.
//
// It answers ErrNoAuthContext when the browser session holds no ceremony at all, whatever the request
// names, and ErrCeremonyNotHeld when it holds a ceremony but not the one named, or the request names
// none.
func (s *Store) GetAuthContext(r *http.Request) (*AuthContext, error) {
	return s.authContextNamed(r, RequestedId(r))
}

// authContextNamed reads the ceremony the browser session holds under ceremonyId: ErrNoAuthContext
// when it holds none, and ErrCeremonyNotHeld when it holds another, or a context naming none, since
// an empty id is never held (idMatches).
func (s *Store) authContextNamed(r *http.Request, ceremonyId string) (*AuthContext, error) {
	authContext, err := s.LatestAuthContext(r)
	if err != nil {
		return nil, err
	}
	if !idMatches(authContext.CeremonyId, ceremonyId) {
		return nil, errs.WithStack(ErrCeremonyNotHeld)
	}
	return authContext, nil
}

// LatestAuthContext reads the ceremony the browser most recently wrote, whichever one the request
// names, which while a browser holds one ceremony is the one it holds. It answers ErrNoAuthContext
// when the session holds none. The ceremony mismatch audit event records it, and the page language
// falls back to it when the URL names no ceremony the browser holds.
func (s *Store) LatestAuthContext(r *http.Request) (*AuthContext, error) {
	sess, err := s.sessionStore.Get(r, s.sessionName)
	if err != nil {
		return nil, err
	}
	jsonData, ok := sess.Values[sessionkeys.AuthContext].(string)
	if !ok {
		return nil, ErrNoAuthContext
	}

	var authContext AuthContext
	err = json.Unmarshal([]byte(jsonData), &authContext)
	if err != nil {
		return nil, err
	}
	return &authContext, nil
}

// SaveAuthContext is every step's save after /auth/authorize, and it writes only while the
// browser session still holds the ceremony authContext names (#579). The step loaded its context
// when its request began, and another tab's /auth/authorize may have replaced it since, so the
// session is read afresh, its ceremony compared with this one, and the context written on
// condition nothing wrote the session in between, through ChangeAndSave. Anything else the session
// holds is kept as the fresh read found it, rather than put back as the request read it.
//
// It answers ErrCeremonyReplaced, writing nothing, when the session holds another ceremony, none,
// or is gone: the browser has moved on from this ceremony, and the newer one carries on. Ownership
// is the ceremony id, not the state, so two requests of one ceremony stay last-writer-wins between
// themselves, as a double-submitted consent form needs. An empty stored id is never owned, as
// idMatches refuses it.
func (s *Store) SaveAuthContext(w http.ResponseWriter, r *http.Request, authContext *AuthContext) error {
	jsonData, err := json.Marshal(authContext)
	if err != nil {
		return err
	}

	return s.changeOwnCeremony(w, r, authContext.CeremonyId, func(values map[string]any) {
		values[sessionkeys.AuthContext] = string(jsonData)
	})
}

// changeOwnCeremony applies change to the browser session as it is stored now, only while it holds
// the ceremony named, through ChangeAndSave: the one write SaveAuthContext and ClearAuthContext are
// made with. It answers ErrCeremonyReplaced, having written nothing, when the session holds another
// ceremony, none, or is gone.
func (s *Store) changeOwnCeremony(w http.ResponseWriter, r *http.Request, ceremonyId string,
	change func(values map[string]any)) error {

	sess, err := s.sessionStore.Get(r, s.sessionName)
	if err != nil {
		return err
	}

	isHeld := held(ceremonyId)
	return goneIsReplaced(s.sessionStore.ChangeAndSave(r, w, sess, func(values map[string]any) error {
		if err := isHeld(values); err != nil {
			return err
		}
		change(values)
		return nil
	}))
}

// goneIsReplaced reads a conditional write that found the session this step loaded gone as a
// replaced ceremony: signed out in another tab, rotated away by another request of this browser,
// or expired. Its ceremony is not in the browser's session any more, and the write has not put it
// back (#579 decision 3).
func goneIsReplaced(err error) error {
	if errors.Is(err, sessionstore.ErrNotFound) {
		return errs.Wrap(ErrCeremonyReplaced, "the browser session is gone")
	}
	return err
}

// held is the condition every write of the ceremony named makes on the browser session, applied to
// the session's values as a fresh read found them: nil while they hold that ceremony, and
// ErrCeremonyReplaced when they hold another, none, or a context naming none, since an empty id is
// never held, as idMatches refuses it (#579). A context that does not decode is a fault and
// is returned as one.
func held(ceremonyId string) func(values map[string]any) error {
	return func(values map[string]any) error {
		jsonData, ok := values[sessionkeys.AuthContext].(string)
		if !ok || ceremonyId == "" {
			return errs.WithStack(ErrCeremonyReplaced)
		}
		var stored AuthContext
		if err := json.Unmarshal([]byte(jsonData), &stored); err != nil {
			return errs.Wrap(err, "unable to read the auth context the browser session holds")
		}
		if stored.CeremonyId != ceremonyId {
			return errs.WithStack(ErrCeremonyReplaced)
		}
		return nil
	}
}

// ReplaceAuthContext is /auth/authorize's save. It starts a ceremony, so it replaces whatever the
// browser session held, the session's other values included, as every save did before #579.
func (s *Store) ReplaceAuthContext(w http.ResponseWriter, r *http.Request, authContext *AuthContext) error {
	sess, err := s.sessionStore.Get(r, s.sessionName)
	if err != nil {
		return err
	}

	jsonData, err := json.Marshal(authContext)
	if err != nil {
		return err
	}
	sess.Values[sessionkeys.AuthContext] = string(jsonData)
	return s.sessionStore.Save(r, w, sess)
}

// ClearAuthContext is a step's clear, which ends the ceremony only while the browser session still
// holds it, for SaveAuthContext's reason (#579). It answers ErrCeremonyReplaced, writing nothing, when
// the session holds another ceremony, none, or is gone, and a session never stored is one holding
// none, so the clear of a ceremony the browser does not hold creates no row and no cookie. Anything
// else the session holds is kept as the fresh read found it.
func (s *Store) ClearAuthContext(w http.ResponseWriter, r *http.Request, ceremonyId string) error {
	return s.changeOwnCeremony(w, r, ceremonyId, func(values map[string]any) {
		delete(values, sessionkeys.AuthContext)
	})
}

// DiscardAuthContext is /auth/authorize's clear, before it answers a request it refused at once. It
// ends whatever ceremony the browser session held, without a condition, as /auth/authorize's saves
// replace it. A browser with no stored session holds nothing to end, so nothing is written for it:
// no row holding nothing for the session's lifetime, and no cookie naming one (#579 decision 6).
func (s *Store) DiscardAuthContext(w http.ResponseWriter, r *http.Request) error {
	sess, err := s.sessionStore.Get(r, s.sessionName)
	if err != nil {
		return err
	}
	if sess.ID == "" {
		return nil
	}
	delete(sess.Values, sessionkeys.AuthContext)
	return s.sessionStore.Save(r, w, sess)
}

// RegenerateSession replaces the browser session's identifier, keeping its contents, only while the
// session still holds the ceremony named (#579). The step loaded its context when its request began,
// and another tab's /auth/authorize may have replaced it since, so the session is read afresh, its
// ceremony compared with this one, and the new row written from what that read found; the old row
// is removed on condition nothing wrote it in between, through ChangeAndRegenerate. A rotation from
// the request's own copy put the replaced ceremony back under the new identifier and deleted the row
// holding the newer one.
//
// It answers ErrCeremonyReplaced, having written nothing and set no cookie, when the session holds
// another ceremony, none, or is gone. A gone session is not re-created under a new name: that is
// what would let a stalled step end a newer ceremony that has passed its own rotation meanwhile
// (#579 decision 3).
//
// Handlers reach rotation through here rather than through the store, so the one port that
// names a rotation is this type's and sessionstore.Store stays Get and Save for the
// hundred places that take it (#266, #431).
func (s *Store) RegenerateSession(w http.ResponseWriter, r *http.Request, ceremonyId string) error {
	sess, err := s.sessionStore.Get(r, s.sessionName)
	if err != nil {
		return err
	}

	return goneIsReplaced(s.sessionStore.ChangeAndRegenerate(w, r, sess, held(ceremonyId)))
}

// RegenerateSessionAndBind is RegenerateSession for /auth/completed's create arm: the rotation also
// writes userSessionIdentifier, the user session the arm has just committed, into the browser
// session, so no identifier that existed before the sign-in names the session it produced, and the
// sign-in reaches the browser as one Set-Cookie. A planted identifier would otherwise name the row
// the victim's sign-in fills in (session fixation, #266).
//
// It writes, as RegenerateSession does, only while the browser session still holds the ceremony
// named, and answers ErrCeremonyReplaced, having written nothing and set no cookie, when it holds
// another, none, or is gone (#579 decision 4). The caller then abandons the user session it bound
// nothing to.
func (s *Store) RegenerateSessionAndBind(w http.ResponseWriter, r *http.Request, ceremonyId string,
	userSessionIdentifier string) error {

	sess, err := s.sessionStore.Get(r, s.sessionName)
	if err != nil {
		return err
	}

	isHeld := held(ceremonyId)
	return goneIsReplaced(s.sessionStore.ChangeAndRegenerate(w, r, sess, func(values map[string]any) error {
		if err := isHeld(values); err != nil {
			return err
		}
		values[sessionkeys.SessionIdentifier] = userSessionIdentifier
		return nil
	}))
}

// errCeremonyConfirmed is the refusal ConfirmCeremony's change answers when the session holds its
// ceremony, so the conditional write it reads through writes nothing either way.
var errCeremonyConfirmed = errors.New("the browser session holds this ceremony")

// ConfirmCeremony reads the browser session afresh and answers nil while it holds the ceremony
// named, and ErrCeremonyReplaced when it holds another, none, or is gone. It writes nothing and sets
// no cookie, whatever it answers. /auth/completed's create arm asks it before it ends a foreign
// session or opens the transaction that creates the new one, so a ceremony the browser has
// abandoned ends and creates nothing (#579 decision 4).
//
// The read is ChangeAndSave's fresh read, through a change that refuses in every case, since a
// refused change writes nothing.
func (s *Store) ConfirmCeremony(w http.ResponseWriter, r *http.Request, ceremonyId string) error {
	sess, err := s.sessionStore.Get(r, s.sessionName)
	if err != nil {
		return err
	}

	isHeld := held(ceremonyId)
	err = goneIsReplaced(s.sessionStore.ChangeAndSave(r, w, sess, func(values map[string]any) error {
		if heldErr := isHeld(values); heldErr != nil {
			return heldErr
		}
		return errCeremonyConfirmed
	}))
	if errors.Is(err, errCeremonyConfirmed) {
		return nil
	}
	return err
}

// UILocales is the ui_locales of the ceremony the request's URL names, which the locale middleware
// renders every page in, and of the ceremony the browser most recently wrote when the URL names none
// it holds. It reads the URL's parameter whatever the method and never a form body: the middleware
// runs ahead of every handler, and a step's form posts to the URL its page was loaded with.
func (s *Store) UILocales(r *http.Request) []string {
	authContext, err := s.authContextNamed(r, r.URL.Query().Get(QueryParameter))
	if errors.Is(err, ErrCeremonyNotHeld) {
		authContext, err = s.LatestAuthContext(r)
	}
	if err != nil || authContext == nil || len(authContext.UILocales) == 0 {
		return nil
	}
	return authContext.UILocales
}
