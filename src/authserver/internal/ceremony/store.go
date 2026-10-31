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

// MaxHeldCeremonies is how many sign-ins a browser session holds at once. A sixth pushes out the one
// least recently written, so a sign-in the user is moving through outlives the tabs they abandoned,
// and a page sending the browser to sign in again and again pushes the user's sign-in out only by
// starting this many of its own (#246 decision 2).
const MaxHeldCeremonies = 5

// Store keeps a browser's sign-ins in progress in the server-side session, each an AuthContext,
// under sessionkeys.AuthContexts, up to MaxHeldCeremonies of them, between the hops of each
// authorization ceremony. Every reader reads the ceremony the request names (GetAuthContext,
// UILocales), and every write names the ceremony it writes and changes no other, so two sign-ins of
// one browser each finish on their own (#246). It was handlerhelpers.AuthHelper until #435 moved it
// beside the type it persists; the handlers reach it through their CeremonyStore port, and
// server.go's locale middleware through UILocales.
//
// The held ceremonies are stored least recently written first: an add puts its ceremony last, a
// save moves its ceremony last, and an add that makes one too many removes the first. A rotation,
// the instant a user's password or code is accepted or a session bound to them, removes every
// ceremony held for another user (heldRotation). Every write also removes
// sessionkeys.RetiredAuthContext, which nothing reads (#246 decision 3).
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
// names, and ErrCeremonyNotHeld when it holds ceremonies but not the one named, or the request names
// none.
func (s *Store) GetAuthContext(r *http.Request) (*AuthContext, error) {
	return s.authContextNamed(r, RequestedId(r))
}

// authContextNamed reads the ceremony the browser session holds under ceremonyId: ErrNoAuthContext
// when it holds none, and ErrCeremonyNotHeld when it holds others, or contexts naming none, since an
// empty id is never held (idMatches).
func (s *Store) authContextNamed(r *http.Request, ceremonyId string) (*AuthContext, error) {
	held, err := s.heldNow(r)
	if err != nil {
		return nil, err
	}
	if len(held) == 0 {
		return nil, ErrNoAuthContext
	}
	i := indexOf(held, ceremonyId)
	if i < 0 {
		return nil, errs.WithStack(ErrCeremonyNotHeld)
	}
	return &held[i], nil
}

// LatestAuthContext reads the ceremony the browser most recently wrote, whichever one the request
// names. It answers ErrNoAuthContext when the session holds none. The ceremony mismatch audit event
// records it, and a page's ui_locales and sign-in user fall back to it when the URL names no ceremony
// the browser holds.
func (s *Store) LatestAuthContext(r *http.Request) (*AuthContext, error) {
	held, err := s.heldNow(r)
	if err != nil {
		return nil, err
	}
	if len(held) == 0 {
		return nil, ErrNoAuthContext
	}
	return &held[len(held)-1], nil
}

// heldNow is the ceremonies the browser session holds as the request read it.
func (s *Store) heldNow(r *http.Request) ([]AuthContext, error) {
	sess, err := s.sessionStore.Get(r, s.sessionName)
	if err != nil {
		return nil, err
	}
	return heldIn(sess.Values)
}

// heldIn decodes the ceremonies values hold, least recently written first, and none when they hold
// none. A list that is there but does not decode is a fault and is returned as one.
func heldIn(values map[string]any) ([]AuthContext, error) {
	jsonData, ok := values[sessionkeys.AuthContexts].(string)
	if !ok {
		return nil, nil
	}
	var held []AuthContext
	if err := json.Unmarshal([]byte(jsonData), &held); err != nil {
		return nil, errs.Wrap(err, "unable to read the sign-ins the browser session holds")
	}
	return held, nil
}

// putHeld writes held into values, least recently written first, and removes the key before #246's,
// which every write of the store does (#246 decision 3). A session left holding no ceremony has no
// key for them.
func putHeld(values map[string]any, held []AuthContext) error {
	delete(values, sessionkeys.RetiredAuthContext)
	if len(held) == 0 {
		delete(values, sessionkeys.AuthContexts)
		return nil
	}
	jsonData, err := json.Marshal(held)
	if err != nil {
		return err
	}
	values[sessionkeys.AuthContexts] = string(jsonData)
	return nil
}

// indexOf is where held holds the ceremony ceremonyId names, and -1 when it holds none by that id.
// An empty id is never held, as idMatches refuses it.
func indexOf(held []AuthContext, ceremonyId string) int {
	for i := range held {
		if idMatches(held[i].CeremonyId, ceremonyId) {
			return i
		}
	}
	return -1
}

// without is held less the ceremony at i, in the same order.
func without(held []AuthContext, i int) []AuthContext {
	return append(held[:i:i], held[i+1:]...)
}

// SaveAuthContext is every step's save after /auth/authorize, and it writes only while the
// browser session still holds the ceremony authContext names (#579). The step loaded its context
// when its request began, and since then another tab's step may have ended it, five newer sign-ins
// may have pushed it out, or the browser may have signed out, so the session is read afresh, the
// ceremony looked for in what it holds, and the context written on condition nothing wrote the
// session in between, through ChangeAndSave. Every other ceremony, and anything else the session
// holds, is kept as the fresh read found it, rather than put back as the request read it. The saved
// ceremony becomes the most recently written (#246 decision 2).
//
// It answers ErrCeremonyReplaced, writing nothing, when the session no longer holds the ceremony, or
// is gone. Ownership is the ceremony id, not the state, so two requests of one ceremony stay
// last-writer-wins between themselves, as a double-submitted consent form needs. An empty id is
// never held, as idMatches refuses it.
func (s *Store) SaveAuthContext(w http.ResponseWriter, r *http.Request, authContext *AuthContext) error {
	return s.changeOwnCeremony(w, r, authContext.CeremonyId, func(held []AuthContext, i int) []AuthContext {
		return append(without(held, i), *authContext)
	})
}

// errNoRecoveryCodesHeld is the refusal TakeRecoveryCodes's change answers when the ceremony, as
// stored now, holds no set, so the conditional write it is made through writes nothing.
var errNoRecoveryCodesHeld = errors.New("the ceremony holds no recovery codes")

// TakeRecoveryCodes takes the set of recovery codes off the ceremony named, as the browser session
// stores it now, and answers the set taken: the one write the sign-in setup's codes page shows a set
// after (#257 decision 14). The fresh read and the clearing write are one conditional write, through
// ChangeAndSave, so of two requests that loaded the ceremony while it held the set, only the one
// whose write lands takes it, and the other finds it gone and answers none. A step's save is
// last-writer-wins between two requests of one ceremony (SaveAuthContext), which would let both show
// the set they loaded.
//
// Only the set changes: the ceremony is kept as the fresh read found it, made the most recently
// written. It answers no set, writing nothing, when the ceremony holds none, and
// ErrCeremonyReplaced, writing nothing, when the session no longer holds the ceremony, or is gone.
func (s *Store) TakeRecoveryCodes(w http.ResponseWriter, r *http.Request, ceremonyId string) ([]string, error) {
	var taken []string
	err := s.changeOwnCeremonyRefusable(w, r, ceremonyId, func(held []AuthContext, i int) ([]AuthContext, error) {
		// ChangeAndSave applies the change again on each attempt, to that attempt's read, so the
		// set is the one the attempt whose write lands found.
		taken = nil
		own := held[i]
		if len(own.RecoveryCodes) == 0 {
			return nil, errNoRecoveryCodesHeld
		}
		taken = own.RecoveryCodes
		own.RecoveryCodes = nil
		return append(without(held, i), own), nil
	})
	if errors.Is(err, errNoRecoveryCodesHeld) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return taken, nil
}

// changeOwnCeremony applies change to the ceremonies the browser session holds as it is stored now,
// only while it holds the ceremony named, through ChangeAndSave: the one write SaveAuthContext and
// ClearAuthContext are made with. change is handed the held ceremonies, least recently written
// first, and where the one named is, and answers the ceremonies to store. It answers
// ErrCeremonyReplaced, having written nothing, when the session does not hold the ceremony, or is
// gone.
func (s *Store) changeOwnCeremony(w http.ResponseWriter, r *http.Request, ceremonyId string,
	change func(held []AuthContext, i int) []AuthContext) error {

	return s.changeOwnCeremonyRefusable(w, r, ceremonyId, func(held []AuthContext, i int) ([]AuthContext, error) {
		return change(held, i), nil
	})
}

// changeOwnCeremonyRefusable is changeOwnCeremony for a change that can refuse the write: an error
// from change writes nothing and is returned as it is.
func (s *Store) changeOwnCeremonyRefusable(w http.ResponseWriter, r *http.Request, ceremonyId string,
	change func(held []AuthContext, i int) ([]AuthContext, error)) error {

	sess, err := s.sessionStore.Get(r, s.sessionName)
	if err != nil {
		return err
	}

	return goneIsReplaced(s.sessionStore.ChangeAndSave(r, w, sess, func(values map[string]any) error {
		ceremonies, readErr := heldIn(values)
		if readErr != nil {
			return readErr
		}
		i := indexOf(ceremonies, ceremonyId)
		if i < 0 {
			return errs.WithStack(ErrCeremonyReplaced)
		}
		changed, changeErr := change(ceremonies, i)
		if changeErr != nil {
			return changeErr
		}
		return putHeld(values, changed)
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

// heldRotation is the change every rotation of the ceremony named makes to the browser session,
// applied to the session's values as a fresh read found them: ErrCeremonyReplaced when they do not
// hold that ceremony, and otherwise the removal of every other ceremony held for a user other than
// userId, the user the rotation is for, and of the key before #246's, since a rotation is a write of
// the session (#246 decision 3). It moves no ceremony and changes none it keeps. A list that does not
// decode is a fault and is returned as one.
//
// A rotation is a privilege change: a password or a code has just been accepted for userId in this
// browser, or a session is being bound to them. A ceremony another user verified a password in and
// walked away from would otherwise ride along into this user's session, outliving the pre-sign-in
// lifetime it was stored under, and whoever used the browser next could finish it as that user: scan
// the code its enrolment shows, enter it, and be signed in as them (#246). A ceremony naming no user
// carries no credential and is kept, as are this user's own.
func heldRotation(ceremonyId string, userId int64) func(values map[string]any) error {
	return func(values map[string]any) error {
		ceremonies, err := heldIn(values)
		if err != nil {
			return err
		}
		own := indexOf(ceremonies, ceremonyId)
		if own < 0 {
			return errs.WithStack(ErrCeremonyReplaced)
		}
		kept := make([]AuthContext, 0, len(ceremonies))
		for i, c := range ceremonies {
			if i == own || c.UserId == 0 || c.UserId == userId {
				kept = append(kept, c)
			}
		}
		return putHeld(values, kept)
	}
}

// holds is the condition every write of the ceremony named makes on the browser session, applied to
// the session's values as a fresh read found them: nil while they hold that ceremony among the
// others, and ErrCeremonyReplaced when they do not, or name none, since an empty id is never held,
// as idMatches refuses it (#579). A list that does not decode is a fault and is returned as one.
func holds(ceremonyId string) func(values map[string]any) error {
	return func(values map[string]any) error {
		ceremonies, err := heldIn(values)
		if err != nil {
			return err
		}
		if indexOf(ceremonies, ceremonyId) < 0 {
			return errs.WithStack(ErrCeremonyReplaced)
		}
		return nil
	}
}

// AddAuthContext is /auth/authorize's save. It starts a ceremony beside the ones the browser session
// holds, as the most recently written, and when that makes one too many it removes the one least
// recently written (#246 decisions 1 and 2). Like a step's write, it is applied to the session as it
// is stored now and written on condition nothing wrote it in between, so a step's save or rotation
// that lands meanwhile is kept.
//
// A session the request loaded that is gone by then, signed out in another tab or expired, is not
// put back: the new ceremony is stored as in a browser holding none, in a new session holding it
// alone.
func (s *Store) AddAuthContext(w http.ResponseWriter, r *http.Request, authContext *AuthContext) error {
	sess, err := s.sessionStore.Get(r, s.sessionName)
	if err != nil {
		return err
	}

	add := func(values map[string]any) error {
		ceremonies, readErr := heldIn(values)
		if readErr != nil {
			return readErr
		}
		if i := indexOf(ceremonies, authContext.CeremonyId); i >= 0 {
			ceremonies = without(ceremonies, i)
		}
		ceremonies = append(ceremonies, *authContext)
		if len(ceremonies) > MaxHeldCeremonies {
			ceremonies = ceremonies[len(ceremonies)-MaxHeldCeremonies:]
		}
		return putHeld(values, ceremonies)
	}

	err = s.sessionStore.ChangeAndSave(r, w, sess, add)
	if errors.Is(err, sessionstore.ErrNotFound) {
		// A session with no identifier is one never stored, which ChangeAndSave creates from empty
		// values under a new identifier, as for a browser that arrived holding none.
		sess.ID = ""
		sess.Values = make(map[string]any)
		return s.sessionStore.ChangeAndSave(r, w, sess, add)
	}
	return err
}

// ClearAuthContext is a step's clear, which ends the ceremony only while the browser session still
// holds it, for SaveAuthContext's reason (#579), and ends no other. It answers ErrCeremonyReplaced,
// writing nothing, when the session does not hold it, or is gone, and a session never stored is one
// holding none, so the clear of a ceremony the browser does not hold creates no row and no cookie.
// Every other ceremony, and anything else the session holds, is kept as the fresh read found it.
func (s *Store) ClearAuthContext(w http.ResponseWriter, r *http.Request, ceremonyId string) error {
	return s.changeOwnCeremony(w, r, ceremonyId, without)
}

// RegenerateSession replaces the browser session's identifier, keeping its contents, every held
// ceremony among them but those held for a user other than userId, the user whose password or code
// the step has just accepted (heldRotation), only while the session still holds the ceremony named
// (#579). The step loaded its context when its request began, and the ceremony may have ended or been
// pushed out since, so the session is read afresh, the ceremony looked for in what it holds, and the
// new row written from what that read found; the old row is removed on condition nothing wrote it in
// between, through ChangeAndRegenerate. A rotation from the request's own copy put an ended ceremony
// back under the new identifier and deleted the row holding the newer ones.
//
// It answers ErrCeremonyReplaced, having written nothing and set no cookie, when the session does
// not hold the ceremony, or is gone. A gone session is not re-created under a new name: that is
// what would let a stalled step end a newer ceremony that has passed its own rotation meanwhile
// (#579 decision 3).
//
// Handlers reach rotation through here rather than through the store, so the one port that
// names a rotation is this type's and sessionstore.Store stays Get and Save for the
// hundred places that take it (#266, #431).
func (s *Store) RegenerateSession(w http.ResponseWriter, r *http.Request, ceremonyId string, userId int64) error {
	sess, err := s.sessionStore.Get(r, s.sessionName)
	if err != nil {
		return err
	}

	return goneIsReplaced(s.sessionStore.ChangeAndRegenerate(w, r, sess, heldRotation(ceremonyId, userId)))
}

// RegenerateSessionAndBind is RegenerateSession for /auth/completed's create arm: the rotation also
// writes userSessionIdentifier, the user session the arm has just committed, into the browser
// session, so no identifier that existed before the sign-in names the session it produced, and the
// sign-in reaches the browser as one Set-Cookie. A planted identifier would otherwise name the row
// the victim's sign-in fills in (session fixation, #266).
//
// It keeps, as RegenerateSession does, no ceremony held for a user other than userId, the user the
// session is bound to, and writes only while the browser session still holds the ceremony named,
// answering ErrCeremonyReplaced, having written nothing and set no cookie, when it does not, or is
// gone (#579 decision 4). The caller then abandons the user session it bound nothing to.
func (s *Store) RegenerateSessionAndBind(w http.ResponseWriter, r *http.Request, ceremonyId string,
	userId int64, userSessionIdentifier string) error {

	sess, err := s.sessionStore.Get(r, s.sessionName)
	if err != nil {
		return err
	}

	rotation := heldRotation(ceremonyId, userId)
	return goneIsReplaced(s.sessionStore.ChangeAndRegenerate(w, r, sess, func(values map[string]any) error {
		if err := rotation(values); err != nil {
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
// named, and ErrCeremonyReplaced when it does not, or is gone. It writes nothing and sets no cookie,
// whatever it answers. /auth/completed's create arm asks it before it ends a foreign session or
// opens the transaction that creates the new one, so a ceremony the browser has abandoned ends and
// creates nothing (#579 decision 4).
//
// The read is ChangeAndSave's fresh read, through a change that refuses in every case, since a
// refused change writes nothing.
func (s *Store) ConfirmCeremony(w http.ResponseWriter, r *http.Request, ceremonyId string) error {
	sess, err := s.sessionStore.Get(r, s.sessionName)
	if err != nil {
		return err
	}

	isHeld := holds(ceremonyId)
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

// UILocales is the ui_locales of the ceremony the page belongs to (pageAuthContext), which the locale
// middleware renders every page in.
func (s *Store) UILocales(r *http.Request) []string {
	authContext := s.pageAuthContext(r)
	if authContext == nil || len(authContext.UILocales) == 0 {
		return nil
	}
	return authContext.UILocales
}

// SignInUserId is the user of the sign-in the page belongs to (pageAuthContext) once it knows one:
// once it has verified the password (RecordPasswordVerified) or adopted a session (AdoptSession).
// It is zero before then, and when the page belongs to no sign-in. A user's page language then wins
// over the ceremony's ui_locales on that page (#631 decision 5), being the person signing in now.
func (s *Store) SignInUserId(r *http.Request) int64 {
	authContext := s.pageAuthContext(r)
	if authContext == nil {
		return 0
	}
	return authContext.UserId
}

// pageAuthContext is the ceremony a page belongs to: the one the request's URL names, and the one the
// browser most recently wrote when the URL names none it holds. It reads the URL's parameter
// whatever the method and never a form body: the page-language middleware runs ahead of every
// handler, and a step's form posts to the URL its page was loaded with. Nil when the browser holds no
// ceremony, or its session cannot be read.
func (s *Store) pageAuthContext(r *http.Request) *AuthContext {
	authContext, err := s.authContextNamed(r, r.URL.Query().Get(QueryParameter))
	if errors.Is(err, ErrCeremonyNotHeld) {
		authContext, err = s.LatestAuthContext(r)
	}
	if err != nil {
		return nil
	}
	return authContext
}
