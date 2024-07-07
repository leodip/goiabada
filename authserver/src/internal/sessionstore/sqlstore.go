package sessionstore

import (
	"database/sql"
	"encoding/gob"
	"fmt"
	"net/http"
	"time"

	"github.com/leodip/goiabada/internal/data"
	"github.com/leodip/goiabada/internal/models"
	"github.com/pkg/errors"

	"log/slog"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
)

type SQLStore struct {
	db data.Database

	Codecs  []securecookie.Codec
	Options *sessions.Options
}

func init() {
	gob.Register(time.Time{})
}

func NewSQLStore(db data.Database, path string, maxAge int, httpOnly bool,
	secure bool, sameSite http.SameSite, keyPairs ...[]byte) *SQLStore {

	codecs := securecookie.CodecsFromPairs(keyPairs...)
	for _, codec := range codecs {
		if sc, ok := codec.(*securecookie.SecureCookie); ok {
			sc.MaxLength(1024 * 64) // 64k
		}
	}

	return &SQLStore{
		db:     db,
		Codecs: codecs,
		Options: &sessions.Options{
			Path:     path,
			MaxAge:   maxAge,
			HttpOnly: httpOnly,
			Secure:   secure,
			SameSite: sameSite,
		},
	}
}

func (store *SQLStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	return sessions.GetRegistry(r).Get(store, name)
}

func (store *SQLStore) New(r *http.Request, name string) (*sessions.Session, error) {
	session := sessions.NewSession(store, name)
	session.Options = &sessions.Options{
		Path:     store.Options.Path,
		Domain:   store.Options.Domain,
		MaxAge:   store.Options.MaxAge,
		Secure:   store.Options.Secure,
		HttpOnly: store.Options.HttpOnly,
		SameSite: store.Options.SameSite,
	}
	session.IsNew = true
	var err error
	if cook, errCookie := r.Cookie(name); errCookie == nil {
		err = securecookie.DecodeMulti(name, cook.Value, &session.ID, store.Codecs...)
		if err == nil {
			err = store.load(session)
			if err == nil {
				session.IsNew = false
			} else {
				err = nil
			}
		}
	}
	return session, err
}

func (store *SQLStore) Save(r *http.Request, w http.ResponseWriter, session *sessions.Session) error {
	var err error
	if session.ID == "" {
		if err = store.insert(session); err != nil {
			return err
		}
	} else if err = store.save(session); err != nil {
		return err
	}
	encoded, err := securecookie.EncodeMulti(session.Name(), session.ID, store.Codecs...)
	if err != nil {
		return err
	}
	http.SetCookie(w, sessions.NewCookie(session.Name(), encoded, session.Options))
	return nil
}

func (store *SQLStore) insert(session *sessions.Session) error {
	var createdOn time.Time
	var modifiedOn time.Time
	var expiresOn time.Time
	crOn := session.Values["created_on"]
	now := time.Now().UTC()
	if crOn == nil {
		createdOn = now
	} else {
		createdOn = crOn.(time.Time)
	}
	modifiedOn = createdOn
	exOn := session.Values["expires_on"]
	if exOn == nil {
		expiresOn = now.Add(time.Second * time.Duration(session.Options.MaxAge))
	} else {
		expiresOn = exOn.(time.Time)
	}
	delete(session.Values, "created_on")
	delete(session.Values, "expires_on")
	delete(session.Values, "modified_on")

	encoded, encErr := securecookie.EncodeMulti(session.Name(), session.Values, store.Codecs...)
	if encErr != nil {
		return encErr
	}

	sess := models.HttpSession{
		Data:      encoded,
		CreatedAt: sql.NullTime{Time: createdOn, Valid: true},
		UpdatedAt: sql.NullTime{Time: modifiedOn, Valid: true},
		ExpiresOn: sql.NullTime{Time: expiresOn, Valid: true},
	}
	err := store.db.CreateHttpSession(nil, &sess)
	if err != nil {
		return err
	}
	session.ID = fmt.Sprintf("%d", sess.Id)
	return nil
}

func (store *SQLStore) Delete(w http.ResponseWriter, session *sessions.Session) error {

	// Set cookie to expire.
	options := *session.Options
	options.MaxAge = -1
	http.SetCookie(w, sessions.NewCookie(session.Name(), "", &options))
	// Clear session values.
	for k := range session.Values {
		delete(session.Values, k)
	}

	sessIDint, err := parseSessionID(session.ID)
	if err != nil {
		return err
	}
	err = store.db.DeleteHttpSession(nil, sessIDint)
	if err != nil {
		return err
	}
	return nil
}

func parseSessionID(sessionID string) (int64, error) {
	var sessIDint int64
	n, err := fmt.Sscanf(sessionID, "%d", &sessIDint)
	if err != nil {
		return 0, errors.Wrapf(err, "unable to parse session ID: %s", sessionID)
	} else if n != 1 {
		return 0, errors.WithStack(fmt.Errorf("unable to parse session ID: %s", sessionID))
	}
	return sessIDint, nil
}

func (store *SQLStore) save(session *sessions.Session) error {
	if session.IsNew {
		return store.insert(session)
	}
	var createdOn time.Time
	var expiresOn time.Time
	now := time.Now().UTC()
	crOn := session.Values["created_on"]
	if crOn == nil {
		createdOn = now
	} else {
		createdOn = crOn.(time.Time)
	}

	exOn := session.Values["expires_on"]
	if exOn == nil {
		expiresOn = now.Add(time.Second * time.Duration(session.Options.MaxAge))
	} else {
		expiresOn = exOn.(time.Time)
		if expiresOn.Sub(now.Add(time.Second*time.Duration(session.Options.MaxAge))) < 0 {
			expiresOn = now.Add(time.Second * time.Duration(session.Options.MaxAge))
		}
	}

	delete(session.Values, "created_on")
	delete(session.Values, "expires_on")
	delete(session.Values, "modified_on")
	encoded, encErr := securecookie.EncodeMulti(session.Name(), session.Values, store.Codecs...)
	if encErr != nil {
		return encErr
	}

	sessIDint, err := parseSessionID(session.ID)
	if err != nil {
		return err
	}

	sess := models.HttpSession{
		Id:        sessIDint,
		Data:      encoded,
		CreatedAt: sql.NullTime{Time: createdOn, Valid: true},
		UpdatedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true},
		ExpiresOn: sql.NullTime{Time: expiresOn, Valid: true},
	}
	err = store.db.UpdateHttpSession(nil, &sess)
	if err != nil {
		return err
	}
	return nil
}

func (store *SQLStore) load(session *sessions.Session) error {
	sessIDint, err := parseSessionID(session.ID)
	if err != nil {
		return err
	}
	var sess *models.HttpSession
	sess, err = store.db.GetHttpSessionById(nil, sessIDint)
	if err != nil {
		return err
	} else if sess == nil {
		return errors.WithStack(errors.New("session not found"))
	}

	if time.Until(sess.ExpiresOn.Time) < 0 {
		return errors.WithStack(errors.New("session expired"))
	}
	err = securecookie.DecodeMulti(session.Name(), sess.Data, &session.Values, store.Codecs...)
	if err != nil {
		return err
	}
	session.Values["created_on"] = sess.CreatedAt.Time
	session.Values["modified_on"] = sess.UpdatedAt.Time
	session.Values["expires_on"] = sess.ExpiresOn.Time
	return nil
}

var defaultInterval = time.Minute * 5

// Cleanup runs a background goroutine every interval that deletes expired
// sessions from the database.
//
// The design is based on https://github.com/yosssi/boltstore
func (store *SQLStore) Cleanup(interval time.Duration) (chan<- struct{}, <-chan struct{}) {
	if interval <= 0 {
		interval = defaultInterval
	}

	quit, done := make(chan struct{}), make(chan struct{})
	go store.cleanup(interval, quit, done)
	return quit, done
}

// StopCleanup stops the background cleanup from running.
func (store *SQLStore) StopCleanup(quit chan<- struct{}, done <-chan struct{}) {
	quit <- struct{}{}
	<-done
}

// cleanup deletes expired sessions at set intervals.
func (store *SQLStore) cleanup(interval time.Duration, quit <-chan struct{}, done chan<- struct{}) {
	ticker := time.NewTicker(interval)

	defer func() {
		ticker.Stop()
	}()

	for {
		select {
		case <-quit:
			// Handle the quit signal.
			done <- struct{}{}
			return
		case <-ticker.C:
			// Delete expired sessions on each tick.
			err := store.deleteExpired()
			if err != nil {
				slog.Warn("SQLStore: unable to delete expired sessions", slog.String("error", err.Error()))
			}
		}
	}
}

// deleteExpired deletes expired sessions from the database.
func (store *SQLStore) deleteExpired() error {
	err := store.db.DeleteHttpSessionExpired(nil)
	if err != nil {
		return err
	}
	return nil
}
