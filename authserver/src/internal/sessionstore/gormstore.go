package sessionstore

import (
	"encoding/gob"
	"fmt"
	"net/http"
	"time"

	"github.com/leodip/goiabada/internal/entities"
	"github.com/pkg/errors"
	"gorm.io/gorm"

	"log/slog"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
)

type GORMStore struct {
	gormDB *gorm.DB

	Codecs  []securecookie.Codec
	Options *sessions.Options
}

func init() {
	gob.Register(time.Time{})
}

func NewGORMStoreFromConnection(gormDB *gorm.DB, path string, maxAge int, httpOnly bool,
	secure bool, sameSite http.SameSite, keyPairs ...[]byte) (*GORMStore, error) {

	codecs := securecookie.CodecsFromPairs(keyPairs...)
	for _, codec := range codecs {
		if sc, ok := codec.(*securecookie.SecureCookie); ok {
			sc.MaxLength(1024 * 64) // 64k
		}
	}

	return &GORMStore{
		gormDB: gormDB,
		Codecs: codecs,
		Options: &sessions.Options{
			Path:     path,
			MaxAge:   maxAge,
			HttpOnly: httpOnly,
			Secure:   secure,
			SameSite: sameSite,
		},
	}, nil
}

func (g *GORMStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	return sessions.GetRegistry(r).Get(g, name)
}

func (g *GORMStore) New(r *http.Request, name string) (*sessions.Session, error) {
	session := sessions.NewSession(g, name)
	session.Options = &sessions.Options{
		Path:     g.Options.Path,
		Domain:   g.Options.Domain,
		MaxAge:   g.Options.MaxAge,
		Secure:   g.Options.Secure,
		HttpOnly: g.Options.HttpOnly,
		SameSite: g.Options.SameSite,
	}
	session.IsNew = true
	var err error
	if cook, errCookie := r.Cookie(name); errCookie == nil {
		err = securecookie.DecodeMulti(name, cook.Value, &session.ID, g.Codecs...)
		if err == nil {
			err = g.load(session)
			if err == nil {
				session.IsNew = false
			} else {
				err = nil
			}
		}
	}
	return session, err
}

func (g *GORMStore) Save(r *http.Request, w http.ResponseWriter, session *sessions.Session) error {
	var err error
	if session.ID == "" {
		if err = g.insert(session); err != nil {
			return err
		}
	} else if err = g.save(session); err != nil {
		return err
	}
	encoded, err := securecookie.EncodeMulti(session.Name(), session.ID, g.Codecs...)
	if err != nil {
		return err
	}
	http.SetCookie(w, sessions.NewCookie(session.Name(), encoded, session.Options))
	return nil
}

func (g *GORMStore) insert(session *sessions.Session) error {
	var createdOn time.Time
	var modifiedOn time.Time
	var expiresOn time.Time
	crOn := session.Values["created_on"]
	if crOn == nil {
		createdOn = time.Now()
	} else {
		createdOn = crOn.(time.Time)
	}
	modifiedOn = createdOn
	exOn := session.Values["expires_on"]
	if exOn == nil {
		expiresOn = time.Now().Add(time.Second * time.Duration(session.Options.MaxAge))
	} else {
		expiresOn = exOn.(time.Time)
	}
	delete(session.Values, "created_on")
	delete(session.Values, "expires_on")
	delete(session.Values, "modified_on")

	encoded, encErr := securecookie.EncodeMulti(session.Name(), session.Values, g.Codecs...)
	if encErr != nil {
		return encErr
	}

	sess := entities.HttpSession{
		Data:      encoded,
		CreatedAt: createdOn,
		UpdatedAt: modifiedOn,
		ExpiresOn: expiresOn,
	}
	res := g.gormDB.Create(&sess)
	if res.Error != nil {
		return errors.Wrap(res.Error, res.Error.Error())
	} else if res.RowsAffected == 0 {
		return errors.New("no rows affected")
	}
	session.ID = fmt.Sprintf("%d", sess.Id)
	return nil
}

func (g *GORMStore) Delete(r *http.Request, w http.ResponseWriter, session *sessions.Session) error {

	// Set cookie to expire.
	options := *session.Options
	options.MaxAge = -1
	http.SetCookie(w, sessions.NewCookie(session.Name(), "", &options))
	// Clear session values.
	for k := range session.Values {
		delete(session.Values, k)
	}

	sessIDUint, err := parseSessionID(session.ID)
	if err != nil {
		return err
	}
	res := g.gormDB.Delete(&entities.HttpSession{}, sessIDUint)
	if res.Error != nil {
		return errors.Wrap(res.Error, res.Error.Error())
	}
	return nil
}

func parseSessionID(sessionID string) (uint, error) {
	var sessIDUint uint
	n, err := fmt.Sscanf(sessionID, "%d", &sessIDUint)
	if err != nil {
		return 0, errors.Wrapf(err, "unable to parse session ID: %s", sessionID)
	} else if n != 1 {
		return 0, fmt.Errorf("unable to parse session ID: %s", sessionID)
	}
	return sessIDUint, nil
}

func (g *GORMStore) save(session *sessions.Session) error {
	if session.IsNew {
		return g.insert(session)
	}
	var createdOn time.Time
	var expiresOn time.Time
	crOn := session.Values["created_on"]
	if crOn == nil {
		createdOn = time.Now()
	} else {
		createdOn = crOn.(time.Time)
	}

	exOn := session.Values["expires_on"]
	if exOn == nil {
		expiresOn = time.Now().Add(time.Second * time.Duration(session.Options.MaxAge))
	} else {
		expiresOn = exOn.(time.Time)
		if expiresOn.Sub(time.Now().Add(time.Second*time.Duration(session.Options.MaxAge))) < 0 {
			expiresOn = time.Now().Add(time.Second * time.Duration(session.Options.MaxAge))
		}
	}

	delete(session.Values, "created_on")
	delete(session.Values, "expires_on")
	delete(session.Values, "modified_on")
	encoded, encErr := securecookie.EncodeMulti(session.Name(), session.Values, g.Codecs...)
	if encErr != nil {
		return encErr
	}

	sessIDUint, err := parseSessionID(session.ID)
	if err != nil {
		return err
	}

	sess := entities.HttpSession{
		Id:        sessIDUint,
		Data:      encoded,
		CreatedAt: createdOn,
		UpdatedAt: time.Now(),
		ExpiresOn: expiresOn,
	}
	res := g.gormDB.Save(&sess)
	if res.Error != nil {
		return errors.Wrap(res.Error, res.Error.Error())
	} else if res.RowsAffected != 1 {
		return fmt.Errorf("not only one rows affected: %d", res.RowsAffected)
	}
	return nil
}

func (g *GORMStore) load(session *sessions.Session) error {
	sessIDUint, err := parseSessionID(session.ID)
	if err != nil {
		return err
	}
	var sess entities.HttpSession
	res := g.gormDB.First(&sess, sessIDUint)
	if res.Error != nil {
		return errors.Wrap(res.Error, res.Error.Error())
	} else if res.RowsAffected != 1 {
		return fmt.Errorf("not only one rows affected: %d", res.RowsAffected)
	}

	if time.Until(sess.ExpiresOn) < 0 {
		return errors.New("session expired")
	}
	err = securecookie.DecodeMulti(session.Name(), sess.Data, &session.Values, g.Codecs...)
	if err != nil {
		return err
	}
	session.Values["created_on"] = sess.CreatedAt
	session.Values["modified_on"] = sess.UpdatedAt
	session.Values["expires_on"] = sess.ExpiresOn
	return nil
}

var defaultInterval = time.Minute * 5

// Cleanup runs a background goroutine every interval that deletes expired
// sessions from the database.
//
// The design is based on https://github.com/yosssi/boltstore
func (g *GORMStore) Cleanup(interval time.Duration) (chan<- struct{}, <-chan struct{}) {
	if interval <= 0 {
		interval = defaultInterval
	}

	quit, done := make(chan struct{}), make(chan struct{})
	go g.cleanup(interval, quit, done)
	return quit, done
}

// StopCleanup stops the background cleanup from running.
func (g *GORMStore) StopCleanup(quit chan<- struct{}, done <-chan struct{}) {
	quit <- struct{}{}
	<-done
}

// cleanup deletes expired sessions at set intervals.
func (g *GORMStore) cleanup(interval time.Duration, quit <-chan struct{}, done chan<- struct{}) {
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
			err := g.deleteExpired()
			if err != nil {
				slog.Warn("GORMStore: unable to delete expired sessions: %v", err)
			}
		}
	}
}

// deleteExpired deletes expired sessions from the database.
func (g *GORMStore) deleteExpired() error {
	res := g.gormDB.Delete(&entities.HttpSession{}, "expires_on < ?", time.Now())
	if res.Error != nil {
		return errors.Wrap(res.Error, res.Error.Error())
	}
	return nil
}
