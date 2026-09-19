package sessionbackend

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/leodip/goiabada/authserver/internal/constants"
	"github.com/leodip/goiabada/authserver/internal/data"
	coreconstants "github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/sessionstore"
)

// dbBackend keeps browser sessions in the database this deployment already runs. It is
// what the auth server uses directly, and it is also what the session endpoint runs on
// behalf of the admin console.
type dbBackend struct {
	database data.Database
	owner    string
	now      func() time.Time
}

// NewAuthServerBackend returns a database backend scoped to the auth server's rows.
func NewAuthServerBackend(database data.Database) sessionstore.Backend {
	return newBackend(database, constants.AuthServerSessionName)
}

// NewAdminConsoleBackend returns a database backend scoped to the admin console's rows.
//
// One table holds both applications' sessions, and the owner is all that keeps them
// apart. Fixing it in these constructors rather than accepting it from a caller makes
// it impossible for the session endpoint to select the auth server's rows (#334).
func NewAdminConsoleBackend(database data.Database) sessionstore.Backend {
	return newBackend(database, coreconstants.AdminConsoleSessionName)
}

func newBackend(database data.Database, owner string) *dbBackend {
	return &dbBackend{
		database: database,
		owner:    owner,
		now:      func() time.Time { return time.Now().UTC() },
	}
}

func (b *dbBackend) Load(ctx context.Context, id string) (*sessionstore.Record, error) {
	browserSession, err := b.database.GetBrowserSessionByOwnerAndSessionIdHash(nil, b.owner,
		hashSessionId(id), b.now())
	if err != nil {
		return nil, errs.Wrap(err, "unable to read the browser session")
	}
	if browserSession == nil {
		return nil, sessionstore.ErrNotFound
	}

	return &sessionstore.Record{
		Data:         []byte(browserSession.Data),
		LastAccessed: browserSession.LastAccessed,
		ExpiresAt:    browserSession.ExpiresAt,
	}, nil
}

func (b *dbBackend) Create(ctx context.Context, id string, data []byte, authenticated bool) (time.Time, error) {
	now := b.now()

	idleTimeout, maxLifetime, err := b.lifetimes(ctx)
	if err != nil {
		return time.Time{}, err
	}

	// A row being created now was created now, so the absolute deadline is measured
	// from this instant without reading anything back.
	expiresAt := sessionstore.ExpiresAt(now, now, authenticated, idleTimeout, maxLifetime)

	browserSession := &models.BrowserSession{
		Owner:         b.owner,
		SessionId:     id,
		SessionIdHash: hashSessionId(id),
		Data:          string(data),
		LastAccessed:  now,
		ExpiresAt:     expiresAt,
	}

	if err := b.database.CreateBrowserSession(nil, browserSession); err != nil {
		return time.Time{}, errs.Wrap(err, "unable to create the browser session")
	}

	return expiresAt, nil
}

func (b *dbBackend) Update(ctx context.Context, id string, data []byte, authenticated bool) (time.Time, error) {
	now := b.now()
	hash := hashSessionId(id)

	expiresAt, err := b.expiryFor(ctx, hash, authenticated, now)
	if err != nil {
		return time.Time{}, err
	}

	updated, err := b.database.UpdateBrowserSessionData(nil, b.owner, hash, string(data), now, expiresAt)
	if err != nil {
		return time.Time{}, errs.Wrap(err, "unable to update the browser session")
	}
	if !updated {
		return time.Time{}, sessionstore.ErrNotFound
	}

	return expiresAt, nil
}

func (b *dbBackend) Touch(ctx context.Context, id string, authenticated bool) (time.Time, error) {
	now := b.now()
	hash := hashSessionId(id)

	expiresAt, err := b.expiryFor(ctx, hash, authenticated, now)
	if err != nil {
		return time.Time{}, err
	}

	touched, err := b.database.TouchBrowserSession(nil, b.owner, hash, now, expiresAt)
	if err != nil {
		return time.Time{}, errs.Wrap(err, "unable to touch the browser session")
	}
	if !touched {
		return time.Time{}, sessionstore.ErrNotFound
	}

	return expiresAt, nil
}

func (b *dbBackend) Delete(ctx context.Context, id string) error {
	if err := b.database.DeleteBrowserSession(nil, b.owner, hashSessionId(id)); err != nil {
		return errs.Wrap(err, "unable to delete the browser session")
	}
	return nil
}

// expiryFor computes the new deadline for a session that already exists.
//
// An authenticated session's maximum lifetime is measured from when its row was created,
// so this reads the row to find out. That read is the price of deriving created_at
// server-side, and it is not optional: a value supplied by a caller would let anyone
// holding the admin console's credential extend a session past the maximum lifetime the
// operator configured, which is the one deadline no amount of activity may move.
//
// A session that has not authenticated needs neither the row nor the settings: its
// deadline is a flat constant. That is the path an unauthenticated caller hitting
// /auth/authorize in a loop takes, so it deliberately costs no read at all.
func (b *dbBackend) expiryFor(ctx context.Context, hash string, authenticated bool, now time.Time) (time.Time, error) {
	if !authenticated {
		return sessionstore.ExpiresAt(now, now, false, 0, 0), nil
	}

	idleTimeout, maxLifetime, err := b.lifetimes(ctx)
	if err != nil {
		return time.Time{}, err
	}

	browserSession, err := b.database.GetBrowserSessionByOwnerAndSessionIdHash(nil, b.owner, hash, now)
	if err != nil {
		return time.Time{}, errs.Wrap(err, "unable to read the browser session")
	}
	if browserSession == nil {
		return time.Time{}, sessionstore.ErrNotFound
	}

	// created_at is written by CreateBrowserSession on every insert, so an invalid one
	// cannot happen; treating it as the current instant keeps a corrupt row usable for
	// one more window rather than making it unreadable.
	createdAt := now
	if browserSession.CreatedAt.Valid {
		createdAt = browserSession.CreatedAt.Time
	}

	return sessionstore.ExpiresAt(now, createdAt, true, idleTimeout, maxLifetime), nil
}

// lifetimes returns the deployment's session deadlines.
//
// The auth server's settings middleware has already read them for this request and put
// them in the context, so the common path costs nothing; the fallback covers a caller
// that has no request behind it. Both halves read the same settings, so which one runs
// changes no outcome, only whether a read happens.
func (b *dbBackend) lifetimes(ctx context.Context) (idleTimeout, maxLifetime time.Duration, err error) {
	settings, ok := ctx.Value(constants.ContextKeySettings).(*models.Settings)
	if !ok || settings == nil {
		settings, err = b.database.GetSettingsById(nil, 1)
		if err != nil {
			return 0, 0, errs.Wrap(err, "unable to read the settings")
		}
		if settings == nil {
			return 0, 0, errs.New("settings row is missing")
		}
	}

	return time.Duration(settings.UserSessionIdleTimeoutInSeconds) * time.Second,
		time.Duration(settings.UserSessionMaxLifetimeInSeconds) * time.Second, nil
}

// hashSessionId is what reaches the column. The identifier itself is never persisted:
// the model tags it db:"-" and everything below this line works on the digest, the shape
// migration 000028 established for reset and activation codes (#112, #266).
func hashSessionId(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:])
}
