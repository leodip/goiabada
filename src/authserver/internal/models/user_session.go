package models

import (
	"database/sql"
	"math"
	"time"
)

type UserSession struct {
	Id                int64        `db:"id" fieldtag:"pk"`
	CreatedAt         sql.NullTime `db:"created_at" fieldtag:"dont-update"`
	UpdatedAt         sql.NullTime `db:"updated_at"`
	SessionIdentifier string       `db:"session_identifier"`
	Started           time.Time    `db:"started"`
	LastAccessed      time.Time    `db:"last_accessed"`
	AuthMethods       string       `db:"auth_methods"`
	AcrLevel          AcrLevel     `db:"acr_level"`
	AuthTime          time.Time    `db:"auth_time"`
	IpAddress         string       `db:"ip_address"`
	DeviceName        string       `db:"device_name"`
	DeviceType        string       `db:"device_type"`
	DeviceOS          string       `db:"device_os"`
	// UserAgent is the request's User-Agent header as the browser sent it, repaired to
	// valid UTF-8 and cut to 512 bytes by useragent.Bound. With IpAddress it is the key
	// StartNewUserSession sweeps on: two logins are the same device when both match.
	//
	// The three Device* fields above it are display only. They are a parser's guess at a
	// browser name, so keying the sweep on them meant every change of parser or of label
	// format silently changed which sessions superseded which (#281).
	UserAgent string `db:"user_agent"`
	// AuthStateGeneration records the user's generation when this session was
	// created. Tagged dont-update so an ordinary full-row UpdateUserSession cannot
	// regress it: it is written on insert and afterwards only by
	// PromoteUserSessionGeneration (#106).
	AuthStateGeneration int64 `db:"auth_state_generation" fieldtag:"dont-update"`
	// OtpConfigGeneration is the user's otp_config_generation as it stood when this
	// session last satisfied the level 2 question, so this session owes a level 2
	// re-prompt whenever the two differ. It replaced a boolean the readers cleared as
	// they read it, which is why the comparison here is the whole point: reading is not
	// writing, so a ceremony abandoned at the OTP prompt no longer spends the re-prompt
	// it was owed (#242).
	//
	// Tagged dont-update for the reason AuthStateGeneration is: every credential handler
	// loads the whole row and writes it back, and BumpUserSession rewrites it on every
	// request, so leaving it in the ordinary update set would let a stale model regress
	// it. It is written on insert and afterwards only by
	// PromoteUserSessionOtpConfigGeneration.
	OtpConfigGeneration int64 `db:"otp_config_generation" fieldtag:"dont-update"`
	// UserId is the session's owner, written on insert and never changed: no code path
	// reassigns a session to another user, and the cross-user handover at /auth/completed
	// ends the old session and starts a new one rather than moving it.
	//
	// Tagged dont-update for a different reason from the two generations above. user_id is a
	// foreign key to users.id, and SQL Server re-checks a foreign key whenever the column is
	// in an UPDATE's SET list, unchanged value or not, by taking a shared lock on the parent
	// row. So a full-row UpdateUserSession took the session row and then the users row, which
	// is the reverse of the order every transaction writing a session and its grants agrees
	// to: users, then user_sessions, then the grants. Measured on SQL Server: BumpUserSession
	// racing an authorization ceremony that already holds the users row deadlocks with the
	// ceremony as the victim. Leaving the column out of the update set is what removes that
	// edge; PostgreSQL and MySQL skip the re-check on an unchanged value and were never
	// affected (#139).
	UserId  int64               `db:"user_id" fieldtag:"dont-update"`
	User    User                `db:"-"`
	Clients []UserSessionClient `db:"-"`
}

// IsValid reports whether the session may still be used at now: idle for no longer than
// idleTimeoutInSeconds since LastAccessed, alive for no longer than maxLifetimeInSeconds since
// Started and, when the client sent max_age, authenticated no longer than that ago. Each bound is
// inclusive, because OIDC Core 1.0 section 3.1.2.1 forces re-authentication when the elapsed time
// "is greater than this value", so elapsed equal to max_age is still valid and max_age=0 is not,
// once any time has passed at all.
//
// max_age is measured from AuthTime, "the last time the End-User was actively authenticated by
// the OP" in the same section, and not from Started: a re-authentication inside a session
// refreshes AuthTime and leaves Started alone, so measuring from Started refused a session its
// user had signed in to minutes ago once the session itself was older than max_age. A zero
// AuthTime is a row written before the column was filled, and falls back to Started (#243).
//
// now is a parameter so the three callers and the session manager read the clock once each and a
// test can fix it.
func (us *UserSession) IsValid(now time.Time, idleTimeoutInSeconds int, maxLifetimeInSeconds int,
	requestedMaxAgeInSeconds *int64) bool {

	if !notExceeded(us.LastAccessed, now, int64(idleTimeoutInSeconds)) ||
		!notExceeded(us.Started, now, int64(maxLifetimeInSeconds)) {
		return false
	}

	if requestedMaxAgeInSeconds != nil {
		authenticatedAt := us.AuthTime
		if authenticatedAt.IsZero() {
			authenticatedAt = us.Started
		}
		return notExceeded(authenticatedAt, now, *requestedMaxAgeInSeconds)
	}

	return true
}

// maxDurationSeconds is the largest whole number of seconds a time.Duration can hold.
const maxDurationSeconds = math.MaxInt64 / int64(time.Second)

// notExceeded reports whether no more than seconds have elapsed between since and now.
//
// A value of seconds above maxDurationSeconds is never exceeded, and is answered without
// multiplying it into a time.Duration, which would wrap: max_age=9223372037 used to become a
// deadline in 1734 and refuse every session. Such a bound is longer than 292 years, and
// time.Time.Sub saturates at the same limit, so no elapsed time this comparison can see exceeds it
// (#243).
func notExceeded(since, now time.Time, seconds int64) bool {
	if seconds > maxDurationSeconds {
		return true
	}
	return now.Sub(since) <= time.Duration(seconds)*time.Second
}
