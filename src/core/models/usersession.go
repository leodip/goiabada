package models

import (
	"database/sql"
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
	AcrLevel          string       `db:"acr_level"`
	AuthTime          time.Time    `db:"auth_time"`
	IpAddress         string       `db:"ip_address"`
	DeviceName        string       `db:"device_name"`
	DeviceType        string       `db:"device_type"`
	DeviceOS          string       `db:"device_os"`
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
	OtpConfigGeneration int64               `db:"otp_config_generation" fieldtag:"dont-update"`
	UserId              int64               `db:"user_id"`
	User                User                `db:"-"`
	Clients             []UserSessionClient `db:"-"`
}

func (us *UserSession) isValidSinceStarted(userSessionMaxLifetimeInSeconds int) bool {
	utcNow := time.Now().UTC()
	max := us.Started.Add(time.Second * time.Duration(userSessionMaxLifetimeInSeconds))
	return utcNow.Before(max) || utcNow.Equal(max)
}

func (us *UserSession) isValidSinceLastAcessed(userSessionIdleTimeoutInSeconds int) bool {
	utcNow := time.Now().UTC()
	max := us.LastAccessed.Add(time.Second * time.Duration(userSessionIdleTimeoutInSeconds))
	return utcNow.Before(max) || utcNow.Equal(max)
}

func (us *UserSession) IsValid(userSessionIdleTimeoutInSeconds int, userSessionMaxLifetimeInSeconds int,
	requestedMaxAgeInSeconds *int) bool {

	isValid := us.isValidSinceLastAcessed(userSessionIdleTimeoutInSeconds) &&
		us.isValidSinceStarted(userSessionMaxLifetimeInSeconds)

	if requestedMaxAgeInSeconds != nil {
		isValid = isValid && us.isValidSinceStarted(*requestedMaxAgeInSeconds)
	}

	return isValid
}
