package models

import (
	"database/sql"
	"time"
)

type UserSession struct {
	Id                         int64               `db:"id" fieldtag:"pk"`
	CreatedAt                  sql.NullTime        `db:"created_at" fieldtag:"dont-update"`
	UpdatedAt                  sql.NullTime        `db:"updated_at"`
	SessionIdentifier          string              `db:"session_identifier"`
	Started                    time.Time           `db:"started"`
	LastAccessed               time.Time           `db:"last_accessed"`
	AuthMethods                string              `db:"auth_methods"`
	AcrLevel                   string              `db:"acr_level"`
	AuthTime                   time.Time           `db:"auth_time"`
	IpAddress                  string              `db:"ip_address"`
	DeviceName                 string              `db:"device_name"`
	DeviceType                 string              `db:"device_type"`
	DeviceOS                   string              `db:"device_os"`
	Level2AuthConfigHasChanged bool                `db:"level2_auth_config_has_changed"`
	UserId                     int64               `db:"user_id"`
	User                       User                `db:"-"`
	Clients                    []UserSessionClient `db:"-"`
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
