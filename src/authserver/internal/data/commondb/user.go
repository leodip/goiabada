package commondb

import (
	"context"
	"database/sql"
	"sort"
	"strings"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// userColumns is the users table as scanUser reads it, each column qualified by its table so the
// list reads the same in a join with users_groups or users_permissions, whose own id, created_at
// and updated_at it would otherwise name ambiguously.
var userColumns = columnList{
	sqlite: "users.id, users.created_at, users.updated_at, users.enabled, users.subject, " +
		"users.username, users.given_name, users.middle_name, users.family_name, users.nickname, " +
		"users.website, users.gender, users.email, users.email_verified, " +
		"users.email_verification_code_encrypted, users.email_verification_code_issued_at, " +
		"users.zone_info_country_name, users.zone_info, users.locale, users.birth_date, " +
		"users.phone_number_country_uniqueid, users.phone_number_country_callingcode, " +
		"users.phone_number, users.phone_number_verified, users.address_line1, users.address_line2, " +
		"users.address_locality, users.address_region, users.address_postal_code, " +
		"users.address_country, users.password_hash, users.otp_secret_encrypted, users.otp_enabled, " +
		"users.forgot_password_code_encrypted, users.forgot_password_code_issued_at, " +
		"users.forgot_password_code_hash, users.auth_state_generation, users.last_otp_step, " +
		"users.otp_config_generation, users.otp_consecutive_failures, " +
		"users.otp_enrollment_secret_encrypted, users.otp_enrollment_issued_at",
	mysql: "users.id, users.created_at, users.updated_at, users.enabled, users.subject, " +
		"users.username, users.given_name, users.middle_name, users.family_name, users.nickname, " +
		"users.website, users.gender, users.email, users.email_verified, " +
		"users.email_verification_code_encrypted, users.email_verification_code_issued_at, " +
		"users.zone_info_country_name, users.zone_info, users.locale, users.birth_date, " +
		"users.phone_number_country_uniqueid, users.phone_number_country_callingcode, " +
		"users.phone_number, users.phone_number_verified, users.address_line1, users.address_line2, " +
		"users.address_locality, users.address_region, users.address_postal_code, " +
		"users.address_country, users.password_hash, users.otp_secret_encrypted, users.otp_enabled, " +
		"users.forgot_password_code_encrypted, users.forgot_password_code_issued_at, " +
		"users.forgot_password_code_hash, users.auth_state_generation, users.last_otp_step, " +
		"users.otp_config_generation, users.otp_consecutive_failures, " +
		"users.otp_enrollment_secret_encrypted, users.otp_enrollment_issued_at",
	postgres: "users.id, users.created_at, users.updated_at, users.enabled, users.subject, " +
		"users.username, users.given_name, users.middle_name, users.family_name, users.nickname, " +
		"users.website, users.gender, users.email, users.email_verified, " +
		"users.email_verification_code_encrypted, users.email_verification_code_issued_at, " +
		"users.zone_info_country_name, users.zone_info, users.locale, users.birth_date, " +
		"users.phone_number_country_uniqueid, users.phone_number_country_callingcode, " +
		"users.phone_number, users.phone_number_verified, users.address_line1, users.address_line2, " +
		"users.address_locality, users.address_region, users.address_postal_code, " +
		"users.address_country, users.password_hash, users.otp_secret_encrypted, users.otp_enabled, " +
		"users.forgot_password_code_encrypted, users.forgot_password_code_issued_at, " +
		"users.forgot_password_code_hash, users.auth_state_generation, users.last_otp_step, " +
		"users.otp_config_generation, users.otp_consecutive_failures, " +
		"users.otp_enrollment_secret_encrypted, users.otp_enrollment_issued_at",
	mssql: "users.id, users.created_at, users.updated_at, users.enabled, users.subject, " +
		"users.username, users.given_name, users.middle_name, users.family_name, users.nickname, " +
		"users.website, users.gender, users.email, users.email_verified, " +
		"users.email_verification_code_encrypted, users.email_verification_code_issued_at, " +
		"users.zone_info_country_name, users.zone_info, users.locale, users.birth_date, " +
		"users.phone_number_country_uniqueid, users.phone_number_country_callingcode, " +
		"users.phone_number, users.phone_number_verified, users.address_line1, users.address_line2, " +
		"users.address_locality, users.address_region, users.address_postal_code, " +
		"users.address_country, users.password_hash, users.otp_secret_encrypted, users.otp_enabled, " +
		"users.forgot_password_code_encrypted, users.forgot_password_code_issued_at, " +
		"users.forgot_password_code_hash, users.auth_state_generation, users.last_otp_step, " +
		"users.otp_config_generation, users.otp_consecutive_failures, " +
		"users.otp_enrollment_secret_encrypted, users.otp_enrollment_issued_at",
}

// scanUser reads one row selected with userColumns.
func scanUser(row rowScanner, user *record.User) error {
	return row.Scan(
		&user.Id,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.Enabled,
		&user.Subject,
		&user.Username,
		&user.GivenName,
		&user.MiddleName,
		&user.FamilyName,
		&user.Nickname,
		&user.Website,
		&user.Gender,
		&user.Email,
		&user.EmailVerified,
		&user.EmailVerificationCodeEncrypted,
		&user.EmailVerificationCodeIssuedAt,
		&user.ZoneInfoCountryName,
		&user.ZoneInfo,
		&user.Locale,
		&user.BirthDate,
		&user.PhoneNumberCountryUniqueId,
		&user.PhoneNumberCountryCallingCode,
		&user.PhoneNumber,
		&user.PhoneNumberVerified,
		&user.AddressLine1,
		&user.AddressLine2,
		&user.AddressLocality,
		&user.AddressRegion,
		&user.AddressPostalCode,
		&user.AddressCountry,
		&user.PasswordHash,
		&user.OTPSecretEncrypted,
		&user.OTPEnabled,
		&user.ForgotPasswordCodeEncrypted,
		&user.ForgotPasswordCodeIssuedAt,
		&user.ForgotPasswordCodeHash,
		&user.AuthStateGeneration,
		&user.LastOTPStep,
		&user.OtpConfigGeneration,
		&user.OtpConsecutiveFailures,
		&user.OtpEnrollmentSecretEncrypted,
		&user.OtpEnrollmentIssuedAt,
	)
}

// insertUser writes every column but id, the dont-update ones included: a new user starts its
// generations, its one-time code step and its pending enrolment from the values it is created with.
var insertUser = statement{
	sqlite: "INSERT INTO users (created_at, updated_at, enabled, subject, username, given_name, " +
		"middle_name, family_name, nickname, website, gender, email, email_verified, " +
		"email_verification_code_encrypted, email_verification_code_issued_at, " +
		"zone_info_country_name, zone_info, locale, birth_date, phone_number_country_uniqueid, " +
		"phone_number_country_callingcode, phone_number, phone_number_verified, address_line1, " +
		"address_line2, address_locality, address_region, address_postal_code, address_country, " +
		"password_hash, otp_secret_encrypted, otp_enabled, forgot_password_code_encrypted, " +
		"forgot_password_code_issued_at, forgot_password_code_hash, auth_state_generation, " +
		"last_otp_step, otp_config_generation, otp_consecutive_failures, " +
		"otp_enrollment_secret_encrypted, otp_enrollment_issued_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, " +
		"?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, " +
		"?, ?, ?)",
	mysql: "INSERT INTO users (created_at, updated_at, enabled, subject, username, given_name, " +
		"middle_name, family_name, nickname, website, gender, email, email_verified, " +
		"email_verification_code_encrypted, email_verification_code_issued_at, " +
		"zone_info_country_name, zone_info, locale, birth_date, phone_number_country_uniqueid, " +
		"phone_number_country_callingcode, phone_number, phone_number_verified, address_line1, " +
		"address_line2, address_locality, address_region, address_postal_code, address_country, " +
		"password_hash, otp_secret_encrypted, otp_enabled, forgot_password_code_encrypted, " +
		"forgot_password_code_issued_at, forgot_password_code_hash, auth_state_generation, " +
		"last_otp_step, otp_config_generation, otp_consecutive_failures, " +
		"otp_enrollment_secret_encrypted, otp_enrollment_issued_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, " +
		"?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, " +
		"?, ?, ?)",
	postgres: "INSERT INTO users (created_at, updated_at, enabled, subject, username, given_name, " +
		"middle_name, family_name, nickname, website, gender, email, email_verified, " +
		"email_verification_code_encrypted, email_verification_code_issued_at, " +
		"zone_info_country_name, zone_info, locale, birth_date, phone_number_country_uniqueid, " +
		"phone_number_country_callingcode, phone_number, phone_number_verified, address_line1, " +
		"address_line2, address_locality, address_region, address_postal_code, address_country, " +
		"password_hash, otp_secret_encrypted, otp_enabled, forgot_password_code_encrypted, " +
		"forgot_password_code_issued_at, forgot_password_code_hash, auth_state_generation, " +
		"last_otp_step, otp_config_generation, otp_consecutive_failures, " +
		"otp_enrollment_secret_encrypted, otp_enrollment_issued_at) VALUES ($1, $2, $3, $4, $5, $6, " +
		"$7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, " +
		"$26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37, $38, $39, $40, $41) RETURNING id",
	mssql: "INSERT INTO users (created_at, updated_at, enabled, subject, username, given_name, " +
		"middle_name, family_name, nickname, website, gender, email, email_verified, " +
		"email_verification_code_encrypted, email_verification_code_issued_at, " +
		"zone_info_country_name, zone_info, locale, birth_date, phone_number_country_uniqueid, " +
		"phone_number_country_callingcode, phone_number, phone_number_verified, address_line1, " +
		"address_line2, address_locality, address_region, address_postal_code, address_country, " +
		"password_hash, otp_secret_encrypted, otp_enabled, forgot_password_code_encrypted, " +
		"forgot_password_code_issued_at, forgot_password_code_hash, auth_state_generation, " +
		"last_otp_step, otp_config_generation, otp_consecutive_failures, " +
		"otp_enrollment_secret_encrypted, otp_enrollment_issued_at) OUTPUT INSERTED.id VALUES (@p1, " +
		"@p2, @p3, @p4, @p5, @p6, @p7, @p8, @p9, @p10, @p11, @p12, @p13, @p14, @p15, @p16, @p17, " +
		"@p18, @p19, @p20, @p21, @p22, @p23, @p24, @p25, @p26, @p27, @p28, @p29, @p30, @p31, @p32, " +
		"@p33, @p34, @p35, @p36, @p37, @p38, @p39, @p40, @p41)",
}

// updateUser writes the whole row but created_at and the six dont-update columns that only
// their own narrow writers move: auth_state_generation, last_otp_step, otp_config_generation,
// otp_consecutive_failures, otp_enrollment_secret_encrypted and otp_enrollment_issued_at. Their
// absence from this text is the whole of their protection from a stale record (#471).
var updateUser = statement{
	sqlite: "UPDATE users SET updated_at = ?, enabled = ?, subject = ?, username = ?, " +
		"given_name = ?, middle_name = ?, family_name = ?, nickname = ?, website = ?, gender = ?, " +
		"email = ?, email_verified = ?, email_verification_code_encrypted = ?, " +
		"email_verification_code_issued_at = ?, zone_info_country_name = ?, zone_info = ?, " +
		"locale = ?, birth_date = ?, phone_number_country_uniqueid = ?, " +
		"phone_number_country_callingcode = ?, phone_number = ?, phone_number_verified = ?, " +
		"address_line1 = ?, address_line2 = ?, address_locality = ?, address_region = ?, " +
		"address_postal_code = ?, address_country = ?, password_hash = ?, otp_secret_encrypted = ?, " +
		"otp_enabled = ?, forgot_password_code_encrypted = ?, forgot_password_code_issued_at = ?, " +
		"forgot_password_code_hash = ? WHERE id = ?",
	mysql: "UPDATE users SET updated_at = ?, enabled = ?, subject = ?, username = ?, " +
		"given_name = ?, middle_name = ?, family_name = ?, nickname = ?, website = ?, gender = ?, " +
		"email = ?, email_verified = ?, email_verification_code_encrypted = ?, " +
		"email_verification_code_issued_at = ?, zone_info_country_name = ?, zone_info = ?, " +
		"locale = ?, birth_date = ?, phone_number_country_uniqueid = ?, " +
		"phone_number_country_callingcode = ?, phone_number = ?, phone_number_verified = ?, " +
		"address_line1 = ?, address_line2 = ?, address_locality = ?, address_region = ?, " +
		"address_postal_code = ?, address_country = ?, password_hash = ?, otp_secret_encrypted = ?, " +
		"otp_enabled = ?, forgot_password_code_encrypted = ?, forgot_password_code_issued_at = ?, " +
		"forgot_password_code_hash = ? WHERE id = ?",
	postgres: "UPDATE users SET updated_at = $1, enabled = $2, subject = $3, username = $4, " +
		"given_name = $5, middle_name = $6, family_name = $7, nickname = $8, website = $9, " +
		"gender = $10, email = $11, email_verified = $12, email_verification_code_encrypted = $13, " +
		"email_verification_code_issued_at = $14, zone_info_country_name = $15, zone_info = $16, " +
		"locale = $17, birth_date = $18, phone_number_country_uniqueid = $19, " +
		"phone_number_country_callingcode = $20, phone_number = $21, phone_number_verified = $22, " +
		"address_line1 = $23, address_line2 = $24, address_locality = $25, address_region = $26, " +
		"address_postal_code = $27, address_country = $28, password_hash = $29, " +
		"otp_secret_encrypted = $30, otp_enabled = $31, forgot_password_code_encrypted = $32, " +
		"forgot_password_code_issued_at = $33, forgot_password_code_hash = $34 WHERE id = $35",
	mssql: "UPDATE users SET updated_at = @p1, enabled = @p2, subject = @p3, username = @p4, " +
		"given_name = @p5, middle_name = @p6, family_name = @p7, nickname = @p8, website = @p9, " +
		"gender = @p10, email = @p11, email_verified = @p12, " +
		"email_verification_code_encrypted = @p13, email_verification_code_issued_at = @p14, " +
		"zone_info_country_name = @p15, zone_info = @p16, locale = @p17, birth_date = @p18, " +
		"phone_number_country_uniqueid = @p19, phone_number_country_callingcode = @p20, " +
		"phone_number = @p21, phone_number_verified = @p22, address_line1 = @p23, " +
		"address_line2 = @p24, address_locality = @p25, address_region = @p26, " +
		"address_postal_code = @p27, address_country = @p28, password_hash = @p29, " +
		"otp_secret_encrypted = @p30, otp_enabled = @p31, forgot_password_code_encrypted = @p32, " +
		"forgot_password_code_issued_at = @p33, forgot_password_code_hash = @p34 WHERE id = @p35",
}

var selectUserById = statement{
	sqlite:   "SELECT " + userColumns.sqlite + " FROM users WHERE id = ?",
	mysql:    "SELECT " + userColumns.mysql + " FROM users WHERE id = ?",
	postgres: "SELECT " + userColumns.postgres + " FROM users WHERE id = $1",
	mssql:    "SELECT " + userColumns.mssql + " FROM users WHERE id = @p1",
}

// selectUserByIdForUpdate is the locking read GetUserByIdForUpdate runs, the lock in each engine's
// own grammar: FOR UPDATE on MySQL and PostgreSQL, the UPDLOCK and ROWLOCK table hints on SQL
// Server, which has no FOR UPDATE on a SELECT, and none on SQLite, which has no row locks.
var selectUserByIdForUpdate = statement{
	sqlite:   "SELECT " + userColumns.sqlite + " FROM users WHERE id = ?",
	mysql:    "SELECT " + userColumns.mysql + " FROM users WHERE id = ? FOR UPDATE",
	postgres: "SELECT " + userColumns.postgres + " FROM users WHERE id = $1 FOR UPDATE",
	mssql:    "SELECT " + userColumns.mssql + " FROM users WITH (UPDLOCK, ROWLOCK) WHERE id = @p1",
}

// selectUsersWhere is completed by an IN list of user ids.
var selectUsersWhere = statement{
	sqlite:   "SELECT " + userColumns.sqlite + " FROM users WHERE ",
	mysql:    "SELECT " + userColumns.mysql + " FROM users WHERE ",
	postgres: "SELECT " + userColumns.postgres + " FROM users WHERE ",
	mssql:    "SELECT " + userColumns.mssql + " FROM users WHERE ",
}

var selectUserByUsername = statement{
	sqlite:   "SELECT " + userColumns.sqlite + " FROM users WHERE username = ?",
	mysql:    "SELECT " + userColumns.mysql + " FROM users WHERE username = ?",
	postgres: "SELECT " + userColumns.postgres + " FROM users WHERE username = $1",
	mssql:    "SELECT " + userColumns.mssql + " FROM users WHERE username = @p1",
}

var selectUserBySubject = statement{
	sqlite:   "SELECT " + userColumns.sqlite + " FROM users WHERE subject = ?",
	mysql:    "SELECT " + userColumns.mysql + " FROM users WHERE subject = ?",
	postgres: "SELECT " + userColumns.postgres + " FROM users WHERE subject = $1",
	mssql:    "SELECT " + userColumns.mssql + " FROM users WHERE subject = @p1",
}

var selectUserByEmail = statement{
	sqlite:   "SELECT " + userColumns.sqlite + " FROM users WHERE email = ?",
	mysql:    "SELECT " + userColumns.mysql + " FROM users WHERE email = ?",
	postgres: "SELECT " + userColumns.postgres + " FROM users WHERE email = $1",
	mssql:    "SELECT " + userColumns.mssql + " FROM users WHERE email = @p1",
}

var selectUserByForgotPasswordCodeHash = statement{
	sqlite:   "SELECT " + userColumns.sqlite + " FROM users WHERE forgot_password_code_hash = ?",
	mysql:    "SELECT " + userColumns.mysql + " FROM users WHERE forgot_password_code_hash = ?",
	postgres: "SELECT " + userColumns.postgres + " FROM users WHERE forgot_password_code_hash = $1",
	mssql:    "SELECT " + userColumns.mssql + " FROM users WHERE forgot_password_code_hash = @p1",
}

// searchUsersFilter is the user search's predicate: the term, bound once per searched column,
// matched against subject, username, given_name, middle_name, family_name and email. The page and
// the count of a search both splice this one text, so the two cannot drift apart and start
// disagreeing about how many rows a page is a slice of.
//
// LOWER() on both sides rather than leaving the fold to the column's collation, because the
// collation means four different things: PostgreSQL and SQLite compare case-sensitively, so a
// search for "alice" misses "Alice" there, while MySQL and SQL Server fold. Deciding it in the
// query is the only spelling that is the same on all four (#283). The ESCAPE clause names
// likeEscapeChar, which escapeLikePattern writes before each of the term's own wildcards (#95).
// Removing the LOWER() calls puts PostgreSQL's case-sensitive search back and takes the other three
// with it; removing the ESCAPE clause makes the escaping inert.
var searchUsersFilter = statement{
	sqlite: "(LOWER(subject) LIKE LOWER(?) ESCAPE '!' OR " +
		"LOWER(username) LIKE LOWER(?) ESCAPE '!' OR LOWER(given_name) LIKE LOWER(?) ESCAPE '!' OR " +
		"LOWER(middle_name) LIKE LOWER(?) ESCAPE '!' OR LOWER(family_name) LIKE LOWER(?) ESCAPE '!' OR " +
		"LOWER(email) LIKE LOWER(?) ESCAPE '!')",
	mysql: "(LOWER(subject) LIKE LOWER(?) ESCAPE '!' OR " +
		"LOWER(username) LIKE LOWER(?) ESCAPE '!' OR LOWER(given_name) LIKE LOWER(?) ESCAPE '!' OR " +
		"LOWER(middle_name) LIKE LOWER(?) ESCAPE '!' OR LOWER(family_name) LIKE LOWER(?) ESCAPE '!' OR " +
		"LOWER(email) LIKE LOWER(?) ESCAPE '!')",
	postgres: "(LOWER(subject) LIKE LOWER($1) ESCAPE '!' OR " +
		"LOWER(username) LIKE LOWER($2) ESCAPE '!' OR LOWER(given_name) LIKE LOWER($3) ESCAPE '!' OR " +
		"LOWER(middle_name) LIKE LOWER($4) ESCAPE '!' OR LOWER(family_name) LIKE LOWER($5) ESCAPE '!' OR " +
		"LOWER(email) LIKE LOWER($6) ESCAPE '!')",
	mssql: "(LOWER(subject) LIKE LOWER(@p1) ESCAPE '!' OR " +
		"LOWER(username) LIKE LOWER(@p2) ESCAPE '!' OR LOWER(given_name) LIKE LOWER(@p3) ESCAPE '!' OR " +
		"LOWER(middle_name) LIKE LOWER(@p4) ESCAPE '!' OR LOWER(family_name) LIKE LOWER(@p5) ESCAPE '!' OR " +
		"LOWER(email) LIKE LOWER(@p6) ESCAPE '!')",
}

// The two pages of users bind the page size, then the offset, after the search's six terms when
// there is a term. SQL Server pages with OFFSET … FETCH after its ORDER BY, naming the offset
// first, so its text numbers the two the other way round.
//
// given_name is not unique, so it does not order the rows totally, and a page is a slice of an
// order. Where tied rows straddle a page boundary the database is free to arrange them differently
// for the page-1 query than for the page-2 query, which shows one user on both pages and omits
// another entirely. The ties are the common case rather than the exception: every self-registered
// user has an empty given name, as does the seeded admin. Ordering by the primary key as well makes
// the order total, which is what makes paging through it correct. Same reason audit_log.go pages
// by created_at DESC, id DESC (#112).
var selectUsersPage = statement{
	sqlite: "SELECT " + userColumns.sqlite +
		" FROM users ORDER BY users.given_name ASC, users.id ASC LIMIT ? OFFSET ?",
	mysql: "SELECT " + userColumns.mysql +
		" FROM users ORDER BY users.given_name ASC, users.id ASC LIMIT ? OFFSET ?",
	postgres: "SELECT " + userColumns.postgres +
		" FROM users ORDER BY users.given_name ASC, users.id ASC LIMIT $1 OFFSET $2",
	mssql: "SELECT " + userColumns.mssql +
		" FROM users ORDER BY users.given_name ASC, users.id ASC OFFSET @p2 ROWS FETCH NEXT @p1 ROWS ONLY",
}

var selectUsersSearchPage = statement{
	sqlite: "SELECT " + userColumns.sqlite + " FROM users WHERE " + searchUsersFilter.sqlite +
		" ORDER BY users.given_name ASC, users.id ASC LIMIT ? OFFSET ?",
	mysql: "SELECT " + userColumns.mysql + " FROM users WHERE " + searchUsersFilter.mysql +
		" ORDER BY users.given_name ASC, users.id ASC LIMIT ? OFFSET ?",
	postgres: "SELECT " + userColumns.postgres + " FROM users WHERE " + searchUsersFilter.postgres +
		" ORDER BY users.given_name ASC, users.id ASC LIMIT $7 OFFSET $8",
	mssql: "SELECT " + userColumns.mssql + " FROM users WHERE " + searchUsersFilter.mssql +
		" ORDER BY users.given_name ASC, users.id ASC OFFSET @p8 ROWS FETCH NEXT @p7 ROWS ONLY",
}

var countUsers = statement{
	sqlite:   "SELECT count(*) FROM users",
	mysql:    "SELECT count(*) FROM users",
	postgres: "SELECT count(*) FROM users",
	mssql:    "SELECT count(*) FROM users",
}

var countUsersSearch = statement{
	sqlite:   "SELECT count(*) FROM users WHERE " + searchUsersFilter.sqlite,
	mysql:    "SELECT count(*) FROM users WHERE " + searchUsersFilter.mysql,
	postgres: "SELECT count(*) FROM users WHERE " + searchUsersFilter.postgres,
	mssql:    "SELECT count(*) FROM users WHERE " + searchUsersFilter.mssql,
}

var deleteUser = statement{
	sqlite:   "DELETE FROM users WHERE id = ?",
	mysql:    "DELETE FROM users WHERE id = ?",
	postgres: "DELETE FROM users WHERE id = $1",
	mssql:    "DELETE FROM users WHERE id = @p1",
}

// acquireUserRow assigns auth_state_generation to itself: see AcquireUserRow.
var acquireUserRow = statement{
	sqlite:   "UPDATE users SET auth_state_generation = auth_state_generation WHERE id = ?",
	mysql:    "UPDATE users SET auth_state_generation = auth_state_generation WHERE id = ?",
	postgres: "UPDATE users SET auth_state_generation = auth_state_generation WHERE id = $1",
	mssql:    "UPDATE users SET auth_state_generation = auth_state_generation WHERE id = @p1",
}

func (d *Database) CreateUser(ctx context.Context, tx *sql.Tx, user *record.User) error {

	now := time.Now().UTC()

	originalCreatedAt := user.CreatedAt
	originalUpdatedAt := user.UpdatedAt
	user.CreatedAt = sql.NullTime{Time: now, Valid: true}
	user.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	id, err := d.insert(ctx, tx, insertUser, "user",
		user.CreatedAt, user.UpdatedAt, user.Enabled, user.Subject, user.Username, user.GivenName,
		user.MiddleName, user.FamilyName, user.Nickname, user.Website, user.Gender, user.Email,
		user.EmailVerified, user.EmailVerificationCodeEncrypted, user.EmailVerificationCodeIssuedAt,
		user.ZoneInfoCountryName, user.ZoneInfo, user.Locale, user.BirthDate,
		user.PhoneNumberCountryUniqueId, user.PhoneNumberCountryCallingCode, user.PhoneNumber,
		user.PhoneNumberVerified, user.AddressLine1, user.AddressLine2, user.AddressLocality,
		user.AddressRegion, user.AddressPostalCode, user.AddressCountry, user.PasswordHash,
		user.OTPSecretEncrypted, user.OTPEnabled, user.ForgotPasswordCodeEncrypted,
		user.ForgotPasswordCodeIssuedAt, user.ForgotPasswordCodeHash, user.AuthStateGeneration,
		user.LastOTPStep, user.OtpConfigGeneration, user.OtpConsecutiveFailures,
		user.OtpEnrollmentSecretEncrypted, user.OtpEnrollmentIssuedAt)
	if err != nil {
		user.CreatedAt = originalCreatedAt
		user.UpdatedAt = originalUpdatedAt
		return err
	}

	user.Id = id
	return nil
}

func (d *Database) UpdateUser(ctx context.Context, tx *sql.Tx, user *record.User) error {

	if user.Id == 0 {
		return errs.New("can't update user with id 0")
	}

	originalUpdatedAt := user.UpdatedAt
	user.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	_, err := d.ExecSQL(ctx, tx, updateUser.text(d.Dialect),
		user.UpdatedAt, user.Enabled, user.Subject, user.Username, user.GivenName, user.MiddleName,
		user.FamilyName, user.Nickname, user.Website, user.Gender, user.Email, user.EmailVerified,
		user.EmailVerificationCodeEncrypted, user.EmailVerificationCodeIssuedAt,
		user.ZoneInfoCountryName, user.ZoneInfo, user.Locale, user.BirthDate,
		user.PhoneNumberCountryUniqueId, user.PhoneNumberCountryCallingCode, user.PhoneNumber,
		user.PhoneNumberVerified, user.AddressLine1, user.AddressLine2, user.AddressLocality,
		user.AddressRegion, user.AddressPostalCode, user.AddressCountry, user.PasswordHash,
		user.OTPSecretEncrypted, user.OTPEnabled, user.ForgotPasswordCodeEncrypted,
		user.ForgotPasswordCodeIssuedAt, user.ForgotPasswordCodeHash,
		user.Id)
	if err != nil {
		user.UpdatedAt = originalUpdatedAt
		return errs.Wrap(err, "unable to update user")
	}

	return nil
}

func (d *Database) GetUsersByIds(ctx context.Context, tx *sql.Tx, userIds []int64) (map[int64]record.User, error) {

	if len(userIds) == 0 {
		return nil, nil
	}

	var list []record.User

	err := forEachIdBatch(userIds, func(batch []int64) error {
		query := selectUsersWhere.text(d.Dialect) + inList(d.Dialect, "id", 1, len(batch))
		var err error
		list, err = queryAll(ctx, d, tx, list, query, int64Args(batch), scanUser, "user")
		return err
	})
	if err != nil {
		return nil, err
	}

	users := make(map[int64]record.User, len(list))
	for _, user := range list {
		users[user.Id] = user
	}

	return users, nil
}

func (d *Database) GetUserById(ctx context.Context, tx *sql.Tx, userId int64) (*record.User, error) {
	return queryOne(ctx, d, tx, selectUserById.text(d.Dialect), []any{userId}, scanUser, "user")
}

// GetUserByIdForUpdate reads the user as last committed and takes the row for the rest of the
// caller's transaction: a locking read, where GetUserById is a consistent one.
//
// The difference is MySQL's. Under InnoDB's default REPEATABLE READ every consistent read in a
// transaction reads the snapshot the first one established, so a plain read after waiting on a
// row lock still answers what the row held before the wait when anything was read earlier in the
// transaction; a locking read answers the latest committed row whatever was read before it. On
// PostgreSQL and SQL Server at READ COMMITTED each statement reads what was committed when it
// started, and SQLite has one writer at a time, so on those three only the lock is added (#498).
//
// The locking clause is the engine's own, so each version of selectUserByIdForUpdate spells it:
// FOR UPDATE on MySQL and PostgreSQL, the UPDLOCK and ROWLOCK table hints on SQL Server, which has
// no FOR UPDATE on a SELECT, and none on SQLite, which has no row locks.
//
// tx is required: without one the statement autocommits and the row is released before the
// caller can decide on what it read.
func (d *Database) GetUserByIdForUpdate(ctx context.Context, tx *sql.Tx, userId int64) (*record.User, error) {

	if tx == nil {
		return nil, errs.New("a locking read of a user requires a transaction: an autocommitted statement releases the row before the caller can decide on it")
	}

	return queryOne(ctx, d, tx, selectUserByIdForUpdate.text(d.Dialect), []any{userId}, scanUser, "user")
}

func (d *Database) UsersLoadPermissions(ctx context.Context, tx *sql.Tx, users []record.User) error {

	if users == nil {
		return nil
	}

	userIds := make([]int64, len(users))
	for i, user := range users {
		userIds[i] = user.Id
	}

	userPermissions, err := d.GetUserPermissionsByUserIds(ctx, tx, userIds)
	if err != nil {
		return err
	}

	permissionIds := make([]int64, len(userPermissions))
	for i, userPermission := range userPermissions {
		permissionIds[i] = userPermission.PermissionId
	}

	permissions, err := d.GetPermissionsByIds(ctx, tx, permissionIds)
	if err != nil {
		return err
	}

	// Create a map for faster permission lookups
	permissionMap := make(map[int64]record.Permission)
	for _, permission := range permissions {
		permissionMap[permission.Id] = permission
	}

	permissionsByUserId := make(map[int64][]record.Permission)
	for _, userPermission := range userPermissions {
		if permission, ok := permissionMap[userPermission.PermissionId]; ok {
			permissionsByUserId[userPermission.UserId] = append(permissionsByUserId[userPermission.UserId], permission)
		}
	}

	for i, user := range users {
		users[i].Permissions = permissionsByUserId[user.Id]
	}

	return nil
}

func (d *Database) UserLoadAttributes(ctx context.Context, tx *sql.Tx, user *record.User) error {

	if user == nil {
		return nil
	}

	userAttributes, err := d.GetUserAttributesByUserId(ctx, tx, user.Id)
	if err != nil {
		return err
	}

	user.Attributes = userAttributes

	return nil
}

func (d *Database) UserLoadPermissions(ctx context.Context, tx *sql.Tx, user *record.User) error {

	if user == nil {
		return nil
	}

	userPermissions, err := d.GetUserPermissionsByUserId(ctx, tx, user.Id)
	if err != nil {
		return err
	}

	permissionIds := make([]int64, len(userPermissions))
	for i, userPermission := range userPermissions {
		permissionIds[i] = userPermission.PermissionId
	}

	permissions, err := d.GetPermissionsByIds(ctx, tx, permissionIds)
	if err != nil {
		return err
	}

	user.Permissions = permissions

	return nil

}

func (d *Database) UsersLoadGroups(ctx context.Context, tx *sql.Tx, users []record.User) error {

	if users == nil {
		return nil
	}

	userIds := make([]int64, len(users))
	for i, user := range users {
		userIds[i] = user.Id
	}

	userGroups, err := d.GetUserGroupsByUserIds(ctx, tx, userIds)
	if err != nil {
		return err
	}

	groupIds := make([]int64, len(userGroups))
	for i, userGroup := range userGroups {
		groupIds[i] = userGroup.GroupId
	}

	groups, err := d.GetGroupsByIds(ctx, tx, groupIds)
	if err != nil {
		return err
	}

	groupsByUserId := make(map[int64][]record.Group)
	for _, userGroup := range userGroups {
		var group record.Group
		for _, g := range groups {
			if g.Id == userGroup.GroupId {
				group = g
				break
			}
		}
		groupsByUserId[userGroup.UserId] = append(groupsByUserId[userGroup.UserId], group)
	}

	for i, user := range users {
		users[i].Groups = groupsByUserId[user.Id]
	}

	return nil
}

func (d *Database) UserLoadGroups(ctx context.Context, tx *sql.Tx, user *record.User) error {

	if user == nil {
		return nil
	}

	userGroups, err := d.GetUserGroupsByUserId(ctx, tx, user.Id)
	if err != nil {
		return err
	}

	groupIds := make([]int64, len(userGroups))
	for i, group := range userGroups {
		groupIds[i] = group.GroupId
	}

	groups, err := d.GetGroupsByIds(ctx, tx, groupIds)
	if err != nil {
		return err
	}

	user.Groups = groups

	return nil
}

func (d *Database) GetUserByUsername(ctx context.Context, tx *sql.Tx, username string) (*record.User, error) {
	return queryOne(ctx, d, tx, selectUserByUsername.text(d.Dialect), []any{username}, scanUser, "user")
}

func (d *Database) GetUserBySubject(ctx context.Context, tx *sql.Tx, subject string) (*record.User, error) {

	user, err := queryOne(ctx, d, tx, selectUserBySubject.text(d.Dialect), []any{subject}, scanUser, "user")
	if err != nil {
		return nil, err
	}
	// The engine may have folded a value this lookup did not ask for; see
	// engineFoldedTheMatch. OpenID Connect Core section 2 makes sub case sensitive.
	//
	// user.Subject is the stored spelling rather than a normalisation of it: the column is
	// only ever written from uuid.New, which emits the canonical lowercase hyphenated
	// form, so every row holds that form already. Parsing and re-emitting the value here
	// would be exactly the re-normalisation this guard must not do (#278).
	if user != nil && engineFoldedTheMatch(user.Subject, subject) {
		return nil, nil
	}

	return user, nil
}

func (d *Database) GetUserByEmail(ctx context.Context, tx *sql.Tx, email string) (*record.User, error) {

	user, err := queryOne(ctx, d, tx, selectUserByEmail.text(d.Dialect), []any{email}, scanUser, "user")
	if err != nil {
		return nil, err
	}
	// The engine may have folded a value this lookup did not ask for; see
	// engineFoldedTheMatch. Both credential paths hand this a trimmed, lowercased address
	// and every write path stores one, so a stored address that differs from the one asked
	// for differs in something no engine should be resolving away.
	if user != nil && engineFoldedTheMatch(user.Email, email) {
		return nil, nil
	}

	return user, nil
}

// GetUserByForgotPasswordCodeHash finds the user holding an outstanding reset code, by
// an unsalted SHA-256 of that code. It is what lets the reset link carry the code and
// nothing else, so no email address travels in it and no part of the link ever needs
// percent-encoding (#112). Follows GetCodeByCodeHash, which looks a row up by the same
// kind of hash.
//
// Locating the row is not authenticating it. The caller still compares the submitted
// code against the encrypted column in constant time and checks the code's expiry; this
// only says which row to compare against.
func (d *Database) GetUserByForgotPasswordCodeHash(ctx context.Context, tx *sql.Tx, codeHash string) (*record.User, error) {

	// The dormant value is '' on every user with no code outstanding, so an empty
	// codeHash reaching the query would match one of them and hand the caller somebody
	// else's account. Refused here rather than trusted to callers, which is a second
	// line behind the fact that SHA-256 hex is always 64 characters and so no supplied
	// code can produce ''.
	if codeHash == "" {
		return nil, nil
	}

	return queryOne(ctx, d, tx, selectUserByForgotPasswordCodeHash.text(d.Dialect), []any{codeHash},
		scanUser, "user")
}

// likeEscapeChar is the character searchUsersFilter declares in its ESCAPE clause and the one
// escapeLikePattern writes. It is "!" rather than the usual backslash because the clause has
// to parse on all four engines: MySQL reads backslash escapes inside string literals, so
// ESCAPE '\' is ERROR 1064 there, while PostgreSQL, SQL Server and SQLite read it as one
// backslash. A character that is special nowhere avoids an engine branch entirely (#95).
const likeEscapeChar = '!'

// escapeLikePattern makes a user's search term match literally, by prefixing likeEscapeChar
// before every character LIKE would otherwise read as a wildcard. The caller wraps the %...%
// around the result, so those two are the only wildcards left.
//
// Without it the term is not data but a pattern the caller of the admin API chooses: a search
// for "%" matches every user in the deployment and returns them a page at a time, and
// "bob_smith" matches "bobxsmith" as well (#95).
//
// The four characters are the union of what the engines treat as special, not what any one of
// them does. "[" is here because SQL Server's LIKE has a third wildcard the other three do not,
// the [abc] character class, so leaving it would keep search meaning one thing there and another
// everywhere else, which is the divergence #283 exists to end. Escaping it is a plain literal on
// the other three, measured on all four. And likeEscapeChar escapes itself because an email
// local part may legally contain "!", so a term carrying one has to survive.
func escapeLikePattern(term string) string {
	var b strings.Builder
	b.Grow(len(term))
	// Byte-wise rather than rune-wise on purpose: every character escaped here is ASCII, and a
	// UTF-8 continuation byte is never one of them, so the multi-byte runes pass through whole.
	// One pass also means an escape this writes is never re-read as input and escaped again.
	for i := 0; i < len(term); i++ {
		switch c := term[i]; c {
		case likeEscapeChar, '%', '_', '[':
			b.WriteByte(likeEscapeChar)
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func (d *Database) SearchUsersPaginated(ctx context.Context, tx *sql.Tx, query string, page int, pageSize int) ([]record.User, int, error) {

	if page < 1 {
		page = 1
	}

	if pageSize < 1 {
		pageSize = 10
	}

	pageQuery, countQuery := selectUsersPage, countUsers
	var filterArgs []any
	if query != "" {
		pageQuery, countQuery = selectUsersSearchPage, countUsersSearch
		pattern := "%" + escapeLikePattern(query) + "%"
		filterArgs = []any{pattern, pattern, pattern, pattern, pattern, pattern}
	}

	pageArgs := append(append([]any{}, filterArgs...), pageSize, PageOffset(page, pageSize))
	users, err := queryAll(ctx, d, tx, nil, pageQuery.text(d.Dialect), pageArgs, scanUser, "user")
	if err != nil {
		return nil, 0, err
	}

	rows, err := d.QuerySQL(ctx, tx, countQuery.text(d.Dialect), filterArgs...)
	if err != nil {
		return nil, 0, errs.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var count int
	if rows.Next() {
		err = rows.Scan(&count)
		if err != nil {
			return nil, 0, errs.Wrap(err, "unable to scan count")
		}
	}
	if err := rows.Err(); err != nil {
		return nil, 0, errs.Wrap(err, "unable to read count results")
	}

	return users, count, nil
}

// DeleteUser removes the user and, by ON DELETE CASCADE, every row that references it.
// Refresh tokens are cleared explicitly first because SQL Server cannot cascade them: see
// deleteRefreshTokensByColumn.
//
// THE SESSION ROWS GO BEFORE BOTH OF THOSE, and the order is load bearing rather than
// tidiness to be folded back into the cascade. The cascade would remove the same rows one
// statement later, so nothing about the outcome changes; what changes is which row this
// transaction writes first. A termination of one of these sessions, the replay response to a
// reused code and an authorization ceremony all write the session row before anything that
// hangs off it, so a delete that starts on the same row waits behind them, or they behind it,
// instead of each holding half of what the other wants and reaching the retry (#139, #301).
// Measured clean against a ceremony holding the session row, in both orderings, on all four
// engines.
//
// No users row is acquired ahead of the loop. The final DELETE takes that row itself, and a
// credential change for the same user, which writes the users row first, is the one pair this
// shape can still deadlock with; that pair is answered by RunInTransaction rerunning the
// victim rather than by an ordering here.
func (d *Database) DeleteUser(ctx context.Context, tx *sql.Tx, userId int64) error {

	return d.inTransaction(ctx, tx, func(tx *sql.Tx) error {
		sessions, err := d.GetUserSessionsByUserId(ctx, tx, userId)
		if err != nil {
			return err
		}

		// Ordered by id so several sessions are always taken in the same sequence.
		// GetUserSessionsByUserId carries no ORDER BY of its own, so two transactions of
		// this shape could otherwise take the same two rows in opposite orders and deadlock
		// on nothing but the order the engine returned them in (#139).
		sort.Slice(sessions, func(i, j int) bool { return sessions[i].Id < sessions[j].Id })

		for i := range sessions {
			if deleteUserSessionErr := d.DeleteUserSession(ctx, tx, sessions[i].Id); deleteUserSessionErr != nil {
				return deleteUserSessionErr
			}
		}

		if deleteRefreshTokensErr := d.deleteRefreshTokensByColumn(ctx, tx, "user_id", userId); deleteRefreshTokensErr != nil {
			return deleteRefreshTokensErr
		}

		_, err = d.ExecSQL(ctx, tx, deleteUser.text(d.Dialect), userId)
		if err != nil {
			return errs.Wrap(err, "unable to delete user")
		}

		return nil
	})
}

// AcquireUserRow takes the user's row and holds it for the rest of the caller's transaction, the
// way AcquireUserSessionRow and AcquireClientRow hold theirs: one unconditional UPDATE on the row,
// which waits for any transaction writing it and makes the next writer wait for this one (#131).
//
// A refresh rotation takes this row first, and a credential change takes it first too, because
// its credential write and IncrementUserAuthStateGeneration both update it. Whichever arrives
// second waits, so a rotation's child is stamped from a token row no revocation can move before the
// child commits, and a revocation's sweep sees every child a rotation committed. Without it the two
// touch no common row until the child's insert, and a child can be inserted under a generation the
// revocation has already left behind.
//
// It assigns auth_state_generation to itself and never touches updated_at, unlike its two
// siblings: the admin console shows users.updated_at as "Last updated at", and a refresh is not an
// edit of the account. Assigning a column to its own value is the same text on every engine and
// locks the row on each, which the data tier shows on each.
//
// A user that is not there affects no rows and is not reported here, as AcquireClientRow does not
// report a missing client: there is nothing to hold, and the read that follows decides whether the
// user exists. RowsAffected could not report it anyway, since MySQL counts a row whose columns did
// not change as unaffected.
//
// tx is required: without one the statement autocommits and the row is released before the caller
// can use it.
func (d *Database) AcquireUserRow(ctx context.Context, tx *sql.Tx, userId int64) error {

	if tx == nil {
		return errs.New("acquiring a user row requires a transaction: an autocommitted statement releases the row before the caller can use it")
	}

	if userId == 0 {
		return errs.New("can't acquire a user row with an id of 0")
	}

	if _, err := d.ExecSQL(ctx, tx, acquireUserRow.text(d.Dialect), userId); err != nil {
		return errs.Wrap(err, "unable to acquire user row")
	}

	return nil
}

// IncrementUserAuthStateGeneration advances the user's authentication generation and
// returns the new value.
//
// This is the security boundary for #106: credentials authenticated under generation N
// cannot create or use authentication state once the user reaches N+1.
//
// **tx is required.** The increment and the read-back are two statements, because no
// single syntax for both increments-and-returns is portable across all four supported
// engines. Outside a transaction another increment can land between them, and this
// caller would then return the OTHER caller's generation and stamp it on the session and
// tokens it is preserving, which would leave them valid past the boundary the other
// credential change just established. A nil tx is refused rather than documented against,
// since every caller already owns a transaction: the credential write, the increment and
// the revocation sweep are one atomic unit by design.
//
// Deliberately not part of UpdateUser. auth_state_generation is tagged dont-update
// because credential handlers used to load the whole user and write it back, and leaving
// it in the ordinary update set would have let a request holding a stale model silently
// regress the boundary. No production code saves the whole row any more, and
// TestNoWholeRowUserSave holds it (#471); the tag stays because the data and integration
// tiers still seed fixtures through UpdateUser.
func (d *Database) IncrementUserAuthStateGeneration(ctx context.Context, tx *sql.Tx, userId int64) (int64, error) {

	if userId == 0 {
		return 0, errs.New("can't increment the auth state generation of user with id 0")
	}
	if tx == nil {
		return 0, errs.New("incrementing the auth state generation requires a transaction: the increment and the read-back must not be separable")
	}

	ub := d.Flavor.NewUpdateBuilder()
	ub.Update("users")
	ub.Set(
		"auth_state_generation = auth_state_generation + 1",
		ub.Assign("updated_at", time.Now().UTC()),
	)
	ub.Where(ub.Equal("id", userId))

	query, args := ub.BuildWithFlavor(d.Flavor)
	result, err := d.ExecSQL(ctx, tx, query, args...)
	if err != nil {
		return 0, errs.Wrap(err, "unable to increment user auth state generation")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, errs.Wrap(err, "unable to get rows affected when incrementing user auth state generation")
	}
	if rowsAffected != 1 {
		return 0, errs.New("user not found when incrementing auth state generation")
	}

	// Read back rather than computing the successor in Go: the increment happened in the
	// database, so this is the value that actually landed.
	sb := d.Flavor.NewSelectBuilder()
	sb.Select("auth_state_generation").From("users")
	sb.Where(sb.Equal("id", userId))
	query, args = sb.BuildWithFlavor(d.Flavor)

	var generation int64
	rows, err := d.QuerySQL(ctx, tx, query, args...)
	if err != nil {
		return 0, errs.Wrap(err, "unable to read back user auth state generation")
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		// Next answers false on a read error as well as on no row, and only rows.Err tells
		// them apart.
		if err := rows.Err(); err != nil {
			return 0, errs.Wrap(err, "unable to read back user auth state generation")
		}
		return 0, errs.New("user vanished while incrementing auth state generation")
	}
	if err := rows.Scan(&generation); err != nil {
		return 0, errs.Wrap(err, "unable to scan user auth state generation")
	}

	return generation, nil
}

// IncrementUserOtpConfigGeneration advances the user's OTP configuration generation and
// returns the value that landed.
//
// Called at every site that establishes or removes an authenticator, inside the same
// transaction as the write that changed it. That is the whole point of decision 2 in
// #242: a separate write whose error is merely surfaced leaves exactly the state the
// re-prompt exists to prevent, the authenticator on with the counter unmoved and every
// existing session's snapshot still matching, and the caller cannot recover from it
// because a retry is refused with OTP_ALREADY_ENABLED.
//
// Narrow rather than going through UpdateUser, which writes every non-tagged column:
// otp_config_generation is tagged dont-update precisely so a handler that loaded the
// user before a concurrent change cannot write the old counter back and discharge every
// session's obligation at once (#106, #242).
func (d *Database) IncrementUserOtpConfigGeneration(ctx context.Context, tx *sql.Tx, userId int64) (int64, error) {

	if userId == 0 {
		return 0, errs.New("can't increment the otp config generation of user with id 0")
	}
	if tx == nil {
		return 0, errs.New("incrementing the otp config generation requires a transaction: it must commit with the write that changed the authenticator")
	}

	ub := d.Flavor.NewUpdateBuilder()
	ub.Update("users")
	ub.Set(
		"otp_config_generation = otp_config_generation + 1",
		ub.Assign("updated_at", time.Now().UTC()),
	)
	ub.Where(ub.Equal("id", userId))

	query, args := ub.BuildWithFlavor(d.Flavor)
	result, err := d.ExecSQL(ctx, tx, query, args...)
	if err != nil {
		return 0, errs.Wrap(err, "unable to increment user otp config generation")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, errs.Wrap(err, "unable to get rows affected when incrementing user otp config generation")
	}
	if rowsAffected != 1 {
		return 0, errs.New("user not found when incrementing otp config generation")
	}

	// Read back rather than computing the successor in Go: the increment happened in the
	// database, so this is the value that actually landed. The browser enrollment caller
	// promotes this value onto the session it is about to create, and computing N+1 here
	// would promote a number a concurrent change may already have passed.
	sb := d.Flavor.NewSelectBuilder()
	sb.Select("otp_config_generation").From("users")
	sb.Where(sb.Equal("id", userId))
	query, args = sb.BuildWithFlavor(d.Flavor)

	var generation int64
	rows, err := d.QuerySQL(ctx, tx, query, args...)
	if err != nil {
		return 0, errs.Wrap(err, "unable to read back user otp config generation")
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		// Next answers false on a read error as well as on no row, and only rows.Err tells
		// them apart.
		if err := rows.Err(); err != nil {
			return 0, errs.Wrap(err, "unable to read back user otp config generation")
		}
		return 0, errs.New("user vanished while incrementing otp config generation")
	}
	if err := rows.Scan(&generation); err != nil {
		return 0, errs.Wrap(err, "unable to scan user otp config generation")
	}

	return generation, nil
}

// SetUserPasswordHash writes a new password hash and clears any outstanding
// forgot-password code in the same statement, so a reset cannot leave a usable code
// behind.
//
// Narrow rather than going through UpdateUser, which writes every non-tagged column:
// a credential handler that loaded the user before a concurrent admin disable would
// otherwise write Enabled back as it was and silently re-enable the account. (#106)
func (d *Database) SetUserPasswordHash(ctx context.Context, tx *sql.Tx, userId int64, passwordHash string) error {

	if userId == 0 {
		return errs.New("can't set the password hash of user with id 0")
	}

	ub := d.Flavor.NewUpdateBuilder()
	ub.Update("users")
	// The clears are raw SQL rather than Assign(..., nil). sqlbuilder sends an
	// untyped Go nil as a parameter, and the SQL Server driver types it as nvarchar,
	// which it then refuses to convert implicitly to varbinary(max):
	// "Implicit conversion from data type nvarchar to varbinary(max) is not allowed".
	// A literal NULL has no parameter type to get wrong and is portable across all four
	// engines.
	//
	// The hash clears to '' rather than NULL because its column is NOT NULL, '' being
	// the dormant value meaning no code outstanding. Clearing it matters for the same
	// reason clearing the encrypted code does: the expiry check would still refuse a
	// used code, but the row should not be findable by that hash at all (#112).
	ub.Set(
		ub.Assign("password_hash", passwordHash),
		"forgot_password_code_encrypted = NULL",
		"forgot_password_code_issued_at = NULL",
		"forgot_password_code_hash = ''",
		ub.Assign("updated_at", time.Now().UTC()),
	)
	ub.Where(ub.Equal("id", userId))

	query, args := ub.BuildWithFlavor(d.Flavor)
	_, err := d.ExecSQL(ctx, tx, query, args...)
	if err != nil {
		return errs.Wrap(err, "unable to set user password hash")
	}

	return nil
}

// SetUserProfile writes the user's eleven profile columns from user, and updated_at, and no
// other column. SetUserAddress and SetUserPhone below are its twins for the address and the
// phone. Each serves the self-service and the administrator's save of its group alike.
//
// Narrow rather than going through UpdateUser, for SetUserPasswordHash's reason: the saves
// load the user at the start of the request, and writing that read back would re-enable an
// account an administrator disabled under it, put back a password hash a concurrent change or
// reset replaced after its revocation had run, or undo a concurrent OTP change (#471). They are
// unconditional, so the last save of a group wins, as it always has: none of them depends on
// anything it read.
func (d *Database) SetUserProfile(ctx context.Context, tx *sql.Tx, user *record.User) error {
	if user.Id == 0 {
		return errs.New("can't set the profile of user with id 0")
	}
	return d.setUserColumns(ctx, tx, user, "profile", func(ub *sqlbuilder.UpdateBuilder) []string {
		return []string{
			ub.Assign("username", user.Username),
			ub.Assign("given_name", user.GivenName),
			ub.Assign("middle_name", user.MiddleName),
			ub.Assign("family_name", user.FamilyName),
			ub.Assign("nickname", user.Nickname),
			ub.Assign("website", user.Website),
			ub.Assign("gender", user.Gender),
			ub.Assign("birth_date", user.BirthDate),
			ub.Assign("zone_info_country_name", user.ZoneInfoCountryName),
			ub.Assign("zone_info", user.ZoneInfo),
			ub.Assign("locale", user.Locale),
		}
	})
}

// SetUserAddress writes the user's six address columns from user, and updated_at, and no other
// column, for SetUserProfile's reason.
func (d *Database) SetUserAddress(ctx context.Context, tx *sql.Tx, user *record.User) error {
	if user.Id == 0 {
		return errs.New("can't set the address of user with id 0")
	}
	return d.setUserColumns(ctx, tx, user, "address", func(ub *sqlbuilder.UpdateBuilder) []string {
		return []string{
			ub.Assign("address_line1", user.AddressLine1),
			ub.Assign("address_line2", user.AddressLine2),
			ub.Assign("address_locality", user.AddressLocality),
			ub.Assign("address_region", user.AddressRegion),
			ub.Assign("address_postal_code", user.AddressPostalCode),
			ub.Assign("address_country", user.AddressCountry),
		}
	})
}

// SetUserPhone writes the user's phone country, calling code, number and verified flag from
// user, and updated_at, and no other column, for SetUserProfile's reason. Whether the number
// is verified is the caller's to decide: the self-service save always clears it, and the
// administrator's keeps what the administrator sent.
func (d *Database) SetUserPhone(ctx context.Context, tx *sql.Tx, user *record.User) error {
	if user.Id == 0 {
		return errs.New("can't set the phone of user with id 0")
	}
	return d.setUserColumns(ctx, tx, user, "phone", func(ub *sqlbuilder.UpdateBuilder) []string {
		return []string{
			ub.Assign("phone_number_country_uniqueid", user.PhoneNumberCountryUniqueId),
			ub.Assign("phone_number_country_callingcode", user.PhoneNumberCountryCallingCode),
			ub.Assign("phone_number", user.PhoneNumber),
			ub.Assign("phone_number_verified", user.PhoneNumberVerified),
		}
	})
}

// setUserColumns is the one statement the column-group writes share: the assignments
// columns builds, updated_at, keyed on the user's id. It sets user.UpdatedAt to what it stored
// once the statement succeeds, as UpdateUser did, so a response built from user reports it.
func (d *Database) setUserColumns(ctx context.Context, tx *sql.Tx, user *record.User, group string,
	columns func(ub *sqlbuilder.UpdateBuilder) []string) error {

	now := time.Now().UTC()
	ub := d.Flavor.NewUpdateBuilder()
	ub.Update("users")
	ub.Set(append(columns(ub), ub.Assign("updated_at", now))...)
	ub.Where(ub.Equal("id", user.Id))

	query, args := ub.BuildWithFlavor(d.Flavor)
	if _, err := d.ExecSQL(ctx, tx, query, args...); err != nil {
		return errs.Wrapf(err, "unable to set user %s", group)
	}

	user.UpdatedAt = sql.NullTime{Time: now, Valid: true}
	return nil
}

// SetUserEmail writes the administrator's email change: the address and the verified flag from
// user, a cleared verification code and issued-at, a reset code cleared when the address changes,
// and updated_at, and no other column. It sets user.UpdatedAt to what it stored, as SetUserProfile does.
//
// Narrow rather than going through UpdateUser, for SetUserProfile's reason (#471). Unconditional,
// unlike TrySetUserEmail: the administrator sends the verified flag rather than having it cleared,
// notifies nobody, and nothing it writes depends on what it read, so the last change wins, as it
// always has. A taken address arrives as ErrUniqueViolation through ExecSQL.
//
// The reset code goes with the address, as it does in TrySetUserEmail: a code belongs to the
// address it was mailed to, so a link mailed to the previous address, an administrator's setup
// email sent to a mistyped one included, must stop setting the account's password (#471 decision
// 6). It stays when the row already holds the address written: the console sends the address with
// the verified flag, and marking verified the address a setup email was just mailed to, or saving
// the form unchanged, changes no address and must leave that link working.
func (d *Database) SetUserEmail(ctx context.Context, tx *sql.Tx, user *record.User) error {
	if user.Id == 0 {
		return errs.New("can't set the email of user with id 0")
	}
	return d.setUserColumns(ctx, tx, user, "email", func(ub *sqlbuilder.UpdateBuilder) []string {
		// The clears are raw SQL rather than Assign(..., nil), for the reason SetUserPasswordHash
		// gives, and the reset code's hash clears to its dormant '' for the same reason there.
		//
		// The reset code keeps its value when the row already holds the address being written, so
		// it is compared against the row's email as the statement finds it, not the request's read.
		// The three CASEs come before the email assignment because MySQL evaluates a single-table
		// UPDATE's assignments left to right, each seeing the ones before it; every other engine
		// reads the row as it was before the statement whatever the order.
		sameEmail := "email = " + ub.Var(user.Email)
		return []string{
			"forgot_password_code_encrypted = CASE WHEN " + sameEmail +
				" THEN forgot_password_code_encrypted ELSE NULL END",
			"forgot_password_code_issued_at = CASE WHEN " + sameEmail +
				" THEN forgot_password_code_issued_at ELSE NULL END",
			"forgot_password_code_hash = CASE WHEN " + sameEmail +
				" THEN forgot_password_code_hash ELSE '' END",
			ub.Assign("email", user.Email),
			ub.Assign("email_verified", user.EmailVerified),
			"email_verification_code_encrypted = NULL",
			"email_verification_code_issued_at = NULL",
		}
	})
}

// TrySetUserEmail moves a user's address from fromEmail to toEmail and, in the same
// statement, clears the verified flag, any pending verification code and any outstanding reset
// code: the new address has not been verified, a code issued for the previous one must not verify
// it, and a reset link mailed to the previous one must not set the account's password (#471
// decision 6). It reports whether it made the change.
//
// Compare-and-set on the address and the verified flag the caller read, for the reason
// TrySetUserEnabled gives. The self-service email change reads the user, checks the password,
// and notifies the previous address when that address was verified; with an unconditional
// write, concurrent changes from one read each believed they had made the change and each
// queued a notice, so one verification bought as many mails as requests sent at once. Now one
// of them matches the row and the rest match nothing (#404).
//
// The code's issued-at is kept. It is what the verification resend cooldown reads, and that
// cooldown bounds the account rather than the address: clearing it here let a caller set any
// address, have a code mailed to it, change away and back, and have it mailed again at once,
// as often as they liked. A stale issued-at verifies nothing, because there is no code left
// for it to date (#404).
//
// Narrow rather than going through UpdateUser, for SetUserPasswordHash's reason: the
// self-service email change loads the user at the start of the request, and writing that
// snapshot back would re-enable an account an administrator disabled under it, put back a
// password hash a concurrent change or reset replaced after its revocation had run, or
// undo a concurrent OTP change (#404). A taken address arrives as ErrUniqueViolation through
// ExecSQL, as it does on UpdateUser.
func (d *Database) TrySetUserEmail(ctx context.Context, tx *sql.Tx, userId int64, fromEmail string,
	fromVerified bool, toEmail string) (bool, error) {

	if userId == 0 {
		return false, errs.New("can't set the email of user with id 0")
	}
	// The same address in and out would leave the row as it was, and MySQL counts a row it
	// matched but did not change as unaffected, so the answer would depend on the engine. The
	// caller answers that request without writing.
	if fromEmail == toEmail {
		return false, errs.New("can't move an email to the address it already has")
	}

	ub := d.Flavor.NewUpdateBuilder()
	ub.Update("users")
	// The clears are raw SQL rather than Assign(..., nil), for the reason SetUserPasswordHash
	// gives: the SQL Server driver types an untyped Go nil as nvarchar and refuses to convert it
	// to varbinary(max).
	ub.Set(
		ub.Assign("email", toEmail),
		ub.Assign("email_verified", false),
		"email_verification_code_encrypted = NULL",
		"forgot_password_code_encrypted = NULL",
		"forgot_password_code_issued_at = NULL",
		"forgot_password_code_hash = ''",
		ub.Assign("updated_at", time.Now().UTC()),
	)
	ub.Where(
		ub.Equal("id", userId),
		ub.Equal("email", fromEmail),
		ub.Equal("email_verified", fromVerified),
	)

	query, args := ub.BuildWithFlavor(d.Flavor)
	result, err := d.ExecSQL(ctx, tx, query, args...)
	if err != nil {
		return false, errs.Wrap(err, "unable to set user email")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, errs.Wrap(err, "unable to get rows affected when setting user email")
	}

	// The address always changes, so a matched row is a changed row on all four engines.
	return rowsAffected == 1, nil
}

// TryStoreEmailVerificationCode stores a freshly issued verification code, encrypted, and
// when it was issued, only while the account still holds email, unverified, and no code was
// issued after issuedNotAfter. It reports whether it did.
//
// This is the resend cooldown, and it has to be one statement. The send used to read the
// issued-at, decide, and write the whole row back, so concurrent sends all read the same old
// issued-at, all passed, and all mailed a code: the cooldown bounded nothing the caller could
// not parallelise past, and the account chooses the address the code is mailed to (#404). The
// address is in the predicate too, so a code is never stored for an address the account moved
// away from while the code was being issued, and the row the request loaded is never written
// back, for TrySetUserEmail's reason.
func (d *Database) TryStoreEmailVerificationCode(ctx context.Context, tx *sql.Tx, userId int64, email string,
	codeEncrypted []byte, issuedAt time.Time, issuedNotAfter time.Time) (bool, error) {

	if userId == 0 {
		return false, errs.New("can't store an email verification code for user with id 0")
	}
	if len(codeEncrypted) == 0 {
		return false, errs.New("can't store an empty email verification code")
	}

	ub := d.Flavor.NewUpdateBuilder()
	ub.Update("users")
	ub.Set(
		ub.Assign("email_verification_code_encrypted", codeEncrypted),
		ub.Assign("email_verification_code_issued_at", issuedAt),
		ub.Assign("updated_at", time.Now().UTC()),
	)
	ub.Where(
		ub.Equal("id", userId),
		ub.Equal("email", email),
		ub.Equal("email_verified", false),
		ub.Or(
			ub.IsNull("email_verification_code_issued_at"),
			ub.LessEqualThan("email_verification_code_issued_at", issuedNotAfter),
		),
	)

	query, args := ub.BuildWithFlavor(d.Flavor)
	result, err := d.ExecSQL(ctx, tx, query, args...)
	if err != nil {
		return false, errs.Wrap(err, "unable to store email verification code")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, errs.Wrap(err, "unable to get rows affected when storing email verification code")
	}

	// A fresh ciphertext always differs from whatever the row carried, so a matched row is a
	// changed row on all four engines, as in TryStoreForgotPasswordCode.
	return rowsAffected == 1, nil
}

// TryIssueEmailVerificationCode stores the code the administrator generates, encrypted, and when
// it was issued, and unverifies the address, only while the account still holds email, the
// address the request read. It reports whether it did.
//
// Conditional because the generation reports the address, in its response and its audit record,
// as the one the code was issued for: a code stored after a concurrent change had moved the
// account to another address would be answered with an address it was never stored for (#471
// decision 1). There is no cooldown in the predicate, unlike TryStoreEmailVerificationCode's: an
// administrator reads the code from the response rather than having it mailed, and generating a
// second one replaces the first, as it always has. Narrow rather than writing back the row the
// request loaded, for SetUserProfile's reason.
func (d *Database) TryIssueEmailVerificationCode(ctx context.Context, tx *sql.Tx, userId int64, email string,
	codeEncrypted []byte, issuedAt time.Time) (bool, error) {

	if userId == 0 {
		return false, errs.New("can't issue an email verification code for user with id 0")
	}
	if len(codeEncrypted) == 0 {
		return false, errs.New("can't issue an empty email verification code")
	}

	ub := d.Flavor.NewUpdateBuilder()
	ub.Update("users")
	ub.Set(
		ub.Assign("email_verified", false),
		ub.Assign("email_verification_code_encrypted", codeEncrypted),
		ub.Assign("email_verification_code_issued_at", issuedAt),
		ub.Assign("updated_at", time.Now().UTC()),
	)
	ub.Where(
		ub.Equal("id", userId),
		ub.Equal("email", email),
	)

	query, args := ub.BuildWithFlavor(d.Flavor)
	result, err := d.ExecSQL(ctx, tx, query, args...)
	if err != nil {
		return false, errs.Wrap(err, "unable to issue email verification code")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, errs.Wrap(err, "unable to get rows affected when issuing email verification code")
	}

	// A fresh ciphertext always differs from whatever the row carried, so a matched row is a
	// changed row on all four engines, as in TryStoreEmailVerificationCode.
	return rowsAffected == 1, nil
}

// TryVerifyUserEmail marks a user's address verified and clears the code, only while the
// account still holds email, unverified, and codeEncrypted is still the pending code. It
// reports whether it did.
//
// codeEncrypted is the ciphertext the caller decrypted and compared, so the predicate says the
// code that was checked is the code being spent: one the account replaced with a new send, or
// lost to an email change, between the comparison and this write matches nothing, and of two
// submissions of one code only one verifies. The issued-at stays for the resend cooldown.
// Narrow rather than writing back the row the request loaded, which would re-enable an account
// an administrator disabled under it, or put back an address a concurrent change replaced
// (#404).
func (d *Database) TryVerifyUserEmail(ctx context.Context, tx *sql.Tx, userId int64, email string,
	codeEncrypted []byte) (bool, error) {

	if userId == 0 {
		return false, errs.New("can't verify the email of user with id 0")
	}
	// An empty ciphertext is the dormant value, and NULL compares equal to nothing anyway.
	if len(codeEncrypted) == 0 {
		return false, errs.New("can't verify an email against an empty code")
	}

	ub := d.Flavor.NewUpdateBuilder()
	ub.Update("users")
	ub.Set(
		ub.Assign("email_verified", true),
		"email_verification_code_encrypted = NULL",
		ub.Assign("updated_at", time.Now().UTC()),
	)
	ub.Where(
		ub.Equal("id", userId),
		ub.Equal("email", email),
		ub.Equal("email_verified", false),
		ub.Equal("email_verification_code_encrypted", codeEncrypted),
	)

	query, args := ub.BuildWithFlavor(d.Flavor)
	result, err := d.ExecSQL(ctx, tx, query, args...)
	if err != nil {
		return false, errs.Wrap(err, "unable to verify user email")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, errs.Wrap(err, "unable to get rows affected when verifying user email")
	}

	// email_verified always moves from false to true, so a matched row is a changed row on all
	// four engines.
	return rowsAffected == 1, nil
}

// TryConsumeForgotPasswordCode writes a new password hash, claims the outstanding reset
// code and marks the address verified in one conditional UPDATE, reporting whether this
// call is the one that made the transition. The claim is codeHash matching what the row still carries, so a second
// call with the same hash matches no row, returns false, and leaves the first call's
// password in place.
//
// Compare-and-set for the same reason MarkCodeAsUsed, TrySetUserEnabled and
// TryConsumeUserOTPStep are: a read-then-unconditional-write lets two concurrent
// requests both believe they performed the transition. Here that would mean two
// submissions of one reset link both setting a password, with the later one winning.
//
// **Why the predicate is the code hash and not just the user id.** The reset flow keeps
// its "this code was validated" marker in the session. A marker naming only the durable
// user id would outlive the password write, a newly issued code, and any other password
// change, for as long as the session holding it lives. Naming the hash and claiming it
// here is what keeps a replayed marker from setting a password a second time, which is
// the property the encrypted column's NULLing already gives the pre-#112 flow.
//
// The original argument for this was stronger and has expired: the session used to be a
// client-side encrypted cookie, so clearing the marker could not invalidate a copy an
// attacker kept. The session is a database row now and clearing it reaches every copy
// (#266). The predicate stays because clearing at the end of a flow says nothing about a
// code consumed or reissued inside a session nobody cleared.
//
// **A false return is not proof of replay**, the same imprecision MarkCodeAsUsed
// documents: the code may have been consumed already, cleared by an unrelated password
// change, superseded by a newly issued one, the account may have been disabled, or the user
// row may be gone. The caller
// responds identically in all of them.
//
// Separate from SetUserPasswordHash rather than a fourth parameter on it: its other two
// callers, the admin user-create path and the account password-change API, hold no
// outstanding code and would have to pass a meaningless predicate.
func (d *Database) TryConsumeForgotPasswordCode(ctx context.Context, tx *sql.Tx, userId int64, codeHash string,
	passwordHash string) (bool, error) {

	if userId == 0 {
		return false, errs.New("can't consume a forgot password code for user with id 0")
	}
	// An error rather than a benign false, and it is not defensive: '' is the dormant
	// value on every user with no code outstanding, so an empty predicate would claim
	// one of them and set a password on an account nobody asked to reset.
	if codeHash == "" {
		return false, errs.New("can't consume an empty forgot password code hash")
	}

	ub := d.Flavor.NewUpdateBuilder()
	ub.Update("users")
	// The same narrow write SetUserPasswordHash performs, plus the hash clear. Narrow
	// rather than a full-row UpdateUser so a concurrent admin disable cannot be undone
	// by it (#106). See SetUserPasswordHash for why the clears are raw SQL.
	//
	// It also marks the address verified, and drops any verification code outstanding for
	// it. A reset link is sent to the address the row holds and dies when that address
	// changes, so redeeming it proves the user reads that mailbox, as entering a
	// verification code does. A forgot-password link only ever goes to a verified address,
	// so this changes nothing there; the link an administrator has emailed to a new user
	// goes to an unverified one, which until this stayed unverified after the user set
	// their password through it, and so could not recover a password later.
	ub.Set(
		ub.Assign("password_hash", passwordHash),
		"forgot_password_code_encrypted = NULL",
		"forgot_password_code_issued_at = NULL",
		"forgot_password_code_hash = ''",
		ub.Assign("email_verified", true),
		"email_verification_code_encrypted = NULL",
		"email_verification_code_issued_at = NULL",
		ub.Assign("updated_at", time.Now().UTC()),
	)
	// enabled is in the predicate so a disable landing between the reset handler's read and
	// this write refuses the reset instead of setting a password (#404 decision 2).
	ub.Where(
		ub.Equal("id", userId),
		ub.Equal("forgot_password_code_hash", codeHash),
		ub.Equal("enabled", true),
	)

	query, args := ub.BuildWithFlavor(d.Flavor)
	result, err := d.ExecSQL(ctx, tx, query, args...)
	if err != nil {
		return false, errs.Wrap(err, "unable to consume forgot password code")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, errs.Wrap(err, "unable to get rows affected when consuming forgot password code")
	}

	// rowsAffected == 1 means this call transitioned the row on all four engines: the
	// predicate requires a non-empty hash and the SET clears it to '', so the row always
	// changes and MySQL's changed-rows accounting agrees with matched rows. That is the
	// trap RevokeCodesBySessionIdentifier documents, and it does not bite here.
	return rowsAffected == 1, nil
}

// TryStoreForgotPasswordCode stores an issued reset code (its encrypted form, the hash the
// link finds it by, and when it was issued) only while the account is still enabled, its
// address still verified and still the one the request looked up, reporting whether it did.
//
// Narrow for SetUserEmail's reason: forgot-password used to write back the whole row it loaded
// at the start of the request, which re-enabled an account an administrator disabled meanwhile.
// Conditional so that the same disable, an address change or anything else that unverified the
// address since the lookup leaves the row untouched and the request mails nothing (#404
// decision 2). A false return does not say which of them happened.
func (d *Database) TryStoreForgotPasswordCode(ctx context.Context, tx *sql.Tx, userId int64, email string,
	codeEncrypted []byte, codeHash string, issuedAt time.Time) (bool, error) {

	if userId == 0 {
		return false, errs.New("can't store a forgot password code for user with id 0")
	}
	// '' is the dormant value meaning no code outstanding, so a code stored with it could
	// never be found by its link.
	if codeHash == "" {
		return false, errs.New("can't store an empty forgot password code hash")
	}

	ub := d.Flavor.NewUpdateBuilder()
	ub.Update("users")
	ub.Set(
		ub.Assign("forgot_password_code_encrypted", codeEncrypted),
		ub.Assign("forgot_password_code_hash", codeHash),
		ub.Assign("forgot_password_code_issued_at", issuedAt),
		ub.Assign("updated_at", time.Now().UTC()),
	)
	// Bound Go bools, as TrySetUserEnabled does against users.enabled.
	ub.Where(
		ub.Equal("id", userId),
		ub.Equal("email", email),
		ub.Equal("enabled", true),
		ub.Equal("email_verified", true),
	)

	query, args := ub.BuildWithFlavor(d.Flavor)
	result, err := d.ExecSQL(ctx, tx, query, args...)
	if err != nil {
		return false, errs.Wrap(err, "unable to store forgot password code")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, errs.Wrap(err, "unable to get rows affected when storing forgot password code")
	}

	// rowsAffected == 1 means the row was stored on all four engines: a fresh code's hash
	// always differs from whatever the row carried, so the row always changes and MySQL's
	// changed-rows accounting agrees with matched rows.
	return rowsAffected == 1, nil
}

// TrySetUserEnabled flips enabled from expected to desired, reporting whether this
// call is the one that made the transition. A false return means the row was already
// in the desired state (or the user does not exist), which callers treat as "nothing
// to do" rather than an error.
//
// Compare-and-set for the same reason MarkCodeAsUsed is: a read-then-unconditional-write
// lets two concurrent requests both believe they performed the transition. The disable
// direction's return is what gates the revocation sweep, so a second disable of an
// already-disabled account does not sweep or audit again.
//
// Covers both directions on purpose. The endpoint behind it serves enable as well as
// disable, and leaving enable on the full-row UpdateUser would keep the clobbering
// problem alive in half of it. (#106)
func (d *Database) TrySetUserEnabled(ctx context.Context, tx *sql.Tx, userId int64, expected bool, desired bool) (bool, error) {

	if userId == 0 {
		return false, errs.New("can't set enabled on user with id 0")
	}

	ub := d.Flavor.NewUpdateBuilder()
	ub.Update("users")
	ub.Set(
		ub.Assign("enabled", desired),
		ub.Assign("updated_at", time.Now().UTC()),
	)
	ub.Where(
		ub.Equal("id", userId),
		ub.Equal("enabled", expected),
	)

	query, args := ub.BuildWithFlavor(d.Flavor)
	result, err := d.ExecSQL(ctx, tx, query, args...)
	if err != nil {
		return false, errs.Wrap(err, "unable to set user enabled")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, errs.Wrap(err, "unable to get rows affected when setting user enabled")
	}

	return rowsAffected == 1, nil
}

// TryConsumeUserOTPStep records step as the user's most recently consumed TOTP time
// step, but only if it is strictly newer than what is stored, and reports whether
// this call is the one that made the transition. Compare-and-set for the same reason
// MarkCodeAsUsed is: accepting a code and recording it as used must not be separable,
// or two concurrent submissions of one code both pass. The single conditional UPDATE
// is the claim and the replay check at once (#111).
//
// This is the enrolment claim, and it names no authenticator state: enrolment claims
// before the establish, while otp_enabled is still off, and the establish is itself the
// compare-and-set on the authenticator the request read (#111 decision 10, #471
// decision 2). Verification claims go through TryConsumeEnrolledUserOTPStep.
//
// **A false return is not proof of replay.** It means no row transitioned, and the
// causes are not distinguishable here: the step is at or below the stored one, the
// user row is gone, or, at a verification site, the authenticator was removed or
// replaced under this request. The caller loaded the user moments earlier, so replay
// is overwhelmingly the cause, and the response is identical either way. This is the
// same imprecision MarkCodeAsUsed documents about its own three-way false.
//
// **A query error is not benign.** It returns (false, err) and the caller responds
// 500. Collapsing a database fault into "not consumed" would refuse valid codes;
// collapsing it into "consumed" would accept replays for the duration of the fault.
//
// tx is optional, as on MarkCodeAsUsed: this is one statement and nothing is read
// back, so the transaction requirement IncrementUserAuthStateGeneration documents
// does not apply.
//
// Deliberately not part of UpdateUser. last_otp_step is tagged dont-update because a
// whole-row write from a snapshot read before the claim would write the pre-claim value
// over it.
func (d *Database) TryConsumeUserOTPStep(ctx context.Context, tx *sql.Tx, userId int64, step int64) (bool, error) {
	return d.consumeUserOTPStep(ctx, tx, userId, step, nil)
}

// TryConsumeEnrolledUserOTPStep is the verification claim: TryConsumeUserOTPStep's
// claim, with the authenticator the passcode was checked against added to the
// predicate. A verification claim asserts a factor, and that assertion is only true of
// the authenticator the passcode matched.
//
// `otp_enabled = true` refuses a request that loaded the user before a concurrent
// removal, which would otherwise be issued a token naming amr "otp" for an
// authenticator that had just been removed (#111 decision 10). `otp_config_generation =
// expectedGeneration`, the generation read with the secret, refuses one that loaded the
// user before the authenticator was removed and another established in its place: the
// row reads enabled again and the removal returned the marker to 0, so the enabled term
// alone lets the stale passcode claim a step and assert otp for a secret that no longer
// exists. Every establish and every remove advances the generation in its own
// transaction, so a matching generation is the authenticator the request read (#144,
// #471 decision 3).
//
// The claim also carries the consecutive-failure count's two rules, in the same
// statement: it returns otp_consecutive_failures to 0, and it refuses while the count
// stands at record.OtpConsecutiveFailureLimit, where the authenticator is disabled until
// it is rebound (NIST SP 800-63B section 3.2.2, #489).
//
// Everything else, the false and the error, is as TryConsumeUserOTPStep documents.
func (d *Database) TryConsumeEnrolledUserOTPStep(ctx context.Context, tx *sql.Tx, userId int64, step int64,
	expectedGeneration int64) (bool, error) {
	return d.consumeUserOTPStep(ctx, tx, userId, step, &expectedGeneration)
}

// consumeUserOTPStep is the one conditional UPDATE both claims run. enrolledAt is nil for
// the enrolment claim and the generation read with the secret for the verification claim.
func (d *Database) consumeUserOTPStep(ctx context.Context, tx *sql.Tx, userId int64, step int64,
	enrolledAt *int64) (bool, error) {

	if userId == 0 {
		return false, errs.New("can't consume an OTP step for user with id 0")
	}

	ub := d.Flavor.NewUpdateBuilder()
	ub.Update("users")
	ub.Set(
		ub.Assign("last_otp_step", step),
		ub.Assign("updated_at", time.Now().UTC()),
	)
	if enrolledAt != nil {
		// The verification claim returns the consecutive-failure count to 0 in the same
		// statement, which is the "disregard any previous failed attempts" NIST SP 800-63B
		// section 3.2.2 asks of a verifier, done beside the claim rather than after it so
		// no committed state has a step consumed and the attempts before it still
		// standing (#489). SetMore rather than a second Set, which replaces: the claim
		// must keep the step it came for.
		ub.SetMore(ub.Assign("otp_consecutive_failures", 0))
	}
	// The strict inequality is what refuses a replay: the second submission of one code
	// carries the step already stored, so it matches no row. rowsAffected == 1 means
	// this call transitioned the row on all four engines, because matching the WHERE
	// implies the assigned step differs from the stored one, so MySQL's changed-rows
	// accounting agrees with matched rows. That is the trap
	// RevokeCodesBySessionIdentifier documents, and it does not bite here.
	predicates := []string{
		ub.Equal("id", userId),
		ub.LessThan("last_otp_step", step),
	}
	if enrolledAt != nil {
		// A bound Go bool, as TrySetUserEnabled does against users.enabled. The two
		// columns carry the same type on every engine, so nothing here is dialect
		// specific.
		predicates = append(predicates,
			ub.Equal("otp_enabled", true),
			ub.Equal("otp_config_generation", *enrolledAt),
			// The count's limit is part of the claim, not a read before it: an
			// authenticator disabled at record.OtpConsecutiveFailureLimit stays disabled
			// even to a request that loaded the user before the count reached it, the
			// same way the generation term refuses a replaced authenticator (#489).
			ub.LessThan("otp_consecutive_failures", record.OtpConsecutiveFailureLimit),
		)
	}
	ub.Where(predicates...)

	query, args := ub.BuildWithFlavor(d.Flavor)
	result, err := d.ExecSQL(ctx, tx, query, args...)
	if err != nil {
		return false, errs.Wrap(err, "unable to consume user OTP step")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, errs.Wrap(err, "unable to get rows affected when consuming user OTP step")
	}

	return rowsAffected == 1, nil
}

// ResetUserOTPStep returns the user's consumed-step marker to 0, meaning no code has
// been consumed. Called when OTP is disabled: the marker belongs to the enrolled
// authenticator, and it is the only remedy if a clock jump strands the marker in the
// future, where every code would be refused until wall time caught up (#111
// decision 4).
//
// **Callers must reset AFTER the write that clears otp_enabled, not before.** Neither
// order needs a transaction, but reversed there is a window in which the marker reads
// 0 while the authenticator still reads enabled, and a verification request that
// loaded the old state claims an already-consumed step through it, which is precisely
// the hole TryConsumeEnrolledUserOTPStep's otp_enabled term closes.
//
// Not a bypass: self-service disable verifies the password first, admin disable
// requires authserver:manage, and re-enrolling requires possession of a fresh secret.
//
// Resetting an already-reset user is not a failure, so this reports only an error
// rather than whether anything changed. Nothing gates on the transition, unlike
// TrySetUserEnabled's disable direction.
func (d *Database) ResetUserOTPStep(ctx context.Context, tx *sql.Tx, userId int64) error {

	if userId == 0 {
		return errs.New("can't reset the OTP step of user with id 0")
	}

	ub := d.Flavor.NewUpdateBuilder()
	ub.Update("users")
	ub.Set(
		ub.Assign("last_otp_step", 0),
		ub.Assign("updated_at", time.Now().UTC()),
	)
	ub.Where(ub.Equal("id", userId))

	query, args := ub.BuildWithFlavor(d.Flavor)
	_, err := d.ExecSQL(ctx, tx, query, args...)
	if err != nil {
		return errs.Wrap(err, "unable to reset user OTP step")
	}

	return nil
}

// IncrementUserOtpConsecutiveFailures advances the count of consecutive failed attempts
// against the user's enrolled authenticator by one, stopping at
// record.OtpConsecutiveFailureLimit, where the authenticator is disabled until it is
// rebound (NIST SP 800-63B section 3.2.2, #489), and reports whether this call is the one
// that moved the count to the limit, so the caller audits the disable exactly once.
//
// The count is bound to the authenticator the refused code was checked against, as the
// verification claim is: the statements match only while otp_enabled is true and
// otp_config_generation is still expectedGeneration, the generation the caller read
// beside the seed. A request in flight while the authenticator is removed, or removed
// and replaced, therefore charges nothing to the replacement, which no failed attempt
// was tried against.
//
// Two statements, each a compare-and-set, rather than an increment and a read-back: the
// first advances a count still short of the last step, and only when it matches nothing
// does the second move the count from the limit's last step to the limit. Exactly one
// call can match that second statement, which is what makes "this call disabled it" a
// fact of the row rather than of the caller's snapshot, and neither statement needs a
// transaction to hold it with, so tx stays optional, as on TryConsumeUserOTPStep. A
// count cleared by a success landing between the two matches neither, and this attempt,
// which came before that success, is disregarded with the others.
//
// A row that matches nothing is not an error, unlike IncrementUserOtpConfigGeneration's
// missing row: a user already at the limit matches no row, and so does an authenticator
// removed or replaced since the read, or a row deleted, and none is a failure. The
// ceiling is the load-bearing half -- an attacker grinding a disabled authenticator must
// not move the row at all.
//
// updated_at is left alone, for AcquireUserRow's reason: a refused code is not an edit of
// the account, and the column is the OIDC updated_at claim and the console's "Last
// updated at", which anyone holding the password could otherwise move at will.
//
// Deliberately not part of UpdateUser. otp_consecutive_failures is tagged dont-update
// because a whole-row write from a model read before the refusal would write the
// pre-attempt count back over the row's, silently unlocking a disabled authenticator.
func (d *Database) IncrementUserOtpConsecutiveFailures(ctx context.Context, tx *sql.Tx, userId int64,
	expectedGeneration int64) (bool, error) {

	if userId == 0 {
		return false, errs.New("can't increment the OTP consecutive failures of user with id 0")
	}

	advanced, err := d.casUserOtpConsecutiveFailures(ctx, tx, userId, expectedGeneration,
		func(ub *sqlbuilder.UpdateBuilder) string {
			return "otp_consecutive_failures = otp_consecutive_failures + 1"
		},
		func(ub *sqlbuilder.UpdateBuilder) string {
			return ub.LessThan("otp_consecutive_failures", record.OtpConsecutiveFailureLimit-1)
		})
	if err != nil || advanced {
		return false, err
	}

	return d.casUserOtpConsecutiveFailures(ctx, tx, userId, expectedGeneration,
		func(ub *sqlbuilder.UpdateBuilder) string {
			return ub.Assign("otp_consecutive_failures", record.OtpConsecutiveFailureLimit)
		},
		func(ub *sqlbuilder.UpdateBuilder) string {
			return ub.Equal("otp_consecutive_failures", record.OtpConsecutiveFailureLimit-1)
		})
}

// casUserOtpConsecutiveFailures is one of IncrementUserOtpConsecutiveFailures' two
// statements: the assignment applied where the row still holds the authenticator at
// expectedGeneration and the count matches countTerm, reporting whether it matched.
func (d *Database) casUserOtpConsecutiveFailures(ctx context.Context, tx *sql.Tx, userId int64,
	expectedGeneration int64, assignment, countTerm func(*sqlbuilder.UpdateBuilder) string) (bool, error) {

	ub := d.Flavor.NewUpdateBuilder()
	ub.Update("users")
	ub.Set(assignment(ub))
	ub.Where(
		ub.Equal("id", userId),
		ub.Equal("otp_enabled", true),
		ub.Equal("otp_config_generation", expectedGeneration),
		countTerm(ub),
	)

	query, args := ub.BuildWithFlavor(d.Flavor)
	result, err := d.ExecSQL(ctx, tx, query, args...)
	if err != nil {
		return false, errs.Wrap(err, "unable to increment user OTP consecutive failures")
	}
	// Both assignments change the count, so a matched row is a changed row and MySQL's
	// changed-rows count agrees with the other engines' matched-rows count here.
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, errs.Wrap(err, "unable to get rows affected when incrementing user OTP consecutive failures")
	}
	return rowsAffected == 1, nil
}

// ClearUserOtpConsecutiveFailures returns the consecutive-failure count to 0, the state
// of a user no failed attempt has been counted against. Called inside the same
// transaction as the write that binds a fresh authenticator, because rebinding is the
// one path back from record.OtpConsecutiveFailureLimit: a count committed with the
// authenticator would disable the enrolment that exists to clear it (NIST SP 800-63B
// section 3.2.2, #489).
//
// Unconditional and narrow, as ResetUserOTPStep is: the enrolment transaction already
// matched the row it expected, and nothing gates on whether the count was already 0.
// Unlike the increment, tx is required, as IncrementUserOtpConfigGeneration's is -- the
// clear must commit with the establish that rebinds, or not at all.
func (d *Database) ClearUserOtpConsecutiveFailures(ctx context.Context, tx *sql.Tx, userId int64) error {

	if userId == 0 {
		return errs.New("can't clear the OTP consecutive failures of user with id 0")
	}
	if tx == nil {
		return errs.New("clearing the OTP consecutive failures requires a transaction: it must commit with the write that rebinds the authenticator")
	}

	ub := d.Flavor.NewUpdateBuilder()
	ub.Update("users")
	ub.Set(
		ub.Assign("otp_consecutive_failures", 0),
		ub.Assign("updated_at", time.Now().UTC()),
	)
	ub.Where(ub.Equal("id", userId))

	query, args := ub.BuildWithFlavor(d.Flavor)
	_, err := d.ExecSQL(ctx, tx, query, args...)
	if err != nil {
		return errs.Wrap(err, "unable to clear user OTP consecutive failures")
	}

	return nil
}

// TryInstallPendingOTPEnrollment records a TOTP enrolment the server has just issued, but only if
// this user has no live one already, and reports whether this call is the one that installed it.
//
// The predicate carries three terms, and each of them is load-bearing:
//
//   - the user id, which is what the write is keyed on;
//   - otp_enabled being false, so an authenticator that already exists cannot have a pending
//     enrolment staged behind it. Without it a caller could park a seed on an enrolled account and
//     wait for the authenticator to be removed;
//   - the existing pending value being absent or issued before staleBefore, which is what makes the
//     issuing endpoint idempotent. Two concurrent enrolment requests both find no pending value,
//     both call this, and exactly one wins; the loser re-reads the row and answers with the
//     winner's seed, so a user who reloads the enrolment page is not handed a second QR code that
//     silently invalidates the one they already scanned (#247, goal 7).
//
// staleBefore rather than a lifetime, because how long an enrolment stays valid is a product
// decision and belongs with the handler that issues it. A zero staleBefore means nothing counts as
// expired, so an existing pending value is never replaced, which fails closed.
//
// **A false return is not an error and is not proof of a race**, the same imprecision
// TryConsumeUserOTPStep documents: it means no row transitioned, and the causes are not
// distinguishable here. Another request installed a seed first, the authenticator was enabled under
// this request, or the user row is gone. The caller re-reads and responds from what it finds.
//
// rowsAffected == 1 means this call transitioned the row on all four engines. Matching the predicate
// implies the row changes: what it held was either NULL or an older issued_at, and AES-GCM's random
// nonce means even an identical plaintext re-encrypts to different bytes, so MySQL's changed-rows
// accounting agrees with matched rows. That is the trap RevokeCodesBySessionIdentifier documents,
// and it does not bite here.
//
// Deliberately not part of UpdateUser: both columns are tagged dont-update, because the full-row
// write is what would let one enrolment request erase another's issuance. See record.User.
func (d *Database) TryInstallPendingOTPEnrollment(ctx context.Context, tx *sql.Tx, userId int64,
	secretEncrypted []byte, issuedAt time.Time, staleBefore time.Time) (bool, error) {

	if userId == 0 {
		return false, errs.New("can't install a pending OTP enrollment for user with id 0")
	}
	// Errors rather than benign falses, and neither is defensive. An empty ciphertext is the
	// dormant value of every user with no enrollment pending, so installing one would leave the
	// row looking untouched while reporting success. A zero issuedAt is worse: it installs a seed
	// that every real staleBefore immediately treats as expired, so the enrollment appears to
	// succeed and can never be read back.
	if len(secretEncrypted) == 0 {
		return false, errs.New("can't install an empty pending OTP enrollment")
	}
	if issuedAt.IsZero() {
		return false, errs.New("can't install a pending OTP enrollment with a zero issued at")
	}

	ub := d.Flavor.NewUpdateBuilder()
	ub.Update("users")
	ub.Set(
		ub.Assign("otp_enrollment_secret_encrypted", secretEncrypted),
		ub.Assign("otp_enrollment_issued_at", issuedAt),
		ub.Assign("updated_at", time.Now().UTC()),
	)
	ub.Where(
		ub.Equal("id", userId),
		// A bound Go bool, as TrySetUserEnabled does against users.enabled and
		// TryConsumeUserOTPStep against this same column. The four engines declare it
		// numeric, tinyint(1), boolean and BIT, and the driver types the parameter, so
		// nothing here is dialect specific.
		ub.Equal("otp_enabled", false),
		ub.Or(
			ub.IsNull("otp_enrollment_secret_encrypted"),
			// Both halves of the OR on the timestamp, because a row carrying ciphertext with
			// a NULL issued_at has no expiry to compare and would otherwise be permanent. No
			// writer produces that state, and this is what stops it being unrecoverable if
			// one ever did.
			ub.IsNull("otp_enrollment_issued_at"),
			ub.LessThan("otp_enrollment_issued_at", staleBefore),
		),
	)

	query, args := ub.BuildWithFlavor(d.Flavor)
	result, err := d.ExecSQL(ctx, tx, query, args...)
	if err != nil {
		return false, errs.Wrap(err, "unable to install pending OTP enrollment")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, errs.Wrap(err, "unable to get rows affected when installing pending OTP enrollment")
	}

	return rowsAffected == 1, nil
}

// ClearPendingOTPEnrollment returns the pending enrollment pair to its dormant NULL state. Called
// once the authenticator it staged has been established, inside the same transaction as the write
// that established it, so there is no committed state in which OTP is on and a live pending seed is
// still installed.
//
// Unconditional and keyed on the user id alone, in ResetUserOTPStep's shape: clearing a user who has
// nothing pending is not a failure, and nothing gates on the transition, unlike TrySetUserEnabled's
// disable direction. So this reports only an error.
//
// The clears are raw SQL rather than Assign(..., nil), for the reason SetUserPasswordHash gives:
// sqlbuilder sends an untyped Go nil as a parameter and the SQL Server driver types it nvarchar,
// which it then refuses to convert implicitly to varbinary(max). A literal NULL has no parameter
// type to get wrong and is portable across all four engines (#247).
func (d *Database) ClearPendingOTPEnrollment(ctx context.Context, tx *sql.Tx, userId int64) error {

	if userId == 0 {
		return errs.New("can't clear the pending OTP enrollment of user with id 0")
	}

	ub := d.Flavor.NewUpdateBuilder()
	ub.Update("users")
	ub.Set(
		"otp_enrollment_secret_encrypted = NULL",
		"otp_enrollment_issued_at = NULL",
		ub.Assign("updated_at", time.Now().UTC()),
	)
	ub.Where(ub.Equal("id", userId))

	query, args := ub.BuildWithFlavor(d.Flavor)
	_, err := d.ExecSQL(ctx, tx, query, args...)
	if err != nil {
		return errs.Wrap(err, "unable to clear pending OTP enrollment")
	}

	return nil
}

// TryEstablishUserOTP installs an authenticator: it stores secretEncrypted and turns otp_enabled
// on, and writes no other column but updated_at, only while OTP is still off at
// expectedGeneration, the otp_config_generation the caller read. It reports whether it did.
//
// Narrow rather than going through UpdateUser, for SetUserProfile's reason: the enrolment reads the
// user at the start of the request, and writing that read back would re-enable an account an
// administrator disabled under it or put back a password hash a concurrent change replaced (#471).
//
// Compare-and-set on the authenticator rather than on the flag (#471 decision 2, #144): of two
// enrolments from one read exactly one lands, so the second no longer replaces the first's secret,
// and the generation term refuses an enrolment read before an enable and a disable landed in
// between, which leave otp_enabled where it was and move the generation twice. The generation
// advance itself stays IncrementUserOtpConfigGeneration's, in the caller's transaction, and runs
// only when this reports true.
//
// otp_enabled flips from false to true on every matched row, so a matched row is a changed row on
// all four engines and MySQL's changed-rows accounting agrees with matched rows.
func (d *Database) TryEstablishUserOTP(ctx context.Context, tx *sql.Tx, userId int64, expectedGeneration int64,
	secretEncrypted []byte) (bool, error) {

	if userId == 0 {
		return false, errs.New("can't establish OTP for user with id 0")
	}
	if len(secretEncrypted) == 0 {
		return false, errs.New("can't establish OTP with an empty secret")
	}

	ub := d.Flavor.NewUpdateBuilder()
	ub.Update("users")
	ub.Set(
		ub.Assign("otp_secret_encrypted", secretEncrypted),
		ub.Assign("otp_enabled", true),
		ub.Assign("updated_at", time.Now().UTC()),
	)
	ub.Where(
		ub.Equal("id", userId),
		ub.Equal("otp_enabled", false),
		ub.Equal("otp_config_generation", expectedGeneration),
	)

	query, args := ub.BuildWithFlavor(d.Flavor)
	result, err := d.ExecSQL(ctx, tx, query, args...)
	if err != nil {
		return false, errs.Wrap(err, "unable to establish user OTP")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, errs.Wrap(err, "unable to get rows affected when establishing user OTP")
	}

	return rowsAffected == 1, nil
}

// TryRemoveUserOTP removes an authenticator: it clears the seed and turns otp_enabled off, and
// writes no other column but updated_at, only while OTP is still on at expectedGeneration, the
// otp_config_generation the caller read. It reports whether it did.
//
// Narrow and conditional for TryEstablishUserOTP's reasons (#471 decision 2): it cannot undo a
// disable or a password change made since the read, and a removal read before the authenticator
// was removed and another established in its place matches nothing rather than removing the
// replacement. The consumed-step reset and the generation advance stay the caller's, in the same
// transaction, and run only when this reports true.
//
// The seed clears to a literal NULL rather than Assign(..., nil), for the reason
// SetUserPasswordHash gives. otp_enabled flips on every matched row, so a matched row is a changed
// row on all four engines.
func (d *Database) TryRemoveUserOTP(ctx context.Context, tx *sql.Tx, userId int64, expectedGeneration int64) (bool, error) {

	if userId == 0 {
		return false, errs.New("can't remove OTP for user with id 0")
	}

	ub := d.Flavor.NewUpdateBuilder()
	ub.Update("users")
	ub.Set(
		"otp_secret_encrypted = NULL",
		ub.Assign("otp_enabled", false),
		ub.Assign("updated_at", time.Now().UTC()),
	)
	ub.Where(
		ub.Equal("id", userId),
		ub.Equal("otp_enabled", true),
		ub.Equal("otp_config_generation", expectedGeneration),
	)

	query, args := ub.BuildWithFlavor(d.Flavor)
	result, err := d.ExecSQL(ctx, tx, query, args...)
	if err != nil {
		return false, errs.Wrap(err, "unable to remove user OTP")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, errs.Wrap(err, "unable to get rows affected when removing user OTP")
	}

	return rowsAffected == 1, nil
}
