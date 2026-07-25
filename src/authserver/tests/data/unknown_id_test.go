package datatests

import (
	"database/sql"
	"fmt"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Reading a row that does not exist.
//
// Every single-row getter returns (nil, nil) when it finds nothing, rather than an
// error. That is a deliberate convention, but it means a caller who forgets to
// check the pointer dereferences nil, and it has already cost us real bugs:
// /api/public/settings panicked on a missing settings row, and ValidateEmailUpdate
// held a `user != nil` conjunct that made its whole uniqueness check fail open.
//
// Only four of the thirty-three single-row getters had any unknown-id coverage, so
// nothing stopped one of them from drifting to a returned error or a zero-valued
// struct. These two table-driven tests cover all of them on every engine.
//
// The table closures report a bool rather than handing back the pointer, so each
// comparison happens at the getter's own concrete type and there is no interface
// boxing in the assertion to reason about.

type byIdReader struct {
	name  string
	found func(tx *sql.Tx, id int64) (bool, error)
}

func byIdReaders() []byIdReader {
	return []byIdReader{
		{"GetClientById", func(tx *sql.Tx, id int64) (bool, error) {
			v, err := database.GetClientById(tx, id)
			return v != nil, err
		}},
		{"GetUserById", func(tx *sql.Tx, id int64) (bool, error) { v, err := database.GetUserById(tx, id); return v != nil, err }},
		{"GetCodeById", func(tx *sql.Tx, id int64) (bool, error) { v, err := database.GetCodeById(tx, id); return v != nil, err }},
		{"GetResourceById", func(tx *sql.Tx, id int64) (bool, error) {
			v, err := database.GetResourceById(tx, id)
			return v != nil, err
		}},
		{"GetPermissionById", func(tx *sql.Tx, id int64) (bool, error) {
			v, err := database.GetPermissionById(tx, id)
			return v != nil, err
		}},
		{"GetKeyPairById", func(tx *sql.Tx, id int64) (bool, error) {
			v, err := database.GetKeyPairById(tx, id)
			return v != nil, err
		}},
		{"GetRedirectURIById", func(tx *sql.Tx, id int64) (bool, error) {
			v, err := database.GetRedirectURIById(tx, id)
			return v != nil, err
		}},
		{"GetWebOriginById", func(tx *sql.Tx, id int64) (bool, error) {
			v, err := database.GetWebOriginById(tx, id)
			return v != nil, err
		}},
		{"GetSettingsById", func(tx *sql.Tx, id int64) (bool, error) {
			v, err := database.GetSettingsById(tx, id)
			return v != nil, err
		}},
		{"GetUserPermissionById", func(tx *sql.Tx, id int64) (bool, error) {
			v, err := database.GetUserPermissionById(tx, id)
			return v != nil, err
		}},
		{"GetGroupById", func(tx *sql.Tx, id int64) (bool, error) {
			v, err := database.GetGroupById(tx, id)
			return v != nil, err
		}},
		{"GetUserAttributeById", func(tx *sql.Tx, id int64) (bool, error) {
			v, err := database.GetUserAttributeById(tx, id)
			return v != nil, err
		}},
		{"GetUserProfilePictureByUserId", func(tx *sql.Tx, id int64) (bool, error) {
			v, err := database.GetUserProfilePictureByUserId(tx, id)
			return v != nil, err
		}},
		{"GetClientLogoByClientId", func(tx *sql.Tx, id int64) (bool, error) {
			v, err := database.GetClientLogoByClientId(tx, id)
			return v != nil, err
		}},
		{"GetClientPermissionById", func(tx *sql.Tx, id int64) (bool, error) {
			v, err := database.GetClientPermissionById(tx, id)
			return v != nil, err
		}},
		{"GetUserSessionById", func(tx *sql.Tx, id int64) (bool, error) {
			v, err := database.GetUserSessionById(tx, id)
			return v != nil, err
		}},
		{"GetUserConsentById", func(tx *sql.Tx, id int64) (bool, error) {
			v, err := database.GetUserConsentById(tx, id)
			return v != nil, err
		}},
		{"GetPreRegistrationById", func(tx *sql.Tx, id int64) (bool, error) {
			v, err := database.GetPreRegistrationById(tx, id)
			return v != nil, err
		}},
		{"GetUserGroupById", func(tx *sql.Tx, id int64) (bool, error) {
			v, err := database.GetUserGroupById(tx, id)
			return v != nil, err
		}},
		{"GetGroupAttributeById", func(tx *sql.Tx, id int64) (bool, error) {
			v, err := database.GetGroupAttributeById(tx, id)
			return v != nil, err
		}},
		{"GetGroupPermissionById", func(tx *sql.Tx, id int64) (bool, error) {
			v, err := database.GetGroupPermissionById(tx, id)
			return v != nil, err
		}},
		{"GetRefreshTokenById", func(tx *sql.Tx, id int64) (bool, error) {
			v, err := database.GetRefreshTokenById(tx, id)
			return v != nil, err
		}},
		{"GetUserSessionClientById", func(tx *sql.Tx, id int64) (bool, error) {
			v, err := database.GetUserSessionClientById(tx, id)
			return v != nil, err
		}},
	}
}

// TestUnknownId_ReturnsNilWithoutError covers every getter that takes an int64 id.
// Zero and a negative id are included because they are what a caller passes after
// failing to parse a path parameter, and they must read as "not found" rather than
// as a malformed query.
func TestUnknownId_ReturnsNilWithoutError(t *testing.T) {
	ids := []int64{999999999, 0, -1}

	for _, reader := range byIdReaders() {
		for _, id := range ids {
			t.Run(fmt.Sprintf("%s/%d", reader.name, id), func(t *testing.T) {
				found, err := reader.found(nil, id)
				require.NoErrorf(t, err, "%s(%d) must not return an error for a missing row", reader.name, id)
				assert.Falsef(t, found, "%s(%d) must return nil for a missing row", reader.name, id)
			})
		}
	}
}

type byValueReader struct {
	name string
	// value is generated per run so it cannot collide with a row left behind by
	// an earlier test: the three server databases are never reset.
	value func() string
	found func(tx *sql.Tx, value string) (bool, error)
}

func byValueReaders() []byValueReader {
	randomUUID := func() string { return uuid.New().String() }
	randomWord := func() string { return "missing_" + gofakeit.LetterN(16) }

	return []byValueReader{
		{"GetClientByClientIdentifier", randomWord, func(tx *sql.Tx, v string) (bool, error) {
			c, err := database.GetClientByClientIdentifier(tx, v)
			return c != nil, err
		}},
		{"GetUserByUsername", randomWord, func(tx *sql.Tx, v string) (bool, error) {
			u, err := database.GetUserByUsername(tx, v)
			return u != nil, err
		}},
		{"GetUserBySubject", randomUUID, func(tx *sql.Tx, v string) (bool, error) {
			u, err := database.GetUserBySubject(tx, v)
			return u != nil, err
		}},
		{"GetUserByEmail", func() string { return "missing_" + gofakeit.LetterN(12) + "@example.com" },
			func(tx *sql.Tx, v string) (bool, error) {
				u, err := database.GetUserByEmail(tx, v)
				return u != nil, err
			}},
		{"GetResourceByResourceIdentifier", randomWord, func(tx *sql.Tx, v string) (bool, error) {
			r, err := database.GetResourceByResourceIdentifier(tx, v)
			return r != nil, err
		}},
		{"GetGroupByGroupIdentifier", randomWord, func(tx *sql.Tx, v string) (bool, error) {
			g, err := database.GetGroupByGroupIdentifier(tx, v)
			return g != nil, err
		}},
		{"GetUserSessionBySessionIdentifier", randomUUID, func(tx *sql.Tx, v string) (bool, error) {
			s, err := database.GetUserSessionBySessionIdentifier(tx, v)
			return s != nil, err
		}},
		{"GetPreRegistrationByEmail", func() string { return "missing_" + gofakeit.LetterN(12) + "@example.com" },
			func(tx *sql.Tx, v string) (bool, error) {
				p, err := database.GetPreRegistrationByEmail(tx, v)
				return p != nil, err
			}},
		{"GetRefreshTokenByJti", randomUUID, func(tx *sql.Tx, v string) (bool, error) {
			rt, err := database.GetRefreshTokenByJti(tx, v)
			return rt != nil, err
		}},
		{"GetCodeByCodeHash", randomWord, func(tx *sql.Tx, v string) (bool, error) {
			c, err := database.GetCodeByCodeHash(tx, v, false)
			return c != nil, err
		}},
	}
}

// TestUnknownValue_ReturnsNilWithoutError is the same contract for the getters
// that look a row up by a unique string rather than by id.
//
// Only values that cannot exist are used, never the empty string: this suite
// shares one accumulating database, so a getter like GetUserByUsername("") could
// legitimately match a row some other test left behind, and the failure would
// look like a bug in the getter.
func TestUnknownValue_ReturnsNilWithoutError(t *testing.T) {
	for _, reader := range byValueReaders() {
		t.Run(reader.name, func(t *testing.T) {
			value := reader.value()
			found, err := reader.found(nil, value)
			require.NoErrorf(t, err, "%s(%q) must not return an error for a missing row", reader.name, value)
			assert.Falsef(t, found, "%s(%q) must return nil for a missing row", reader.name, value)
		})
	}
}

// The convention has to hold inside a transaction too, since that is where the
// callers that check for nil before writing do their reads.
func TestUnknownId_ReturnsNilWithoutErrorInTransaction(t *testing.T) {
	tx := beginTx(t)

	for _, reader := range byIdReaders() {
		found, err := reader.found(tx, 999999999)
		require.NoErrorf(t, err, "%s must not return an error for a missing row in a transaction", reader.name)
		assert.Falsef(t, found, "%s must return nil for a missing row in a transaction", reader.name)
	}

	require.NoError(t, database.RollbackTransaction(tx), "RollbackTransaction")
}
