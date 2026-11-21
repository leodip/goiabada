package datatests

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Reading a row that does not exist.
//
// Every single-row getter returns (nil, nil) when it finds nothing, rather than an
// error. That is a deliberate convention, but it means a caller who forgets to
// check the pointer dereferences nil, and it has already cost us real bugs:
// /api/public/settings panicked on a missing settings row, and an email validator
// held a `user != nil` conjunct that made its whole uniqueness check fail open.
//
// Only four of the thirty-three single-row getters had any unknown-id coverage, so
// nothing stopped one of them from drifting to a returned error or a zero-valued
// struct. These two table-driven tests cover all of them on every engine.
//
// The table closures report a bool rather than handing back the pointer, so each
// comparison happens at the getter's own concrete type and there is no interface
// boxing in the assertion to reason about.

type byIDReader struct {
	name  string
	found func(tx *sql.Tx, id int64) (bool, error)
}

func byIDReaders() []byIDReader {
	return []byIDReader{
		{"GetClientByID", func(tx *sql.Tx, id int64) (bool, error) {
			v, err := database.GetClientByID(context.Background(), tx, id)
			return v != nil, err
		}},
		{"GetUserByID", func(tx *sql.Tx, id int64) (bool, error) {
			v, err := database.GetUserByID(context.Background(), tx, id)
			return v != nil, err
		}},
		{"GetCodeByID", func(tx *sql.Tx, id int64) (bool, error) {
			v, err := database.GetCodeByID(context.Background(), tx, id)
			return v != nil, err
		}},
		{"GetResourceByID", func(tx *sql.Tx, id int64) (bool, error) {
			v, err := database.GetResourceByID(context.Background(), tx, id)
			return v != nil, err
		}},
		{"GetPermissionByID", func(tx *sql.Tx, id int64) (bool, error) {
			v, err := database.GetPermissionByID(context.Background(), tx, id)
			return v != nil, err
		}},
		{"GetKeyPairByID", func(tx *sql.Tx, id int64) (bool, error) {
			v, err := database.GetKeyPairByID(context.Background(), tx, id)
			return v != nil, err
		}},
		{"GetRedirectURIByID", func(tx *sql.Tx, id int64) (bool, error) {
			v, err := database.GetRedirectURIByID(context.Background(), tx, id)
			return v != nil, err
		}},
		{"GetWebOriginByID", func(tx *sql.Tx, id int64) (bool, error) {
			v, err := database.GetWebOriginByID(context.Background(), tx, id)
			return v != nil, err
		}},
		{"GetSettingsByID", func(tx *sql.Tx, id int64) (bool, error) {
			v, err := database.GetSettingsByID(context.Background(), tx, id)
			return v != nil, err
		}},
		{"GetUserPermissionByID", func(tx *sql.Tx, id int64) (bool, error) {
			v, err := database.GetUserPermissionByID(context.Background(), tx, id)
			return v != nil, err
		}},
		{"GetGroupByID", func(tx *sql.Tx, id int64) (bool, error) {
			v, err := database.GetGroupByID(context.Background(), tx, id)
			return v != nil, err
		}},
		{"GetUserAttributeByID", func(tx *sql.Tx, id int64) (bool, error) {
			v, err := database.GetUserAttributeByID(context.Background(), tx, id)
			return v != nil, err
		}},
		{"GetUserProfilePictureByUserID", func(tx *sql.Tx, id int64) (bool, error) {
			v, err := database.GetUserProfilePictureByUserID(context.Background(), tx, id)
			return v != nil, err
		}},
		{"GetClientLogoByClientID", func(tx *sql.Tx, id int64) (bool, error) {
			v, err := database.GetClientLogoByClientID(context.Background(), tx, id)
			return v != nil, err
		}},
		{"GetClientPermissionByID", func(tx *sql.Tx, id int64) (bool, error) {
			v, err := database.GetClientPermissionByID(context.Background(), tx, id)
			return v != nil, err
		}},
		{"GetUserSessionByID", func(tx *sql.Tx, id int64) (bool, error) {
			v, err := database.GetUserSessionByID(context.Background(), tx, id)
			return v != nil, err
		}},
		{"GetUserConsentByID", func(tx *sql.Tx, id int64) (bool, error) {
			v, err := database.GetUserConsentByID(context.Background(), tx, id)
			return v != nil, err
		}},
		{"GetPreRegistrationByID", func(tx *sql.Tx, id int64) (bool, error) {
			v, err := database.GetPreRegistrationByID(context.Background(), tx, id)
			return v != nil, err
		}},
		{"GetUserGroupByID", func(tx *sql.Tx, id int64) (bool, error) {
			v, err := database.GetUserGroupByID(context.Background(), tx, id)
			return v != nil, err
		}},
		{"GetGroupAttributeByID", func(tx *sql.Tx, id int64) (bool, error) {
			v, err := database.GetGroupAttributeByID(context.Background(), tx, id)
			return v != nil, err
		}},
		{"GetGroupPermissionByID", func(tx *sql.Tx, id int64) (bool, error) {
			v, err := database.GetGroupPermissionByID(context.Background(), tx, id)
			return v != nil, err
		}},
		{"GetRefreshTokenByID", func(tx *sql.Tx, id int64) (bool, error) {
			v, err := database.GetRefreshTokenByID(context.Background(), tx, id)
			return v != nil, err
		}},
		{"GetUserSessionClientByID", func(tx *sql.Tx, id int64) (bool, error) {
			v, err := database.GetUserSessionClientByID(context.Background(), tx, id)
			return v != nil, err
		}},
	}
}

// TestUnknownID_ReturnsNilWithoutError covers every getter that takes an int64 id.
// Zero and a negative id are included because they are what a caller passes after
// failing to parse a path parameter, and they must read as "not found" rather than
// as a malformed query.
func TestUnknownID_ReturnsNilWithoutError(t *testing.T) {
	ids := []int64{999999999, 0, -1}

	for _, reader := range byIDReaders() {
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
	// an earlier test: a run starts from an empty database (#433), and every test
	// in it shares that database.
	value func() string
	found func(tx *sql.Tx, value string) (bool, error)
}

func byValueReaders() []byValueReader {
	randomUUID := fake.UUID
	randomWord := func() string { return "missing_" + fake.LetterN(16) }

	return []byValueReader{
		{"GetClientByClientIdentifier", randomWord, func(tx *sql.Tx, v string) (bool, error) {
			c, err := database.GetClientByClientIdentifier(context.Background(), tx, v)
			return c != nil, err
		}},
		{"GetUserByUsername", randomWord, func(tx *sql.Tx, v string) (bool, error) {
			u, err := database.GetUserByUsername(context.Background(), tx, v)
			return u != nil, err
		}},
		{"GetUserBySubject", randomUUID, func(tx *sql.Tx, v string) (bool, error) {
			u, err := database.GetUserBySubject(context.Background(), tx, v)
			return u != nil, err
		}},
		{"GetUserByEmail", func() string { return "missing_" + fake.LetterN(12) + "@example.com" },
			func(tx *sql.Tx, v string) (bool, error) {
				u, err := database.GetUserByEmail(context.Background(), tx, v)
				return u != nil, err
			}},
		{"GetResourceByResourceIdentifier", randomWord, func(tx *sql.Tx, v string) (bool, error) {
			r, err := database.GetResourceByResourceIdentifier(context.Background(), tx, v)
			return r != nil, err
		}},
		{"GetGroupByGroupIdentifier", randomWord, func(tx *sql.Tx, v string) (bool, error) {
			g, err := database.GetGroupByGroupIdentifier(context.Background(), tx, v)
			return g != nil, err
		}},
		{"GetUserSessionBySessionIdentifier", randomUUID, func(tx *sql.Tx, v string) (bool, error) {
			s, err := database.GetUserSessionBySessionIdentifier(context.Background(), tx, v)
			return s != nil, err
		}},
		{"GetPreRegistrationByEmail", func() string { return "missing_" + fake.LetterN(12) + "@example.com" },
			func(tx *sql.Tx, v string) (bool, error) {
				p, err := database.GetPreRegistrationByEmail(context.Background(), tx, v)
				return p != nil, err
			}},
		{"GetRefreshTokenByJTI", randomUUID, func(tx *sql.Tx, v string) (bool, error) {
			rt, err := database.GetRefreshTokenByJTI(context.Background(), tx, v)
			return rt != nil, err
		}},
		{"GetCodeByCodeHash", randomWord, func(tx *sql.Tx, v string) (bool, error) {
			c, err := database.GetCodeByCodeHash(context.Background(), tx, v, false)
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
func TestUnknownID_ReturnsNilWithoutErrorInTransaction(t *testing.T) {
	tx := beginTx(t)

	for _, reader := range byIDReaders() {
		found, err := reader.found(tx, 999999999)
		require.NoErrorf(t, err, "%s must not return an error for a missing row in a transaction", reader.name)
		assert.Falsef(t, found, "%s must return nil for a missing row in a transaction", reader.name)
	}

	require.NoError(t, database.RollbackTransaction(context.Background(), tx), "RollbackTransaction")
}
