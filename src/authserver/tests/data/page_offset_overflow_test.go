package datatests

import (
	"math"
	"testing"

	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/testutil/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every paginated read turns its page number into a SQL OFFSET by multiplying,
// and the page number arrives from a "?page=" query parameter that the admin
// API validated as "> 0" and nothing more. At a page near math.MaxInt the
// product wrapped negative, and what happened then depended on the engine and
// on how the number reached it (#305):
//
//   - Six of the seven reads hand the offset to sqlbuilder, which drops the
//     clause when it is negative, so on sqlite, mysql and postgres the query
//     ran with no offset and returned the FIRST page's rows -- labelled as the
//     page asked for. Not an error. A wrong answer.
//   - The SQL Server audit log override formats the number into the statement
//     itself, so SQL Server saw it and refused: "The offset specified in a
//     OFFSET clause may not be negative", which the API turns into a 500.
//
// That is why the assertion below is "no error AND no rows": an error-only
// assertion passes on three engines while they hand back page 1, and a
// rows-only assertion would miss the engine that refuses outright.
//
// commondb.PageOffset saturates instead, and its own arithmetic is pinned in
// the core tier. What cannot be pinned there is the half that matters here:
// that the saturated offset is a number all four engines actually accept.
// math.MaxInt/pageSize*pageSize is a nine-quintillion-row OFFSET, and whether
// sqlite, mysql, postgres and sql server take it or reject it as out of range
// is a fact about them, not about Go -- so this runs in the data tier, on each
// of the four.
//
// The audit log is exercised twice over, because it is the reader with the SQL
// Server override: on the mssql job this test is what runs the seventh site.

// overflowingPages are page numbers whose offset wraps at any page size these
// readers use. The first is the value from the report; the rest surround the
// boundary where the wrap begins, which is far below math.MaxInt.
func overflowingPages(pageSize int) []int {
	return []int{
		math.MaxInt,
		math.MaxInt - 1,
		math.MaxInt/pageSize + 2,
		math.MaxInt / 2,
	}
}

// assertEmptyPagePastTheEnd runs read at each overflowing page and holds it to
// the answer every other page past the end already gives: no error, no rows,
// and the same total the first page reported. The total is a property of the
// query rather than of the page, so a reader that lost it here would be
// reporting a different table than the one it just refused to page into.
func assertEmptyPagePastTheEnd(t *testing.T, name string, pageSize int,
	read func(page, pageSize int) (rows int, total int, err error)) {

	t.Helper()

	rows, wantTotal, err := read(1, pageSize)
	require.NoError(t, err, "%s: reading page 1", name)
	require.NotZero(t, wantTotal, "%s: the fixture put nothing in the table, so this proves nothing", name)
	require.NotZero(t, rows, "%s: page 1 came back empty", name)

	for _, page := range overflowingPages(pageSize) {
		rows, total, err := read(page, pageSize)

		// The two assertions the fix is for, and both are needed: before it,
		// sqlite, mysql and postgres came back here with no error and the first
		// page's three rows, while SQL Server came back with the error instead.
		require.NoError(t, err, "%s: page %d", name, page)
		assert.Zero(t, rows, "%s: page %d is past the end and must hold no rows", name, page)
		assert.Equal(t, wantTotal, total, "%s: page %d reported a different total", name, page)
	}
}

func TestPaginatedReads_AnOverflowingPageIsAnEmptyPage(t *testing.T) {
	t.Run("SearchUsersPaginated", func(t *testing.T) {
		// A given name shared by three users, so the search has rows of its own
		// rather than depending on what the shared database happens to hold.
		givenName := "offsettest" + fake.LetterN(10)
		for i := 0; i < 3; i++ {
			user := createUserWithGivenName(t, givenName)
			t.Cleanup(func() { _ = database.DeleteUser(nil, user.Id) })
		}

		assertEmptyPagePastTheEnd(t, "SearchUsersPaginated", 10,
			func(page, pageSize int) (int, int, error) {
				users, total, err := database.SearchUsersPaginated(nil, givenName, page, pageSize)
				return len(users), total, err
			})
	})

	t.Run("GetAllGroupsPaginated", func(t *testing.T) {
		// This reader spans the whole table, which every other test in the
		// package adds to, so it needs no fixture of its own -- but one group
		// makes the total certainly non-zero even on an empty database.
		group := createTestGroup(t)
		t.Cleanup(func() { _ = database.DeleteGroup(nil, group.Id) })

		assertEmptyPagePastTheEnd(t, "GetAllGroupsPaginated", 10,
			func(page, pageSize int) (int, int, error) {
				groups, total, err := database.GetAllGroupsPaginated(nil, page, pageSize)
				return len(groups), total, err
			})
	})

	t.Run("GetGroupMembersPaginated", func(t *testing.T) {
		group := createTestGroup(t)
		t.Cleanup(func() { _ = database.DeleteGroup(nil, group.Id) })
		for i := 0; i < 3; i++ {
			user := createTestUser(t)
			createTestUserGroupWithUserAndGroup(t, user.Id, group.Id)
			t.Cleanup(func() { _ = database.DeleteUser(nil, user.Id) })
		}

		assertEmptyPagePastTheEnd(t, "GetGroupMembersPaginated", 10,
			func(page, pageSize int) (int, int, error) {
				users, total, err := database.GetGroupMembersPaginated(nil, group.Id, page, pageSize)
				return len(users), total, err
			})
	})

	t.Run("GetUsersByPermissionIdPaginated", func(t *testing.T) {
		resource := createTestResource(t)
		t.Cleanup(func() { _ = database.DeleteResource(nil, resource.Id) })
		permission := createTestPermission(t, resource)
		t.Cleanup(func() { _ = database.DeletePermission(nil, permission.Id) })
		for i := 0; i < 3; i++ {
			user := createTestUser(t)
			createTestUserPermissionWithUserAndPermission(t, user.Id, permission.Id)
			t.Cleanup(func() { _ = database.DeleteUser(nil, user.Id) })
		}

		assertEmptyPagePastTheEnd(t, "GetUsersByPermissionIdPaginated", 10,
			func(page, pageSize int) (int, int, error) {
				users, total, err := database.GetUsersByPermissionIdPaginated(nil, permission.Id, page, pageSize)
				return len(users), total, err
			})
	})

	t.Run("GetUserSessionsByClientIdPaginated", func(t *testing.T) {
		user := createTestUser(t)
		t.Cleanup(func() { _ = database.DeleteUser(nil, user.Id) })
		client := createTestClient(t)
		t.Cleanup(func() { _ = database.DeleteClient(nil, client.Id) })
		createTestUserSessionsWithClient(t, user.Id, client.Id, 3)

		assertEmptyPagePastTheEnd(t, "GetUserSessionsByClientIdPaginated", 50,
			func(page, pageSize int) (int, int, error) {
				sessions, total, err := database.GetUserSessionsByClientIdPaginated(nil, client.Id, page, pageSize)
				return len(sessions), total, err
			})
	})

	// The audit log runs twice: once at its own page size, and once at the
	// largest the API accepts, because the offset is a product of both and the
	// SQL Server override formats it into the statement by hand.
	auditEvent := "PageOffsetOverflowTest"
	for i := 0; i < 3; i++ {
		auditLog := &models.AuditLog{AuditEvent: auditEvent, Details: `{"n":1}`}
		require.NoError(t, database.CreateAuditLog(nil, auditLog))
	}

	for _, pageSize := range []int{20, 200} {
		t.Run("GetAuditLogsPaginated_size"+itoa(pageSize), func(t *testing.T) {
			assertEmptyPagePastTheEnd(t, "GetAuditLogsPaginated", pageSize,
				func(page, pageSize int) (int, int, error) {
					logs, total, err := database.GetAuditLogsPaginated(nil, page, pageSize, auditEvent, "")
					return len(logs), total, err
				})
		})
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
