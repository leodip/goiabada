package datatests

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data/migrator"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The two versions migration 000064 sits between. Literals, as for 000061: nothing in production
// code names this number.
const (
	beforeThreeStateClaimsDefault000064 = 63
	threeStateClaimsDefault000064       = 64
)

// TestMigration000064_ClientsThreeStateClaimsDefault exercises the backfill that gives every client
// one of the three values of its two "Include OpenID Connect claims" columns, against a REAL engine
// of the configured dialect (see migration_testdb_helper_test.go). Until it ran, a client the admin
// API or a registration created held "" in the ID token column, which the admin console's Tokens
// tab showed with no choice selected and refused to save as loaded (#562).
//
// The properties:
//
//  1. A value other than on, off or default, in either column, ends as default: the empty string
//     both creation paths wrote, a different case, a value with a space beside it, anything else.
//  2. On, off and default are kept, in either column.
//  3. The down migration changes nothing, and 000064 applies again after it.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000064_ClientsThreeStateClaimsDefault
func TestMigration000064_ClientsThreeStateClaimsDefault(t *testing.T) {
	ctx := context.Background()
	h := newIsolatedDB(t)

	// Seeded through the ORM at head, then carried down to 000063 and back up, as 000061's test
	// does and for its reason. 000064's down is a no-op, so the rows keep what the seed wrote until
	// the up runs again.
	if err := h.Migrator.Up(ctx); err != nil && !errors.Is(err, migrator.ErrNoChange) {
		require.NoError(t, err, "migrate to head before seeding through the ORM")
	}

	random := fake.LetterN(6)
	cases := []struct {
		identifier      string
		accessToken     string
		idToken         string
		wantAccessToken string
		wantIdToken     string
		why             string
	}{
		{"m63_empty_" + random, "", "",
			"default", "default",
			"an empty value, which the admin API and registration wrote, becomes default"},
		{"m63_on_off_" + random, "on", "off",
			"on", "off",
			"on and off are kept"},
		{"m63_off_default_" + random, "off", "default",
			"off", "default",
			"off and default are kept"},
		{"m63_default_on_" + random, "default", "on",
			"default", "on",
			"default and on are kept"},
		{"m63_case_" + random, "ON", "Off",
			"default", "default",
			"a value in another case is not one of the three, and issuance read it as default"},
		{"m63_spaces_" + random, "on ", " off",
			"default", "default",
			"a value with a space beside it is not one of the three, and issuance read it as default"},
		{"m63_other_" + random, "yes", "true",
			"default", "default",
			"any other value becomes default"},
		{"m63_ignorable_" + random, "o\u00adn", "of\u00adf",
			"default", "default",
			"a value with a soft hyphen in it, which a linguistic collation compares equal to on " +
				"or off, is not one of the three, and issuance read it as default"},
	}

	ids := make([]int64, len(cases))
	for i, c := range cases {
		client := &record.Client{
			ClientIdentifier:                        c.identifier,
			Description:                             "Migration 000064 test client",
			IncludeOpenIDConnectClaimsInAccessToken: c.accessToken,
			IncludeOpenIDConnectClaimsInIdToken:     c.idToken,
		}
		require.NoErrorf(t, h.DB.CreateClient(ctx, nil, client), "seed client %s on %s", c.identifier, dbType())
		ids[i] = client.Id
	}

	// 3. Down to 000063 changes nothing: the seeded values are still what the seed wrote.
	require.NoErrorf(t, h.Migrator.Migrate(ctx, beforeThreeStateClaimsDefault000064), "roll back to 000063 on %s", dbType())
	for i, c := range cases {
		accessToken, idToken := readThreeStateClaims000064(t, h, ids[i])
		assert.Equalf(t, c.accessToken, accessToken, "%s: access token column after the no-op down on %s", c.identifier, dbType())
		assert.Equalf(t, c.idToken, idToken, "%s: ID token column after the no-op down on %s", c.identifier, dbType())
	}

	// 1 and 2. The up's backfill.
	require.NoErrorf(t, h.Migrator.Migrate(ctx, threeStateClaimsDefault000064), "apply 000064 on %s", dbType())
	for i, c := range cases {
		accessToken, idToken := readThreeStateClaims000064(t, h, ids[i])
		assert.Equalf(t, c.wantAccessToken, accessToken, "%s: include_open_id_connect_claims_in_access_token on %s, because %s", c.identifier, dbType(), c.why)
		assert.Equalf(t, c.wantIdToken, idToken, "%s: include_open_id_connect_claims_in_id_token on %s, because %s", c.identifier, dbType(), c.why)
	}
}

func readThreeStateClaims000064(t *testing.T, h *isolatedDB, clientId int64) (string, string) {
	t.Helper()
	var accessToken, idToken string
	q := fmt.Sprintf("SELECT include_open_id_connect_claims_in_access_token, include_open_id_connect_claims_in_id_token FROM clients WHERE id = %d", clientId)
	require.NoErrorf(t, h.SQL.QueryRow(q).Scan(&accessToken, &idToken), "read the three-state claim columns on %s", dbType())
	return accessToken, idToken
}
