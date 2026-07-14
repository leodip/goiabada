package datatests

import (
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMigration000021_CountryData exercises the data migration that moves stored
// user phone-country and address-country values from the biter777 dataset to the
// datahub dataset. It runs against an ISOLATED database of the configured dialect
// (see migration_testdb_helper.go): migrate to 000020, seed pre-migration rows
// covering every branch of the state hierarchy, apply 000021, and assert. Then it
// re-applies 000021 (Force back to 20) to prove idempotency / restart-safety.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000021_CountryData
func TestMigration000021_CountryData(t *testing.T) {
	h := newIsolatedDB(t)

	// Bring the isolated DB to exactly 000020 (pre-000021 schema == current
	// schema; 000021 is data-only).
	require.NoError(t, h.Migrator.Migrate(20), "migrate to 000020")

	fixtures := migration000021Fixtures()

	// Seed every fixture co-resident in the same DB so double-transforms are
	// detectable, capturing each row's id.
	ids := make(map[string]int64, len(fixtures))
	for i := range fixtures {
		ids[fixtures[i].label] = seedMigrationFixture(t, h, fixtures[i])
	}

	// Apply 000021.
	require.NoError(t, h.Migrator.Migrate(21), "apply 000021")
	assertMigration000021(t, h, fixtures, ids, "after first apply")

	// Idempotency / restart-safety: re-run 000021 against already-migrated data.
	// Force back to 20 (the down is a no-op, so don't execute it) then step up.
	require.NoError(t, h.Migrator.Force(20), "force to 000020")
	require.NoError(t, h.Migrator.Migrate(21), "re-apply 000021")
	assertMigration000021(t, h, fixtures, ids, "after re-apply (idempotency)")
}

type migFixture struct {
	label    string
	uid, cc  string // seeded phone_number_country_uniqueid / _callingcode
	phone    string
	verified bool
	pending  bool // seed a pending verification code + issued_at
	addr     string
	// NULL injections applied via raw SQL after CreateUser:
	nullPhone, nullUID, nullCC, nullAddr bool
	// expected post-migration:
	wUID, wCC, wPhone string
	wVerified         bool
	wPending          bool
	wAddr             string
}

// Affected-mapping tables (mirror migration 000021), used to generate fixtures
// covering EVERY mapping rather than a sample.

var mig21Prefix = []struct{ oldID, oldCC, newID, newCC, prefix string }{
	{"ALA_0", "+35818", "ALA_0", "+358", "18"},
	{"BES_0", "+5993", "BES_0", "+599", "3"},
	{"BES_1", "+5994", "BES_0", "+599", "4"},
	{"CCK_1", "+6189162", "CCK_0", "+61", "89162"},
	{"CUW_0", "+5999", "CUW_0", "+599", "9"},
	{"CXR_0", "+6189164", "CXR_0", "+61", "89164"},
	{"GGY_0", "+441481", "GGY_0", "+44", "1481"},
	{"IMN_0", "+441624", "IMN_0", "+44", "1624"},
	{"JEY_0", "+441534", "JEY_0", "+44", "1534"},
	{"PRI_0", "+1787", "PRI_0", "+1", "787"},
	{"PRI_1", "+1939", "PRI_0", "+1", "939"},
	{"SJM_0", "+4779", "SJM_0", "+47", "79"},
	{"VAT_0", "+3906698", "VAT_0", "+3906", "698"},
	{"MYT_0", "+262269", "MYT_0", "+262", "269"},
	{"MYT_1", "+262639", "MYT_0", "+262", "639"},
}

var mig21Nonprefix = []struct{ oldID, oldCC, newID, newCC string }{
	{"ABW_1", "+5998", "ABW_0", "+297"},
	{"CCK_0", "+672", "CCK_0", "+61"},
	{"HMD_0", "+61", "HMD_0", "+672"},
	{"JAM_1", "+1658", "JAM_0", "+1876"},
	{"PCN_0", "+64", "PCN_0", "+870"},
	{"ATF_0", "+1", "ATF_0", "+262"},
}

// Collapse families: (_0 id, _1 id, canonical code, _0's old code, _1's old code).
// For ABW/JAM the _0 code was unchanged, so its old code == canonical code.
var mig21Collapse = []struct{ id0, id1, canonCC, old0CC, old1CC string }{
	{"BES_0", "BES_1", "+599", "+5993", "+5994"},
	{"CCK_0", "CCK_1", "+61", "+672", "+6189162"},
	{"PRI_0", "PRI_1", "+1", "+1787", "+1939"},
	{"MYT_0", "MYT_1", "+262", "+262269", "+262639"},
	{"ABW_0", "ABW_1", "+297", "+297", "+5998"},
	{"JAM_0", "JAM_1", "+1876", "+1876", "+1658"},
}

// Single-id affected countries: (id, canonical code).
var mig21Single = []struct{ id, canonCC string }{
	{"ALA_0", "+358"}, {"CUW_0", "+599"}, {"CXR_0", "+61"}, {"GGY_0", "+44"},
	{"IMN_0", "+44"}, {"JEY_0", "+44"}, {"SJM_0", "+47"}, {"VAT_0", "+3906"},
	{"HMD_0", "+672"}, {"PCN_0", "+870"}, {"ATF_0", "+262"},
}

func migration000021Fixtures() []migFixture {
	const usAddr = "US" // benign, unchanged address for phone-focused rows
	const sp = "5551234"
	x25 := strings.Repeat("1", 25)
	x26 := strings.Repeat("1", 26)
	x28 := strings.Repeat("1", 28)
	x29 := strings.Repeat("1", 29)

	// phone-focused fixture with address defaulted to US (unchanged).
	ph := func(label, uid, cc, phone string, verified, pending bool, wUID, wCC, wPhone string, wVerified, wPending bool) migFixture {
		return migFixture{
			label: label, uid: uid, cc: cc, phone: phone, verified: verified, pending: pending, addr: usAddr,
			wUID: wUID, wCC: wCC, wPhone: wPhone, wVerified: wVerified, wPending: wPending, wAddr: usAddr,
		}
	}

	var fs []migFixture

	// Branch 1: EVERY prefix mapping, preserved (verified + pending kept).
	for _, r := range mig21Prefix {
		fs = append(fs, ph("px_"+r.oldID, r.oldID, r.oldCC, sp, true, true,
			r.newID, r.newCC, r.prefix+sp, true, true))
	}
	// Branch 3: EVERY non-prefix mapping, invalidated (number unchanged).
	for _, r := range mig21Nonprefix {
		fs = append(fs, ph("np_"+r.oldID, r.oldID, r.oldCC, sp, true, true,
			r.newID, r.newCC, sp, false, false))
	}
	// Branch 5: EVERY collapse _1 already at the canonical code, remapped + preserved.
	for _, f := range mig21Collapse {
		fs = append(fs, ph("rm_"+f.id1, f.id1, f.canonCC, sp, true, true,
			f.id0, f.canonCC, sp, true, true))
	}
	// Branch 4: canonical _0 + new code is a no-op (verified + pending kept).
	for _, f := range mig21Collapse {
		fs = append(fs, ph("noop_"+f.id0, f.id0, f.canonCC, sp, true, true,
			f.id0, f.canonCC, sp, true, true))
	}
	// Branch 6: swapped-old-code dirty cases for every collapse family -- the bug
	// the union whitelist missed. id0 carrying id1's old code is always dirty;
	// id1 carrying id0's old code is dirty only when the _0 code actually changed
	// (for ABW/JAM the _0 code IS the canonical code, i.e. the remap case above).
	for _, f := range mig21Collapse {
		fs = append(fs, ph("dsw_"+f.id0, f.id0, f.old1CC, sp, true, true,
			f.id0, f.canonCC, sp, false, false))
		if f.old0CC != f.canonCC {
			fs = append(fs, ph("dsw_"+f.id1, f.id1, f.old0CC, sp, true, true,
				f.id0, f.canonCC, sp, false, false))
		}
		// Bogus code on the _1 id, exercising its dirty clause independently of
		// the old-code and canonical-code paths (for ABW_1/JAM_1 the swapped
		// case is the remap, so this is their only dirty-code coverage).
		fs = append(fs, ph("dbog_"+f.id1, f.id1, "+99999", sp, true, true,
			f.id0, f.canonCC, sp, false, false))
	}
	// Branch 6: bogus code on EVERY single-id affected country.
	for _, s := range mig21Single {
		fs = append(fs, ph("dbog_"+s.id, s.id, "+99999", sp, true, true,
			s.id, s.canonCC, sp, false, false))
	}
	// Branch 6 NULL-safety: NULL callingcode on a single-id and a collapse _1.
	nullGGY := ph("dnull_GGY_0", "GGY_0", "+44", sp, true, true, "GGY_0", "+44", sp, false, false)
	nullGGY.nullCC = true
	nullMYT := ph("dnull_MYT_1", "MYT_1", "+262", sp, true, true, "MYT_0", "+262", sp, false, false)
	nullMYT.nullCC = true
	fs = append(fs, nullGGY, nullMYT)

	// Branch 1/2 length boundaries: 2-digit prefix (ALA) at 30 (preserve) / 31
	// (fallback) and 5-digit prefix (CCK_1) at 30 (25+5) / 31 (26+5).
	fs = append(fs,
		ph("b_ala_30", "ALA_0", "+35818", x28, true, false, "ALA_0", "+358", "18"+x28, true, false),
		ph("b_ala_31", "ALA_0", "+35818", x29, true, true, "ALA_0", "+358", x29, false, false),
		ph("b_cck_30", "CCK_1", "+6189162", x25, true, false, "CCK_0", "+61", "89162"+x25, true, false),
		ph("b_cck_31", "CCK_1", "+6189162", x26, true, true, "CCK_0", "+61", x26, false, false),
		// SQL Server trailing space: 28 ones + space = 29 chars > 28 -> fallback
		// (DATALENGTH counts the trailing space; LEN would wrongly admit it).
		ph("b_trailing_space", "ALA_0", "+35818", x28+" ", true, false, "ALA_0", "+358", x28+" ", false, false),
		// Branch 2 empty phone (strengthened: verified + pending -> must invalidate).
		ph("empty_GGY", "GGY_0", "+441481", "", true, true, "GGY_0", "+44", "", false, false),
	)

	// Branch 0: removed phone countries (retain number, clear the rest).
	fs = append(fs,
		ph("removed_ANT", "ANT_0", "+599", "7654321", true, true, "", "", "7654321", false, false),
		ph("removed_YUG", "YUG_0", "+38", "123456", true, true, "", "", "123456", false, false),
		// Branch 7: unaffected country untouched.
		ph("unaffected_BR", "BRA_0", "+55", "1234567", true, true, "BRA_0", "+55", "1234567", true, true),
	)

	// Branch E: NULL normalization of the plain-string phone columns.
	nullCols := ph("null_phone_columns", "ZZ_9", "+000", "555", false, false, "", "", "", false, false)
	nullCols.nullPhone, nullCols.nullUID, nullCols.nullCC = true, true, true
	fs = append(fs, nullCols)

	// Branch D: address migration (phone left empty / unaffected).
	addr := func(label, in string, nullIn bool, want string) migFixture {
		return migFixture{label: label, addr: in, nullAddr: nullIn,
			wUID: "", wCC: "", wPhone: "", wVerified: false, wPending: false, wAddr: want}
	}
	fs = append(fs,
		addr("addr_AN", "AN", false, ""),
		addr("addr_YU", "YU", false, ""),
		addr("addr_null", "US", true, ""),
		addr("addr_valid_US", "US", false, "US"),
		addr("addr_empty", "", false, ""),
	)

	return fs
}

func seedMigrationFixture(t *testing.T, h *isolatedDB, f migFixture) int64 {
	t.Helper()
	u := &models.User{
		Subject: uuid.New(),
		// username is varchar(32); the fixture label is unique and short.
		Username:                      f.label,
		Email:                         uuid.NewString() + "@example.com",
		PasswordHash:                  "x",
		PhoneNumberCountryUniqueId:    f.uid,
		PhoneNumberCountryCallingCode: f.cc,
		PhoneNumber:                   f.phone,
		PhoneNumberVerified:           f.verified,
		AddressCountry:                f.addr,
	}
	if f.pending {
		u.PhoneNumberVerificationCodeEncrypted = []byte("PENDINGCODE12345")
		u.PhoneNumberVerificationCodeIssuedAt = sql.NullTime{Time: time.Now().UTC().Truncate(time.Second), Valid: true}
	}
	require.NoErrorf(t, h.DB.CreateUser(nil, u), "%s: CreateUser", f.label)

	// Apply NULL injections that CreateUser (Go string -> '') cannot produce.
	var sets []string
	if f.nullPhone {
		sets = append(sets, "phone_number = NULL")
	}
	if f.nullUID {
		sets = append(sets, "phone_number_country_uniqueid = NULL")
	}
	if f.nullCC {
		sets = append(sets, "phone_number_country_callingcode = NULL")
	}
	if f.nullAddr {
		sets = append(sets, "address_country = NULL")
	}
	if len(sets) > 0 {
		q := fmt.Sprintf("UPDATE users SET %s WHERE id = %d", strings.Join(sets, ", "), u.Id)
		_, err := h.SQL.Exec(q)
		require.NoErrorf(t, err, "%s: NULL injection", f.label)
	}
	return u.Id
}

func assertMigration000021(t *testing.T, h *isolatedDB, fixtures []migFixture, ids map[string]int64, phase string) {
	t.Helper()
	for _, f := range fixtures {
		// Every row must remain loadable via GetUserById (commondb scans the
		// plain-string columns, which cannot hold SQL NULL) -- this proves the
		// NULL normalization worked.
		u, err := h.DB.GetUserById(nil, ids[f.label])
		require.NoErrorf(t, err, "%s [%s]: GetUserById", f.label, phase)
		require.NotNilf(t, u, "%s [%s]: user nil", f.label, phase)

		assert.Equalf(t, f.wUID, u.PhoneNumberCountryUniqueId, "%s [%s]: uniqueid", f.label, phase)
		assert.Equalf(t, f.wCC, u.PhoneNumberCountryCallingCode, "%s [%s]: callingcode", f.label, phase)
		assert.Equalf(t, f.wPhone, u.PhoneNumber, "%s [%s]: phone_number", f.label, phase)
		assert.Equalf(t, f.wVerified, u.PhoneNumberVerified, "%s [%s]: verified", f.label, phase)
		assert.Equalf(t, f.wAddr, u.AddressCountry, "%s [%s]: address_country", f.label, phase)

		hasPending := len(u.PhoneNumberVerificationCodeEncrypted) > 0 && u.PhoneNumberVerificationCodeIssuedAt.Valid
		assert.Equalf(t, f.wPending, hasPending, "%s [%s]: pending verification present", f.label, phase)
	}
}
