package commondb

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"math/bits"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The record mapping, held to the records' tags on all four engines (#644 decision 3).
//
// Each record's read column list, scan function, whole-row INSERT and whole-row UPDATE are written
// out by hand, per engine. The `db` and `fieldtag` tags on the record stay the column contract,
// and this is what holds the hand-written SQL to them: through the scripted driver, with a
// distinct value per column, every read must land each column in the field tagged with its name,
// and every whole-row write must take each written value from the field tagged with its column.
// The INSERT writes every tagged column but the primary key; the UPDATE every tagged column but
// the primary key and the dont-update ones, whose absence from its text is the whole of their
// protection.
//
// WHY HERE AS WELL AS THE DATA TIER. Two same-typed columns swapped in a scan, or a dont-update
// column written back by an UPDATE whose data test does not happen to read it back, pass every
// data test. This reads which column each value went to, on each engine's own text, in seconds
// and without a database.
//
// The statements are read off what reached the driver, not off the Go values that hold them, so
// a method that builds its statement from the wrong list is caught as surely as a wrong list.

// mappingCase is one record's reads and whole-row writes, driven through the shared
// implementation's own methods.
type mappingCase struct {
	name  string
	table string
	// record is the record's struct type, whose tags are the contract.
	record reflect.Type
	// reads each run one read answering whole records and return the first, as a pointer.
	reads map[string]func(ctx context.Context, d *Database) (any, error)
	// insert and update run the record's whole-row writes on a pointer to the record. update is
	// nil for a record that has no whole-row UPDATE, which is then not checked.
	insert func(ctx context.Context, d *Database, rec any) error
	update func(ctx context.Context, d *Database, rec any) error
}

var allDialects = []data.Dialect{data.SQLite, data.MySQL, data.Postgres, data.MSSQL}

// firstOf answers the first record of a read returning a list, or an error naming an empty one.
func firstOf[T any](list []T, err error) (any, error) {
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("the read answered no record")
	}
	return &list[0], nil
}

func permissionMapping() mappingCase {
	return mappingCase{
		name:   "permission",
		table:  "permissions",
		record: reflect.TypeOf(record.Permission{}),
		reads: map[string]func(ctx context.Context, d *Database) (any, error){
			"GetPermissionById": func(ctx context.Context, d *Database) (any, error) {
				return d.GetPermissionById(ctx, nil, 1)
			},
			"GetPermissionsByResourceId": func(ctx context.Context, d *Database) (any, error) {
				return firstOf(d.GetPermissionsByResourceId(ctx, nil, 1))
			},
			"GetPermissionsByIds": func(ctx context.Context, d *Database) (any, error) {
				return firstOf(d.GetPermissionsByIds(ctx, nil, []int64{1, 2}))
			},
		},
		insert: func(ctx context.Context, d *Database, rec any) error {
			return d.CreatePermission(ctx, nil, rec.(*record.Permission))
		},
		update: func(ctx context.Context, d *Database, rec any) error {
			return d.UpdatePermission(ctx, nil, rec.(*record.Permission))
		},
	}
}

func resourceMapping() mappingCase {
	return mappingCase{
		name:   "resource",
		table:  "resources",
		record: reflect.TypeOf(record.Resource{}),
		reads: map[string]func(ctx context.Context, d *Database) (any, error){
			"GetResourceById": func(ctx context.Context, d *Database) (any, error) {
				return d.GetResourceById(ctx, nil, 1)
			},
			"GetResourceByResourceIdentifier": func(ctx context.Context, d *Database) (any, error) {
				// The distinct value the row carries, so the exact-match check keeps it.
				return d.GetResourceByResourceIdentifier(ctx, nil, distinctString("resource_identifier"))
			},
			"GetResourcesByIds": func(ctx context.Context, d *Database) (any, error) {
				return firstOf(d.GetResourcesByIds(ctx, nil, []int64{1, 2}))
			},
			"GetAllResources": func(ctx context.Context, d *Database) (any, error) {
				return firstOf(d.GetAllResources(ctx, nil))
			},
		},
		insert: func(ctx context.Context, d *Database, rec any) error {
			return d.CreateResource(ctx, nil, rec.(*record.Resource))
		},
		update: func(ctx context.Context, d *Database, rec any) error {
			return d.UpdateResource(ctx, nil, rec.(*record.Resource))
		},
	}
}

func clientMapping() mappingCase {
	return mappingCase{
		name:   "client",
		table:  "clients",
		record: reflect.TypeOf(record.Client{}),
		reads: map[string]func(ctx context.Context, d *Database) (any, error){
			"GetClientById": func(ctx context.Context, d *Database) (any, error) {
				return d.GetClientById(ctx, nil, 1)
			},
			"GetClientByClientIdentifier": func(ctx context.Context, d *Database) (any, error) {
				// The distinct value the row carries, so the exact-match check keeps it.
				return d.GetClientByClientIdentifier(ctx, nil, distinctString("client_identifier"))
			},
			"GetClientsByIds": func(ctx context.Context, d *Database) (any, error) {
				return firstOf(d.GetClientsByIds(ctx, nil, []int64{1, 2}))
			},
			"GetAllClients": func(ctx context.Context, d *Database) (any, error) {
				return firstOf(d.GetAllClients(ctx, nil))
			},
		},
		insert: func(ctx context.Context, d *Database, rec any) error {
			return d.CreateClient(ctx, nil, rec.(*record.Client))
		},
		update: func(ctx context.Context, d *Database, rec any) error {
			return d.UpdateClient(ctx, nil, rec.(*record.Client))
		},
	}
}

func clientLogoMapping() mappingCase {
	return mappingCase{
		name:   "client logo",
		table:  "client_logos",
		record: reflect.TypeOf(record.ClientLogo{}),
		reads: map[string]func(ctx context.Context, d *Database) (any, error){
			"GetClientLogoByClientId": func(ctx context.Context, d *Database) (any, error) {
				return d.GetClientLogoByClientId(ctx, nil, 1)
			},
		},
		insert: func(ctx context.Context, d *Database, rec any) error {
			return d.CreateClientLogo(ctx, nil, rec.(*record.ClientLogo))
		},
		update: func(ctx context.Context, d *Database, rec any) error {
			return d.UpdateClientLogo(ctx, nil, rec.(*record.ClientLogo))
		},
	}
}

func clientPermissionMapping() mappingCase {
	return mappingCase{
		name:   "client permission",
		table:  "clients_permissions",
		record: reflect.TypeOf(record.ClientPermission{}),
		reads: map[string]func(ctx context.Context, d *Database) (any, error){
			"GetClientPermissionById": func(ctx context.Context, d *Database) (any, error) {
				return d.GetClientPermissionById(ctx, nil, 1)
			},
			"GetClientPermissionByClientIdAndPermissionId": func(ctx context.Context, d *Database) (any, error) {
				return d.GetClientPermissionByClientIdAndPermissionId(ctx, nil, 1, 2)
			},
			"GetClientPermissionsByClientId": func(ctx context.Context, d *Database) (any, error) {
				return firstOf(d.GetClientPermissionsByClientId(ctx, nil, 1))
			},
		},
		insert: func(ctx context.Context, d *Database, rec any) error {
			return d.CreateClientPermission(ctx, nil, rec.(*record.ClientPermission))
		},
		update: func(ctx context.Context, d *Database, rec any) error {
			return d.UpdateClientPermission(ctx, nil, rec.(*record.ClientPermission))
		},
	}
}

// redirectURIMapping has no update: a redirect URI is created and deleted, never rewritten.
func redirectURIMapping() mappingCase {
	return mappingCase{
		name:   "redirect URI",
		table:  "redirect_uris",
		record: reflect.TypeOf(record.RedirectURI{}),
		reads: map[string]func(ctx context.Context, d *Database) (any, error){
			"GetRedirectURIById": func(ctx context.Context, d *Database) (any, error) {
				return d.GetRedirectURIById(ctx, nil, 1)
			},
			"GetRedirectURIsByClientId": func(ctx context.Context, d *Database) (any, error) {
				return firstOf(d.GetRedirectURIsByClientId(ctx, nil, 1))
			},
		},
		insert: func(ctx context.Context, d *Database, rec any) error {
			return d.CreateRedirectURI(ctx, nil, rec.(*record.RedirectURI))
		},
	}
}

// webOriginMapping has no update: a web origin is created and deleted, never rewritten.
func webOriginMapping() mappingCase {
	return mappingCase{
		name:   "web origin",
		table:  "web_origins",
		record: reflect.TypeOf(record.WebOrigin{}),
		reads: map[string]func(ctx context.Context, d *Database) (any, error){
			"GetWebOriginById": func(ctx context.Context, d *Database) (any, error) {
				return d.GetWebOriginById(ctx, nil, 1)
			},
			"GetWebOriginsByClientId": func(ctx context.Context, d *Database) (any, error) {
				return firstOf(d.GetWebOriginsByClientId(ctx, nil, 1))
			},
			"GetAllWebOrigins": func(ctx context.Context, d *Database) (any, error) {
				return firstOf(d.GetAllWebOrigins(ctx, nil))
			},
		},
		insert: func(ctx context.Context, d *Database, rec any) error {
			return d.CreateWebOrigin(ctx, nil, rec.(*record.WebOrigin))
		},
	}
}

func groupMapping() mappingCase {
	return mappingCase{
		name:   "group",
		table:  "groups",
		record: reflect.TypeOf(record.Group{}),
		reads: map[string]func(ctx context.Context, d *Database) (any, error){
			"GetGroupById": func(ctx context.Context, d *Database) (any, error) {
				return d.GetGroupById(ctx, nil, 1)
			},
			"GetGroupsByIds": func(ctx context.Context, d *Database) (any, error) {
				return firstOf(d.GetGroupsByIds(ctx, nil, []int64{1, 2}))
			},
			"GetGroupByGroupIdentifier": func(ctx context.Context, d *Database) (any, error) {
				// The distinct value the row carries, so the exact-match check keeps it.
				return d.GetGroupByGroupIdentifier(ctx, nil, distinctString("group_identifier"))
			},
			"GetAllGroups": func(ctx context.Context, d *Database) (any, error) {
				return firstOf(d.GetAllGroups(ctx, nil))
			},
			"GetAllGroupsPaginated": func(ctx context.Context, d *Database) (any, error) {
				groups, _, err := d.GetAllGroupsPaginated(ctx, nil, 2, 10)
				return firstOf(groups, err)
			},
		},
		insert: func(ctx context.Context, d *Database, rec any) error {
			return d.CreateGroup(ctx, nil, rec.(*record.Group))
		},
		update: func(ctx context.Context, d *Database, rec any) error {
			return d.UpdateGroup(ctx, nil, rec.(*record.Group))
		},
	}
}

func groupAttributeMapping() mappingCase {
	return mappingCase{
		name:   "group attribute",
		table:  "group_attributes",
		record: reflect.TypeOf(record.GroupAttribute{}),
		reads: map[string]func(ctx context.Context, d *Database) (any, error){
			"GetGroupAttributeById": func(ctx context.Context, d *Database) (any, error) {
				return d.GetGroupAttributeById(ctx, nil, 1)
			},
			"GetGroupAttributesByGroupIds": func(ctx context.Context, d *Database) (any, error) {
				return firstOf(d.GetGroupAttributesByGroupIds(ctx, nil, []int64{1, 2}))
			},
			"GetGroupAttributesByGroupId": func(ctx context.Context, d *Database) (any, error) {
				return firstOf(d.GetGroupAttributesByGroupId(ctx, nil, 1))
			},
		},
		insert: func(ctx context.Context, d *Database, rec any) error {
			return d.CreateGroupAttribute(ctx, nil, rec.(*record.GroupAttribute))
		},
		update: func(ctx context.Context, d *Database, rec any) error {
			return d.UpdateGroupAttribute(ctx, nil, rec.(*record.GroupAttribute))
		},
	}
}

func groupPermissionMapping() mappingCase {
	return mappingCase{
		name:   "group permission",
		table:  "groups_permissions",
		record: reflect.TypeOf(record.GroupPermission{}),
		reads: map[string]func(ctx context.Context, d *Database) (any, error){
			"GetGroupPermissionById": func(ctx context.Context, d *Database) (any, error) {
				return d.GetGroupPermissionById(ctx, nil, 1)
			},
			"GetGroupPermissionByGroupIdAndPermissionId": func(ctx context.Context, d *Database) (any, error) {
				return d.GetGroupPermissionByGroupIdAndPermissionId(ctx, nil, 1, 2)
			},
			"GetGroupPermissionsByGroupId": func(ctx context.Context, d *Database) (any, error) {
				return firstOf(d.GetGroupPermissionsByGroupId(ctx, nil, 1))
			},
			"GetGroupPermissionsByGroupIds": func(ctx context.Context, d *Database) (any, error) {
				return firstOf(d.GetGroupPermissionsByGroupIds(ctx, nil, []int64{1, 2}))
			},
		},
		insert: func(ctx context.Context, d *Database, rec any) error {
			return d.CreateGroupPermission(ctx, nil, rec.(*record.GroupPermission))
		},
		update: func(ctx context.Context, d *Database, rec any) error {
			return d.UpdateGroupPermission(ctx, nil, rec.(*record.GroupPermission))
		},
	}
}

func userGroupMapping() mappingCase {
	return mappingCase{
		name:   "user group",
		table:  "users_groups",
		record: reflect.TypeOf(record.UserGroup{}),
		reads: map[string]func(ctx context.Context, d *Database) (any, error){
			"GetUserGroupById": func(ctx context.Context, d *Database) (any, error) {
				return d.GetUserGroupById(ctx, nil, 1)
			},
			"GetUserGroupByUserIdAndGroupId": func(ctx context.Context, d *Database) (any, error) {
				return d.GetUserGroupByUserIdAndGroupId(ctx, nil, 1, 2)
			},
			"GetUserGroupsByUserId": func(ctx context.Context, d *Database) (any, error) {
				return firstOf(d.GetUserGroupsByUserId(ctx, nil, 1))
			},
			"GetUserGroupsByUserIds": func(ctx context.Context, d *Database) (any, error) {
				return firstOf(d.GetUserGroupsByUserIds(ctx, nil, []int64{1, 2}))
			},
		},
		insert: func(ctx context.Context, d *Database, rec any) error {
			return d.CreateUserGroup(ctx, nil, rec.(*record.UserGroup))
		},
		update: func(ctx context.Context, d *Database, rec any) error {
			return d.UpdateUserGroup(ctx, nil, rec.(*record.UserGroup))
		},
	}
}

// anyOf answers one record of a read returning a map, or an error naming an empty one.
func anyOf[K comparable, T any](m map[K]T, err error) (any, error) {
	if err != nil {
		return nil, err
	}
	for _, v := range m {
		return &v, nil
	}
	return nil, fmt.Errorf("the read answered no record")
}

// userMapping covers every read answering whole users, the group members' page among them, which
// joins users_groups and so selects each column qualified by its table.
func userMapping() mappingCase {
	return mappingCase{
		name:   "user",
		table:  "users",
		record: reflect.TypeOf(record.User{}),
		reads: map[string]func(ctx context.Context, d *Database) (any, error){
			"GetUserById": func(ctx context.Context, d *Database) (any, error) {
				return d.GetUserById(ctx, nil, 1)
			},
			"GetUserByIdForUpdate": func(ctx context.Context, d *Database) (any, error) {
				tx, err := d.BeginTransaction(ctx)
				if err != nil {
					return nil, err
				}
				defer func() { _ = tx.Rollback() }()
				return d.GetUserByIdForUpdate(ctx, tx, 1)
			},
			"GetUsersByIds": func(ctx context.Context, d *Database) (any, error) {
				return anyOf(d.GetUsersByIds(ctx, nil, []int64{1, 2}))
			},
			"GetUserByUsername": func(ctx context.Context, d *Database) (any, error) {
				return d.GetUserByUsername(ctx, nil, distinctString("username"))
			},
			"GetUserBySubject": func(ctx context.Context, d *Database) (any, error) {
				// The distinct value the row carries, so the exact-match check keeps it.
				return d.GetUserBySubject(ctx, nil, distinctString("subject"))
			},
			"GetUserByEmail": func(ctx context.Context, d *Database) (any, error) {
				// The distinct value the row carries, so the exact-match check keeps it.
				return d.GetUserByEmail(ctx, nil, distinctString("email"))
			},
			"GetUserByForgotPasswordCodeHash": func(ctx context.Context, d *Database) (any, error) {
				return d.GetUserByForgotPasswordCodeHash(ctx, nil, distinctString("forgot_password_code_hash"))
			},
			"SearchUsersPaginated": func(ctx context.Context, d *Database) (any, error) {
				users, _, err := d.SearchUsersPaginated(ctx, nil, "", 2, 10)
				return firstOf(users, err)
			},
			"SearchUsersPaginated with a term": func(ctx context.Context, d *Database) (any, error) {
				users, _, err := d.SearchUsersPaginated(ctx, nil, "ali_ce%", 2, 10)
				return firstOf(users, err)
			},
			"GetGroupMembersPaginated": func(ctx context.Context, d *Database) (any, error) {
				users, _, err := d.GetGroupMembersPaginated(ctx, nil, 1, 2, 10)
				return firstOf(users, err)
			},
		},
		insert: func(ctx context.Context, d *Database, rec any) error {
			return d.CreateUser(ctx, nil, rec.(*record.User))
		},
		update: func(ctx context.Context, d *Database, rec any) error {
			return d.UpdateUser(ctx, nil, rec.(*record.User))
		},
	}
}

// TestRecordMapping_EveryRecordMatchesItsTagsOnEveryEngine holds each record written per engine
// to its tags. A record joins this list in the slice that writes its SQL per engine.
func TestRecordMapping_EveryRecordMatchesItsTagsOnEveryEngine(t *testing.T) {
	for _, c := range []mappingCase{
		permissionMapping(), resourceMapping(),
		clientMapping(), clientLogoMapping(), clientPermissionMapping(), redirectURIMapping(), webOriginMapping(),
		groupMapping(), groupAttributeMapping(), groupPermissionMapping(), userGroupMapping(),
		userMapping(),
	} {
		for _, dialect := range allDialects {
			t.Run(c.name+"/"+string(dialect), func(t *testing.T) {
				problems := checkMapping(t, dialect, c)
				assert.Empty(t, problems, "\n%s", strings.Join(problems, "\n"))
			})
		}
	}
}

// taggedField is one column of the contract: a field with a `db` tag other than "-".
type taggedField struct {
	column     string
	index      int
	pk         bool
	dontUpdate bool
	withQuote  bool
}

func taggedFields(rt reflect.Type) []taggedField {
	var fields []taggedField
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		column := f.Tag.Get("db")
		if column == "" || column == "-" {
			continue
		}
		tf := taggedField{column: column, index: i}
		for _, tag := range strings.Split(f.Tag.Get("fieldtag"), ",") {
			switch strings.TrimSpace(tag) {
			case "pk":
				tf.pk = true
			case "dont-update":
				tf.dontUpdate = true
			}
		}
		for _, opt := range strings.Split(f.Tag.Get("fieldopt"), ",") {
			if strings.TrimSpace(opt) == "withquote" {
				tf.withQuote = true
			}
		}
		fields = append(fields, tf)
	}
	return fields
}

// distinctString is the value a string column carries in this test: its own name, so no two
// columns of a record carry the same one.
func distinctString(column string) string {
	return "value of " + column
}

// passesFor is how many passes checkMapping makes over a record: two per bit of the largest field
// code, so that any two bool fields hold different values in at least one pass and every bool
// field holds both values in some pass. A bool has two values, so one pass cannot tell a swapped
// pair of bool columns apart; a record carries many of them (#644).
func passesFor(rt reflect.Type) int {
	return 2 * bits.Len(uint(rt.NumField()))
}

// boolFor is the value bool field i holds in pass: bit (pass mod the bit count) of i, inverted in
// the second half of the passes. Two fields' indexes differ in some bit, and the inversion gives
// every field both values.
func boolFor(rt reflect.Type, i int, pass int) bool {
	n := bits.Len(uint(rt.NumField()))
	bit := i>>(pass%n)&1 == 1
	if pass >= n {
		return !bit
	}
	return bit
}

// distinctValue is the value field i of the record carries in this test's pass, as the driver
// hands it over and as the field holds it once scanned. Distinct per field for every type but
// bool, which has two values and is told apart across passes (boolFor); a type it does not know
// is reported rather than guessed, so the record that brings one extends this.
func distinctValue(rt reflect.Type, i int, column string, pass int) (driver.Value, reflect.Value, error) {
	ft := rt.Field(i).Type
	at := time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC).Add(time.Duration(i) * time.Hour)
	n := int64(1000 + i)
	b := boolFor(rt, i, pass)
	var dv driver.Value
	var gv any
	switch ft {
	case reflect.TypeOf(int64(0)):
		dv, gv = n, n
	case reflect.TypeOf(int(0)):
		dv, gv = n, int(n)
	case reflect.TypeOf(""):
		dv, gv = distinctString(column), distinctString(column)
	case reflect.TypeOf(false):
		dv, gv = b, b
	case reflect.TypeOf((*bool)(nil)):
		dv, gv = b, &b
	case reflect.TypeOf(time.Time{}):
		dv, gv = at, at
	case reflect.TypeOf([]byte(nil)):
		dv, gv = []byte(distinctString(column)), []byte(distinctString(column))
	case reflect.TypeOf(sql.NullTime{}):
		dv, gv = at, sql.NullTime{Time: at, Valid: true}
	case reflect.TypeOf(sql.NullString{}):
		dv, gv = distinctString(column), sql.NullString{String: distinctString(column), Valid: true}
	case reflect.TypeOf(sql.NullInt64{}):
		dv, gv = n, sql.NullInt64{Int64: n, Valid: true}
	case reflect.TypeOf(sql.NullInt32{}):
		dv, gv = n, sql.NullInt32{Int32: int32(n), Valid: true}
	case reflect.TypeOf(sql.NullBool{}):
		dv, gv = b, sql.NullBool{Bool: b, Valid: true}
	default:
		// A named string type, such as record.AcrLevel, is stored and scanned as its string.
		if ft.Kind() == reflect.String {
			return distinctString(column), reflect.ValueOf(distinctString(column)).Convert(ft), nil
		}
		return nil, reflect.Value{}, fmt.Errorf("no distinct value is written for a %s field (column %s)", ft, column)
	}
	return dv, reflect.ValueOf(gv), nil
}

// identifier is one column or table name as a statement spells it.
type identifier struct {
	name  string
	quote string
}

func parseIdentifier(s string) identifier {
	s = strings.TrimSpace(s)
	for _, q := range []string{"`", `"`} {
		if len(s) >= 2 && strings.HasPrefix(s, q) && strings.HasSuffix(s, q) {
			return identifier{name: s[1 : len(s)-1], quote: q}
		}
	}
	return identifier{name: s}
}

// parseColumn reads one entry of a select list, which may be qualified by its table.
func parseColumn(s string, table string) identifier {
	s = strings.TrimSpace(s)
	for _, prefix := range []string{table + ".", `"` + table + `".`, "`" + table + "`."} {
		s = strings.TrimPrefix(s, prefix)
	}
	return parseIdentifier(s)
}

// quoteProblems holds an identifier to the engine's quoting: MySQL quotes with backticks and the
// other three with double quotes, and a column tagged withquote is a reserved word somewhere and
// must be quoted on every engine.
func quoteProblems(dialect data.Dialect, id identifier, field taggedField, where string) []string {
	want := `"`
	if dialect == data.MySQL {
		want = "`"
	}
	var problems []string
	if id.quote != "" && id.quote != want {
		problems = append(problems, fmt.Sprintf("%s: column %s is quoted with %s, which %s does not quote with", where, id.name, id.quote, dialect))
	}
	if field.withQuote && id.quote == "" {
		problems = append(problems, fmt.Sprintf("%s: column %s is tagged withquote and is not quoted", where, id.name))
	}
	return problems
}

var (
	selectList    = regexp.MustCompile(`(?s)^SELECT (.+?) FROM (\S+)`)
	insertShape   = regexp.MustCompile(`(?s)^INSERT INTO (\S+) \((.+?)\)( OUTPUT INSERTED\.id)? VALUES \((.+?)\)( RETURNING id)?$`)
	updateShape   = regexp.MustCompile(`(?s)^UPDATE (\S+) SET (.+) WHERE (.+)$`)
	numberedParam = regexp.MustCompile(`^(\$|@p)([1-9][0-9]*)$`)
)

// placeholderIndexes reads a run of placeholders in the dialect's style and answers the argument
// each one binds, counting the `?`s before it on the two engines that do not number theirs.
type placeholderReader struct {
	dialect data.Dialect
	next    int
}

func (p *placeholderReader) read(s string) (int, error) {
	s = strings.TrimSpace(s)
	switch p.dialect {
	case data.SQLite, data.MySQL:
		if s != "?" {
			return 0, fmt.Errorf("placeholder %q is not %s's ?", s, p.dialect)
		}
		p.next++
		return p.next - 1, nil
	}
	m := numberedParam.FindStringSubmatch(s)
	want := "$"
	if p.dialect == data.MSSQL {
		want = "@p"
	}
	if m == nil || m[1] != want {
		return 0, fmt.Errorf("placeholder %q is not %s's %sN", s, p.dialect, want)
	}
	n, _ := strconv.Atoi(m[2])
	return n - 1, nil
}

// driverValueOf is a field's value as database/sql hands it to the driver.
func driverValueOf(v reflect.Value) (driver.Value, error) {
	if valuer, ok := v.Interface().(driver.Valuer); ok {
		return valuer.Value()
	}
	return driver.DefaultParameterConverter.ConvertValue(v.Interface())
}

func sameValue(a, b any) bool {
	if at, ok := a.(time.Time); ok {
		bt, ok := b.(time.Time)
		return ok && at.Equal(bt)
	}
	return reflect.DeepEqual(a, b)
}

// checkMapping runs every read and both whole-row writes of c on dialect's text, and answers what
// does not match the tags, one line per problem.
func checkMapping(t *testing.T, dialect data.Dialect, c mappingCase) []string {
	t.Helper()
	fields := taggedFields(c.record)
	byColumn := map[string]taggedField{}
	for _, f := range fields {
		byColumn[f.column] = f
	}

	var problems []string
	seen := map[string]bool{}
	for pass := 0; pass < passesFor(c.record); pass++ {
		var found []string
		for name, read := range c.reads {
			found = append(found, checkRead(t, dialect, c, fields, byColumn, name, read, pass)...)
		}
		found = append(found, checkInsert(t, dialect, c, fields, byColumn, pass)...)
		if c.update != nil {
			found = append(found, checkUpdate(t, dialect, c, fields, byColumn, pass)...)
		}
		// A problem that does not depend on the pass is reported once.
		for _, problem := range found {
			if !seen[problem] {
				seen[problem] = true
				problems = append(problems, problem)
			}
		}
	}
	return problems
}

func checkRead(t *testing.T, dialect data.Dialect, c mappingCase, fields []taggedField,
	byColumn map[string]taggedField, name string, read func(context.Context, *Database) (any, error), pass int) []string {
	t.Helper()
	where := fmt.Sprintf("%s %s", dialect, name)
	var problems []string

	script := &scriptedDriver{}
	script.answer = func(query string, _ []driver.Value) *scriptedRows {
		m := selectList.FindStringSubmatch(query)
		if m == nil {
			problems = append(problems, fmt.Sprintf("%s: the statement is not a SELECT this test reads: %q", where, query))
			return &scriptedRows{}
		}
		// A paged read counts the rows beside the page, which selects no field of the record.
		if strings.EqualFold(strings.TrimSpace(m[1]), "count(*)") {
			return &scriptedRows{cols: []string{"count"}, values: [][]driver.Value{{int64(1)}}}
		}
		selected := map[string]bool{}
		row := &scriptedRows{values: [][]driver.Value{{}}}
		for _, entry := range strings.Split(m[1], ",") {
			id := parseColumn(entry, c.table)
			field, known := byColumn[id.name]
			if !known {
				problems = append(problems, fmt.Sprintf("%s: selects %s, which no field is tagged with", where, id.name))
				row.cols = append(row.cols, id.name)
				row.values[0] = append(row.values[0], nil)
				continue
			}
			if selected[id.name] {
				problems = append(problems, fmt.Sprintf("%s: selects %s twice", where, id.name))
			}
			selected[id.name] = true
			problems = append(problems, quoteProblems(dialect, id, field, where)...)
			dv, _, err := distinctValue(c.record, field.index, field.column, pass)
			if err != nil {
				problems = append(problems, where+": "+err.Error())
			}
			row.cols = append(row.cols, id.name)
			row.values[0] = append(row.values[0], dv)
		}
		for _, f := range fields {
			if !selected[f.column] {
				problems = append(problems, fmt.Sprintf("%s: does not select %s", where, f.column))
			}
		}
		return row
	}

	got, err := read(context.Background(), scriptedDBFor(t, script, dialect))
	if err != nil {
		return append(problems, fmt.Sprintf("%s: %v", where, err))
	}
	if got == nil || reflect.ValueOf(got).IsNil() {
		return append(problems, fmt.Sprintf("%s: answered no record", where))
	}
	rv := reflect.ValueOf(got).Elem()
	for _, f := range fields {
		_, want, err := distinctValue(c.record, f.index, f.column, pass)
		if err != nil {
			continue
		}
		if have := rv.Field(f.index).Interface(); !reflect.DeepEqual(have, want.Interface()) {
			problems = append(problems, fmt.Sprintf("%s: field %s holds %v, want %v, the value of column %s",
				where, c.record.Field(f.index).Name, have, want.Interface(), f.column))
		}
	}
	return problems
}

// filledRecord is a new record whose every tagged field holds its distinct value.
func filledRecord(c mappingCase, fields []taggedField, pass int) (reflect.Value, []string) {
	rec := reflect.New(c.record)
	var problems []string
	for _, f := range fields {
		_, gv, err := distinctValue(c.record, f.index, f.column, pass)
		if err != nil {
			problems = append(problems, err.Error())
			continue
		}
		rec.Elem().Field(f.index).Set(gv)
	}
	return rec, problems
}

// checkWrittenColumn holds one written column to the field tagged with it: the value bound to its
// placeholder must be the field's value as it stood when the write returned.
func checkWrittenColumn(where string, dialect data.Dialect, rec reflect.Value, byColumn map[string]taggedField,
	col identifier, argIndex int, args []driver.Value) []string {
	field, known := byColumn[col.name]
	if !known {
		return []string{fmt.Sprintf("%s: writes %s, which no field is tagged with", where, col.name)}
	}
	problems := quoteProblems(dialect, col, field, where)
	if argIndex >= len(args) {
		return append(problems, fmt.Sprintf("%s: column %s binds argument %d of %d", where, col.name, argIndex+1, len(args)))
	}
	want, err := driverValueOf(rec.Elem().Field(field.index))
	if err != nil {
		return append(problems, fmt.Sprintf("%s: %v", where, err))
	}
	if !sameValue(args[argIndex], want) {
		problems = append(problems, fmt.Sprintf("%s: column %s is written %v, want %v, the value of the field tagged with it",
			where, col.name, args[argIndex], want))
	}
	return problems
}

// newId is the id the scripted engine reports for every insert.
const newId = 4242

func checkInsert(t *testing.T, dialect data.Dialect, c mappingCase, fields []taggedField,
	byColumn map[string]taggedField, pass int) []string {
	t.Helper()
	where := fmt.Sprintf("%s insert", dialect)
	rec, problems := filledRecord(c, fields, pass)

	script := &scriptedDriver{execs: []*scriptedExec{{rowsAffected: 1, lastInsertId: newId}}}
	script.answer = func(string, []driver.Value) *scriptedRows {
		return &scriptedRows{cols: []string{"id"}, values: [][]driver.Value{{int64(newId)}}}
	}
	if err := c.insert(context.Background(), scriptedDBFor(t, script, dialect), rec.Interface()); err != nil {
		return append(problems, fmt.Sprintf("%s: %v", where, err))
	}
	if len(script.statements) != 1 {
		return append(problems, fmt.Sprintf("%s: %d statements reached the engine, want 1", where, len(script.statements)))
	}
	query := script.statements[0]

	// Where the new id comes back is the engine's own grammar: a row on PostgreSQL and SQL Server,
	// whose drivers refuse LastInsertId, and LastInsertId on SQLite and MySQL.
	args := script.execArgs
	switch dialect {
	case data.Postgres, data.MSSQL:
		args = script.queryArgs
		if script.queryCount != 1 {
			problems = append(problems, fmt.Sprintf("%s: the insert did not run as a query answering its id", where))
		}
	default:
		if script.execCount != 1 {
			problems = append(problems, fmt.Sprintf("%s: the insert did not run as a statement", where))
		}
	}
	if len(args) != 1 {
		return append(problems, fmt.Sprintf("%s: no arguments were recorded", where))
	}

	m := insertShape.FindStringSubmatch(query)
	if m == nil {
		return append(problems, fmt.Sprintf("%s: the statement is not an INSERT this test reads: %q", where, query))
	}
	if table := parseIdentifier(m[1]).name; table != c.table {
		problems = append(problems, fmt.Sprintf("%s: inserts into %s, want %s", where, table, c.table))
	}
	output, returning := m[3] != "", m[5] != ""
	if output != (dialect == data.MSSQL) || returning != (dialect == data.Postgres) {
		problems = append(problems, fmt.Sprintf("%s: the statement does not answer the new id in %s's own grammar: %q", where, dialect, query))
	}

	columns := strings.Split(m[2], ",")
	values := strings.Split(m[4], ",")
	if len(columns) != len(values) {
		return append(problems, fmt.Sprintf("%s: %d columns and %d values", where, len(columns), len(values)))
	}
	reader := &placeholderReader{dialect: dialect}
	written := map[string]bool{}
	for i, entry := range columns {
		col := parseIdentifier(entry)
		if written[col.name] {
			problems = append(problems, fmt.Sprintf("%s: writes %s twice", where, col.name))
		}
		written[col.name] = true
		argIndex, err := reader.read(values[i])
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", where, err))
			continue
		}
		problems = append(problems, checkWrittenColumn(where, dialect, rec, byColumn, col, argIndex, args[0])...)
	}
	for _, f := range fields {
		switch {
		case f.pk && written[f.column]:
			problems = append(problems, fmt.Sprintf("%s: writes the primary key %s", where, f.column))
		case !f.pk && !written[f.column]:
			problems = append(problems, fmt.Sprintf("%s: does not write %s", where, f.column))
		}
	}

	if id := rec.Elem().FieldByName("Id"); !id.IsValid() || id.Int() != newId {
		problems = append(problems, fmt.Sprintf("%s: the record's Id is not the id the engine answered, %d", where, newId))
	}
	return problems
}

func checkUpdate(t *testing.T, dialect data.Dialect, c mappingCase, fields []taggedField,
	byColumn map[string]taggedField, pass int) []string {
	t.Helper()
	where := fmt.Sprintf("%s update", dialect)
	rec, problems := filledRecord(c, fields, pass)

	script := &scriptedDriver{}
	if err := c.update(context.Background(), scriptedDBFor(t, script, dialect), rec.Interface()); err != nil {
		return append(problems, fmt.Sprintf("%s: %v", where, err))
	}
	if len(script.statements) != 1 || len(script.execArgs) != 1 {
		return append(problems, fmt.Sprintf("%s: %d statements reached the engine, want 1", where, len(script.statements)))
	}
	query, args := script.statements[0], script.execArgs[0]

	m := updateShape.FindStringSubmatch(query)
	if m == nil {
		return append(problems, fmt.Sprintf("%s: the statement is not an UPDATE this test reads: %q", where, query))
	}
	if table := parseIdentifier(m[1]).name; table != c.table {
		problems = append(problems, fmt.Sprintf("%s: updates %s, want %s", where, table, c.table))
	}

	reader := &placeholderReader{dialect: dialect}
	written := map[string]bool{}
	for _, assignment := range strings.Split(m[2], ",") {
		parts := strings.SplitN(assignment, "=", 2)
		if len(parts) != 2 {
			problems = append(problems, fmt.Sprintf("%s: %q is not an assignment", where, assignment))
			continue
		}
		col := parseIdentifier(parts[0])
		if written[col.name] {
			problems = append(problems, fmt.Sprintf("%s: writes %s twice", where, col.name))
		}
		written[col.name] = true
		argIndex, err := reader.read(parts[1])
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", where, err))
			continue
		}
		problems = append(problems, checkWrittenColumn(where, dialect, rec, byColumn, col, argIndex, args)...)
	}
	for _, f := range fields {
		switch {
		case f.pk && written[f.column]:
			problems = append(problems, fmt.Sprintf("%s: writes the primary key %s", where, f.column))
		case f.dontUpdate && written[f.column]:
			problems = append(problems, fmt.Sprintf("%s: writes %s, which is tagged dont-update", where, f.column))
		case !f.pk && !f.dontUpdate && !written[f.column]:
			problems = append(problems, fmt.Sprintf("%s: does not write %s", where, f.column))
		}
	}

	// The row addressed is the record's own: WHERE id = <its Id>.
	condition := strings.SplitN(m[3], "=", 2)
	if len(condition) != 2 || parseIdentifier(condition[0]).name != "id" {
		return append(problems, fmt.Sprintf("%s: the row is not addressed by id alone: %q", where, m[3]))
	}
	argIndex, err := reader.read(condition[1])
	if err != nil {
		return append(problems, fmt.Sprintf("%s: %v", where, err))
	}
	return append(problems, checkWrittenColumn(where+" WHERE", dialect, rec, byColumn,
		identifier{name: "id"}, argIndex, args)...)
}

// The checker's own cases, over a made-up record whose hand-written SQL is right on every
// engine, and then wrong in each of the ways decision 3 names. Without these the test above would
// pass on a checker that had stopped reading anything.

type widget struct {
	Id        int64        `db:"id" fieldtag:"pk"`
	CreatedAt sql.NullTime `db:"created_at" fieldtag:"dont-update"`
	Name      string       `db:"name"`
	Label     string       `db:"label"`
	Key       string       `db:"key" fieldopt:"withquote"`
	Enabled   bool         `db:"enabled"`
	Visible   bool         `db:"visible"`
	Parent    record.Group `db:"-"`
}

// widgetSQL is a widget's hand-written SQL; each case below breaks one piece of it.
type widgetSQL struct {
	columns columnList
	scan    func(rowScanner, *widget) error
	insert  statement
	update  statement
}

func rightWidgetSQL() widgetSQL {
	return widgetSQL{
		columns: columnList{
			sqlite:   `id, created_at, name, label, "key", enabled, visible`,
			mysql:    "id, created_at, name, label, `key`, enabled, visible",
			postgres: `id, created_at, name, label, "key", enabled, visible`,
			mssql:    `id, created_at, name, label, "key", enabled, visible`,
		},
		scan: func(r rowScanner, w *widget) error {
			return r.Scan(&w.Id, &w.CreatedAt, &w.Name, &w.Label, &w.Key, &w.Enabled, &w.Visible)
		},
		insert: statement{
			sqlite:   `INSERT INTO widgets (created_at, name, label, "key", enabled, visible) VALUES (?, ?, ?, ?, ?, ?)`,
			mysql:    "INSERT INTO widgets (created_at, name, label, `key`, enabled, visible) VALUES (?, ?, ?, ?, ?, ?)",
			postgres: `INSERT INTO widgets (created_at, name, label, "key", enabled, visible) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
			mssql:    `INSERT INTO widgets (created_at, name, label, "key", enabled, visible) OUTPUT INSERTED.id VALUES (@p1, @p2, @p3, @p4, @p5, @p6)`,
		},
		update: statement{
			sqlite:   `UPDATE widgets SET name = ?, label = ?, "key" = ?, enabled = ?, visible = ? WHERE id = ?`,
			mysql:    "UPDATE widgets SET name = ?, label = ?, `key` = ?, enabled = ?, visible = ? WHERE id = ?",
			postgres: `UPDATE widgets SET name = $1, label = $2, "key" = $3, enabled = $4, visible = $5 WHERE id = $6`,
			mssql:    `UPDATE widgets SET name = @p1, label = @p2, "key" = @p3, enabled = @p4, visible = @p5 WHERE id = @p6`,
		},
	}
}

func widgetMapping(w widgetSQL) mappingCase {
	return mappingCase{
		name:   "widget",
		table:  "widgets",
		record: reflect.TypeOf(widget{}),
		reads: map[string]func(ctx context.Context, d *Database) (any, error){
			"read": func(ctx context.Context, d *Database) (any, error) {
				rows, err := d.QuerySQL(ctx, nil, "SELECT "+w.columns.text(d.Dialect)+" FROM widgets WHERE id = 1")
				if err != nil {
					return nil, err
				}
				defer func() { _ = rows.Close() }()
				var got widget
				if !rows.Next() {
					return nil, rows.Err()
				}
				return &got, w.scan(rows, &got)
			},
		},
		insert: func(ctx context.Context, d *Database, rec any) error {
			v := rec.(*widget)
			id, err := d.insert(ctx, nil, w.insert, "widget", v.CreatedAt, v.Name, v.Label, v.Key, v.Enabled, v.Visible)
			v.Id = id
			return err
		},
		update: func(ctx context.Context, d *Database, rec any) error {
			v := rec.(*widget)
			_, err := d.ExecSQL(ctx, nil, w.update.text(d.Dialect), v.Name, v.Label, v.Key, v.Enabled, v.Visible, v.Id)
			return err
		},
	}
}

func TestRecordMapping_TheCheckerPassesRightSQLOnEveryEngine(t *testing.T) {
	for _, dialect := range allDialects {
		t.Run(string(dialect), func(t *testing.T) {
			problems := checkMapping(t, dialect, widgetMapping(rightWidgetSQL()))
			assert.Empty(t, problems, "\n%s", strings.Join(problems, "\n"))
		})
	}
}

func TestRecordMapping_TheCheckerRefusesAColumnMissingFromTheList(t *testing.T) {
	w := rightWidgetSQL()
	w.columns.postgres = `id, created_at, name, "key", enabled, visible`
	w.scan = func(r rowScanner, v *widget) error {
		return r.Scan(&v.Id, &v.CreatedAt, &v.Name, &v.Key, &v.Enabled, &v.Visible)
	}

	problems := checkMapping(t, data.Postgres, widgetMapping(w))
	require.NotEmpty(t, problems)
	assert.Contains(t, strings.Join(problems, "\n"), "postgres read: does not select label")
}

func TestRecordMapping_TheCheckerRefusesAFieldScannedOutOfOrder(t *testing.T) {
	w := rightWidgetSQL()
	w.scan = func(r rowScanner, v *widget) error {
		return r.Scan(&v.Id, &v.CreatedAt, &v.Label, &v.Name, &v.Key, &v.Enabled, &v.Visible)
	}

	problems := checkMapping(t, data.MySQL, widgetMapping(w))
	require.NotEmpty(t, problems)
	joined := strings.Join(problems, "\n")
	assert.Contains(t, joined, "field Name holds value of label")
	assert.Contains(t, joined, "field Label holds value of name")
}

func TestRecordMapping_TheCheckerRefusesAnUpdateWritingADontUpdateColumn(t *testing.T) {
	w := rightWidgetSQL()
	w.update.mssql = `UPDATE widgets SET created_at = @p1, name = @p2, label = @p3, "key" = @p4, enabled = @p5, visible = @p6 WHERE id = @p7`
	broken := widgetMapping(w)
	broken.update = func(ctx context.Context, d *Database, rec any) error {
		v := rec.(*widget)
		_, err := d.ExecSQL(ctx, nil, w.update.text(d.Dialect), v.CreatedAt, v.Name, v.Label, v.Key, v.Enabled, v.Visible, v.Id)
		return err
	}

	problems := checkMapping(t, data.MSSQL, broken)
	require.NotEmpty(t, problems)
	assert.Contains(t, strings.Join(problems, "\n"), "mssql update: writes created_at, which is tagged dont-update")
}

func TestRecordMapping_TheCheckerRefusesAWrittenValueFromAnotherField(t *testing.T) {
	broken := widgetMapping(rightWidgetSQL())
	broken.insert = func(ctx context.Context, d *Database, rec any) error {
		v := rec.(*widget)
		id, err := d.insert(ctx, nil, rightWidgetSQL().insert, "widget", v.CreatedAt, v.Label, v.Name, v.Key, v.Enabled, v.Visible)
		v.Id = id
		return err
	}

	problems := checkMapping(t, data.SQLite, broken)
	require.NotEmpty(t, problems)
	assert.Contains(t, strings.Join(problems, "\n"), "sqlite insert: column name is written value of label")
}

func TestRecordMapping_TheCheckerRefusesTheOtherEnginesQuote(t *testing.T) {
	w := rightWidgetSQL()
	w.columns.mysql = `id, created_at, name, label, "key", enabled, visible`

	problems := checkMapping(t, data.MySQL, widgetMapping(w))
	assert.Contains(t, strings.Join(problems, "\n"), `mysql read: column key is quoted with ", which mysql does not quote with`)
}

func TestRecordMapping_TheCheckerRefusesAnInsertNotAnsweringItsIdInTheEnginesGrammar(t *testing.T) {
	w := rightWidgetSQL()
	w.insert.postgres = `INSERT INTO widgets (created_at, name, label, "key", enabled, visible) VALUES ($1, $2, $3, $4, $5, $6)`

	problems := checkMapping(t, data.Postgres, widgetMapping(w))
	assert.Contains(t, strings.Join(problems, "\n"), "postgres insert: the statement does not answer the new id in postgres's own grammar")
}

func TestRecordMapping_TheCheckerRefusesTwoBoolColumnsScannedSwapped(t *testing.T) {
	w := rightWidgetSQL()
	w.scan = func(r rowScanner, v *widget) error {
		return r.Scan(&v.Id, &v.CreatedAt, &v.Name, &v.Label, &v.Key, &v.Visible, &v.Enabled)
	}

	problems := checkMapping(t, data.Postgres, widgetMapping(w))
	require.NotEmpty(t, problems)
	joined := strings.Join(problems, "\n")
	assert.Contains(t, joined, "field Enabled holds")
	assert.Contains(t, joined, "field Visible holds")
}

func TestRecordMapping_TheCheckerRefusesTwoBoolValuesWrittenSwapped(t *testing.T) {
	broken := widgetMapping(rightWidgetSQL())
	broken.update = func(ctx context.Context, d *Database, rec any) error {
		v := rec.(*widget)
		_, err := d.ExecSQL(ctx, nil, rightWidgetSQL().update.text(d.Dialect), v.Name, v.Label, v.Key, v.Visible, v.Enabled, v.Id)
		return err
	}

	problems := checkMapping(t, data.SQLite, broken)
	require.NotEmpty(t, problems)
	joined := strings.Join(problems, "\n")
	assert.Contains(t, joined, "sqlite update: column enabled is written")
	assert.Contains(t, joined, "sqlite update: column visible is written")
}
