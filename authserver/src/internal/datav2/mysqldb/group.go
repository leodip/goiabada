package mysqldb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/pkg/errors"
)

func (d *MySQLDatabase) CreateGroup(tx *sql.Tx, group *entitiesv2.Group) error {

	now := time.Now().UTC()

	originalCreatedAt := group.CreatedAt
	originalUpdatedAt := group.UpdatedAt
	group.CreatedAt = sql.NullTime{Time: now, Valid: true}
	group.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	groupStruct := sqlbuilder.NewStruct(new(entitiesv2.Group)).
		For(sqlbuilder.MySQL)

	insertBuilder := groupStruct.WithoutTag("pk").InsertInto("`groups`", group)

	sql, args := insertBuilder.Build()
	result, err := d.execSql(tx, sql, args...)
	if err != nil {
		group.CreatedAt = originalCreatedAt
		group.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to insert group")
	}

	id, err := result.LastInsertId()
	if err != nil {
		group.CreatedAt = originalCreatedAt
		group.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to get last insert id")
	}

	group.Id = id
	return nil
}

func (d *MySQLDatabase) UpdateGroup(tx *sql.Tx, group *entitiesv2.Group) error {

	if group.Id == 0 {
		return errors.New("can't update group with id 0")
	}

	originalUpdatedAt := group.UpdatedAt
	group.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	groupStruct := sqlbuilder.NewStruct(new(entitiesv2.Group)).
		For(sqlbuilder.MySQL)

	updateBuilder := groupStruct.WithoutTag("pk").Update("`groups`", group)
	updateBuilder.Where(updateBuilder.Equal("id", group.Id))

	sql, args := updateBuilder.Build()
	_, err := d.execSql(tx, sql, args...)
	if err != nil {
		group.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to update group")
	}

	return nil
}

func (d *MySQLDatabase) getGroupCommon(tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	groupStruct *sqlbuilder.Struct) (*entitiesv2.Group, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.querySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var group entitiesv2.Group
	if rows.Next() {
		addr := groupStruct.Addr(&group)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan group")
		}
		return &group, nil
	}
	return nil, nil
}

func (d *MySQLDatabase) GetGroupById(tx *sql.Tx, groupId int64) (*entitiesv2.Group, error) {

	if groupId <= 0 {
		return nil, errors.New("group id must be greater than 0")
	}

	groupStruct := sqlbuilder.NewStruct(new(entitiesv2.Group)).
		For(sqlbuilder.MySQL)

	selectBuilder := groupStruct.SelectFrom("`groups`")
	selectBuilder.Where(selectBuilder.Equal("id", groupId))

	group, err := d.getGroupCommon(tx, selectBuilder, groupStruct)
	if err != nil {
		return nil, err
	}

	return group, nil
}

func (d *MySQLDatabase) GetGroupByGroupIdentifier(tx *sql.Tx, groupIdentifier string) (*entitiesv2.Group, error) {
	if groupIdentifier == "" {
		return nil, errors.New("group identifier must not be empty")
	}

	groupStruct := sqlbuilder.NewStruct(new(entitiesv2.Group)).
		For(sqlbuilder.MySQL)

	selectBuilder := groupStruct.SelectFrom("`groups`")
	selectBuilder.Where(selectBuilder.Equal("group_identifier", groupIdentifier))

	group, err := d.getGroupCommon(tx, selectBuilder, groupStruct)
	if err != nil {
		return nil, err
	}

	return group, nil
}

func (d *MySQLDatabase) GetAllGroups(tx *sql.Tx) ([]*entitiesv2.Group, error) {

	groupStruct := sqlbuilder.NewStruct(new(entitiesv2.Group)).
		For(sqlbuilder.MySQL)

	selectBuilder := groupStruct.SelectFrom("`groups`")

	sql, args := selectBuilder.Build()
	rows, err := d.querySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var groups []*entitiesv2.Group
	for rows.Next() {
		var group entitiesv2.Group
		addr := groupStruct.Addr(&group)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan group")
		}
		groups = append(groups, &group)
	}

	return groups, nil
}

func (d *MySQLDatabase) GetAllGroupsPaginated(tx *sql.Tx, page int, pageSize int) ([]*entitiesv2.Group, int, error) {
	if page < 1 {
		page = 1
	}

	if pageSize < 1 {
		pageSize = 10
	}

	groupStruct := sqlbuilder.NewStruct(new(entitiesv2.Group)).
		For(sqlbuilder.MySQL)

	selectBuilder := groupStruct.SelectFrom("`groups`")
	selectBuilder.OrderBy("group_identifier").Asc()
	selectBuilder.Offset((page - 1) * pageSize)
	selectBuilder.Limit(pageSize)

	sql, args := selectBuilder.Build()
	rows, err := d.querySql(tx, sql, args...)
	if err != nil {
		return nil, 0, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var groups []*entitiesv2.Group
	for rows.Next() {
		var group entitiesv2.Group
		addr := groupStruct.Addr(&group)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, 0, errors.Wrap(err, "unable to scan group")
		}
		groups = append(groups, &group)
	}

	selectBuilder = sqlbuilder.MySQL.NewSelectBuilder()
	selectBuilder.Select("count(*)").From("`groups`")

	sql, args = selectBuilder.Build()
	rows, err = d.querySql(tx, sql, args...)
	if err != nil {
		return nil, 0, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var total int
	if rows.Next() {
		rows.Scan(&total)
	}

	return groups, total, nil
}

func (d *MySQLDatabase) GetGroupMembersPaginated(tx *sql.Tx, groupId uint, page int, pageSize int) ([]entitiesv2.User, int, error) {
	if groupId <= 0 {
		return nil, 0, errors.New("group id must be greater than 0")
	}

	if page < 1 {
		page = 1
	}

	if pageSize < 1 {
		pageSize = 10
	}

	userStruct := sqlbuilder.NewStruct(new(entitiesv2.User)).
		For(sqlbuilder.MySQL)

	selectBuilder := userStruct.SelectFrom("users")
	selectBuilder.JoinWithOption(sqlbuilder.InnerJoin, "users_groups", "users.id = users_groups.user_id")
	selectBuilder.Where(selectBuilder.Equal("users_groups.group_id", groupId))
	selectBuilder.OrderBy("users.given_name").Asc()
	selectBuilder.Offset((page - 1) * pageSize)
	selectBuilder.Limit(pageSize)

	sql, args := selectBuilder.Build()
	rows, err := d.querySql(nil, sql, args...)
	if err != nil {
		return nil, 0, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var users []entitiesv2.User
	for rows.Next() {
		var user entitiesv2.User
		addr := userStruct.Addr(&user)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, 0, errors.Wrap(err, "unable to scan user")
		}
		users = append(users, user)
	}

	selectBuilder = sqlbuilder.MySQL.NewSelectBuilder()
	selectBuilder.Select("count(*)").From("users")
	selectBuilder.JoinWithOption(sqlbuilder.InnerJoin, "users_groups", "users.id = users_groups.user_id")
	selectBuilder.Where(selectBuilder.Equal("users_groups.group_id", groupId))

	sql, args = selectBuilder.Build()
	rows, err = d.querySql(nil, sql, args...)
	if err != nil {
		return nil, 0, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var total int
	if rows.Next() {
		rows.Scan(&total)
	}

	return users, total, nil
}

func (d *MySQLDatabase) CountGroupMembers(tx *sql.Tx, groupId int64) (int, error) {
	if groupId <= 0 {
		return 0, errors.New("group id must be greater than 0")
	}

	selectBuilder := sqlbuilder.MySQL.NewSelectBuilder()
	selectBuilder.Select("count(*)").From("users_groups")
	selectBuilder.Where(selectBuilder.Equal("group_id", groupId))

	sql, args := selectBuilder.Build()
	rows, err := d.querySql(tx, sql, args...)
	if err != nil {
		return 0, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var count int
	if rows.Next() {
		err = rows.Scan(&count)
		if err != nil {
			return 0, errors.Wrap(err, "unable to scan count")
		}
		return count, nil
	}
	return 0, nil
}

func (d *MySQLDatabase) DeleteGroup(tx *sql.Tx, groupId int64) error {
	if groupId <= 0 {
		return errors.New("groupId must be greater than 0")
	}

	clientStruct := sqlbuilder.NewStruct(new(entitiesv2.Group)).
		For(sqlbuilder.MySQL)

	deleteBuilder := clientStruct.DeleteFrom("`groups`")
	deleteBuilder.Where(deleteBuilder.Equal("id", groupId))

	sql, args := deleteBuilder.Build()
	_, err := d.execSql(tx, sql, args...)
	if err != nil {
		return errors.Wrap(err, "unable to delete group")
	}

	return nil
}
