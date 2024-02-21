package commondb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/pkg/errors"
)

func (d *CommonDatabase) CreateUserSession(tx *sql.Tx, userSession *entitiesv2.UserSession) error {

	if userSession.UserId == 0 {
		return errors.New("user id must be greater than 0")
	}

	now := time.Now().UTC()

	originalCreatedAt := userSession.CreatedAt
	originalUpdatedAt := userSession.UpdatedAt
	userSession.CreatedAt = sql.NullTime{Time: now, Valid: true}
	userSession.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	userSessionStruct := sqlbuilder.NewStruct(new(entitiesv2.UserSession)).
		For(d.Flavor)

	insertBuilder := userSessionStruct.WithoutTag("pk").InsertInto("user_sessions", userSession)

	sql, args := insertBuilder.Build()
	result, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		userSession.CreatedAt = originalCreatedAt
		userSession.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to insert userSession")
	}

	id, err := result.LastInsertId()
	if err != nil {
		userSession.CreatedAt = originalCreatedAt
		userSession.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to get last insert id")
	}

	userSession.Id = id
	return nil
}

func (d *CommonDatabase) UpdateUserSession(tx *sql.Tx, userSession *entitiesv2.UserSession) error {

	if userSession.Id == 0 {
		return errors.New("can't update userSession with id 0")
	}

	originalUpdatedAt := userSession.UpdatedAt
	userSession.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	userSessionStruct := sqlbuilder.NewStruct(new(entitiesv2.UserSession)).
		For(d.Flavor)

	updateBuilder := userSessionStruct.WithoutTag("pk").Update("user_sessions", userSession)
	updateBuilder.Where(updateBuilder.Equal("id", userSession.Id))

	sql, args := updateBuilder.Build()
	_, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		userSession.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to update userSession")
	}

	return nil
}

func (d *CommonDatabase) getUserSessionCommon(tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	userSessionStruct *sqlbuilder.Struct) (*entitiesv2.UserSession, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var userSession entitiesv2.UserSession
	if rows.Next() {
		addr := userSessionStruct.Addr(&userSession)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan userSession")
		}
		return &userSession, nil
	}
	return nil, nil
}

func (d *CommonDatabase) GetUserSessionById(tx *sql.Tx, userSessionId int64) (*entitiesv2.UserSession, error) {

	userSessionStruct := sqlbuilder.NewStruct(new(entitiesv2.UserSession)).
		For(d.Flavor)

	selectBuilder := userSessionStruct.SelectFrom("user_sessions")
	selectBuilder.Where(selectBuilder.Equal("id", userSessionId))

	userSession, err := d.getUserSessionCommon(tx, selectBuilder, userSessionStruct)
	if err != nil {
		return nil, err
	}

	return userSession, nil
}

func (d *CommonDatabase) GetUserSessionBySessionIdentifier(tx *sql.Tx, sessionIdentifier string) (*entitiesv2.UserSession, error) {

	if sessionIdentifier == "" {
		return nil, nil
	}

	userSessionStruct := sqlbuilder.NewStruct(new(entitiesv2.UserSession)).
		For(d.Flavor)

	selectBuilder := userSessionStruct.SelectFrom("user_sessions")
	selectBuilder.Where(selectBuilder.Equal("session_identifier", sessionIdentifier))

	userSession, err := d.getUserSessionCommon(tx, selectBuilder, userSessionStruct)
	if err != nil {
		return nil, err
	}

	return userSession, nil
}

func (d *CommonDatabase) GetUserSessionsByClientIdPaginated(tx *sql.Tx, clientId int64, page int, pageSize int) ([]entitiesv2.UserSession, int, error) {
	if clientId <= 0 {
		return nil, 0, errors.New("client id must be greater than 0")
	}

	if page < 1 {
		page = 1
	}

	if pageSize < 1 {
		pageSize = 10
	}

	userSessionStruct := sqlbuilder.NewStruct(new(entitiesv2.UserSession)).
		For(d.Flavor)

	selectBuilder := userSessionStruct.SelectFrom("user_sessions")
	selectBuilder.JoinWithOption(sqlbuilder.InnerJoin, "user_session_clients", "user_sessions.id = user_session_clients.user_session_id")
	selectBuilder.Where(selectBuilder.Equal("user_session_clients.client_id", clientId))
	selectBuilder.OrderBy("user_sessions.last_accessed").Desc()
	selectBuilder.Offset((page - 1) * pageSize)
	selectBuilder.Limit(pageSize)

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(nil, sql, args...)
	if err != nil {
		return nil, 0, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var userSessions []entitiesv2.UserSession
	for rows.Next() {
		var userSession entitiesv2.UserSession
		addr := userSessionStruct.Addr(&userSession)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, 0, errors.Wrap(err, "unable to scan userSession")
		}
		userSessions = append(userSessions, userSession)
	}

	selectBuilder = d.Flavor.NewSelectBuilder()
	selectBuilder.Select("count(*)").From("user_sessions")
	selectBuilder.JoinWithOption(sqlbuilder.InnerJoin, "user_session_clients", "user_sessions.id = user_session_clients.user_session_id")
	selectBuilder.Where(selectBuilder.Equal("user_session_clients.client_id", clientId))

	sql, args = selectBuilder.Build()
	rows2, err := d.QuerySql(nil, sql, args...)
	if err != nil {
		return nil, 0, errors.Wrap(err, "unable to query database")
	}
	defer rows2.Close()

	var total int
	if rows2.Next() {
		rows2.Scan(&total)
	}

	return userSessions, total, nil
}

func (d *CommonDatabase) UserSessionsLoadUsers(tx *sql.Tx, userSessions []entitiesv2.UserSession) error {

	if userSessions == nil {
		return nil
	}

	userSessionsIds := make([]int64, 0, len(userSessions))
	for _, userSession := range userSessions {
		userSessionsIds = append(userSessionsIds, userSession.Id)
	}

	users, err := d.GetUsersByIds(tx, userSessionsIds)
	if err != nil {
		return errors.Wrap(err, "unable to load users")
	}

	usersById := make(map[int64]entitiesv2.User)
	for _, user := range users {
		usersById[user.Id] = user
	}

	for i, userSession := range userSessions {
		user, ok := usersById[userSession.Id]
		if !ok {
			return errors.Errorf("unable to find user with id %v", userSession.Id)
		}
		userSessions[i].User = user
	}

	return nil
}

func (d *CommonDatabase) UserSessionsLoadClients(tx *sql.Tx, userSessions []entitiesv2.UserSession) error {
	if userSessions == nil {
		return nil
	}

	userSessionIds := make([]int64, 0, len(userSessions))
	for _, userSession := range userSessions {
		userSessionIds = append(userSessionIds, userSession.Id)
	}

	userSessionClients, err := d.GetUserSessionClientsByUserSessionIds(tx, userSessionIds)
	if err != nil {
		return errors.Wrap(err, "unable to load userSessionClients")
	}

	userSessionClientsByUserSessionId := make(map[int64][]entitiesv2.UserSessionClient)
	for _, userSessionClient := range userSessionClients {
		userSessionClientsByUserSessionId[userSessionClient.UserSessionId] = append(userSessionClientsByUserSessionId[userSessionClient.UserSessionId], userSessionClient)
	}

	for i, userSession := range userSessions {
		userSessions[i].Clients = userSessionClientsByUserSessionId[userSession.Id]
	}

	return nil
}

func (d *CommonDatabase) UserSessionLoadClients(tx *sql.Tx, userSession *entitiesv2.UserSession) error {

	if userSession == nil {
		return nil
	}

	userSessionClients, err := d.GetUserSessionClientsByUserSessionId(tx, userSession.Id)
	if err != nil {
		return errors.Wrap(err, "unable to load userSessionClients")
	}

	userSession.Clients = userSessionClients

	return nil
}

func (d *CommonDatabase) UserSessionLoadUser(tx *sql.Tx, userSession *entitiesv2.UserSession) error {

	if userSession == nil {
		return nil
	}

	user, err := d.GetUserById(tx, userSession.UserId)
	if err != nil {
		return errors.Wrap(err, "unable to load user")
	}

	if user != nil {
		userSession.User = *user
	}
	return nil
}

func (d *CommonDatabase) GetUserSessionsByUserId(tx *sql.Tx, userId int64) ([]entitiesv2.UserSession, error) {

	userSessionStruct := sqlbuilder.NewStruct(new(entitiesv2.UserSession)).
		For(d.Flavor)

	selectBuilder := userSessionStruct.SelectFrom("user_sessions")
	selectBuilder.Where(selectBuilder.Equal("user_id", userId))

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var userSessions []entitiesv2.UserSession
	for rows.Next() {
		var userSession entitiesv2.UserSession
		addr := userSessionStruct.Addr(&userSession)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan userSession")
		}
		userSessions = append(userSessions, userSession)
	}

	return userSessions, nil
}

func (d *CommonDatabase) DeleteUserSession(tx *sql.Tx, userSessionId int64) error {

	userSessionStruct := sqlbuilder.NewStruct(new(entitiesv2.UserSession)).
		For(d.Flavor)

	deleteBuilder := userSessionStruct.DeleteFrom("user_sessions")
	deleteBuilder.Where(deleteBuilder.Equal("id", userSessionId))

	sql, args := deleteBuilder.Build()
	_, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		return errors.Wrap(err, "unable to delete userSession")
	}

	return nil
}
