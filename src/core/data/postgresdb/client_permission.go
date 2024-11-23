package postgresdb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/models"
	"github.com/pkg/errors"
)

func (d *PostgresDatabase) CreateClientPermission(tx *sql.Tx, clientPermission *models.ClientPermission) error {
	if clientPermission.ClientId == 0 {
		return errors.WithStack(errors.New("can't create clientPermission with client_id 0"))
	}

	if clientPermission.PermissionId == 0 {
		return errors.WithStack(errors.New("can't create clientPermission with permission_id 0"))
	}

	now := time.Now().UTC()

	originalCreatedAt := clientPermission.CreatedAt
	originalUpdatedAt := clientPermission.UpdatedAt
	clientPermission.CreatedAt = sql.NullTime{Time: now, Valid: true}
	clientPermission.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	clientPermissionStruct := sqlbuilder.NewStruct(new(models.ClientPermission)).
		For(sqlbuilder.PostgreSQL)

	insertBuilder := clientPermissionStruct.WithoutTag("pk").InsertInto("clients_permissions", clientPermission)
	sql, args := insertBuilder.Build()
	sql = sql + " RETURNING id"

	rows, err := d.CommonDB.QuerySql(tx, sql, args...)
	if err != nil {
		clientPermission.CreatedAt = originalCreatedAt
		clientPermission.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to insert clientPermission")
	}
	defer rows.Close()

	if rows.Next() {
		err = rows.Scan(&clientPermission.Id)
		if err != nil {
			clientPermission.CreatedAt = originalCreatedAt
			clientPermission.UpdatedAt = originalUpdatedAt
			return errors.Wrap(err, "unable to scan clientPermission id")
		}
	}

	return nil
}

func (d *PostgresDatabase) UpdateClientPermission(tx *sql.Tx, clientPermission *models.ClientPermission) error {
	return d.CommonDB.UpdateClientPermission(tx, clientPermission)
}

func (d *PostgresDatabase) GetClientPermissionById(tx *sql.Tx, clientPermissionId int64) (*models.ClientPermission, error) {
	return d.CommonDB.GetClientPermissionById(tx, clientPermissionId)
}

func (d *PostgresDatabase) GetClientPermissionByClientIdAndPermissionId(tx *sql.Tx, clientId, permissionId int64) (*models.ClientPermission, error) {
	return d.CommonDB.GetClientPermissionByClientIdAndPermissionId(tx, clientId, permissionId)
}

func (d *PostgresDatabase) GetClientPermissionsByClientId(tx *sql.Tx, clientId int64) ([]models.ClientPermission, error) {
	return d.CommonDB.GetClientPermissionsByClientId(tx, clientId)
}

func (d *PostgresDatabase) DeleteClientPermission(tx *sql.Tx, clientPermissionId int64) error {
	return d.CommonDB.DeleteClientPermission(tx, clientPermissionId)
}
