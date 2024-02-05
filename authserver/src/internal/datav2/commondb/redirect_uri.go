package commondb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/pkg/errors"
)

func RedirectURISetColsAndValues(insertBuilder *sqlbuilder.InsertBuilder,
	redirectURI *entitiesv2.RedirectURI, clientId int64) *sqlbuilder.InsertBuilder {
	insertBuilder.InsertInto("redirect_uris")
	insertBuilder.Cols(
		"created_at",
		"uri",
		"client_id",
	)
	insertBuilder.Values(
		time.Now().UTC(),
		redirectURI.URI,
		clientId,
	)
	return insertBuilder
}

func RedirectURIScan(rows *sql.Rows) (*entitiesv2.RedirectURI, error) {
	var (
		id         int64
		created_at time.Time
		uri        string
		client_id  int64
	)

	err := rows.Scan(
		&id,
		&created_at,
		&uri,
		&client_id,
	)
	if err != nil {
		return nil, errors.Wrap(err, "unable to scan redirect uri")
	}

	redirectURI := &entitiesv2.RedirectURI{
		Id:        id,
		CreatedAt: created_at,
		URI:       uri,
		ClientId:  client_id,
	}

	return redirectURI, nil
}
