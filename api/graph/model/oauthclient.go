package model

import (
	"context"
	"database/sql"

	sq "github.com/Masterminds/squirrel"

	"git.sr.ht/~sircmpwn/core-go/database"
)

type OAuthClient struct {
	ID          int     `json:"id"`
	UUID        string  `json:"uuid"`
	RedirectURL string  `json:"redirectUrl"`
	Name        string  `json:"name"`
	Description *string `json:"description"`
	URL         *string `json:"url"`

	OwnerID int

	alias  string
	fields *database.ModelFields
}

func (oc *OAuthClient) As(alias string) *OAuthClient {
	oc.alias = alias
	return oc
}

func (o *OAuthClient) Alias() string {
	return o.alias
}

func (o *OAuthClient) Table() string {
	return "oauth2_client"
}

func (o *OAuthClient) Fields() *database.ModelFields {
	if o.fields != nil {
		return o.fields
	}
	o.fields = &database.ModelFields{
		Fields: []*database.FieldMap{
			{"id", "id", &o.ID},
			{"client_uuid", "uuid", &o.UUID},
			{"redirect_url", "redirectUrl", &o.RedirectURL},
			{"client_name", "name", &o.Name},
			{"client_description", "description", &o.Description},
			{"client_url", "url", &o.URL},

			// Always fetch:
			{"id", "", &o.ID},
			{"owner_id", "", &o.OwnerID},
		},
	}
	return o.fields
}

func (oc *OAuthClient) Query(ctx context.Context, runner sq.BaseRunner,
	q sq.SelectBuilder) []*OAuthClient {

	var (
		err  error
		rows *sql.Rows
	)

	if rows, err = q.RunWith(runner).QueryContext(ctx); err != nil {
		panic(err)
	}
	defer rows.Close()

	var clients []*OAuthClient
	for rows.Next() {
		var oc OAuthClient
		if err := rows.Scan(database.Scan(ctx, &oc)...); err != nil {
			panic(err)
		}
		clients = append(clients, &oc)
	}

	return clients
}
