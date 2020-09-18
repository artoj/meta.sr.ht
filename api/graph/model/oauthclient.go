package model

import (
	"context"
	"database/sql"
	"fmt"

	sq "github.com/Masterminds/squirrel"

	"git.sr.ht/~sircmpwn/gql.sr.ht/database"
)

type OAuthClient struct {
	ID          int     `json:"id"`
	UUID        string  `json:"uuid"`
	RedirectURL string  `json:"redirectUrl"`
	Name        string  `json:"name"`
	Description *string `json:"description"`
	URL         *string `json:"url"`

	alias string
	ownerID int
}

func (oc *OAuthClient) Entity() Entity {
	panic(fmt.Errorf("not implemented")) // TODO
}

func (oc *OAuthClient) As(alias string) *OAuthClient {
	oc.alias = alias
	return oc
}

func (oc *OAuthClient) Select(ctx context.Context) []string {
	cols := database.ColumnsFor(ctx, oc.alias, map[string]string{
		"id":          "id",
		"uuid":        "client_uuid",
		"redirectUrl": "redirect_url",
		"name":        "client_name",
		"description": "client_description",
		"url":         "client_url",
	})
	return append(cols,
		database.WithAlias(oc.alias, "id"),
		database.WithAlias(oc.alias, "owner_id"))
}

func (oc *OAuthClient) Fields(ctx context.Context) []interface{} {
	fields := database.FieldsFor(ctx, map[string]interface{}{
		"id":          &oc.ID,
		"uuid":        &oc.UUID,
		"redirectUrl": &oc.RedirectURL,
		"name":        &oc.Name,
		"description": &oc.Description,
		"url":         &oc.URL,
	})
	return append(fields, &oc.ID, &oc.ownerID)
}

// TODO: Add cursor to this?
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
		if err := rows.Scan(oc.Fields(ctx)...); err != nil {
			panic(err)
		}
		clients = append(clients, &oc)
	}

	return clients
}
