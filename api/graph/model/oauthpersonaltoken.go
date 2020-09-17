package model

import (
	"context"
	"database/sql"
	"time"

	sq "github.com/Masterminds/squirrel"

	"git.sr.ht/~sircmpwn/gql.sr.ht/database"
)

type OAuthPersonalToken struct {
	ID      int       `json:"id"`
	Issued  time.Time `json:"issued"`
	Expires time.Time `json:"expires"`
	Comment *string   `json:"comment"`

	alias string
}

func (tok *OAuthPersonalToken) As(alias string) *OAuthPersonalToken {
	tok.alias = alias
	return tok
}

func (tok *OAuthPersonalToken) Select(ctx context.Context) []string {
	cols := database.ColumnsFor(ctx, tok.alias, map[string]string{
		"id":      "id",
		"issued":  "issued",
		"expires": "expires",
		"comment": "comment",
	})
	return append(cols, database.WithAlias(tok.alias, "id"))
}

func (tok *OAuthPersonalToken) Fields(ctx context.Context) []interface{} {
	fields := database.FieldsFor(ctx, map[string]interface{}{
		"id":      &tok.ID,
		"issued":  &tok.Issued,
		"expires": &tok.Expires,
		"comment": &tok.Comment,
	})
	return append(fields, &tok.ID)
}

// TODO: Add cursor to this?
func (tok *OAuthPersonalToken) Query(ctx context.Context, db *sql.DB,
	q sq.SelectBuilder) []*OAuthPersonalToken {

	var (
		err  error
		rows *sql.Rows
	)

	if rows, err = q.RunWith(db).QueryContext(ctx); err != nil {
		panic(err)
	}
	defer rows.Close()

	var tokens []*OAuthPersonalToken
	for rows.Next() {
		var tok OAuthPersonalToken
		if err := rows.Scan(tok.Fields(ctx)...); err != nil {
			panic(err)
		}
		tokens = append(tokens, &tok)
	}

	return tokens
}
