package model

import (
	"context"
	"database/sql"
	"time"

	sq "github.com/Masterminds/squirrel"

	"git.sr.ht/~sircmpwn/core-go/database"
)

type OAuthPersonalToken struct {
	ID      int       `json:"id"`
	Issued  time.Time `json:"issued"`
	Expires time.Time `json:"expires"`
	Comment *string   `json:"comment"`

	alias  string
	fields *database.ModelFields
}

func (tok *OAuthPersonalToken) As(alias string) *OAuthPersonalToken {
	tok.alias = alias
	return tok
}

func (tok *OAuthPersonalToken) Alias() string {
	return tok.alias
}

func (tok *OAuthPersonalToken) Table() string {
	return "oauth2_grant"
}

func (tok *OAuthPersonalToken) Fields() *database.ModelFields {
	if tok.fields != nil {
		return tok.fields
	}
	tok.fields = &database.ModelFields{
		Fields: []*database.FieldMap{
			{ "id", "id", &tok.ID },
			{ "issued", "issued", &tok.Issued },
			{ "expires", "expires", &tok.Expires },
			{ "comment", "comment", &tok.Comment },

			// Always fetch:
			{ "id", "", &tok.ID },
		},
	}
	return tok.fields
}

// TODO: Add cursor to this?
func (tok *OAuthPersonalToken) Query(ctx context.Context, runner sq.BaseRunner,
	q sq.SelectBuilder) []*OAuthPersonalToken {

	var (
		err  error
		rows *sql.Rows
	)

	if rows, err = q.RunWith(runner).QueryContext(ctx); err != nil {
		panic(err)
	}
	defer rows.Close()

	var tokens []*OAuthPersonalToken
	for rows.Next() {
		var tok OAuthPersonalToken
		if err := rows.Scan(database.Scan(ctx, &tok)...); err != nil {
			panic(err)
		}
		tokens = append(tokens, &tok)
	}

	return tokens
}
