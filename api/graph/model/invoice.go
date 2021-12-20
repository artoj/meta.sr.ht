package model

import (
	"context"
	"database/sql"
	"strconv"
	"time"

	sq "github.com/Masterminds/squirrel"

	"git.sr.ht/~sircmpwn/core-go/database"
	"git.sr.ht/~sircmpwn/core-go/model"
)

type Invoice struct {
	ID        int       `json:"id"`
	Created   time.Time `json:"created"`
	Cents     int       `json:"cents"`
	ValidThru time.Time `json:"validThru"`
	Source    *string   `json:"source"`

	UserID int

	alias  string
	fields *database.ModelFields
}

func (inv *Invoice) As(alias string) *Invoice {
	inv.alias = alias
	return inv
}

func (i *Invoice) Alias() string {
	return i.alias
}

func (i *Invoice) Table() string {
	return "invoice"
}

func (i *Invoice) Fields() *database.ModelFields {
	if i.fields != nil {
		return i.fields
	}
	i.fields = &database.ModelFields{
		Fields: []*database.FieldMap{
			{"id", "id", &i.ID},
			{"created", "created", &i.Created},
			{"cents", "cents", &i.Cents},
			{"valid_thru", "validThru", &i.ValidThru},
			{"source", "source", &i.Source},

			// Always fetch:
			{"id", "", &i.ID},
			{"user_id", "", &i.UserID},
		},
	}
	return i.fields
}

func (inv *Invoice) QueryWithCursor(ctx context.Context, runner sq.BaseRunner,
	q sq.SelectBuilder, cur *model.Cursor) ([]*Invoice, *model.Cursor) {
	var (
		err  error
		rows *sql.Rows
	)

	if cur.Next != "" {
		next, _ := strconv.ParseInt(cur.Next, 10, 64)
		q = q.Where(database.WithAlias(inv.alias, "id")+"<= ?", next)
	}
	q = q.
		OrderBy(database.WithAlias(inv.alias, "id")).
		Limit(uint64(cur.Count + 1))

	if rows, err = q.RunWith(runner).QueryContext(ctx); err != nil {
		panic(err)
	}
	defer rows.Close()

	var invoices []*Invoice
	for rows.Next() {
		var inv Invoice
		if err := rows.Scan(database.Scan(ctx, &inv)...); err != nil {
			panic(err)
		}
		invoices = append(invoices, &inv)
	}

	if len(invoices) > cur.Count {
		cur = &model.Cursor{
			Count:  cur.Count,
			Next:   strconv.Itoa(invoices[len(invoices)-1].ID),
			Search: cur.Search,
		}
		invoices = invoices[:cur.Count]
	} else {
		cur = nil
	}

	return invoices, cur
}
