package model

import (
	"context"
	"database/sql"
	"strconv"
	"time"

	sq "github.com/Masterminds/squirrel"

	"git.sr.ht/~sircmpwn/gql.sr.ht/database"
	"git.sr.ht/~sircmpwn/gql.sr.ht/model"
)

type Invoice struct {
	ID        int       `json:"id"`
	Created   time.Time `json:"created"`
	Cents     int       `json:"cents"`
	ValidThru time.Time `json:"validThru"`
	Source    *string   `json:"source"`

	UserID int

	alias string
}

func (inv *Invoice) As(alias string) *Invoice {
	inv.alias = alias
	return inv
}

func (inv *Invoice) Select(ctx context.Context) []string {
	cols := database.ColumnsFor(ctx, inv.alias, map[string]string{
		"id":        "id",
		"created":   "created",
		"cents":     "cents",
		"validThru": "valid_thru",
		"source":    "source",
	})
	return append(cols, "id", "user_id")
}

func (inv *Invoice) Fields(ctx context.Context) []interface{} {
	fields := database.FieldsFor(ctx, map[string]interface{}{
		"id":        &inv.ID,
		"created":   &inv.Created,
		"cents":     &inv.Cents,
		"validThru": &inv.ValidThru,
		"source":    &inv.Source,
	})
	return append(fields, &inv.ID, &inv.UserID)
}

func (inv *Invoice) QueryWithCursor(ctx context.Context, db *sql.DB,
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

	if rows, err = q.RunWith(db).QueryContext(ctx); err != nil {
		panic(err)
	}
	defer rows.Close()

	var invoices []*Invoice
	for rows.Next() {
		var inv Invoice
		if err := rows.Scan(inv.Fields(ctx)...); err != nil {
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
