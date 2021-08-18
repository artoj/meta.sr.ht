package model

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"

	"github.com/lib/pq"
	sq "github.com/Masterminds/squirrel"

	"git.sr.ht/~sircmpwn/core-go/database"
	"git.sr.ht/~sircmpwn/core-go/model"
)

type ProfileWebhookSubscription struct {
	ID     int            `json:"id"`
	Events []WebhookEvent `json:"events"`
	Query  string         `json:"query"`
	URL    string         `json:"url"`

	UserID    int

	alias  string
	fields *database.ModelFields
}

func (we *WebhookEvent) Scan(src interface{}) error {
	bytes, ok := src.([]uint8)
	if !ok {
		return fmt.Errorf("Unable to scan from %T into WebhookEvent", src)
	}
	*we = WebhookEvent(string(bytes))
	if !we.IsValid() {
		return fmt.Errorf("%s is not a valid WebhookEvent", string(bytes))
	}
	return nil
}

func (ProfileWebhookSubscription) IsWebhookSubscription() {}

func (sub *ProfileWebhookSubscription) As(alias string) *ProfileWebhookSubscription {
	sub.alias = alias
	return sub
}

func (sub *ProfileWebhookSubscription) Alias() string {
	return sub.alias
}

func (sub *ProfileWebhookSubscription) Table() string {
	return "gql_profile_wh_sub"
}

func (sub *ProfileWebhookSubscription) Fields() *database.ModelFields {
	if sub.fields != nil {
		return sub.fields
	}
	sub.fields = &database.ModelFields{
		Fields: []*database.FieldMap{
			{ "events", "events", pq.Array(&sub.Events) },
			{ "query", "query", &sub.Query },
			{ "url", "url", &sub.URL },

			// Always fetch:
			{ "id", "", &sub.ID },
			{ "user_id", "", &sub.UserID },
		},
	}
	return sub.fields
}

func (sub *ProfileWebhookSubscription) QueryWithCursor(ctx context.Context,
	runner sq.BaseRunner, q sq.SelectBuilder,
	cur *model.Cursor) ([]*ProfileWebhookSubscription, *model.Cursor) {
	var (
		err  error
		rows *sql.Rows
	)

	if cur.Next != "" {
		next, _ := strconv.ParseInt(cur.Next, 10, 64)
		q = q.Where(database.WithAlias(sub.alias, "id")+"<= ?", next)
	}
	q = q.
		OrderBy(database.WithAlias(sub.alias, "id")).
		Limit(uint64(cur.Count + 1))

	if rows, err = q.RunWith(runner).QueryContext(ctx); err != nil {
		panic(err)
	}
	defer rows.Close()

	var subs []*ProfileWebhookSubscription
	for rows.Next() {
		var sub ProfileWebhookSubscription
		if err := rows.Scan(database.Scan(ctx, &sub)...); err != nil {
			panic(err)
		}
		subs = append(subs, &sub)
	}

	if len(subs) > cur.Count {
		cur = &model.Cursor{
			Count:  cur.Count,
			Next:   strconv.Itoa(subs[len(subs)-1].ID),
			Search: cur.Search,
		}
		subs = subs[:cur.Count]
	} else {
		cur = nil
	}

	return subs, cur
}
