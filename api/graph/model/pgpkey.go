package model

import (
	"context"
	"database/sql"
	"time"
	"strconv"

	sq "github.com/Masterminds/squirrel"

	"git.sr.ht/~sircmpwn/gql.sr.ht/database"
	"git.sr.ht/~sircmpwn/gql.sr.ht/model"
)

type PGPKey struct {
	ID      int       `json:"id"`
	Created time.Time `json:"created"`
	Key     string    `json:"key"`
	KeyID   string    `json:"keyId"`
	Email   string    `json:"email"`

	UserID int

	alias  string
}

func (k *PGPKey) As(alias string) *PGPKey {
	k.alias = alias
	return k
}

func (k *PGPKey) Select(ctx context.Context) []string {
	cols := database.ColumnsFor(ctx, k.alias, map[string]string{
		"id":      "id",
		"created": "created",
		"key":     "key",
		"keyId":   "key_id",
		"email":   "email",
	})
	return append(cols, "id", "user_id")
}

func (k *PGPKey) Fields(ctx context.Context) []interface{} {
	fields := database.FieldsFor(ctx, map[string]interface{}{
		"id":      &k.ID,
		"created": &k.Created,
		"key":     &k.Key,
		"keyId":   &k.KeyID,
		"email":   &k.Email,
	})
	return append(fields, &k.ID, &k.UserID)
}

func (k *PGPKey) QueryWithCursor(ctx context.Context, db *sql.DB,
	q sq.SelectBuilder, cur *model.Cursor) ([]*PGPKey, *model.Cursor) {
	var (
		err  error
		rows *sql.Rows
	)

	if cur.Next != "" {
		next, _ := strconv.ParseInt(cur.Next, 10, 64)
		q = q.Where(database.WithAlias(k.alias, "id") + "<= ?", next)
	}
	q = q.
		OrderBy(database.WithAlias(k.alias, "id")).
		Limit(uint64(cur.Count + 1))

	if rows, err = q.RunWith(db).QueryContext(ctx); err != nil {
		panic(err)
	}
	defer rows.Close()

	var keys []*PGPKey
	for rows.Next() {
		var key PGPKey
		if err := rows.Scan(key.Fields(ctx)...); err != nil {
			panic(err)
		}
		keys = append(keys, &key)
	}

	if len(keys) > cur.Count {
		cur = &model.Cursor{
			Count:  cur.Count,
			Next:   strconv.Itoa(keys[len(keys)-1].ID),
			Search: cur.Search,
		}
		keys = keys[:cur.Count]
	} else {
		cur = nil
	}

	return keys, cur
}
