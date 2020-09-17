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

type SSHKey struct {
	ID          int        `json:"id"`
	Created     time.Time  `json:"created"`
	LastUsed    *time.Time `json:"lastUsed"`
	Key         string     `json:"key"`
	Fingerprint string     `json:"fingerprint"`
	Comment     *string    `json:"comment"`

	UserID int

	alias string
}

func (k *SSHKey) As(alias string) *SSHKey {
	k.alias = alias
	return k
}

func (k *SSHKey) Select(ctx context.Context) []string {
	cols := database.ColumnsFor(ctx, k.alias, map[string]string{
		"id":          "id",
		"created":     "created",
		"lastUsed":    "last_used",
		"key":         "key",
		"fingerprint": "fingerprint",
		"comment":     "comment",
	})
	return append(cols, "id", "user_id")
}

func (k *SSHKey) Fields(ctx context.Context) []interface{} {
	fields := database.FieldsFor(ctx, map[string]interface{}{
		"id":          &k.ID,
		"created":     &k.Created,
		"lastUsed":    &k.LastUsed,
		"key":         &k.Key,
		"fingerprint": &k.Fingerprint,
		"comment":     &k.Comment,
	})
	return append(fields, &k.ID, &k.UserID)
}

func (k *SSHKey) QueryWithCursor(ctx context.Context, db *sql.DB,
	q sq.SelectBuilder, cur *model.Cursor) ([]*SSHKey, *model.Cursor) {
	var (
		err  error
		rows *sql.Rows
	)

	if cur.Next != "" {
		next, _ := strconv.ParseInt(cur.Next, 10, 64)
		q = q.Where(database.WithAlias(k.alias, "id")+"<= ?", next)
	}
	q = q.
		OrderBy(database.WithAlias(k.alias, "id")).
		Limit(uint64(cur.Count + 1))

	if rows, err = q.RunWith(db).QueryContext(ctx); err != nil {
		panic(err)
	}
	defer rows.Close()

	var keys []*SSHKey
	for rows.Next() {
		var key SSHKey
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
