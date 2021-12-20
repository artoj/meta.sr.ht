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

type SSHKey struct {
	ID          int        `json:"id"`
	Created     time.Time  `json:"created"`
	LastUsed    *time.Time `json:"lastUsed"`
	Key         string     `json:"key"`
	Fingerprint string     `json:"fingerprint"`
	Comment     *string    `json:"comment"`

	UserID int

	alias  string
	fields *database.ModelFields
}

func (k *SSHKey) As(alias string) *SSHKey {
	k.alias = alias
	return k
}

func (k *SSHKey) Alias() string {
	return k.alias
}

func (k *SSHKey) Table() string {
	return "sshkey"
}

func (k *SSHKey) Fields() *database.ModelFields {
	if k.fields != nil {
		return k.fields
	}
	k.fields = &database.ModelFields{
		Fields: []*database.FieldMap{
			{"id", "id", &k.ID},
			{"created", "created", &k.Created},
			{"last_used", "lastUsed", &k.LastUsed},
			{"key", "key", &k.Key},
			{"fingerprint", "fingerprint", &k.Fingerprint},
			{"comment", "comment", &k.Comment},

			// Always fetch:
			{"id", "", &k.ID},
			{"user_id", "", &k.UserID},
		},
	}
	return k.fields
}

func (k *SSHKey) QueryWithCursor(ctx context.Context, runner sq.BaseRunner,
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

	if rows, err = q.RunWith(runner).QueryContext(ctx); err != nil {
		panic(err)
	}
	defer rows.Close()

	var keys []*SSHKey
	for rows.Next() {
		var key SSHKey
		if err := rows.Scan(database.Scan(ctx, &key)...); err != nil {
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
