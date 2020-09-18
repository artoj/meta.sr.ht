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

type AuditLogEntry struct {
	ID        int       `json:"id"`
	Created   time.Time `json:"created"`
	IPAddress string    `json:"ipAddress"`
	EventType string    `json:"eventType"`
	Details   *string   `json:"details"`

	UserID int

	alias string
}

func (ent *AuditLogEntry) As(alias string) *AuditLogEntry {
	ent.alias = alias
	return ent
}

func (ent *AuditLogEntry) Select(ctx context.Context) []string {
	cols := database.ColumnsFor(ctx, ent.alias, map[string]string{
		"id":        "id",
		"created":   "created",
		"ipAddress": "ip_address",
		"eventType": "event_type",
		"details":   "details",
	})
	return append(cols, "id", "user_id")
}

func (ent *AuditLogEntry) Fields(ctx context.Context) []interface{} {
	fields := database.FieldsFor(ctx, map[string]interface{}{
		"id":        &ent.ID,
		"created":   &ent.Created,
		"ipAddress": &ent.IPAddress,
		"eventType": &ent.EventType,
		"details":   &ent.Details,
	})
	return append(fields, &ent.ID, &ent.UserID)
}

func (ent *AuditLogEntry) QueryWithCursor(ctx context.Context,
	runner sq.BaseRunner, q sq.SelectBuilder,
	cur *model.Cursor) ([]*AuditLogEntry, *model.Cursor) {
	var (
		err  error
		rows *sql.Rows
	)

	if cur.Next != "" {
		next, _ := strconv.ParseInt(cur.Next, 10, 64)
		q = q.Where(database.WithAlias(ent.alias, "id")+"<= ?", next)
	}
	q = q.
		OrderBy(database.WithAlias(ent.alias, "id") + " DESC").
		Limit(uint64(cur.Count + 1))

	if rows, err = q.RunWith(runner).QueryContext(ctx); err != nil {
		panic(err)
	}
	defer rows.Close()

	var ents []*AuditLogEntry
	for rows.Next() {
		var ent AuditLogEntry
		if err := rows.Scan(ent.Fields(ctx)...); err != nil {
			panic(err)
		}
		ents = append(ents, &ent)
	}

	if len(ents) > cur.Count {
		cur = &model.Cursor{
			Count:  cur.Count,
			Next:   strconv.Itoa(ents[len(ents)-1].ID),
			Search: cur.Search,
		}
		ents = ents[:cur.Count]
	} else {
		cur = nil
	}

	return ents, cur
}
