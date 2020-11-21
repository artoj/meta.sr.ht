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

	alias  string
	fields *database.ModelFields
}

func (e *AuditLogEntry) As(alias string) *AuditLogEntry {
	e.alias = alias
	return e
}

func (e *AuditLogEntry) Alias() string {
	return e.alias
}

func (e *AuditLogEntry) Table() string {
	return "audit_log_entry"
}

func (e *AuditLogEntry) Fields() *database.ModelFields {
	if e.fields != nil {
		return e.fields
	}
	e.fields = &database.ModelFields{
		Fields: []*database.FieldMap{
			{ "id", "id", &e.ID },
			{ "created", "created", &e.Created },
			{ "ip_address", "ipAddress", &e.IPAddress },
			{ "event_type", "eventType", &e.EventType },
			{ "details", "details", &e.Details },

			// Always fetch:
			{ "id", "", &e.ID },
			{ "user_id", "", &e.UserID },
		},
	}
	return e.fields
}

func (e *AuditLogEntry) QueryWithCursor(ctx context.Context,
	runner sq.BaseRunner, q sq.SelectBuilder,
	cur *model.Cursor) ([]*AuditLogEntry, *model.Cursor) {
	var (
		err  error
		rows *sql.Rows
	)

	if cur.Next != "" {
		next, _ := strconv.ParseInt(cur.Next, 10, 64)
		q = q.Where(database.WithAlias(e.alias, "id")+"<= ?", next)
	}
	q = q.
		OrderBy(database.WithAlias(e.alias, "id") + " DESC").
		Limit(uint64(cur.Count + 1))

	if rows, err = q.RunWith(runner).QueryContext(ctx); err != nil {
		panic(err)
	}
	defer rows.Close()

	var ents []*AuditLogEntry
	for rows.Next() {
		var ent AuditLogEntry
		if err := rows.Scan(database.Scan(ctx, &ent)...); err != nil {
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
