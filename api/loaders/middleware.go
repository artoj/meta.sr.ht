package loaders

//go:generate ./gen UsersByIDLoader int api/graph/model.User
//go:generate ./gen UsersByNameLoader string api/graph/model.User
//go:generate ./gen UsersByEmailLoader string api/graph/model.User

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/lib/pq"

	"git.sr.ht/~sircmpwn/gql.sr.ht/database"
	"git.sr.ht/~sircmpwn/meta.sr.ht/api/graph/model"
)

var loadersCtxKey = &contextKey{"loaders"}

type contextKey struct {
	name string
}

type Loaders struct {
	UsersByID     UsersByIDLoader
	UsersByName   UsersByNameLoader
	UsersByEmail  UsersByEmailLoader
}

func fetchUsersByID(ctx context.Context,
	db *sql.DB) func(ids []int) ([]*model.User, []error) {
	return func(ids []int) ([]*model.User, []error) {
		var (
			err  error
			rows *sql.Rows
		)
		query := database.
			Select(ctx, (&model.User{}).As(`u`)).
			From(`"user" u`).
			Where(sq.Expr(`u.id = ANY(?)`, pq.Array(ids)))
		if rows, err = query.RunWith(db).QueryContext(ctx); err != nil {
			panic(err)
		}
		defer rows.Close()

		usersById := map[int]*model.User{}
		for rows.Next() {
			var user model.User
			if err := rows.Scan(user.Fields(ctx)...); err != nil {
				panic(err)
			}
			usersById[user.ID] = &user
		}
		if err = rows.Err(); err != nil {
			panic(err)
		}

		users := make([]*model.User, len(ids))
		for i, id := range ids {
			users[i] = usersById[id]
		}

		return users, nil
	}
}

func fetchUsersByName(ctx context.Context,
	db *sql.DB) func(names []string) ([]*model.User, []error) {
	return func(names []string) ([]*model.User, []error) {
		var (
			err  error
			rows *sql.Rows
		)
		query := database.
			Select(ctx, (&model.User{}).As(`u`)).
			From(`"user" u`).
			Where(sq.Expr(`u.username = ANY(?)`, pq.Array(names)))
		if rows, err = query.RunWith(db).QueryContext(ctx); err != nil {
			panic(err)
		}
		defer rows.Close()

		usersByName := map[string]*model.User{}
		for rows.Next() {
			user := model.User{}
			if err := rows.Scan(user.Fields(ctx)...); err != nil {
				panic(err)
			}
			usersByName[user.Username] = &user
		}
		if err = rows.Err(); err != nil {
			panic(err)
		}

		users := make([]*model.User, len(names))
		for i, name := range names {
			users[i] = usersByName[name]
		}

		return users, nil
	}
}

func fetchUsersByEmail(ctx context.Context,
	db *sql.DB) func(emails []string) ([]*model.User, []error) {
	return func(emails []string) ([]*model.User, []error) {
		var (
			err  error
			rows *sql.Rows
		)
		query := database.
			Select(ctx, (&model.User{}).As(`u`)).
			From(`"user" u`).
			Where(sq.Expr(`u.email = ANY(?)`, pq.Array(emails)))
		if rows, err = query.RunWith(db).QueryContext(ctx); err != nil {
			panic(err)
		}
		defer rows.Close()

		usersByEmail := map[string]*model.User{}
		for rows.Next() {
			user := model.User{}
			if err := rows.Scan(user.Fields(ctx)...); err != nil {
				panic(err)
			}
			usersByEmail[user.Email] = &user
		}
		if err = rows.Err(); err != nil {
			panic(err)
		}

		users := make([]*model.User, len(emails))
		for i, email := range emails {
			users[i] = usersByEmail[email]
		}

		return users, nil
	}
}

func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		db := database.ForContext(r.Context())
		ctx := context.WithValue(r.Context(), loadersCtxKey, &Loaders{
			UsersByID: UsersByIDLoader{
				maxBatch: 100,
				wait:     1 * time.Millisecond,
				fetch:    fetchUsersByID(r.Context(), db),
			},
			UsersByName: UsersByNameLoader{
				maxBatch: 100,
				wait:     1 * time.Millisecond,
				fetch:    fetchUsersByName(r.Context(), db),
			},
			UsersByEmail: UsersByEmailLoader{
				maxBatch: 100,
				wait:     1 * time.Millisecond,
				fetch:    fetchUsersByEmail(r.Context(), db),
			},
		})
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}

func ForContext(ctx context.Context) *Loaders {
	raw, ok := ctx.Value(loadersCtxKey).(*Loaders)
	if !ok {
		panic(errors.New("Invalid data loaders context"))
	}
	return raw
}
