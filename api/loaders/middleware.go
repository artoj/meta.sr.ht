package loaders

//go:generate ./gen UsersByIDLoader int api/graph/model.User
//go:generate ./gen UsersByNameLoader string api/graph/model.User
//go:generate ./gen UsersByEmailLoader string api/graph/model.User
//go:generate ./gen OAuthClientsByIDLoader int api/graph/model.OAuthClient
//go:generate ./gen OAuthClientsByUUIDLoader string api/graph/model.OAuthClient

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"time"

	"github.com/lib/pq"
	sq "github.com/Masterminds/squirrel"

	"git.sr.ht/~sircmpwn/gql.sr.ht/database"
	"git.sr.ht/~sircmpwn/meta.sr.ht/api/graph/model"
)

var loadersCtxKey = &contextKey{"loaders"}

type contextKey struct {
	name string
}

type Loaders struct {
	UsersByID    UsersByIDLoader
	UsersByName  UsersByNameLoader
	UsersByEmail UsersByEmailLoader

	OAuthClientsByID OAuthClientsByIDLoader
	OAuthClientsByUUID OAuthClientsByUUIDLoader
}

func fetchUsersByID(ctx context.Context) func(ids []int) ([]*model.User, []error) {
	return func(ids []int) ([]*model.User, []error) {
		users := make([]*model.User, len(ids))

		if err := database.WithTx(ctx, &sql.TxOptions{
			Isolation: 0,
			ReadOnly: true,
		}, func (tx *sql.Tx) error {
			var (
				err  error
				rows *sql.Rows
			)
			query := database.
				Select(ctx, (&model.User{}).As(`u`)).
				From(`"user" u`).
				Where(sq.Expr(`u.id = ANY(?)`, pq.Array(ids)))
			if rows, err = query.RunWith(tx).QueryContext(ctx); err != nil {
				return err
			}
			defer rows.Close()

			usersById := map[int]*model.User{}
			for rows.Next() {
				var user model.User
				if err := rows.Scan(database.Scan(ctx, &user)...); err != nil {
					return err
				}
				usersById[user.ID] = &user
			}
			if err = rows.Err(); err != nil {
				return err
			}

			for i, id := range ids {
				users[i] = usersById[id]
			}
			return nil
		}); err != nil {
			panic(err)
		}

		return users, nil
	}
}

func fetchUsersByName(ctx context.Context) func(names []string) ([]*model.User, []error) {
	return func(names []string) ([]*model.User, []error) {
		users := make([]*model.User, len(names))
		if err := database.WithTx(ctx, &sql.TxOptions{
			Isolation: 0,
			ReadOnly: true,
		}, func (tx *sql.Tx) error {
			var (
				err  error
				rows *sql.Rows
			)
			query := database.
				Select(ctx, (&model.User{}).As(`u`)).
				From(`"user" u`).
				Where(sq.Expr(`u.username = ANY(?)`, pq.Array(names)))
			if rows, err = query.RunWith(tx).QueryContext(ctx); err != nil {
				return err
			}
			defer rows.Close()

			usersByName := map[string]*model.User{}
			for rows.Next() {
				user := model.User{}
				if err := rows.Scan(database.Scan(ctx, &user)...); err != nil {
					return err
				}
				usersByName[user.Username] = &user
			}
			if err = rows.Err(); err != nil {
				return err
			}

			for i, name := range names {
				users[i] = usersByName[name]
			}

			return nil
		}); err != nil {
			panic(err)
		}

		return users, nil
	}
}

func fetchUsersByEmail(ctx context.Context) func(emails []string) ([]*model.User, []error) {
	return func(emails []string) ([]*model.User, []error) {
		users := make([]*model.User, len(emails))
		if err := database.WithTx(ctx, &sql.TxOptions{
			Isolation: 0,
			ReadOnly: true,
		}, func (tx *sql.Tx) error {
			var (
				err  error
				rows *sql.Rows
			)
			query := database.
				Select(ctx, (&model.User{}).As(`u`)).
				From(`"user" u`).
				Where(sq.Expr(`u.email = ANY(?)`, pq.Array(emails)))
			if rows, err = query.RunWith(tx).QueryContext(ctx); err != nil {
				return err
			}
			defer rows.Close()

			usersByEmail := map[string]*model.User{}
			for rows.Next() {
				user := model.User{}
				if err := rows.Scan(database.Scan(ctx, &user)...); err != nil {
					return err
				}
				usersByEmail[user.Email] = &user
			}
			if err = rows.Err(); err != nil {
				return err
			}

			for i, email := range emails {
				users[i] = usersByEmail[email]
			}

			return nil
		}); err != nil {
			panic(err)
		}

		return users, nil
	}
}

func fetchOAuthClientsByID(ctx context.Context) func(ids []int) ([]*model.OAuthClient, []error) {
	return func(ids []int) ([]*model.OAuthClient, []error) {
		clients := make([]*model.OAuthClient, len(ids))

		if err := database.WithTx(ctx, &sql.TxOptions{
			Isolation: 0,
			ReadOnly: true,
		}, func (tx *sql.Tx) error {
			var (
				err  error
				rows *sql.Rows
			)
			query := database.
				Select(ctx, (&model.OAuthClient{}).As(`c`)).
				From(`oauth2_client c`).
				Where(sq.Expr(`u.id = ANY(?)`, pq.Array(ids)))
			if rows, err = query.RunWith(tx).QueryContext(ctx); err != nil {
				return err
			}
			defer rows.Close()

			clientsById := map[int]*model.OAuthClient{}
			for rows.Next() {
				var client model.OAuthClient
				if err := rows.Scan(database.Scan(ctx, &client)...); err != nil {
					return err
				}
				clientsById[client.ID] = &client
			}
			if err = rows.Err(); err != nil {
				return err
			}

			for i, id := range ids {
				clients[i] = clientsById[id]
			}
			return nil
		}); err != nil {
			panic(err)
		}

		return clients, nil
	}
}

func fetchOAuthClientsByUUID(ctx context.Context) func(uuids []string) ([]*model.OAuthClient, []error) {
	return func(uuids []string) ([]*model.OAuthClient, []error) {
		clients := make([]*model.OAuthClient, len(uuids))

		if err := database.WithTx(ctx, &sql.TxOptions{
			Isolation: 0,
			ReadOnly: true,
		}, func (tx *sql.Tx) error {
			var (
				err  error
				rows *sql.Rows
			)
			query := database.
				Select(ctx, (&model.OAuthClient{}).As(`c`)).
				From(`oauth2_client c`).
				Where(sq.Expr(`c.client_uuid = ANY(?)`, pq.Array(uuids)))
			if rows, err = query.RunWith(tx).QueryContext(ctx); err != nil {
				return err
			}
			defer rows.Close()

			clientsByUUID := map[string]*model.OAuthClient{}
			for rows.Next() {
				var client model.OAuthClient
				if err := rows.Scan(database.Scan(ctx, &client)...); err != nil {
					return err
				}
				clientsByUUID[client.UUID] = &client
			}
			if err = rows.Err(); err != nil {
				return err
			}

			for i, uuid := range uuids {
				clients[i] = clientsByUUID[uuid]
			}
			return nil
		}); err != nil {
			panic(err)
		}

		return clients, nil
	}
}

func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), loadersCtxKey, &Loaders{
			UsersByID: UsersByIDLoader{
				maxBatch: 100,
				wait:     1 * time.Millisecond,
				fetch:    fetchUsersByID(r.Context()),
			},
			UsersByName: UsersByNameLoader{
				maxBatch: 100,
				wait:     1 * time.Millisecond,
				fetch:    fetchUsersByName(r.Context()),
			},
			UsersByEmail: UsersByEmailLoader{
				maxBatch: 100,
				wait:     1 * time.Millisecond,
				fetch:    fetchUsersByEmail(r.Context()),
			},
			OAuthClientsByID: OAuthClientsByIDLoader{
				maxBatch: 100,
				wait:     1 * time.Millisecond,
				fetch:    fetchOAuthClientsByID(r.Context()),
			},
			OAuthClientsByUUID: OAuthClientsByUUIDLoader{
				maxBatch: 100,
				wait:     1 * time.Millisecond,
				fetch:    fetchOAuthClientsByUUID(r.Context()),
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
