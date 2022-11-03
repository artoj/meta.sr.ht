package account

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"strings"
	"sync"

	"git.sr.ht/~sircmpwn/core-go/client"
	"git.sr.ht/~sircmpwn/core-go/config"
	"git.sr.ht/~sircmpwn/core-go/database"
	work "git.sr.ht/~sircmpwn/dowork"
	"github.com/vektah/gqlparser/gqlerror"
)

type contextKey struct {
	name string
}

var ctxKey = &contextKey{"account"}

func Middleware(queue *work.Queue) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), ctxKey, queue)
			r = r.WithContext(ctx)
			next.ServeHTTP(w, r)
		})
	}
}

// Schedules a user account deletion.
func Delete(ctx context.Context, userID int, username string) {
	queue, ok := ctx.Value(ctxKey).(*work.Queue)
	if !ok {
		panic("No account worker for this context")
	}

	var services []string
	conf := config.ForContext(ctx)
	for key, _ := range conf {
		if !strings.HasSuffix(key, ".sr.ht") || key == "meta.sr.ht" {
			continue
		}
		services = append(services, key)
	}

	var wg sync.WaitGroup
	task := work.NewTask(func(ctx context.Context) error {
		log.Printf("Processing deletion of user account %d %s", userID, username)
		wg.Wait()

		if err := database.WithTx(ctx, nil, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, `
				DELETE FROM "user" WHERE id = $1
			`, userID)
			return err
		}); err != nil {
			return err
		}

		log.Printf("Deletion of user account %d %s complete", userID, username)
		return nil
	})

	wg.Add(len(services))
	for _, svc := range services {
		svc := svc
		task := work.NewTask(func(ctx context.Context) error {
			log.Printf("Deleting user account %s on service %s",
				username, svc)
			query := client.GraphQLQuery{
				Query: `mutation {
					deleteUser
				}`,
				Variables: nil,
			}
			resp := struct {
				Data struct {
					DeleteUser int `json:"deleteUser"`
				} `json:"data"`
				Errors []gqlerror.Error `json:"errors"`
			}{}
			return client.Execute(ctx, username, svc, query, &resp)
		}).After(func(ctx context.Context, task *work.Task) {
			wg.Done()
		}).Retries(3)
		queue.Enqueue(task)
	}

	go func() {
		wg.Wait()
		queue.Enqueue(task)
	}()
	log.Printf("Enqueued deletion of user account %d %s", userID, username)
}
