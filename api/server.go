package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"git.sr.ht/~sircmpwn/core-go/auth"
	"git.sr.ht/~sircmpwn/core-go/config"
	"git.sr.ht/~sircmpwn/core-go/database"
	"git.sr.ht/~sircmpwn/core-go/server"
	work "git.sr.ht/~sircmpwn/dowork"
	"github.com/99designs/gqlgen/graphql"
	"github.com/go-chi/chi"

	"git.sr.ht/~sircmpwn/meta.sr.ht/api/account"
	"git.sr.ht/~sircmpwn/meta.sr.ht/api/graph"
	"git.sr.ht/~sircmpwn/meta.sr.ht/api/graph/api"
	"git.sr.ht/~sircmpwn/meta.sr.ht/api/graph/model"
	"git.sr.ht/~sircmpwn/meta.sr.ht/api/invoice"
	"git.sr.ht/~sircmpwn/meta.sr.ht/api/loaders"
	"git.sr.ht/~sircmpwn/meta.sr.ht/api/webhooks"
)

func main() {
	appConfig := config.LoadConfig(":5100")

	gqlConfig := api.Config{Resolvers: &graph.Resolver{}}
	gqlConfig.Directives.Anoninternal = server.AnonInternal
	gqlConfig.Directives.Internal = server.Internal
	gqlConfig.Directives.Private = server.Private
	gqlConfig.Directives.Access = func(ctx context.Context, obj interface{},
		next graphql.Resolver, scope model.AccessScope,
		kind model.AccessKind) (interface{}, error) {
		return server.Access(ctx, obj, next, scope.String(), kind.String())
	}
	schema := api.NewExecutableSchema(gqlConfig)

	scopes := make([]string, len(model.AllAccessScope))
	for i, s := range model.AllAccessScope {
		scopes[i] = s.String()
	}

	accountQueue := work.NewQueue("account")
	webhookQueue := webhooks.NewQueue(schema)
	legacyWebhooks := webhooks.NewLegacyQueue()

	srv := server.NewServer("meta.sr.ht", appConfig).
		WithDefaultMiddleware().
		WithMiddleware(
			loaders.Middleware,
			account.Middleware(accountQueue),
			webhooks.Middleware(webhookQueue),
			webhooks.LegacyMiddleware(legacyWebhooks),
		).
		WithSchema(schema, scopes).
		WithQueues(
			accountQueue,
			webhookQueue.Queue,
			legacyWebhooks.Queue,
		)

	srv.Router().Post("/query/invoice/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.Atoi(chi.URLParam(r, "id"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Invalid invoice ID\r\n"))
			return
		}

		// optional
		billTo := r.PostFormValue("address-to")

		billFromHead, _ := config.ForContext(r.Context()).Get("meta.sr.ht::billing", "address-line1")
		var billFromTail []string

		for _, key := range []string{
			"address-line2",
			"address-line3",
			"address-line4",
		} {
			if line, ok := config.ForContext(r.Context()).Get("meta.sr.ht::billing", key); ok {
				billFromTail = append(billFromTail, line)
			}
		}

		if err := database.WithTx(r.Context(), &sql.TxOptions{
			Isolation: 0,
			ReadOnly:  true,
		}, func(tx *sql.Tx) error {

			rows, err := tx.QueryContext(r.Context(), `
				SELECT invoice.created, invoice.cents, invoice.valid_thru, invoice.source
				FROM invoice
				WHERE invoice.id = $1 AND invoice.user_id = $2
			`, id, auth.ForContext(r.Context()).UserID)
			if err != nil {
				return err
			}

			var (
				created   time.Time
				cents     int
				validThru time.Time
				source    string
			)

			if !rows.Next() {
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte("Not found\r\n"))
				return nil
			}

			if err := rows.Scan(&created, &cents, &validThru, &source); err != nil {
				return err
			}

			inv := invoice.Invoice{
				Id:           id,
				Amount:       fmt.Sprintf("$%.02f", float64(cents)/100.0),
				Source:       source,
				Created:      created.Format("2006-01-02"),
				ValidThru:    validThru.Format("2006-01-02"),
				BillTo:       billTo,
				BillFromHead: billFromHead,
				BillFromTail: billFromTail,
			}
			fmt.Printf("amount is %s, was %d cents\n", inv.Amount, cents)
			w.Header().Add("Content-Type", "application/pdf")
			return inv.Generate(w)
		}); err != nil {
			panic(err)
		}
	})
	srv.Run()
}
