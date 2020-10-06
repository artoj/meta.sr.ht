package main

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"

	"git.sr.ht/~sircmpwn/core-go/email"
	"git.sr.ht/~sircmpwn/core-go/server"
	"git.sr.ht/~sircmpwn/dowork"
	"github.com/99designs/gqlgen/graphql"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"git.sr.ht/~sircmpwn/meta.sr.ht/api/graph"
	"git.sr.ht/~sircmpwn/meta.sr.ht/api/graph/api"
	"git.sr.ht/~sircmpwn/meta.sr.ht/api/graph/model"
	"git.sr.ht/~sircmpwn/meta.sr.ht/api/loaders"
)

func main() {
	appConfig := server.LoadConfig(":5100")

	gqlConfig := api.Config{Resolvers: &graph.Resolver{}}
	gqlConfig.Directives.Internal = server.Internal
	gqlConfig.Directives.Access = func(ctx context.Context, obj interface{},
		next graphql.Resolver, scope model.AccessScope,
		kind model.AccessKind) (interface{}, error) {

		return server.Access(ctx, obj, next, scope.String(), kind.String())
	}
	schema := api.NewExecutableSchema(gqlConfig)

	mail := email.NewQueue()
	mail.Start(context.Background())

	router := server.MakeRouter("meta.sr.ht", appConfig, schema,
		loaders.Middleware,
		email.Middleware(mail))
	router.Get("/query/api-meta.json", func(w http.ResponseWriter, r *http.Request) {
		scopes := make([]string, len(model.AllAccessScope))
		for i, s := range model.AllAccessScope {
			scopes[i] = s.String()
		}

		info := struct {
			Scopes []string `json:"scopes"`
		}{scopes}

		j, err := json.Marshal(&info)
		if err != nil {
			panic(err)
		}

		w.Header().Add("Content-Type", "application/json")
		w.Write(j)
	})
	qserver, qlistener := server.MakeServer(router)
	go qserver.Serve(qlistener)

	mux := &http.ServeMux{}
	mux.Handle("/metrics", promhttp.Handler())
	pserver := &http.Server{Handler: mux}
	plistener, err := net.Listen("tcp", ":0")
	if err != nil {
		panic(err)
	}
	log.Printf("Prometheus listening on :%d", plistener.Addr().(*net.TCPAddr).Port)
	go pserver.Serve(plistener)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig
	signal.Reset(os.Interrupt)
	log.Println("SIGINT caught, initiating warm shutdown")
	log.Println("SIGINT again to terminate immediately and drop pending requests & tasks")

	log.Println("Terminating server...")
	ctx, cancel := context.WithDeadline(context.Background(),
		time.Now().Add(30 * time.Second))
	qserver.Shutdown(ctx)
	cancel()

	log.Println("Terminating work queues...")
	log.Printf("Progress available via Prometheus stats on port %d",
		plistener.Addr().(*net.TCPAddr).Port)
	work.Join(mail)
	qserver.Close()
	log.Println("Terminating process.")
}
