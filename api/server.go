package main

import (
	"context"
	"encoding/json"
	"net/http"

	"git.sr.ht/~sircmpwn/core-go/server"
	"github.com/99designs/gqlgen/graphql"

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

	router := server.MakeRouter("meta.sr.ht",
		appConfig, schema, loaders.Middleware)
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
	server.ListenAndServe(router)
}
