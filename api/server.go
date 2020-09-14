package main

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/99designs/gqlgen/graphql"
	"git.sr.ht/~sircmpwn/gql.sr.ht"

	"git.sr.ht/~sircmpwn/meta.sr.ht/api/graph"
	"git.sr.ht/~sircmpwn/meta.sr.ht/api/graph/api"
	"git.sr.ht/~sircmpwn/meta.sr.ht/api/graph/model"
	"git.sr.ht/~sircmpwn/meta.sr.ht/api/loaders"
)

func main() {
	appConfig := gql.LoadConfig(":5100")

	gqlConfig := api.Config{Resolvers: &graph.Resolver{}}
	gqlConfig.Directives.Internal = gql.Internal
	gqlConfig.Directives.Access = func (ctx context.Context, obj interface{},
		next graphql.Resolver, scope model.AccessScope,
		kind model.AccessKind) (interface{}, error) {

		return gql.Access(ctx, obj, next, scope.String(), kind.String())
	}
	schema := api.NewExecutableSchema(gqlConfig)

	router := gql.MakeRouter("meta.sr.ht", appConfig, schema, loaders.Middleware)

	router.Get("/query/api-meta.json", func(w http.ResponseWriter, r *http.Request) {
		scopes := make([]string, len(model.AllAccessScope))
		for i, s := range model.AllAccessScope {
			scopes[i] = s.String()
		}

		info := struct {
			Scopes []string `json:"scopes"`
		} { scopes }

		j, err := json.Marshal(&info)
		if err != nil {
			panic(err)
		}

		w.Header().Add("Content-Type", "application/json")
		w.Write(j)
	})

	gql.ListenAndServe(router)
}
