package main

import (
	"context"
	"fmt"

	"github.com/99designs/gqlgen/graphql"
	"git.sr.ht/~sircmpwn/gql.sr.ht"
	"git.sr.ht/~sircmpwn/gql.sr.ht/auth"

	"git.sr.ht/~sircmpwn/meta.sr.ht/api/graph"
	"git.sr.ht/~sircmpwn/meta.sr.ht/api/graph/api"
	"git.sr.ht/~sircmpwn/meta.sr.ht/api/loaders"
)

func main() {
	appConfig := gql.LoadConfig(":5100")

	gqlConfig := api.Config{Resolvers: &graph.Resolver{}}
	gqlConfig.Directives.Internal = func(ctx context.Context, obj interface{}, next graphql.Resolver) (interface{}, error) {
		if auth.ForContext(ctx).AuthMethod != auth.AUTH_INTERNAL {
			return nil, fmt.Errorf("Access denied")
		}
		return next(ctx)
	}
	schema := api.NewExecutableSchema(gqlConfig)

	router := gql.MakeRouter("meta.sr.ht", appConfig, schema, loaders.Middleware)
	gql.ListenAndServe(router)
}
