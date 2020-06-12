package main

import (
	"context"
	"fmt"

	"github.com/99designs/gqlgen/graphql"
	"git.sr.ht/~sircmpwn/gql.sr.ht"
	"git.sr.ht/~sircmpwn/gql.sr.ht/auth"

	"git.sr.ht/~sircmpwn/meta.sr.ht/api/graph"
	"git.sr.ht/~sircmpwn/meta.sr.ht/api/graph/api"
	"git.sr.ht/~sircmpwn/meta.sr.ht/api/graph/model"
	"git.sr.ht/~sircmpwn/meta.sr.ht/api/loaders"
)

func main() {
	appConfig := gql.LoadConfig(":5100")

	gqlConfig := api.Config{Resolvers: &graph.Resolver{}}
	// TODO: Move directive implementations into gql.sr.ht
	gqlConfig.Directives.Internal = func(ctx context.Context, obj interface{}, next graphql.Resolver) (interface{}, error) {
		if auth.ForContext(ctx).AuthMethod != auth.AUTH_INTERNAL {
			return nil, fmt.Errorf("Access denied")
		}
		return next(ctx)
	}
	gqlConfig.Directives.Access = func(ctx context.Context, obj interface{}, next graphql.Resolver,
		scope model.AccessScope, kind model.AccessKind) (interface{}, error) {
		if auth.ForContext(ctx).AuthMethod == auth.AUTH_INTERNAL ||
			auth.ForContext(ctx).AuthMethod == auth.AUTH_COOKIE {
			return next(ctx)
		}
		panic(fmt.Errorf("TODO"))
	}
	schema := api.NewExecutableSchema(gqlConfig)

	router := gql.MakeRouter("meta.sr.ht", appConfig, schema, loaders.Middleware)
	gql.ListenAndServe(router)
}
