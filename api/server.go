package main

import (
	"git.sr.ht/~sircmpwn/gql.sr.ht"

	"git.sr.ht/~sircmpwn/meta.sr.ht/api/graph"
	"git.sr.ht/~sircmpwn/meta.sr.ht/api/graph/api"
	"git.sr.ht/~sircmpwn/meta.sr.ht/api/loaders"
)

func main() {
	appConfig := gql.LoadConfig(":5100")

	gqlConfig := api.Config{Resolvers: &graph.Resolver{}}
	schema := api.NewExecutableSchema(gqlConfig)

	router := gql.MakeRouter("meta.sr.ht", appConfig, schema, loaders.Middleware)
	gql.ListenAndServe(router)
}
