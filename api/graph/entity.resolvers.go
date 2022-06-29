package graph

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.

import (
	"context"

	"git.sr.ht/~sircmpwn/meta.sr.ht/api/graph/api"
	"git.sr.ht/~sircmpwn/meta.sr.ht/api/graph/model"
	"git.sr.ht/~sircmpwn/meta.sr.ht/api/loaders"
)

func (r *entityResolver) FindOAuthClientByUUID(ctx context.Context, uuid string) (*model.OAuthClient, error) {
	return loaders.ForContext(ctx).OAuthClientsByUUID.Load(uuid)
}

func (r *entityResolver) FindUserByID(ctx context.Context, id int) (*model.User, error) {
	return loaders.ForContext(ctx).UsersByID.Load(id)
}

// Entity returns api.EntityResolver implementation.
func (r *Resolver) Entity() api.EntityResolver { return &entityResolver{r} }

type entityResolver struct{ *Resolver }
