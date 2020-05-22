package graph

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.

import (
	"context"
	"fmt"

	"git.sr.ht/~sircmpwn/gql.sr.ht/auth"
	"git.sr.ht/~sircmpwn/gql.sr.ht/database"
	gqlmodel "git.sr.ht/~sircmpwn/gql.sr.ht/model"
	"git.sr.ht/~sircmpwn/meta.sr.ht/api/graph/api"
	"git.sr.ht/~sircmpwn/meta.sr.ht/api/graph/model"
	"git.sr.ht/~sircmpwn/meta.sr.ht/api/loaders"
)

func (r *mutationResolver) UpdateUser(ctx context.Context, input map[string]interface{}) (*model.User, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *mutationResolver) CreatePGPKey(ctx context.Context, key string) (*model.PGPKey, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *mutationResolver) DeletePGPKey(ctx context.Context, key string) (*model.PGPKey, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *mutationResolver) CreateSSHKey(ctx context.Context, key string) (*model.SSHKey, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *mutationResolver) DeleteSSHKey(ctx context.Context, key string) (*model.SSHKey, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *queryResolver) Version(ctx context.Context) (*model.Version, error) {
	return &model.Version{
		Major:           0,
		Minor:           0,
		Patch:           0,
		DeprecationDate: nil,
	}, nil
}

func (r *queryResolver) Me(ctx context.Context) (*model.User, error) {
	user := auth.ForContext(ctx)
	return &model.User{
		ID:       user.ID,
		Created:  user.Created,
		Updated:  user.Updated,
		Username: user.Username,
		Email:    user.Email,
		URL:      user.URL,
		Location: user.Location,
		Bio:      user.Bio,
	}, nil
}

func (r *queryResolver) UserByID(ctx context.Context, id int) (*model.User, error) {
	return loaders.ForContext(ctx).UsersByID.Load(id)
}

func (r *queryResolver) UserByName(ctx context.Context, username string) (*model.User, error) {
	return loaders.ForContext(ctx).UsersByName.Load(username)
}

func (r *queryResolver) UserByEmail(ctx context.Context, email string) (*model.User, error) {
	return loaders.ForContext(ctx).UsersByEmail.Load(email)
}

func (r *queryResolver) UserByPGPKey(ctx context.Context, fingerprint string) (*model.User, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *queryResolver) UserBySSHKey(ctx context.Context, key string) (*model.User, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *sSHKeyResolver) User(ctx context.Context, obj *model.SSHKey) (*model.User, error) {
	return loaders.ForContext(ctx).UsersByID.Load(obj.UserId)
}

func (r *userResolver) SSHKeys(ctx context.Context, obj *model.User, cursor *gqlmodel.Cursor) (*model.SSHKeyCursor, error) {
	if cursor == nil {
		cursor = gqlmodel.NewCursor(nil)
	}

	key := (&model.SSHKey{}).As(`key`)
	query := database.
		Select(ctx, key).
		From(`sshkey key`).
		Where(`key.user_id = ?`, obj.ID)

	keys, cursor := key.QueryWithCursor(ctx, database.ForContext(ctx), query, cursor)
	return &model.SSHKeyCursor{keys, cursor}, nil
}

func (r *userResolver) PgpKeys(ctx context.Context, obj *model.User, cursor *gqlmodel.Cursor) (*model.PGPKeyCursor, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *userResolver) Invoices(ctx context.Context, obj *model.User, cursor *gqlmodel.Cursor) (*model.InvoiceCursor, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *userResolver) AuditLog(ctx context.Context, obj *model.User, cursor *gqlmodel.Cursor) (*model.AuditLogCursor, error) {
	panic(fmt.Errorf("not implemented"))
}

// Mutation returns api.MutationResolver implementation.
func (r *Resolver) Mutation() api.MutationResolver { return &mutationResolver{r} }

// Query returns api.QueryResolver implementation.
func (r *Resolver) Query() api.QueryResolver { return &queryResolver{r} }

// SSHKey returns api.SSHKeyResolver implementation.
func (r *Resolver) SSHKey() api.SSHKeyResolver { return &sSHKeyResolver{r} }

// User returns api.UserResolver implementation.
func (r *Resolver) User() api.UserResolver { return &userResolver{r} }

type mutationResolver struct{ *Resolver }
type queryResolver struct{ *Resolver }
type sSHKeyResolver struct{ *Resolver }
type userResolver struct{ *Resolver }
