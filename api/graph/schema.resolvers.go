package graph

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha512"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"git.sr.ht/~sircmpwn/gql.sr.ht/auth"
	"git.sr.ht/~sircmpwn/gql.sr.ht/database"
	gqlmodel "git.sr.ht/~sircmpwn/gql.sr.ht/model"
	"git.sr.ht/~sircmpwn/gql.sr.ht/redis"
	"git.sr.ht/~sircmpwn/meta.sr.ht/api/graph/api"
	"git.sr.ht/~sircmpwn/meta.sr.ht/api/graph/model"
	"git.sr.ht/~sircmpwn/meta.sr.ht/api/loaders"
	"github.com/google/uuid"
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

func (r *mutationResolver) UpdateSSHKey(ctx context.Context, id string) (*model.SSHKey, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *mutationResolver) RegisterOAuthClient(ctx context.Context, redirectURI string, clientName string, clientDescription *string, clientURL *string) (*model.OAuthClientRegistration, error) {
	var seed [64]byte
	n, err := rand.Read(seed[:])
	if err != nil || n != len(seed) {
		panic(err)
	}
	secret := base64.StdEncoding.EncodeToString(seed[:])
	hash := sha512.Sum512(seed[:])
	partial := secret[:8]
	clientID, err := uuid.NewRandom()
	if err != nil {
		panic(err)
	}

	db := database.ForContext(ctx)
	row := db.QueryRowContext(ctx, `
			INSERT INTO oauth2_client (
				created, updated,
				owner_id,
				client_uuid,
				client_secret_hash,
				client_secret_partial,
				redirect_url,
				client_name, client_description, client_url
			) VALUES (
				NOW() at time zone 'utc',
				NOW() at time zone 'utc',
				$1, $2, $3, $4, $5, $6, $7, $8
			) RETURNING (id);
		`, auth.ForContext(ctx).UserID, clientID.String(),
		hex.EncodeToString(hash[:]), partial, redirectURI, clientName,
		clientDescription, clientURL)
	var id int
	if err := row.Scan(&id); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return &model.OAuthClientRegistration{
		Client: &model.OAuthClient{
			ID:          id,
			UUID:        clientID.String(),
			RedirectURL: redirectURI,
			Name:        clientName,
			Description: clientDescription,
			URL:         clientURL,
		},
		Secret: secret,
	}, nil
}

func (r *mutationResolver) RevokeOAuthClient(ctx context.Context, id int) (*model.OAuthClient, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *mutationResolver) RevokeOAuthGrant(ctx context.Context, id int) (*model.OAuthGrant, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *mutationResolver) IssuePersonalAccessToken(ctx context.Context, grants *string, comment *string) (*model.OAuthPersonalTokenRegistration, error) {
	issued := time.Now().UTC()
	expires := issued.Add(366 * 24 * time.Hour)

	user := auth.ForContext(ctx)
	grant := auth.OAuth2Token{
		Version:  auth.TokenVersion,
		Expires:  auth.ToTimestamp(expires),
		Grants:   "",
		Username: user.Username,
		ClientID: "",
	}
	if grants != nil {
		grant.Grants = *grants
	}
	token := grant.Encode()
	hash := sha512.Sum512([]byte(token))
	tokenHash := hex.EncodeToString(hash[:])

	db := database.ForContext(ctx)
	row := db.QueryRowContext(ctx, `
		INSERT INTO oauth2_grant
		(issued, expires, comment, token_hash, user_id)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING (id);
	`, issued, expires, comment, tokenHash, user.UserID)

	var id int
	if err := row.Scan(&id); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return &model.OAuthPersonalTokenRegistration{
		Token: &model.OAuthPersonalToken{
			ID:      id,
			Issued:  issued,
			Expires: expires,
			Comment: comment,
		},
		Secret: token,
	}, nil
}

func (r *mutationResolver) RevokePersonalAccessToken(ctx context.Context, id int) (*model.OAuthPersonalToken, error) {
	db := database.ForContext(ctx)
	row := db.QueryRowContext(ctx, `
		UPDATE oauth2_grant
		SET expires = now() at time zone 'utc'
		WHERE id = $1 AND user_id = $2 AND client_id is null
		RETURNING id, issued, expires, comment, token_hash;
	`, id, auth.ForContext(ctx).UserID)

	var tok model.OAuthPersonalToken
	var hash string
	if err := row.Scan(&tok.ID, &tok.Issued, &tok.Expires,
		&tok.Comment, &hash); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	rc := redis.ForContext(ctx)
	if err := rc.Set(ctx,
		fmt.Sprintf("meta.sr.ht::oauth2::grant_revocations::%s", hash),
		true, tok.Expires.Sub(time.Now().UTC())).Err(); err != nil {

		return nil, err
	}

	return &tok, nil
}

func (r *mutationResolver) IssueAuthorizationCode(ctx context.Context, clientUUID string, grants string) (string, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *mutationResolver) IssueOAuthGrant(ctx context.Context, authorization string, clientSecret string) (*model.OAuthGrantRegistration, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *oAuthClientResolver) Owner(ctx context.Context, obj *model.OAuthClient) (model.Entity, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *pGPKeyResolver) User(ctx context.Context, obj *model.PGPKey) (*model.User, error) {
	return loaders.ForContext(ctx).UsersByID.Load(obj.UserID)
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
		ID:       user.UserID,
		Created:  user.Created,
		Updated:  user.Updated,
		Username: user.Username,
		Email:    user.Email,
		URL:      user.URL,
		Location: user.Location,
		Bio:      user.Bio,

		UserTypeRaw: user.UserType,
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

func (r *queryResolver) SSHKeyByFingerprint(ctx context.Context, fingerprint string) (*model.SSHKey, error) {
	// Normalize fingerprint
	fingerprint = strings.ToLower(fingerprint)
	fingerprint = strings.ReplaceAll(fingerprint, ":", "")
	b, err := hex.DecodeString(fingerprint)
	if err != nil {
		return nil, err
	}
	// TODO: Consider storing the fingerprint in the database in binary
	if len(b) != 16 {
		return nil, fmt.Errorf("Invalid key format; expected 16 bytes")
	}

	var normalized bytes.Buffer
	for i, _ := range b {
		colon := ":"
		if i+1 == len(b) {
			colon = ""
		}
		normalized.WriteString(fmt.Sprintf("%02x%s", b[i], colon))
	}

	key := (&model.SSHKey{}).As(`key`)
	q := database.
		Select(ctx, key).
		From(`sshkey key`).
		Where(`key.fingerprint = ?`, normalized.String()).
		Limit(1)

	row := q.RunWith(database.ForContext(ctx)).QueryRowContext(ctx)
	if err := row.Scan(key.Fields(ctx)...); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return key, nil
}

func (r *queryResolver) PGPKeyByKeyID(ctx context.Context, keyID string) (*model.PGPKey, error) {
	// Normalize keyID
	keyID = strings.ToUpper(keyID)
	keyID = strings.ReplaceAll(keyID, " ", "")
	b, err := hex.DecodeString(keyID)
	if err != nil {
		return nil, err
	}
	// TODO: Consider storing the key ID in the database in binary
	normalized := hex.EncodeToString(b)
	key := (&model.PGPKey{}).As(`key`)
	q := database.
		Select(ctx, key).
		From(`pgpkey key`).
		/* Safe to skip escaping here, after we went to binary and back again */
		Where(`replace(key.key_id, ' ', '') ILIKE '%` + normalized + `%'`).
		Limit(1)

	row := q.RunWith(database.ForContext(ctx)).QueryRowContext(ctx)
	if err := row.Scan(key.Fields(ctx)...); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return key, nil
}

func (r *queryResolver) Invoices(ctx context.Context, cursor *gqlmodel.Cursor) (*model.InvoiceCursor, error) {
	if cursor == nil {
		cursor = gqlmodel.NewCursor(nil)
	}

	inv := (&model.Invoice{})
	query := database.
		Select(ctx, inv).
		From(`invoice`).
		Where(`user_id = ?`, auth.ForContext(ctx).UserID)

	invoices, cursor := inv.QueryWithCursor(ctx, database.ForContext(ctx), query, cursor)
	return &model.InvoiceCursor{invoices, cursor}, nil
}

func (r *queryResolver) AuditLog(ctx context.Context, cursor *gqlmodel.Cursor) (*model.AuditLogCursor, error) {
	if cursor == nil {
		cursor = gqlmodel.NewCursor(nil)
	}

	ent := (&model.AuditLogEntry{}).As(`ent`)
	query := database.
		Select(ctx, ent).
		From(`audit_log_entry ent`).
		Where(`ent.user_id = ?`, auth.ForContext(ctx).UserID)

	ents, cursor := ent.QueryWithCursor(ctx, database.ForContext(ctx), query, cursor)
	return &model.AuditLogCursor{ents, cursor}, nil
}

func (r *queryResolver) TokenRevocationStatus(ctx context.Context, hash string, clientID *string) (bool, error) {
	rc := redis.ForContext(ctx)

	keys := []string{
		fmt.Sprintf("meta.sr.ht::oauth2::grant_revocations::%s", hash),
	}

	if clientID != nil {
		keys = append(keys, fmt.Sprintf(
			"meta.sr.ht::oauth2::client_revocations::%s", clientID))
	}

	if n, err := rc.Exists(ctx, keys...).Result(); err != nil {
		return true, err
	} else if n != 0 {
		return true, nil
	} else {
		return false, nil
	}
}

func (r *queryResolver) OauthClients(ctx context.Context) ([]*model.OAuthClient, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *queryResolver) OauthClientByID(ctx context.Context, id int) (*model.OAuthClient, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *queryResolver) OauthClientByUUID(ctx context.Context, uuid string) (*model.OAuthClient, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *queryResolver) OauthGrants(ctx context.Context) ([]*model.OAuthGrant, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *queryResolver) OauthGrant(ctx context.Context, id int) (*model.OAuthGrant, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *queryResolver) PersonalAccessTokens(ctx context.Context) ([]*model.OAuthPersonalToken, error) {
	token := (&model.OAuthPersonalToken{}).As(`tok`)
	q := database.
		Select(ctx, token).
		From(`oauth2_grant tok`).
		Where(`tok.user_id = ?
			AND tok.client_id is null
			AND tok.expires > now() at time zone 'utc'`,
			auth.ForContext(ctx).UserID)
	tokens := token.Query(ctx, database.ForContext(ctx), q)
	return tokens, nil
}

func (r *sSHKeyResolver) User(ctx context.Context, obj *model.SSHKey) (*model.User, error) {
	return loaders.ForContext(ctx).UsersByID.Load(obj.UserID)
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

func (r *userResolver) PGPKeys(ctx context.Context, obj *model.User, cursor *gqlmodel.Cursor) (*model.PGPKeyCursor, error) {
	if cursor == nil {
		cursor = gqlmodel.NewCursor(nil)
	}

	key := (&model.PGPKey{}).As(`key`)
	query := database.
		Select(ctx, key).
		From(`pgpkey key`).
		Where(`key.user_id = ?`, obj.ID)

	keys, cursor := key.QueryWithCursor(ctx, database.ForContext(ctx), query, cursor)
	return &model.PGPKeyCursor{keys, cursor}, nil
}

// Mutation returns api.MutationResolver implementation.
func (r *Resolver) Mutation() api.MutationResolver { return &mutationResolver{r} }

// OAuthClient returns api.OAuthClientResolver implementation.
func (r *Resolver) OAuthClient() api.OAuthClientResolver { return &oAuthClientResolver{r} }

// PGPKey returns api.PGPKeyResolver implementation.
func (r *Resolver) PGPKey() api.PGPKeyResolver { return &pGPKeyResolver{r} }

// Query returns api.QueryResolver implementation.
func (r *Resolver) Query() api.QueryResolver { return &queryResolver{r} }

// SSHKey returns api.SSHKeyResolver implementation.
func (r *Resolver) SSHKey() api.SSHKeyResolver { return &sSHKeyResolver{r} }

// User returns api.UserResolver implementation.
func (r *Resolver) User() api.UserResolver { return &userResolver{r} }

type mutationResolver struct{ *Resolver }
type oAuthClientResolver struct{ *Resolver }
type pGPKeyResolver struct{ *Resolver }
type queryResolver struct{ *Resolver }
type sSHKeyResolver struct{ *Resolver }
type userResolver struct{ *Resolver }
