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
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"git.sr.ht/~sircmpwn/core-go/auth"
	"git.sr.ht/~sircmpwn/core-go/config"
	"git.sr.ht/~sircmpwn/core-go/database"
	gqlmodel "git.sr.ht/~sircmpwn/core-go/model"
	"git.sr.ht/~sircmpwn/core-go/redis"
	"git.sr.ht/~sircmpwn/meta.sr.ht/api/graph/api"
	"git.sr.ht/~sircmpwn/meta.sr.ht/api/graph/model"
	"git.sr.ht/~sircmpwn/meta.sr.ht/api/loaders"
	"git.sr.ht/~sircmpwn/meta.sr.ht/api/webhooks"
	"github.com/google/uuid"
	"golang.org/x/crypto/openpgp"
)

func (r *mutationResolver) UpdateUser(ctx context.Context, input map[string]interface{}) (*model.User, error) {
	var address string
	if e, ok := input["email"]; ok {
		// Requires separate confirmation step
		address, ok = e.(string)
		if !ok {
			return nil, fmt.Errorf("Invalid type for 'email' field (expected string)")
		}
		if !strings.ContainsRune(address, '@') {
			return nil, fmt.Errorf("Invalid format for 'email' field (expected email address)")
		}
		delete(input, "email")
	}

	user, err := loaders.ForContext(ctx).
		UsersByID.Load(auth.ForContext(ctx).UserID)
	if err != nil {
		return nil, err
	}

	if err := database.WithTx(ctx, nil, func(tx *sql.Tx) error {
		var err error

		if len(input) != 0 {
			_, err = database.Apply(user, input).
				RunWith(tx).
				ExecContext(ctx)
			if err != nil {
				return err
			}
		}

		if address != "" {
			var key *string
			// This query serves two roles: check for email conflicts and look
			// up the user's PGP key. Consolodated to reduce SQL round-trips.
			// The first row will be the user's PGP key, and if there is a
			// second row, there is a conflict on the requested email address.
			rows, err := tx.QueryContext(ctx, `
				SELECT pgpkey.key
				FROM "user"
				LEFT JOIN pgpkey ON pgpkey.id = "user".pgp_key_id
				WHERE "user".email = $1 OR "user".id = $2
				ORDER BY ("user".id = $2) DESC;`, address, user.ID)
			if err != nil {
				return err
			}
			defer rows.Close()

			if !rows.Next() {
				panic(fmt.Errorf("User record not found")) // Invariant
			}
			if err = rows.Scan(&key); err != nil {
				return err
			}

			if rows.Next() {
				return fmt.Errorf("The requested email address is already in use.")
			}

			var seed [18]byte
			n, err := rand.Read(seed[:])
			if err != nil || n != len(seed) {
				panic(err)
			}
			confHash := base64.StdEncoding.EncodeToString(seed[:])

			_, err = tx.ExecContext(ctx, `UPDATE "user"
				SET new_email = $1, confirmation_hash = $2;`, address, confHash)
			if err != nil {
				return err
			}

			sendEmailUpdateConfirmation(ctx, user, key, address, confHash)
		}

		return nil
	}); err != nil {
		return nil, err
	}

	if len(input) != 0 {
		webhooks.DeliverLegacyProfileUpdate(ctx, user)
	}

	return user, nil
}

func (r *mutationResolver) CreatePGPKey(ctx context.Context, key string) (*model.PGPKey, error) {
	keys, err := openpgp.ReadArmoredKeyRing(strings.NewReader(key))
	if err != nil {
		return nil, fmt.Errorf("Failed to read PGP key: %w", err)
	}
	if len(keys) != 1 {
		return nil, fmt.Errorf("Expected one key, found %d", len(keys))
	}

	entity := keys[0]
	if entity.PrivateKey != nil {
		return nil, fmt.Errorf("There's a private key in here, yikes!")
	}

	pkey := entity.PrimaryKey
	if pkey == nil {
		return nil, fmt.Errorf("No public keys found.")
	}
	if !pkey.CanSign() {
		return nil, fmt.Errorf("No public keys suitable for signing found.")
	}

	// TODO: Remove email field
	var email string
	for _, ident := range entity.Identities {
		email = ident.UserId.Email
		break
	}

	// TODO: Use the actual key ID throughout, not the fingerprint
	normalized := strings.ToUpper(hex.EncodeToString(pkey.Fingerprint[:]))
	keyID := ""
	for i := 0; i < len(normalized); i += 4 {
		keyID += normalized[i:i+4] + " "
	}
	keyID = keyID[:len(keyID)-1]

	var (
		id      int
		created time.Time
	)
	if err := database.WithTx(ctx, nil, func(tx *sql.Tx) error {
		// It's safe to skip escaping the Where clause, normalized is hex
		// digits only
		row := tx.QueryRowContext(ctx, `
			SELECT id
			FROM pgpkey
			WHERE replace(key_id, ' ', '') LIKE '%`+normalized+`%'`)
		if row.Scan() != sql.ErrNoRows {
			return fmt.Errorf("This PGP key is already registered in our system.")
		}

		row = tx.QueryRowContext(ctx, `
				INSERT INTO pgpkey (
					created, user_id, key, key_id, email
				) VALUES (
					NOW() at time zone 'utc',
					$1, $2, $3, $4
				) RETURNING id, created;
			`, auth.ForContext(ctx).UserID, key, keyID, email)
		if err := row.Scan(&id, &created); err != nil {
			if err == sql.ErrNoRows {
				panic(fmt.Errorf("PostgreSQL invariant broken"))
			}
			return err
		}
		return nil
	}); err != nil {
		return nil, err
	}

	conf := config.ForContext(ctx)
	siteName, ok := conf.Get("sr.ht", "site-name")
	if !ok {
		panic(fmt.Errorf("Expected [sr.ht]site-name in config"))
	}
	sendSecurityNotification(ctx,
		fmt.Sprintf("A PGP key was added to your %s account", siteName),
		fmt.Sprintf("PGP key %s added to your account", keyID),
		nil) // TODO: Grab user PGP key
	recordAuditLog(ctx, "PGP key added", fmt.Sprintf("PGP key %s added", keyID))

	return &model.PGPKey{
		ID:      id,
		Created: created,
		Key:     key,
		KeyID:   keyID,
		UserID:  auth.ForContext(ctx).UserID,
	}, nil
}

func (r *mutationResolver) DeletePGPKey(ctx context.Context, id int) (*model.PGPKey, error) {
	var key model.PGPKey

	if err := database.WithTx(ctx, nil, func(tx *sql.Tx) error {
		var isPreferredKey bool
		row := tx.QueryRowContext(ctx, `
				SELECT pgp_key_id is not null and pgp_key_id = $1
				FROM "user" WHERE id = $2;
			`, id, auth.ForContext(ctx).UserID)
		if err := row.Scan(&isPreferredKey); err != nil {
			return err
		}
		if isPreferredKey {
			return fmt.Errorf(
				"PGP key ID %d is set as the user's preferred PGP key. It must be unset before removing the key.",
				id)
		}

		row = tx.QueryRowContext(ctx, `
				DELETE FROM pgpkey
				WHERE id = $1 AND user_id = $2
				RETURNING id, created, user_id, key, key_id;
			`, id, auth.ForContext(ctx).UserID)
		if err := row.Scan(&key.ID, &key.Created,
			&key.UserID, &key.Key, &key.KeyID); err != nil {
			return err
		}
		return nil
	}); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("No such PGP key found for the authorized user.")
		}
		return nil, err
	}

	conf := config.ForContext(ctx)
	siteName, ok := conf.Get("sr.ht", "site-name")
	if !ok {
		panic(fmt.Errorf("Expected [sr.ht]site-name in config"))
	}
	sendSecurityNotification(ctx,
		fmt.Sprintf("A PGP key was removed from your %s account", siteName),
		fmt.Sprintf("PGP key %s removed from your account", key.KeyID),
		nil) // TODO: Grab user PGP key
	recordAuditLog(ctx, "PGP key removed",
		fmt.Sprintf("PGP key %s removed", key.KeyID))

	return &key, nil
}

func (r *mutationResolver) CreateSSHKey(ctx context.Context, key string) (*model.SSHKey, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *mutationResolver) DeleteSSHKey(ctx context.Context, id int) (*model.SSHKey, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *mutationResolver) UpdateSSHKey(ctx context.Context, id int) (*model.SSHKey, error) {
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

	var id int
	if err := database.WithTx(ctx, nil, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, `
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
		if err := row.Scan(&id); err != nil {
			if err == sql.ErrNoRows {
				panic(fmt.Errorf("PostgreSQL invariant broken"))
			}
			return err
		}

		return nil
	}); err != nil {
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

	var id int
	if err := database.WithTx(ctx, nil, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, `
			INSERT INTO oauth2_grant
			(issued, expires, comment, token_hash, user_id)
			VALUES ($1, $2, $3, $4, $5)
			RETURNING (id);
		`, issued, expires, comment, tokenHash, user.UserID)

		if err := row.Scan(&id); err != nil {
			if err == sql.ErrNoRows {
				panic(fmt.Errorf("PostgreSQL invariant broken"))
			}
			return err
		}

		return nil
	}); err != nil {
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
	var tok model.OAuthPersonalToken
	var hash string

	if err := database.WithTx(ctx, nil, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, `
			UPDATE oauth2_grant
			SET expires = now() at time zone 'utc'
			WHERE id = $1 AND user_id = $2 AND client_id is null
			RETURNING id, issued, expires, comment, token_hash;
		`, id, auth.ForContext(ctx).UserID)

		if err := row.Scan(&tok.ID, &tok.Issued, &tok.Expires,
			&tok.Comment, &hash); err != nil {
			if err == sql.ErrNoRows {
				return fmt.Errorf("No such personal access token exists")
			}
			return err
		}

		return nil
	}); err != nil {
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
	var seed [64]byte
	n, err := rand.Read(seed[:])
	if err != nil || n != len(seed) {
		panic(err)
	}
	hash := sha512.Sum512(seed[:])
	code := hex.EncodeToString(hash[:])[:32]

	payload := AuthorizationPayload{
		Grants:     grants,
		ClientUUID: clientUUID,
		UserID:     auth.ForContext(ctx).UserID,
	}
	data, err := json.Marshal(&payload)
	if err != nil {
		panic(err)
	}

	rc := redis.ForContext(ctx)
	if err := rc.Set(ctx,
		fmt.Sprintf("meta.sr.ht::oauth2::authorization_code::%s", code),
		data, 5*time.Minute).Err(); err != nil {
		return "", err
	}

	return code, nil
}

func (r *mutationResolver) IssueOAuthGrant(ctx context.Context, authorization string, clientSecret string) (*model.OAuthGrantRegistration, error) {
	key := fmt.Sprintf(
		"meta.sr.ht::oauth2::authorization_code::%s",
		authorization)

	rc := redis.ForContext(ctx)
	bytes, err := rc.Get(ctx, key).Bytes()
	if err != nil {
		return nil, err
	}
	if err = rc.Del(ctx, key).Err(); err != nil {
		panic(err)
	}
	var payload AuthorizationPayload
	if err = json.Unmarshal(bytes, &payload); err != nil {
		panic(err)
	}

	issued := time.Now().UTC()
	expires := issued.Add(366 * 24 * time.Hour)

	user, err := loaders.ForContext(ctx).UsersByID.Load(payload.UserID)
	if err != nil {
		panic(err)
	}
	client, err := loaders.ForContext(ctx).
		OAuthClientsByUUID.Load(payload.ClientUUID)
	if err != nil {
		panic(err)
	}

	grant := auth.OAuth2Token{
		Version:  auth.TokenVersion,
		Expires:  auth.ToTimestamp(expires),
		Grants:   payload.Grants,
		Username: user.Username,
		ClientID: payload.ClientUUID,
	}

	token := grant.Encode()
	hash := sha512.Sum512([]byte(token))
	tokenHash := hex.EncodeToString(hash[:])

	var id int
	if err := database.WithTx(ctx, nil, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, `
			INSERT INTO oauth2_grant
			(issued, expires, token_hash, client_id, user_id)
			VALUES ($1, $2, $3, $4, $5)
			RETURNING (id);
		`, issued, expires, tokenHash, client.ID, user.ID)

		if err := row.Scan(&id); err != nil {
			if err == sql.ErrNoRows {
				panic(fmt.Errorf("PostgreSQL invariant broken"))
			}
			return err
		}

		return nil
	}); err != nil {
		return nil, err
	}

	return &model.OAuthGrantRegistration{
		Grant: &model.OAuthGrant{
			ID:      id,
			Client:  client,
			Issued:  issued,
			Expires: expires,
		},
		Grants: payload.Grants,
		Secret: token,
	}, nil
}

func (r *oAuthClientResolver) Owner(ctx context.Context, obj *model.OAuthClient) (model.Entity, error) {
	return loaders.ForContext(ctx).UsersByID.Load(obj.OwnerID)
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
	if err := database.WithTx(ctx, &sql.TxOptions{
		Isolation: 0,
		ReadOnly:  true,
	}, func(tx *sql.Tx) error {
		q := database.
			Select(ctx, key).
			From(`sshkey key`).
			Where(`key.fingerprint = ?`, normalized.String()).
			Limit(1)

		row := q.RunWith(tx).QueryRowContext(ctx)
		if err := row.Scan(database.Scan(ctx, key)...); err != nil {
			if err == sql.ErrNoRows {
				key = nil
				return nil
			}
			return err
		}

		return nil
	}); err != nil {
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
	if err := database.WithTx(ctx, &sql.TxOptions{
		Isolation: 0,
		ReadOnly:  true,
	}, func(tx *sql.Tx) error {
		q := database.
			Select(ctx, key).
			From(`pgpkey key`).
			/* Safe to skip escaping here, after we went to binary and back again */
			Where(`replace(key.key_id, ' ', '') ILIKE '%` + normalized + `%'`).
			Limit(1)

		row := q.RunWith(tx).QueryRowContext(ctx)
		if err := row.Scan(database.Scan(ctx, key)...); err != nil {
			if err == sql.ErrNoRows {
				key = nil
				return nil
			}
			return err
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return key, nil
}

func (r *queryResolver) Invoices(ctx context.Context, cursor *gqlmodel.Cursor) (*model.InvoiceCursor, error) {
	if cursor == nil {
		cursor = gqlmodel.NewCursor(nil)
	}

	var invoices []*model.Invoice
	if err := database.WithTx(ctx, &sql.TxOptions{
		Isolation: 0,
		ReadOnly:  true,
	}, func(tx *sql.Tx) error {
		inv := (&model.Invoice{})
		query := database.
			Select(ctx, inv).
			From(`invoice`).
			Where(`user_id = ?`, auth.ForContext(ctx).UserID)

		invoices, cursor = inv.QueryWithCursor(ctx, tx, query, cursor)
		return nil
	}); err != nil {
		return nil, err
	}

	return &model.InvoiceCursor{invoices, cursor}, nil
}

func (r *queryResolver) AuditLog(ctx context.Context, cursor *gqlmodel.Cursor) (*model.AuditLogCursor, error) {
	if cursor == nil {
		cursor = gqlmodel.NewCursor(nil)
	}

	var ents []*model.AuditLogEntry
	if err := database.WithTx(ctx, &sql.TxOptions{
		Isolation: 0,
		ReadOnly:  true,
	}, func(tx *sql.Tx) error {
		ent := (&model.AuditLogEntry{}).As(`ent`)
		query := database.
			Select(ctx, ent).
			From(`audit_log_entry ent`).
			Where(`ent.user_id = ?`, auth.ForContext(ctx).UserID)
		ents, cursor = ent.QueryWithCursor(ctx, tx, query, cursor)
		return nil
	}); err != nil {
		return nil, err
	}

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
	var clients []*model.OAuthClient
	if err := database.WithTx(ctx, &sql.TxOptions{
		Isolation: 0,
		ReadOnly:  true,
	}, func(tx *sql.Tx) error {
		client := (&model.OAuthClient{}).As(`oc`)
		q := database.
			Select(ctx, client).
			From(`oauth2_client oc`).
			Where(`oc.owner_id = ?`, auth.ForContext(ctx).UserID)
		clients = client.Query(ctx, tx, q)
		return nil
	}); err != nil {
		return nil, err
	}
	return clients, nil
}

func (r *queryResolver) OauthClientByID(ctx context.Context, id int) (*model.OAuthClient, error) {
	return loaders.ForContext(ctx).OAuthClientsByID.Load(id)
}

func (r *queryResolver) OauthClientByUUID(ctx context.Context, uuid string) (*model.OAuthClient, error) {
	return loaders.ForContext(ctx).OAuthClientsByUUID.Load(uuid)
}

func (r *queryResolver) OauthGrants(ctx context.Context) ([]*model.OAuthGrant, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *queryResolver) OauthGrant(ctx context.Context, id int) (*model.OAuthGrant, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *queryResolver) PersonalAccessTokens(ctx context.Context) ([]*model.OAuthPersonalToken, error) {
	var tokens []*model.OAuthPersonalToken
	if err := database.WithTx(ctx, &sql.TxOptions{
		Isolation: 0,
		ReadOnly:  true,
	}, func(tx *sql.Tx) error {
		token := (&model.OAuthPersonalToken{}).As(`tok`)
		q := database.
			Select(ctx, token).
			From(`oauth2_grant tok`).
			Where(`tok.user_id = ?
				AND tok.client_id is null
				AND tok.expires > now() at time zone 'utc'`,
				auth.ForContext(ctx).UserID)
		tokens = token.Query(ctx, tx, q)
		return nil
	}); err != nil {
		return nil, err
	}
	return tokens, nil
}

func (r *sSHKeyResolver) User(ctx context.Context, obj *model.SSHKey) (*model.User, error) {
	return loaders.ForContext(ctx).UsersByID.Load(obj.UserID)
}

func (r *userResolver) SSHKeys(ctx context.Context, obj *model.User, cursor *gqlmodel.Cursor) (*model.SSHKeyCursor, error) {
	if cursor == nil {
		cursor = gqlmodel.NewCursor(nil)
	}

	var keys []*model.SSHKey
	if err := database.WithTx(ctx, &sql.TxOptions{
		Isolation: 0,
		ReadOnly:  true,
	}, func(tx *sql.Tx) error {
		key := (&model.SSHKey{}).As(`key`)
		query := database.
			Select(ctx, key).
			From(`sshkey key`).
			Where(`key.user_id = ?`, obj.ID)
		keys, cursor = key.QueryWithCursor(ctx, tx, query, cursor)
		return nil
	}); err != nil {
		return nil, err
	}

	return &model.SSHKeyCursor{keys, cursor}, nil
}

func (r *userResolver) PGPKeys(ctx context.Context, obj *model.User, cursor *gqlmodel.Cursor) (*model.PGPKeyCursor, error) {
	if cursor == nil {
		cursor = gqlmodel.NewCursor(nil)
	}

	var keys []*model.PGPKey
	if err := database.WithTx(ctx, &sql.TxOptions{}, func(tx *sql.Tx) error {
		key := (&model.PGPKey{}).As(`key`)
		query := database.
			Select(ctx, key).
			From(`pgpkey key`).
			Where(`key.user_id = ?`, obj.ID)
		keys, cursor = key.QueryWithCursor(ctx, tx, query, cursor)
		return nil
	}); err != nil {
		return nil, err
	}

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
