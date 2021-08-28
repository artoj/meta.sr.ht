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
	"net/url"
	"strings"
	"time"

	"git.sr.ht/~sircmpwn/core-go/auth"
	"git.sr.ht/~sircmpwn/core-go/config"
	"git.sr.ht/~sircmpwn/core-go/database"
	coremodel "git.sr.ht/~sircmpwn/core-go/model"
	"git.sr.ht/~sircmpwn/core-go/redis"
	"git.sr.ht/~sircmpwn/core-go/server"
	"git.sr.ht/~sircmpwn/core-go/valid"
	corewebhooks "git.sr.ht/~sircmpwn/core-go/webhooks"
	"git.sr.ht/~sircmpwn/meta.sr.ht/api/graph/api"
	"git.sr.ht/~sircmpwn/meta.sr.ht/api/graph/model"
	"git.sr.ht/~sircmpwn/meta.sr.ht/api/loaders"
	"git.sr.ht/~sircmpwn/meta.sr.ht/api/webhooks"
	sq "github.com/Masterminds/squirrel"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/ssh"
)

func (r *mutationResolver) UpdateUser(ctx context.Context, input map[string]interface{}) (*model.User, error) {
	valid := valid.New(ctx).WithInput(input)

	var address string
	valid.OptionalString("email", func(addr string) {
		address = addr
		valid.
			Expect(len(addr) < 256, "Email address may not exceed 255 characters").
			WithField("email")
		valid.Expect(strings.ContainsRune(addr, '@'),
			"Invalid email address (missing '@')").
			WithField("email")
		// Updating your email requires a separate confirmation step, so we
		// remove it from the input here and process it manually later
		delete(input, "email")
	})
	valid.OptionalString("url", func(u string) {
		valid.
			Expect(len(u) < 256, "URL may not exceed 255 characters").
			WithField("url")
		url, err := url.Parse(u)
		valid.
			Expect(err == nil, "URL does not pass validation").
			WithField("url").
			And(url.Host != "" && (url.Scheme == "http" ||
				url.Scheme == "https" ||
				url.Scheme == "gopher" ||
				url.Scheme == "gemini" ||
				url.Scheme == "finger"),
				"URL must have a host and a permitted scheme").
			WithField("url")
	})
	valid.OptionalString("location", func(location string) {
		valid.
			Expect(len(location) < 256, "Location may not exceed 255 characters").
			WithField("location")
	})
	valid.OptionalString("bio", func(bio string) {
		valid.
			Expect(len(bio) < 4096, "Bio may not exceed 4096 characters").
			WithField("bio")
	})

	if !valid.Ok() {
		return nil, nil
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
				Where(database.WithAlias(user.Alias(), `id`)+"= ?",
					auth.ForContext(ctx).UserID).
				Set(database.WithAlias(user.Alias(), `updated`),
					sq.Expr(`now() at time zone 'utc'`)).
				RunWith(tx).
				ExecContext(ctx)
			if err != nil {
				return err
			}
		}

		if address != "" && address != user.Email {
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
			confHash := base64.URLEncoding.EncodeToString(seed[:])

			_, err = tx.ExecContext(ctx, `UPDATE "user"
				SET new_email = $1, confirmation_hash = $2
				WHERE id = $3;`, address, confHash, user.ID)
			if err != nil {
				return err
			}

			recordAuditLog(ctx, "Email change requested",
				fmt.Sprintf("%s => %s", user.Email, address))
			sendEmailUpdateConfirmation(ctx, user, key, address, confHash)
		}

		return nil
	}); err != nil {
		return nil, err
	}

	if len(input) != 0 {
		webhooks.DeliverProfileUpdate(ctx, user)
		webhooks.DeliverLegacyProfileUpdate(ctx, user)
		recordAuditLog(ctx, "Profile updated", "Profile updated")
	}

	return user, nil
}

func (r *mutationResolver) CreatePGPKey(ctx context.Context, key string) (*model.PGPKey, error) {
	valid := valid.New(ctx)
	keys, err := openpgp.ReadArmoredKeyRing(strings.NewReader(key))
	valid.
		Expect(err == nil, "Invalid PGP key format: %v", err).
		WithField("key").
		And(len(keys) == 1, "Expected one key, found %d", len(keys)).
		WithField("key")
	if !valid.Ok() {
		return nil, nil
	}

	entity := keys[0]
	valid.Expect(entity.PrivateKey == nil, "There's a private key in here, yikes!")

	pkey := entity.PrimaryKey
	valid.Expect(pkey != nil && pkey.CanSign(),
		"No public keys suitable for signing found.")
	if !valid.Ok() {
		return nil, nil
	}

	// TODO: Remove email field
	var email string
	for _, ident := range entity.Identities {
		email = ident.UserId.Email
		break
	}

	normalized := strings.ToUpper(hex.EncodeToString(pkey.Fingerprint[:]))
	fingerprint := ""
	for i := 0; i < len(normalized); i += 4 {
		fingerprint += normalized[i:i+4] + " "
	}
	fingerprint = fingerprint[:len(fingerprint)-1]

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

		// XXX: The key_id field in the database is actually the fingerprint,
		// and formatted weirdly to boot.
		row = tx.QueryRowContext(ctx, `
				INSERT INTO pgpkey (
					created, user_id, key, key_id, email
				) VALUES (
					NOW() at time zone 'utc',
					$1, $2, $3, $4
				) RETURNING id, created;
			`, auth.ForContext(ctx).UserID, key, fingerprint, email)
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
		fmt.Sprintf("PGP key %s added to your account", fingerprint),
		auth.ForContext(ctx).PGPKey)
	recordAuditLog(ctx, "PGP key added", fmt.Sprintf("PGP key %s added", fingerprint))

	mkey := &model.PGPKey{
		ID:          id,
		Created:     created,
		Key:         key,
		Fingerprint: fingerprint,
		UserID:      auth.ForContext(ctx).UserID,

		// Deprecated:
		Email: email,
	}
	webhooks.DeliverPGPKeyEvent(ctx, model.WebhookEventPGPKeyAdded, mkey)
	webhooks.DeliverLegacyPGPKeyAdded(ctx, mkey)
	return mkey, nil
}

func (r *mutationResolver) DeletePGPKey(ctx context.Context, id int) (*model.PGPKey, error) {
	var key model.PGPKey

	if err := database.WithTx(ctx, nil, func(tx *sql.Tx) error {
		var isPreferredKey bool
		row := tx.QueryRowContext(ctx, `
				SELECT (pgp_key_id = $1) IS TRUE
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
				RETURNING id, created, user_id, key, key_id, email;
			`, id, auth.ForContext(ctx).UserID)
		if err := row.Scan(&key.ID, &key.Created,
			&key.UserID, &key.Key, &key.Fingerprint, &key.Email); err != nil {
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
		fmt.Sprintf("PGP key %s removed from your account", key.Fingerprint),
		auth.ForContext(ctx).PGPKey)
	recordAuditLog(ctx, "PGP key removed",
		fmt.Sprintf("PGP key %s removed", key.Fingerprint))
	webhooks.DeliverPGPKeyEvent(ctx, model.WebhookEventPGPKeyRemoved, &key)
	webhooks.DeliverLegacyPGPKeyRemoved(ctx, &key)
	return &key, nil
}

func (r *mutationResolver) CreateSSHKey(ctx context.Context, key string) (*model.SSHKey, error) {
	valid := valid.New(ctx)
	pkey, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(key))
	valid.
		Expect(err == nil, "Invalid SSH key format: %s", err).
		WithField("key")
	if !valid.Ok() {
		return nil, nil
	}

	// TODO: Use SHA-256 fingerprints
	fingerprint := ssh.FingerprintLegacyMD5(pkey)
	fingerprint = strings.ToLower(fingerprint)
	fingerprint = strings.ReplaceAll(fingerprint, ":", "")
	b, err := hex.DecodeString(fingerprint)
	if err != nil {
		return nil, err
	}
	var normalized bytes.Buffer
	for i, _ := range b {
		colon := ":"
		if i+1 == len(b) {
			colon = ""
		}
		normalized.WriteString(fmt.Sprintf("%02x%s", b[i], colon))
	}
	fingerprint = normalized.String()

	var (
		id      int
		created time.Time
	)
	if err := database.WithTx(ctx, nil, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, `
			SELECT id
			FROM sshkey
			WHERE fingerprint = $1
		`, fingerprint)
		if row.Scan() != sql.ErrNoRows {
			return fmt.Errorf("This SSH key is already registered in our system.")
		}

		row = tx.QueryRowContext(ctx, `
			INSERT INTO sshkey (
				created, user_id, key, fingerprint, comment
			) VALUES (
				NOW() at time zone 'utc',
				$1, $2, $3, $4
			) RETURNING id, created;
		`, auth.ForContext(ctx).UserID, key, fingerprint, comment)
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
		fmt.Sprintf("An SSH key was added to your %s account", siteName),
		fmt.Sprintf("SSH key %s added to your account", fingerprint),
		auth.ForContext(ctx).PGPKey)
	recordAuditLog(ctx, "SSH key added",
		fmt.Sprintf("SSH key %s added", fingerprint))

	var c *string
	if comment != "" {
		c = &comment
	}

	mkey := &model.SSHKey{
		ID:          id,
		Created:     created,
		Key:         key,
		Fingerprint: fingerprint,
		Comment:     c,
		UserID:      auth.ForContext(ctx).UserID,
	}
	webhooks.DeliverSSHKeyEvent(ctx, model.WebhookEventSSHKeyAdded, mkey)
	webhooks.DeliverLegacySSHKeyAdded(ctx, mkey)
	return mkey, nil
}

func (r *mutationResolver) DeleteSSHKey(ctx context.Context, id int) (*model.SSHKey, error) {
	var key model.SSHKey

	if err := database.WithTx(ctx, nil, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, `
				DELETE FROM sshkey
				WHERE id = $1 AND user_id = $2
				RETURNING
					id, created, last_used,
					user_id, key, fingerprint,
					comment;
			`, id, auth.ForContext(ctx).UserID)
		if err := row.Scan(&key.ID, &key.Created, &key.LastUsed,
			&key.UserID, &key.Key, &key.Fingerprint, &key.Comment); err != nil {
			return err
		}
		return nil
	}); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("No such SSH key found for the authorized user.")
		}
		return nil, err
	}

	conf := config.ForContext(ctx)
	siteName, ok := conf.Get("sr.ht", "site-name")
	if !ok {
		panic(fmt.Errorf("Expected [sr.ht]site-name in config"))
	}

	sendSecurityNotification(ctx,
		fmt.Sprintf("An SSH key was removed from your %s account", siteName),
		fmt.Sprintf("SSH key %s removed from your account", key.Fingerprint),
		auth.ForContext(ctx).PGPKey)
	recordAuditLog(ctx, "SSH key removed",
		fmt.Sprintf("SSH key %s removed", key.Fingerprint))
	webhooks.DeliverSSHKeyEvent(ctx, model.WebhookEventSSHKeyRemoved, &key)
	webhooks.DeliverLegacySSHKeyRemoved(ctx, &key)
	return &key, nil
}

func (r *mutationResolver) UpdateSSHKey(ctx context.Context, id int) (*model.SSHKey, error) {
	var key model.SSHKey
	if err := database.WithTx(ctx, nil, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, `
				UPDATE sshkey
				SET created = NOW() at time zone 'utc'
				WHERE id = $1 AND user_id = $2
				RETURNING
					id, created, last_used,
					user_id, key, fingerprint,
					comment;
			`, id, auth.ForContext(ctx).UserID)
		if err := row.Scan(&key.ID, &key.Created, &key.LastUsed,
			&key.UserID, &key.Key, &key.Fingerprint, &key.Comment); err != nil {
			return err
		}
		return nil
	}); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("No such SSH key found for the authorized user.")
		}
		return nil, err
	}
	// XXX: Should we send out webhooks for this?
	return &key, nil
}

func (r *mutationResolver) CreateWebhook(ctx context.Context, config model.ProfileWebhookInput) (model.WebhookSubscription, error) {
	schema := server.ForContext(ctx).Schema
	if err := corewebhooks.Validate(schema, config.Query); err != nil {
		return nil, err
	}

	user := auth.ForContext(ctx)
	ac, err := corewebhooks.NewAuthConfig(ctx)
	if err != nil {
		return nil, err
	}

	var sub model.ProfileWebhookSubscription
	if len(config.Events) == 0 {
		return nil, fmt.Errorf("Must specify at least one event")
	}
	events := make([]string, len(config.Events))
	for i, ev := range config.Events {
		events[i] = ev.String()
		// TODO: gqlgen does not support doing anything useful with directives
		// on enums at the time of writing, so we have to do a little bit of
		// manual fuckery
		var access string
		switch ev {
		case model.WebhookEventProfileUpdate:
			access = "PROFILE"
		case model.WebhookEventPGPKeyAdded, model.WebhookEventPGPKeyRemoved:
			access = "PGP_KEYS"
		case model.WebhookEventSSHKeyAdded, model.WebhookEventSSHKeyRemoved:
			access = "SSH_KEYS"
		}
		if !user.Grants.Has(access, auth.RO) {
			return nil, fmt.Errorf("Insufficient access granted for webhook event %s", ev.String())
		}
	}

	u, err := url.Parse(config.URL)
	if err != nil {
		return nil, err
	} else if u.Host == "" {
		return nil, fmt.Errorf("Cannot use URL without host")
	} else if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("Cannot use non-HTTP or HTTPS URL")
	}

	if err := database.WithTx(ctx, nil, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, `
			INSERT INTO gql_profile_wh_sub (
				created, events, url, query,
				auth_method,
				token_hash, grants, client_id, expires,
				node_id,
				user_id
			) VALUES (
				NOW() at time zone 'utc',
				$1, $2, $3, $4, $5, $6, $7, $8, $9, $10
			) RETURNING id, url, query, events, user_id;`,
			pq.Array(events), config.URL, config.Query,
			ac.AuthMethod,
			ac.TokenHash, ac.Grants, ac.ClientID, ac.Expires, // OAUTH2
			ac.NodeID,                                        // INTERNAL
			user.UserID)

		if err := row.Scan(&sub.ID, &sub.URL,
			&sub.Query, pq.Array(&sub.Events), &sub.UserID); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return &sub, nil
}

func (r *mutationResolver) DeleteWebhook(ctx context.Context, id int) (model.WebhookSubscription, error) {
	var sub model.ProfileWebhookSubscription

	filter, err := filterWebhooks(ctx)
	if err != nil {
		return nil, err
	}

	if err := database.WithTx(ctx, nil, func(tx *sql.Tx) error {
		row := sq.Delete(`gql_profile_wh_sub`).
			PlaceholderFormat(sq.Dollar).
			Where(sq.And{sq.Expr(`id = ?`, id), filter}).
			Suffix(`RETURNING id, url, query, events, user_id`).
			RunWith(tx).
			QueryRowContext(ctx)
		if err := row.Scan(&sub.ID, &sub.URL,
			&sub.Query, pq.Array(&sub.Events), &sub.UserID); err != nil {
			return err
		}
		return nil
	}); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return &sub, nil
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

	recordAuditLog(ctx, "OAuth 2.0 client registered", clientID.String())

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

func (r *mutationResolver) RevokeOAuthClient(ctx context.Context, uuid string) (*model.OAuthClient, error) {
	var oc model.OAuthClient
	if err := database.WithTx(ctx, nil, func(tx *sql.Tx) error {
		user := auth.ForContext(ctx)
		uid := user.UserID
		if user.UserType == auth.USER_ADMIN {
			uid = -1
		}
		row := tx.QueryRowContext(ctx, `
			UPDATE oauth2_client
			SET revoked = true
			WHERE client_uuid = $1
				-- Admins can revoke any token:
				AND CASE WHEN $2 = -1 THEN true ELSE owner_id = $2 END
			RETURNING
				id, client_uuid, redirect_url,
				client_name, client_description, client_url,
				owner_id;
		`, uuid, uid)
		if err := row.Scan(&oc.ID, &oc.UUID, &oc.RedirectURL, &oc.Name,
			&oc.Description, &oc.URL, &oc.OwnerID); err != nil {
			return err
		}

		row = tx.QueryRowContext(ctx, `
			UPDATE oauth2_grant
			SET expires = now() at time zone 'utc'
			WHERE client_id = $1;
		`, oc.ID)

		if err := row.Scan(); err != nil && err != sql.ErrNoRows {
			return err
		}

		return nil
	}); err != nil {
		return nil, err
	}

	recordAuditLog(ctx, "OAuth 2.0 client revoked", oc.UUID)

	rc := redis.ForContext(ctx)
	key := fmt.Sprintf("meta.sr.ht::oauth2::client_revocations::%s", uuid)
	err := rc.Set(ctx, key, true, time.Duration(0)).Err()
	return &oc, err
}

func (r *mutationResolver) RevokeOAuthGrant(ctx context.Context, hash string) (*model.OAuthGrant, error) {
	var grant model.OAuthGrant
	if err := database.WithTx(ctx, nil, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, `
			UPDATE oauth2_grant
			SET expires = now() at time zone 'utc'
			WHERE token_hash = $1
			RETURNING id, issued, expires, token_hash, client_id;
		`, hash)
		if err := row.Scan(&grant.ID, &grant.Issued, &grant.Expires,
			&grant.TokenHash, &grant.ClientID); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return nil, err
	}

	rc := redis.ForContext(ctx)
	err := rc.Set(ctx,
		fmt.Sprintf("meta.sr.ht::oauth2::grant_revocations::%s", hash),
		true, grant.Expires.Sub(time.Now().UTC())).Err()
	if err != nil {
		return nil, err
	}

	recordAuditLog(ctx, "OAuth 2.0 grant revoked", "OAuth 2.0 grant revoked")

	return &grant, nil
}

func (r *mutationResolver) IssuePersonalAccessToken(ctx context.Context, grants *string, comment *string) (*model.OAuthPersonalTokenRegistration, error) {
	issued := time.Now().UTC()
	expires := issued.Add(366 * 24 * time.Hour)

	user := auth.ForContext(ctx)
	grant := auth.BearerToken{
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

	recordAuditLog(ctx, "OAuth 2.0 token issued", "OAuth 2.0 token issued")

	conf := config.ForContext(ctx)
	siteName, ok := conf.Get("sr.ht", "site-name")
	if !ok {
		panic(fmt.Errorf("Expected [sr.ht]site-name in config"))
	}
	sendSecurityNotification(ctx,
		fmt.Sprintf("A personal access token was issued for your %s account", siteName),
		"An OAuth 2.0 personal access token was issued for your account",
		auth.ForContext(ctx).PGPKey)

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
		user := auth.ForContext(ctx)
		uid := user.UserID
		if user.UserType == auth.USER_ADMIN {
			uid = -1
		}
		row := tx.QueryRowContext(ctx, `
			UPDATE oauth2_grant
			SET expires = now() at time zone 'utc'
			WHERE id = $1 AND client_id is null
				-- Admins can revoke any token:
				AND CASE WHEN $2 = -1 THEN true ELSE user_id = $2 END
			RETURNING id, issued, expires, comment, token_hash;
		`, id, uid)

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

	recordAuditLog(ctx, "OAuth 2.0 token revoked", "OAuth 2.0 token revoked")

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

	grant := auth.BearerToken{
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

	recordAuditLog(ctx, "OAuth 2.0 access grant issued",
		fmt.Sprintf("%s (%s)", client.Name, client.UUID))

	conf := config.ForContext(ctx)
	siteName, ok := conf.Get("sr.ht", "site-name")
	if !ok {
		panic(fmt.Errorf("Expected [sr.ht]site-name in config"))
	}
	sendSecurityNotification(ctx,
		fmt.Sprintf("A third party has been granted access to your %s account", siteName),
		fmt.Sprintf("An OAuth 2.0 bearer grant for your account was issued to %s", client.Name),
		auth.ForContext(ctx).PGPKey)

	return &model.OAuthGrantRegistration{
		Grant: &model.OAuthGrant{
			ID:      id,
			Issued:  issued,
			Expires: expires,

			ClientID: client.ID,
		},
		Grants: payload.Grants,
		Secret: token,
	}, nil
}

func (r *oAuthClientResolver) Owner(ctx context.Context, obj *model.OAuthClient) (model.Entity, error) {
	return loaders.ForContext(ctx).UsersByID.Load(obj.OwnerID)
}

func (r *oAuthGrantResolver) Client(ctx context.Context, obj *model.OAuthGrant) (*model.OAuthClient, error) {
	return loaders.ForContext(ctx).OAuthClientsByID.Load(obj.ClientID)
}

func (r *pGPKeyResolver) User(ctx context.Context, obj *model.PGPKey) (*model.User, error) {
	return loaders.ForContext(ctx).UsersByID.Load(obj.UserID)
}

func (r *profileWebhookSubscriptionResolver) Client(ctx context.Context, obj *model.ProfileWebhookSubscription) (*model.OAuthClient, error) {
	if obj.ClientID == nil {
		return nil, nil
	}
	return loaders.ForContext(ctx).OAuthClientsByUUID.Load(*obj.ClientID)
}

func (r *profileWebhookSubscriptionResolver) Deliveries(ctx context.Context, obj *model.ProfileWebhookSubscription, cursor *coremodel.Cursor) (*model.WebhookDeliveryCursor, error) {
	if cursor == nil {
		cursor = coremodel.NewCursor(nil)
	}

	var deliveries []*model.WebhookDelivery
	if err := database.WithTx(ctx, &sql.TxOptions{
		Isolation: 0,
		ReadOnly:  true,
	}, func(tx *sql.Tx) error {
		d := (&model.WebhookDelivery{}).
			WithName(`profile`).
			As(`delivery`)
		query := database.
			Select(ctx, d).
			From(`gql_profile_wh_delivery delivery`).
			Where(`delivery.subscription_id = ?`, obj.ID)
		deliveries, cursor = d.QueryWithCursor(ctx, tx, query, cursor)
		return nil
	}); err != nil {
		return nil, err
	}

	return &model.WebhookDeliveryCursor{deliveries, cursor}, nil
}

func (r *profileWebhookSubscriptionResolver) Sample(ctx context.Context, obj *model.ProfileWebhookSubscription, event *model.WebhookEvent) (string, error) {
	payloadUUID := uuid.New()
	webhook := corewebhooks.WebhookContext{
		User:        auth.ForContext(ctx),
		PayloadUUID: payloadUUID,
		Name:        "profile",
		Event:       event.String(),
		Subscription: &corewebhooks.WebhookSubscription{
			ID:         obj.ID,
			URL:        obj.URL,
			Query:      obj.Query,
			AuthMethod: obj.AuthMethod,
			TokenHash:  obj.TokenHash,
			Grants:     obj.Grants,
			ClientID:   obj.ClientID,
			Expires:    obj.Expires,
			NodeID:     obj.NodeID,
		},
	}

	const samplePGPKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----

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
Ha7hATdH2NIVQnjQvRoHAvq3eaS1+w==
=R7Pf
-----END PGP PUBLIC KEY BLOCK-----`

	auth := auth.ForContext(ctx)
	switch *event {
	case model.WebhookEventProfileUpdate:
		webhook.Payload = &model.ProfileUpdateEvent{
			UUID:  payloadUUID.String(),
			Event: *event,
			Date:  time.Now().UTC(),
			Profile: &model.User{
				ID:       auth.UserID,
				Created:  auth.Created,
				Updated:  auth.Updated,
				Username: auth.Username,
				Email:    auth.Email,
				URL:      auth.URL,
				Location: auth.Location,
				Bio:      auth.Bio,

				UserTypeRaw: auth.UserType,
			},
		}
	case model.WebhookEventPGPKeyAdded, model.WebhookEventPGPKeyRemoved:
		webhook.Payload = &model.PGPKeyEvent{
			UUID:  payloadUUID.String(),
			Event: *event,
			Date:  time.Now().UTC(),
			Key: &model.PGPKey{
				ID:          -1,
				Created:     time.Now().UTC(),
				Key:         samplePGPKey,
				Fingerprint: "44290A3CA573126D4FCB8B4DBFB0D5A69FC5DEF7",
				UserID:      auth.UserID,
			},
		}
	case model.WebhookEventSSHKeyAdded, model.WebhookEventSSHKeyRemoved:
		// TODO: Use SHA256 fingerprints
		webhook.Payload = &model.SSHKeyEvent{
			UUID:  payloadUUID.String(),
			Event: *event,
			Date:  time.Now().UTC(),
			Key: &model.SSHKey{
				ID:          -1,
				Created:     time.Now().UTC(),
				LastUsed:    nil,
				Key:         "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILrSCnjCMOrM/iHrHgsjOHS/Y/7ewwYuDykTvAuELJzJ sample@key",
				Fingerprint: "31:7b:13:10:3b:e5:4c:a3:a8:16:38:e0:c9:a6:7e:4a",
				UserID:      auth.UserID,
			},
		}
	default:
		panic(fmt.Errorf("not implemented"))
	}

	subctx := corewebhooks.Context(ctx, webhook.Payload)
	bytes, err := webhook.Exec(subctx, server.ForContext(ctx).Schema)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
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

func (r *queryResolver) Invoices(ctx context.Context, cursor *coremodel.Cursor) (*model.InvoiceCursor, error) {
	if cursor == nil {
		cursor = coremodel.NewCursor(nil)
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

func (r *queryResolver) AuditLog(ctx context.Context, cursor *coremodel.Cursor) (*model.AuditLogCursor, error) {
	if cursor == nil {
		cursor = coremodel.NewCursor(nil)
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

func (r *queryResolver) ProfileWebhooks(ctx context.Context, cursor *coremodel.Cursor) (*model.WebhookSubscriptionCursor, error) {
	if cursor == nil {
		cursor = coremodel.NewCursor(nil)
	}

	filter, err := filterWebhooks(ctx)
	if err != nil {
		return nil, err
	}

	var subs []model.WebhookSubscription
	if err := database.WithTx(ctx, &sql.TxOptions{
		Isolation: 0,
		ReadOnly:  true,
	}, func(tx *sql.Tx) error {
		sub := (&model.ProfileWebhookSubscription{}).As(`sub`)
		query := database.
			Select(ctx, sub).
			From(`gql_profile_wh_sub sub`).
			Where(filter)
		subs, cursor = sub.QueryWithCursor(ctx, tx, query, cursor)
		return nil
	}); err != nil {
		return nil, err
	}

	return &model.WebhookSubscriptionCursor{subs, cursor}, nil
}

func (r *queryResolver) ProfileWebhook(ctx context.Context, id int) (model.WebhookSubscription, error) {
	var sub model.ProfileWebhookSubscription

	filter, err := filterWebhooks(ctx)
	if err != nil {
		return nil, err
	}

	if err := database.WithTx(ctx, &sql.TxOptions{
		Isolation: 0,
		ReadOnly:  true,
	}, func(tx *sql.Tx) error {
		row := database.
			Select(ctx, &sub).
			From(`gql_profile_wh_sub`).
			Where(sq.And{sq.Expr(`id = ?`, id), filter}).
			RunWith(tx).
			QueryRowContext(ctx)
		if err := row.Scan(database.Scan(ctx, &sub)...); err != nil {
			return err
		}
		return nil
	}); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return &sub, nil
}

func (r *queryResolver) Webhook(ctx context.Context) (model.WebhookPayload, error) {
	raw, err := corewebhooks.Payload(ctx)
	if err != nil {
		return nil, err
	}
	payload, ok := raw.(model.WebhookPayload)
	if !ok {
		panic("Invalid webhook payload context")
	}
	return payload, nil
}

func (r *queryResolver) OauthGrants(ctx context.Context) ([]*model.OAuthGrant, error) {
	var grants []*model.OAuthGrant
	if err := database.WithTx(ctx, &sql.TxOptions{
		Isolation: 0,
		ReadOnly:  true,
	}, func(tx *sql.Tx) error {
		grant := (&model.OAuthGrant{}).As(`grant`)
		q := database.
			Select(ctx, grant).
			From(`oauth2_grant "grant"`).
			Where(`"grant".user_id = ?
				AND "grant".client_id is not null
				AND "grant".expires > now() at time zone 'utc'`,
				auth.ForContext(ctx).UserID)
		grants = grant.Query(ctx, tx, q)
		return nil
	}); err != nil {
		return nil, err
	}
	return grants, nil
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
			Where(`oc.owner_id = ?`, auth.ForContext(ctx).UserID).
			Where(`oc.revoked = false`)
		clients = client.Query(ctx, tx, q)
		return nil
	}); err != nil {
		return nil, err
	}
	return clients, nil
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

func (r *queryResolver) OauthClientByID(ctx context.Context, id int) (*model.OAuthClient, error) {
	return loaders.ForContext(ctx).OAuthClientsByID.Load(id)
}

func (r *queryResolver) OauthClientByUUID(ctx context.Context, uuid string) (*model.OAuthClient, error) {
	return loaders.ForContext(ctx).OAuthClientsByUUID.Load(uuid)
}

func (r *queryResolver) TokenRevocationStatus(ctx context.Context, hash string, clientID *string) (bool, error) {
	rc := redis.ForContext(ctx)

	keys := []string{
		fmt.Sprintf("meta.sr.ht::oauth2::grant_revocations::%s", hash),
	}

	if clientID != nil {
		keys = append(keys, fmt.Sprintf(
			"meta.sr.ht::oauth2::client_revocations::%s", *clientID))
	}

	if n, err := rc.Exists(ctx, keys...).Result(); err != nil {
		return true, err
	} else if n != 0 {
		return true, nil
	} else {
		return false, nil
	}
}

func (r *sSHKeyResolver) User(ctx context.Context, obj *model.SSHKey) (*model.User, error) {
	return loaders.ForContext(ctx).UsersByID.Load(obj.UserID)
}

func (r *userResolver) SSHKeys(ctx context.Context, obj *model.User, cursor *coremodel.Cursor) (*model.SSHKeyCursor, error) {
	if cursor == nil {
		cursor = coremodel.NewCursor(nil)
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

func (r *userResolver) PGPKeys(ctx context.Context, obj *model.User, cursor *coremodel.Cursor) (*model.PGPKeyCursor, error) {
	if cursor == nil {
		cursor = coremodel.NewCursor(nil)
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

func (r *webhookDeliveryResolver) Subscription(ctx context.Context, obj *model.WebhookDelivery) (model.WebhookSubscription, error) {
	if obj.Name == "" {
		panic("WebhookDelivery without name")
	}

	// XXX: This could use a loader but it's unlikely to be a bottleneck
	var sub model.WebhookSubscription
	if err := database.WithTx(ctx, &sql.TxOptions{
		Isolation: 0,
		ReadOnly:  true,
	}, func(tx *sql.Tx) error {
		// XXX: This needs some work to generalize to other kinds of webhooks
		profile := (&model.ProfileWebhookSubscription{}).As(`sub`)
		// Note: No filter needed because, if we have access to the delivery,
		// we also have access to the subscription.
		row := database.
			Select(ctx, profile).
			From(`gql_profile_wh_sub sub`).
			Where(`sub.id = ?`, obj.SubscriptionID).
			RunWith(tx).
			QueryRowContext(ctx)
		if err := row.Scan(database.Scan(ctx, profile)...); err != nil {
			return err
		}
		sub = profile
		return nil
	}); err != nil {
		return nil, err
	}
	return sub, nil
}

// Mutation returns api.MutationResolver implementation.
func (r *Resolver) Mutation() api.MutationResolver { return &mutationResolver{r} }

// OAuthClient returns api.OAuthClientResolver implementation.
func (r *Resolver) OAuthClient() api.OAuthClientResolver { return &oAuthClientResolver{r} }

// OAuthGrant returns api.OAuthGrantResolver implementation.
func (r *Resolver) OAuthGrant() api.OAuthGrantResolver { return &oAuthGrantResolver{r} }

// PGPKey returns api.PGPKeyResolver implementation.
func (r *Resolver) PGPKey() api.PGPKeyResolver { return &pGPKeyResolver{r} }

// ProfileWebhookSubscription returns api.ProfileWebhookSubscriptionResolver implementation.
func (r *Resolver) ProfileWebhookSubscription() api.ProfileWebhookSubscriptionResolver {
	return &profileWebhookSubscriptionResolver{r}
}

// Query returns api.QueryResolver implementation.
func (r *Resolver) Query() api.QueryResolver { return &queryResolver{r} }

// SSHKey returns api.SSHKeyResolver implementation.
func (r *Resolver) SSHKey() api.SSHKeyResolver { return &sSHKeyResolver{r} }

// User returns api.UserResolver implementation.
func (r *Resolver) User() api.UserResolver { return &userResolver{r} }

// WebhookDelivery returns api.WebhookDeliveryResolver implementation.
func (r *Resolver) WebhookDelivery() api.WebhookDeliveryResolver { return &webhookDeliveryResolver{r} }

type mutationResolver struct{ *Resolver }
type oAuthClientResolver struct{ *Resolver }
type oAuthGrantResolver struct{ *Resolver }
type pGPKeyResolver struct{ *Resolver }
type profileWebhookSubscriptionResolver struct{ *Resolver }
type queryResolver struct{ *Resolver }
type sSHKeyResolver struct{ *Resolver }
type userResolver struct{ *Resolver }
type webhookDeliveryResolver struct{ *Resolver }
