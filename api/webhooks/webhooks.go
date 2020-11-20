package webhooks

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"git.sr.ht/~sircmpwn/core-go/auth"
	"git.sr.ht/~sircmpwn/core-go/database"
	"git.sr.ht/~sircmpwn/core-go/webhooks"
	sq "github.com/Masterminds/squirrel"

	"git.sr.ht/~sircmpwn/meta.sr.ht/api/graph/model"
)

func NewLegacyQueue() *webhooks.LegacyQueue {
	return webhooks.NewLegacyQueue()
}

var legacyUserCtxKey = &contextKey{"legacyUser"}

type contextKey struct {
	name string
}

func LegacyMiddleware(
	queue *webhooks.LegacyQueue) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), legacyUserCtxKey, queue)
			r = r.WithContext(ctx)
			next.ServeHTTP(w, r)
		})
	}
}

func DeliverLegacyProfileUpdate(ctx context.Context, user *model.User) {
	// Note: this webhook payload is different for preauthorized (first-party)
	// clients and non-preauthorized (third-party) clients.
	//
	// This legacy garbage is due to be removed at our earliest convenience.
	q, ok := ctx.Value(legacyUserCtxKey).(*webhooks.LegacyQueue)
	if !ok {
		panic(errors.New("No legacy user webhooks worker for this context"))
	}

	type WebhookPayload struct {
		CanonicalName string  `json:"canonical_name"`
		Name          string  `json:"name"`
		Email         string  `json:"email"`
		URL           *string `json:"url"`
		Location      *string `json:"location"`
		Bio           *string `json:"bio"`
		UsePGPKey     *string `json:"use_pgp_key"`

		// Private clients only
		UserType         string  `json:"user_type",omit-empty`
		SuspensionNotice *string `json:"suspension_notice",omit-empty`
	}

	// XXX: Technically we could do the PGP key lookup in a single SQL query if
	// we had a more sophisticated database system (particularly if we had lazy
	// loading queries)
	var keyID *string
	if err := database.WithTx(ctx, &sql.TxOptions{
		Isolation: 1,
		ReadOnly: true,
	}, func(tx *sql.Tx) error {
		return sq.
			Select("p.key_id").
			From(`"user" u`).
			LeftJoin(`pgpkey p ON p.id = u.pgp_key_id`).
			Where("u.id = ?", user.ID).
			PlaceholderFormat(sq.Dollar).
			RunWith(tx).
			ScanContext(ctx, &keyID)
	}); err != nil {
		panic(err)
	}

	payload := WebhookPayload{
		CanonicalName: user.CanonicalName(),
		Name:          user.Username,
		Email:         user.Email,
		URL:           user.URL,
		Location:      user.Location,
		Bio:           user.Bio,
		UsePGPKey:     keyID,
		// user_type & suspension_notice omitted
	}
	publicPayload, err := json.Marshal(&payload)
	if err != nil {
		panic(err) // Programmer error
	}
	payload.UserType = user.UserTypeRaw
	payload.SuspensionNotice = user.SuspensionNotice
	internalPayload, err := json.Marshal(&payload)
	if err != nil {
		panic(err) // Programmer error
	}

	// Third-party clients
	query := sq.
		Select().
		From("user_webhook_subscription sub").
		Join("oauthtoken ot ON sub.token_id = ot.id").
		LeftJoin("oauthclient oc ON ot.client_id = oc.id").
		Where("sub.user_id = ?", user.ID).
		Where("(oc IS NULL OR NOT oc.preauthorized)")
	q.Schedule(query, "user", "profile:update", publicPayload)

	// First-party clients
	query = sq.
		Select().
		From("user_webhook_subscription sub").
		Join("oauthtoken ot ON sub.token_id = ot.id").
		Join("oauthclient oc ON ot.client_id = oc.id").
		Where("sub.user_id = ?", user.ID).
		Where("oc.preauthorized")
	q.Schedule(query, "user", "profile:update", internalPayload)
}

func DeliverLegacyPGPKeyAdded(ctx context.Context, key *model.PGPKey) {
	q, ok := ctx.Value(legacyUserCtxKey).(*webhooks.LegacyQueue)
	if !ok {
		panic(errors.New("No legacy user webhooks worker for this context"))
	}

	type WebhookPayload struct {
		ID         int       `json:"id"`
		Key        string    `json:"key"`
		KeyID      string    `json:"key_id"`
		Email      string    `json:"email"`
		Authorized time.Time `json:"authorized"`

		Owner struct {
			CanonicalName string  `json:"canonical_name"`
			Name          string  `json:"name"`
		}`json:"owner"`
	}

	payload := WebhookPayload{
		ID:         key.ID,
		Key:        key.Key,
		KeyID:      key.Fingerprint,
		Authorized: key.Created,
		Email:      key.Email,
	}

	// TODO: User groups
	user := auth.ForContext(ctx)
	if user.UserID != key.UserID {
		// At the time of writing, the only consumers of this function are in a
		// context where the authenticated user is the owner of this PGP key. We
		// can skip the database round-trip if we just grab their auth context.
		panic(errors.New("TODO: look up user details for this key"))
	}
	payload.Owner.CanonicalName = "~" + user.Username
	payload.Owner.Name = user.Username

	encoded, err := json.Marshal(&payload)
	if err != nil {
		panic(err) // Programmer error
	}

	query := sq.
		Select().
		From("user_webhook_subscription sub").
		Where("sub.user_id = ?", key.UserID)
	q.Schedule(query, "user", "pgp-key:add", encoded)
}

func DeliverLegacyPGPKeyRemoved(ctx context.Context, key *model.PGPKey) {
	q, ok := ctx.Value(legacyUserCtxKey).(*webhooks.LegacyQueue)
	if !ok {
		panic(errors.New("No legacy user webhooks worker for this context"))
	}

	type WebhookPayload struct {
		ID int `json:"id"`
	}
	payload := WebhookPayload{key.ID}

	encoded, err := json.Marshal(&payload)
	if err != nil {
		panic(err) // Programmer error
	}

	query := sq.
		Select().
		From("user_webhook_subscription sub").
		Where("sub.user_id = ?", key.UserID)
	q.Schedule(query, "user", "pgp-key:remove", encoded)
}
