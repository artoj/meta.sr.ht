package webhooks

import (
	"context"
	"log"
	"time"

	"git.sr.ht/~sircmpwn/core-go/webhooks"
	"github.com/google/uuid"
	sq "github.com/Masterminds/squirrel"

	"git.sr.ht/~sircmpwn/meta.sr.ht/api/graph/model"
)

func DeliverProfileUpdate(ctx context.Context, user *model.User) {
	q, ok := ctx.Value(profileWebhooksCtxKey).(*webhooks.WebhookQueue)
	if !ok {
		log.Fatalf("No webhooks worker for this context")
	}
	payloadUUID := uuid.New()
	payload := model.ProfileUpdateEvent{
		UUID:    payloadUUID.String(),
		Event:   model.WebhookEventProfileUpdate,
		Date:    time.Now().UTC(),
		Profile: user,
	}
	query := sq.
		Select().
		From("gql_profile_wh_sub sub").
		Where("sub.user_id = ?", user.ID)
	q.Schedule(ctx, query, "profile",
		model.WebhookEventProfileUpdate.String(),
		payloadUUID, &payload)
}
