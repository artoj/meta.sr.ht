package model

type ProfileWebhookSubscription struct {
	ID     int            `json:"id"`
	Events []WebhookEvent `json:"events"`
	Query  string         `json:"query"`
	URL    string         `json:"url"`

	UserID int
}

func (ProfileWebhookSubscription) IsWebhookSubscription() {}
