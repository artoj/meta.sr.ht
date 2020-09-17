package model

import "fmt"

type OAuthClient struct {
	ID          int     `json:"id"`
	UUID        string  `json:"uuid"`
	RedirectURL string  `json:"redirectUrl"`
	Name        string  `json:"name"`
	Description *string `json:"description"`
	URL         *string `json:"url"`
}

func (oc *OAuthClient) Entity() Entity {
	panic(fmt.Errorf("not implemented")) // TODO
}
