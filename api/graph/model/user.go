package model

import (
	"context"
	"fmt"
	"time"

	"git.sr.ht/~sircmpwn/gql.sr.ht/database"
)

type User struct {
	ID               int       `json:"id"`
	Created          time.Time `json:"created"`
	Updated          time.Time `json:"updated"`
	Username         string    `json:"username"`
	Email            string    `json:"email"`
	URL              *string   `json:"url"`
	Location         *string   `json:"location"`
	Bio              *string   `json:"bio"`
	SuspensionNotice *string   `json:"suspensionNotice"`

	UserTypeRaw string

	alias string
}

func (User) IsEntity() {}

func (u *User) CanonicalName() string {
	return "~" + u.Username
}

func (u *User) UserType() UserType {
	switch u.UserTypeRaw {
	case "unconfirmed":
		return UserTypeUnconfirmed
	case "active_non_paying":
		return UserTypeActiveNonPaying
	case "active_free":
		return UserTypeActiveFree
	case "active_paying":
		return UserTypeActivePaying
	case "active_delinquent":
		return UserTypeActiveDelinquent
	case "admin":
		return UserTypeAdmin
	case "suspended":
		return UserTypeSuspended
	}
	panic(fmt.Errorf("Unknown user type '%s'", u.UserTypeRaw))
}

func (u *User) As(alias string) *User {
	u.alias = alias
	return u
}

func (u *User) Select(ctx context.Context) []string {
	cols := database.ColumnsFor(ctx, u.alias, map[string]string{
		"id":               "id",
		"created":          "created",
		"updated":          "updated",
		"username":         "username",
		"email":            "email",
		"url":              "url",
		"location":         "location",
		"bio":              "bio",
		"userType":         "user_type",
		"suspensionNotice": "suspension_notice",
	})
	return append(cols,
		database.WithAlias(u.alias, "id"),
		database.WithAlias(u.alias, "username"))
}

func (u *User) Fields(ctx context.Context) []interface{} {
	fields := database.FieldsFor(ctx, map[string]interface{}{
		"id":               &u.ID,
		"created":          &u.Created,
		"updated":          &u.Updated,
		"username":         &u.Username,
		"email":            &u.Email,
		"url":              &u.URL,
		"location":         &u.Location,
		"bio":              &u.Bio,
		"userType":         &u.UserTypeRaw,
		"suspensionNotice": &u.SuspensionNotice,
	})
	return append(fields, &u.ID, &u.Username)
}
