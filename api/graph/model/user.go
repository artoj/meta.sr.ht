package model

import (
	"fmt"
	"time"

	"git.sr.ht/~sircmpwn/core-go/database"
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

	alias  string
	fields *database.ModelFields
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

func (u *User) Alias() string {
	return u.alias
}

func (u *User) Table() string {
	return `"user"`
}

func (u *User) Fields() *database.ModelFields {
	if u.fields != nil {
		return u.fields
	}
	u.fields = &database.ModelFields{
		Fields: []*database.FieldMap{
			{ "id", "id", &u.ID },
			{ "created", "created", &u.Created },
			{ "updated", "updated", &u.Updated },
			{ "username", "username", &u.Username },
			{ "email", "email", &u.Email },
			{ "url", "url", &u.URL },
			{ "location", "location", &u.Location },
			{ "bio", "bio", &u.Bio },
			{ "user_type", "userType", &u.UserTypeRaw },
			{ "suspension_notice", "suspensionNotice", &u.SuspensionNotice },

			// Always fetch:
			{ "id", "", &u.ID },
			{ "username", "", &u.Username },
		},
	}
	return u.fields
}
