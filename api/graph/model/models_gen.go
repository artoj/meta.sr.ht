// Code generated by github.com/99designs/gqlgen, DO NOT EDIT.

package model

import (
	"fmt"
	"io"
	"strconv"
	"time"

	"git.sr.ht/~sircmpwn/gql.sr.ht/model"
)

type Entity interface {
	IsEntity()
}

type AuditLogCursor struct {
	Results []*AuditLogEntry `json:"results"`
	Cursor  *model.Cursor    `json:"cursor"`
}

type InvoiceCursor struct {
	Results []*Invoice    `json:"results"`
	Cursor  *model.Cursor `json:"cursor"`
}

type OAuthClientRegistration struct {
	Client *OAuthClient `json:"client"`
	Secret string       `json:"secret"`
}

type OAuthGrant struct {
	ID      int          `json:"id"`
	Client  *OAuthClient `json:"client"`
	Issued  time.Time    `json:"issued"`
	Expires time.Time    `json:"expires"`
}

type OAuthGrantRegistration struct {
	Grant  *OAuthGrant `json:"grant"`
	Secret string      `json:"secret"`
}

type OAuthPersonalTokenRegistration struct {
	Token  *OAuthPersonalToken `json:"token"`
	Secret string              `json:"secret"`
}

type PGPKeyCursor struct {
	Results []*PGPKey     `json:"results"`
	Cursor  *model.Cursor `json:"cursor"`
}

type SSHKeyCursor struct {
	Results []*SSHKey     `json:"results"`
	Cursor  *model.Cursor `json:"cursor"`
}

type Version struct {
	Major           int        `json:"major"`
	Minor           int        `json:"minor"`
	Patch           int        `json:"patch"`
	DeprecationDate *time.Time `json:"deprecationDate"`
}

type AccessKind string

const (
	AccessKindRo AccessKind = "RO"
	AccessKindRw AccessKind = "RW"
)

var AllAccessKind = []AccessKind{
	AccessKindRo,
	AccessKindRw,
}

func (e AccessKind) IsValid() bool {
	switch e {
	case AccessKindRo, AccessKindRw:
		return true
	}
	return false
}

func (e AccessKind) String() string {
	return string(e)
}

func (e *AccessKind) UnmarshalGQL(v interface{}) error {
	str, ok := v.(string)
	if !ok {
		return fmt.Errorf("enums must be strings")
	}

	*e = AccessKind(str)
	if !e.IsValid() {
		return fmt.Errorf("%s is not a valid AccessKind", str)
	}
	return nil
}

func (e AccessKind) MarshalGQL(w io.Writer) {
	fmt.Fprint(w, strconv.Quote(e.String()))
}

type AccessScope string

const (
	AccessScopeAuditLog AccessScope = "AUDIT_LOG"
	AccessScopeBilling  AccessScope = "BILLING"
	AccessScopePGPKeys  AccessScope = "PGP_KEYS"
	AccessScopeSSHKeys  AccessScope = "SSH_KEYS"
	AccessScopeProfile  AccessScope = "PROFILE"
)

var AllAccessScope = []AccessScope{
	AccessScopeAuditLog,
	AccessScopeBilling,
	AccessScopePGPKeys,
	AccessScopeSSHKeys,
	AccessScopeProfile,
}

func (e AccessScope) IsValid() bool {
	switch e {
	case AccessScopeAuditLog, AccessScopeBilling, AccessScopePGPKeys, AccessScopeSSHKeys, AccessScopeProfile:
		return true
	}
	return false
}

func (e AccessScope) String() string {
	return string(e)
}

func (e *AccessScope) UnmarshalGQL(v interface{}) error {
	str, ok := v.(string)
	if !ok {
		return fmt.Errorf("enums must be strings")
	}

	*e = AccessScope(str)
	if !e.IsValid() {
		return fmt.Errorf("%s is not a valid AccessScope", str)
	}
	return nil
}

func (e AccessScope) MarshalGQL(w io.Writer) {
	fmt.Fprint(w, strconv.Quote(e.String()))
}

type UserType string

const (
	UserTypeUnconfirmed      UserType = "UNCONFIRMED"
	UserTypeActiveNonPaying  UserType = "ACTIVE_NON_PAYING"
	UserTypeActiveFree       UserType = "ACTIVE_FREE"
	UserTypeActivePaying     UserType = "ACTIVE_PAYING"
	UserTypeActiveDelinquent UserType = "ACTIVE_DELINQUENT"
	UserTypeAdmin            UserType = "ADMIN"
	UserTypeSuspended        UserType = "SUSPENDED"
)

var AllUserType = []UserType{
	UserTypeUnconfirmed,
	UserTypeActiveNonPaying,
	UserTypeActiveFree,
	UserTypeActivePaying,
	UserTypeActiveDelinquent,
	UserTypeAdmin,
	UserTypeSuspended,
}

func (e UserType) IsValid() bool {
	switch e {
	case UserTypeUnconfirmed, UserTypeActiveNonPaying, UserTypeActiveFree, UserTypeActivePaying, UserTypeActiveDelinquent, UserTypeAdmin, UserTypeSuspended:
		return true
	}
	return false
}

func (e UserType) String() string {
	return string(e)
}

func (e *UserType) UnmarshalGQL(v interface{}) error {
	str, ok := v.(string)
	if !ok {
		return fmt.Errorf("enums must be strings")
	}

	*e = UserType(str)
	if !e.IsValid() {
		return fmt.Errorf("%s is not a valid UserType", str)
	}
	return nil
}

func (e UserType) MarshalGQL(w io.Writer) {
	fmt.Fprint(w, strconv.Quote(e.String()))
}
