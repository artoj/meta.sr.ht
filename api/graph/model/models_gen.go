// Code generated by github.com/99designs/gqlgen, DO NOT EDIT.

package model

import (
	"time"
)

type Entity interface {
	IsEntity()
}

type AuditLogCursor struct {
	Results []*AuditLogEntry `json:"results"`
	Cursor  *string          `json:"cursor"`
}

type AuditLogEntry struct {
	ID        int       `json:"id"`
	Created   time.Time `json:"created"`
	User      *User     `json:"user"`
	IPAddress string    `json:"ipAddress"`
	EventType string    `json:"eventType"`
	Details   *string   `json:"details"`
}

type Invoice struct {
	ID        int       `json:"id"`
	Created   time.Time `json:"created"`
	Cents     int       `json:"cents"`
	User      *User     `json:"user"`
	ValidThru time.Time `json:"validThru"`
	Source    *string   `json:"source"`
}

type InvoiceCursor struct {
	Results []*Invoice `json:"results"`
	Cursor  *string    `json:"cursor"`
}

type PGPKey struct {
	ID      int       `json:"id"`
	Created time.Time `json:"created"`
	User    *User     `json:"user"`
	Key     string    `json:"key"`
	KeyID   string    `json:"keyId"`
	Email   string    `json:"email"`
}

type PGPKeyCursor struct {
	Results []*PGPKey `json:"results"`
	Cursor  *string   `json:"cursor"`
}

type SSHKey struct {
	ID          int       `json:"id"`
	Created     time.Time `json:"created"`
	LastUsed    time.Time `json:"lastUsed"`
	User        *User     `json:"user"`
	Key         string    `json:"key"`
	Fingerprint string    `json:"fingerprint"`
	Comment     *string   `json:"comment"`
}

type SSHKeyCursor struct {
	Results []*SSHKey `json:"results"`
	Cursor  *string   `json:"cursor"`
}

type User struct {
	ID            int             `json:"id"`
	Created       time.Time       `json:"created"`
	Updated       time.Time       `json:"updated"`
	CanonicalName string          `json:"canonicalName"`
	Username      string          `json:"username"`
	Email         string          `json:"email"`
	URL           *string         `json:"url"`
	Location      *string         `json:"location"`
	Bio           *string         `json:"bio"`
	SSHKeys       *SSHKeyCursor   `json:"sshKeys"`
	PgpKeys       *PGPKeyCursor   `json:"pgpKeys"`
	Invoices      *InvoiceCursor  `json:"invoices"`
	AuditLog      *AuditLogCursor `json:"auditLog"`
}

func (User) IsEntity() {}

type UserInput struct {
	URL      *string `json:"url"`
	Location *string `json:"location"`
	Bio      *string `json:"bio"`
	Email    *string `json:"email"`
}

type Version struct {
	Major           int        `json:"major"`
	Minor           int        `json:"minor"`
	Patch           int        `json:"patch"`
	DeprecationDate *time.Time `json:"deprecationDate"`
}
