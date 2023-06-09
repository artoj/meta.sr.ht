package graph

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"regexp"
	"strings"
	"text/template"

	"git.sr.ht/~sircmpwn/core-go/auth"
	"git.sr.ht/~sircmpwn/core-go/config"
	"git.sr.ht/~sircmpwn/core-go/database"
	"git.sr.ht/~sircmpwn/core-go/email"
	"git.sr.ht/~sircmpwn/core-go/server"
	"github.com/emersion/go-message/mail"

	"git.sr.ht/~sircmpwn/meta.sr.ht/api/graph/model"
)

var (
	usernameRE = regexp.MustCompile(`^[a-z_][a-z0-9_-]+$`)
)

type Resolver struct{}

type AuthorizationPayload struct {
	Grants     string
	ClientUUID string
	UserID     int
}

// Records an event in the authorized user's audit log.
func recordAuditLog(ctx context.Context, eventType, details string) {
	database.WithTx(ctx, nil, func(tx *sql.Tx) error {
		addr := server.RemoteAddr(ctx)
		user := auth.ForContext(ctx)
		_, err := tx.ExecContext(ctx, `
			INSERT INTO audit_log_entry (
				created, user_id, ip_address, event_type, details
			) VALUES (
				NOW() at time zone 'utc',
				$1, $2, $3, $4
			);
		`, user.UserID, addr, eventType, details)
		if err != nil {
			panic(err)
		}

		log.Printf("Audit log: %s: %s", eventType, details)
		return nil
	})
}

func pgpKeyForUser(ctx context.Context, user *model.User) (*string, error) {
	var key *string
	if user.PGPKeyID != nil {
		if err := database.WithTx(ctx, &sql.TxOptions{
			Isolation: 0,
			ReadOnly:  true,
		}, func(tx *sql.Tx) error {
			row := tx.QueryRowContext(ctx, `
				SELECT key
				FROM "pgpkey" WHERE id = $1;
				`, *user.PGPKeyID)
			if err := row.Scan(&key); err != nil {
				return err
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}
	return key, nil
}

func sendRegistrationConfirmation(ctx context.Context,
	user *model.User, pgpKey *string, confirmation string) {
	conf := config.ForContext(ctx)
	siteName, ok := conf.Get("sr.ht", "site-name")
	if !ok {
		panic(fmt.Errorf("Expected [sr.ht]site-name in config"))
	}
	ownerName, ok := conf.Get("sr.ht", "owner-name")
	if !ok {
		panic(fmt.Errorf("Expected [sr.ht]owner-name in config"))
	}

	var header mail.Header
	header.SetAddressList("To", []*mail.Address{
		&mail.Address{"~" + user.Username, user.Email},
	})
	header.SetSubject(fmt.Sprintf("Confirm your %s registration", siteName))

	type TemplateContext struct {
		OwnerName    string
		SiteName     string
		Username     string
		Root         string
		Confirmation string
	}
	tctx := TemplateContext{
		OwnerName:    ownerName,
		SiteName:     siteName,
		Username:     user.Username,
		Root:         config.GetOrigin(conf, "meta.sr.ht", true),
		Confirmation: confirmation,
	}

	tmpl := template.Must(template.New("security-event").Parse(`Hello ~{{.Username}}!

You (or someone pretending to be you) have registered for an account on
{{.SiteName}}. 

To complete your registration, please follow this link:

{{.Root}}/confirm-account/{{.Confirmation}}

If not, just ignore this email. If you have any questions, please reply
to this email.

-- 
{{.OwnerName}}
{{.SiteName}}`))

	var body strings.Builder
	err := tmpl.Execute(&body, tctx)
	if err != nil {
		panic(err)
	}

	err = email.EnqueueStd(ctx, header,
		strings.NewReader(body.String()), pgpKey)
	if err != nil {
		panic(err)
	}
}

func sendEmailNotification(ctx context.Context,
	username, userEmail, message string, pgpKey *string) error {
	r := strings.NewReader(message)
	mr, err := mail.CreateReader(r)
	if err != nil {
		return err
	}
	defer mr.Close()
	// We expect exactly one plain text part
	p, err := mr.NextPart()
	if err != nil {
		return err
	}
	if _, ok := p.Header.(*mail.InlineHeader); !ok {
		return fmt.Errorf("Sending attachments is not supported")
	}
	_, err = mr.NextPart()
	if err == nil {
		fmt.Errorf("Sending multi-part mails is not supported")
	}

	header := mr.Header
	// Assert that caller does not try to set any recipients
	for _, h := range []string{"To", "Cc", "Bcc"} {
		rcpts, err := header.AddressList(h)
		if err != nil {
			return err
		}
		if len(rcpts) > 0 {
			return fmt.Errorf("%s header must not be set", h)
		}
	}
	// and that we at least have a subject
	if subject, err := header.Subject(); err != nil || subject == "" {
		return fmt.Errorf("missing or malformed subject")
	}

	header.SetAddressList("To", []*mail.Address{
		&mail.Address{username, userEmail},
	})

	return email.EnqueueStd(ctx, header, p.Body, pgpKey)
}

// Send a security-related notice to the authorized user.
func sendSecurityNotification(ctx context.Context, subject, details string) {
	user := auth.ForContext(ctx)
	sendSecurityNotificationTo(ctx, user.Username, user.Email,
		subject, details, user.PGPKey)
}

// Send a security-related notice to the given user.
// Always prefer using `sendSecurityNotification` if possible.
func sendSecurityNotificationTo(ctx context.Context,
	username, address, subject, details string, pgpKey *string) {
	conf := config.ForContext(ctx)
	siteName, ok := conf.Get("sr.ht", "site-name")
	if !ok {
		panic(fmt.Errorf("Expected [sr.ht]site-name in config"))
	}
	ownerName, ok := conf.Get("sr.ht", "owner-name")
	if !ok {
		panic(fmt.Errorf("Expected [sr.ht]owner-name in config"))
	}

	var header mail.Header
	header.SetAddressList("To", []*mail.Address{
		&mail.Address{username, address},
	})
	header.SetSubject(subject)

	type TemplateContext struct {
		OwnerName string
		SiteName  string
		Username  string
		Details   string
	}
	tctx := TemplateContext{
		OwnerName: ownerName,
		SiteName:  siteName,
		Username:  username,
		Details:   details,
	}

	tmpl := template.Must(template.New("security-event").Parse(`~{{.Username}},

This email was sent to inform you that the following security-sensitive
event has occured on your {{.SiteName}} account:

{{.Details}}

If you did not expect this to occur, please reply to this email urgently
to contact support. Otherwise, no action is required.

-- 
{{.OwnerName}}
{{.SiteName}}`))

	var body strings.Builder
	err := tmpl.Execute(&body, tctx)
	if err != nil {
		panic(err)
	}

	err = email.EnqueueStd(ctx, header,
		strings.NewReader(body.String()), pgpKey)
	if err != nil {
		panic(err)
	}
}

func sendEmailUpdateConfirmation(ctx context.Context, user *model.User,
	pgpKey *string, newEmail, confHash string) {
	conf := config.ForContext(ctx)
	siteName, ok := conf.Get("sr.ht", "site-name")
	if !ok {
		panic(fmt.Errorf("Expected [sr.ht]site-name in config"))
	}
	ownerName, ok := conf.Get("sr.ht", "owner-name")
	if !ok {
		panic(fmt.Errorf("Expected [sr.ht]owner-name in config"))
	}

	var (
		h1 mail.Header
		h2 mail.Header
	)

	h1.SetAddressList("To", []*mail.Address{
		&mail.Address{"~" + user.Username, user.Email},
	})
	h2.SetAddressList("To", []*mail.Address{
		&mail.Address{"~" + user.Username, newEmail},
	})

	h1.SetSubject(fmt.Sprintf("Your email address on %s is changing", siteName))
	h2.SetSubject(fmt.Sprintf("Confirm your new %s email address", siteName))

	type TemplateContext struct {
		ConfHash  string
		NewEmail  string
		OwnerName string
		Root      string
		SiteName  string
		Username  string
	}
	tctx := TemplateContext{
		ConfHash:  confHash,
		NewEmail:  newEmail,
		OwnerName: ownerName,
		Root:      config.GetOrigin(conf, "meta.sr.ht", true),
		SiteName:  siteName,
		Username:  user.Username,
	}

	m1tmpl := template.Must(template.New("update_email_old").Parse(`Hi ~{{.Username}}!

This is a notice that your email address on {{.SiteName}} is being
changed to {{.NewEmail}}. A confirmation email is being sent to
{{.NewEmail}} to finalize the process.

If you did not expect this to happen, please reply to this email
urgently to reach support.

-- 
{{.OwnerName}}
{{.SiteName}}`))

	m2tmpl := template.Must(template.New("update_email_new").Parse(`Hi ~{{.Username}}!

You (or someone pretending to be you) updated the email address for
your account to {{.NewEmail}}. To confirm the new email and apply the
change, click the following link:

{{.Root}}/confirm-account/{{.ConfHash}}

-- 
{{.OwnerName}}
{{.SiteName}}`))

	var (
		m1body strings.Builder
		m2body strings.Builder
	)
	err := m1tmpl.Execute(&m1body, tctx)
	if err != nil {
		panic(err)
	}

	err = m2tmpl.Execute(&m2body, tctx)
	if err != nil {
		panic(err)
	}

	err = email.EnqueueStd(ctx, h1, strings.NewReader(m1body.String()), pgpKey)
	if err != nil {
		panic(err)
	}

	err = email.EnqueueStd(ctx, h2, strings.NewReader(m2body.String()), pgpKey)
	if err != nil {
		panic(err)
	}
}
