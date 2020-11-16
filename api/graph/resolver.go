package graph

import (
	"context"
	"fmt"
	"strings"
	"text/template"

	"git.sr.ht/~sircmpwn/core-go/auth"
	"git.sr.ht/~sircmpwn/core-go/config"
	"git.sr.ht/~sircmpwn/core-go/email"
	"github.com/emersion/go-message/mail"

	"git.sr.ht/~sircmpwn/meta.sr.ht/api/graph/model"
)

//go:generate go run github.com/99designs/gqlgen

type Resolver struct{}

type AuthorizationPayload struct {
	Grants     string
	ClientUUID string
	UserID     int
}

// Sends a security-related notice to the logged-in user.
func sendSecurityNotification(ctx context.Context,
	subject, details string, pgpKey *string) {
	conf := config.ForContext(ctx)
	siteName, ok := conf.Get("sr.ht", "site-name")
	if !ok {
		panic(fmt.Errorf("Expected [sr.ht]site-name in config"))
	}
	ownerName, ok := conf.Get("sr.ht", "owner-name")
	if !ok {
		panic(fmt.Errorf("Expected [sr.ht]owner-name in config"))
	}

	user := auth.ForContext(ctx)
	var header mail.Header
	header.SetAddressList("To", []*mail.Address{
		&mail.Address{user.Username, user.Email},
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
		Username:  user.Username,
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
