package graph

//go:generate go run github.com/99designs/gqlgen

type Resolver struct{}

type AuthorizationPayload struct {
	Grants     string
	ClientUUID string
	UserID     int
}
