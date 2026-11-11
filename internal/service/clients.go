package service

import (
	"context"
	"strings"

	"sso/internal/secure"
	"sso/internal/store"
)

// ClientAuthenticator authenticates the caller of /oauth/token,
// /oauth/introspect and /oauth/revoke.
//
// It supports client_secret_basic, client_secret_post and "none" (public
// clients, which are forced through PKCE at the authorize step).
type ClientAuthenticator struct {
	Store *store.Store
}

// Authenticate resolves the client and checks its secret. Public clients have
// no secret to check: PKCE is their proof, and the authorize step enforces it.
func (c *ClientAuthenticator) Authenticate(ctx context.Context, clientID, secret string) (*store.Client, *OAuthError) {
	if clientID == "" {
		return nil, InvalidClient("client_id is required")
	}

	client, err := c.Store.ClientByClientID(ctx, clientID)
	if err != nil {
		return nil, ServerError("could not read the client")
	}
	if client == nil || !client.Active {
		return nil, InvalidClient("Unknown or inactive client")
	}

	if !VerifyClientSecret(client, secret) {
		return nil, InvalidClient("Client authentication failed")
	}
	return client, nil
}

// VerifyClientSecret is OauthClient::verifySecret. The secret is stored as a
// bcrypt hash, because an administrator hands it to a machine once and a
// database dump must not contain working credentials.
func VerifyClientSecret(client *store.Client, secret string) bool {
	if client.IsPublic() {
		return true // PKCE instead of a secret
	}
	if secret == "" || client.SecretHash == nil {
		return false
	}
	return secure.CheckPassword(*client.SecretHash, secret)
}

// GenerateClientID is OauthClient::generateClientId: "sso_" plus 24 lower-case
// characters, which Str::lower(Str::random(24)) produced.
func GenerateClientID() string {
	return "sso_" + strings.ToLower(secure.RandomString(24))
}
