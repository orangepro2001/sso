package server

import (
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"sso/internal/config"
	"sso/internal/secure"
	"sso/internal/service"
	"sso/internal/store"
)

// ---- discovery -----------------------------------------------------------

// discovery is RFC 8414 / OIDC discovery. The issuer is the canonical public
// URL, including the mount point, because it is embedded in every token.
func (s *Server) discovery(w http.ResponseWriter, r *http.Request) {
	issuer := strings.TrimRight(s.Cfg.Issuer, "/")

	document := map[string]any{
		"issuer":                 issuer,
		"authorization_endpoint": issuer + "/oauth/authorize",
		"token_endpoint":         issuer + "/oauth/token",
		"userinfo_endpoint":      issuer + "/oauth/userinfo",
		"introspection_endpoint": issuer + "/oauth/introspect",
		"revocation_endpoint":    issuer + "/oauth/revoke",
		"jwks_uri":               issuer + "/.well-known/jwks.json",
		// An explicitly ordered list: Go maps would shuffle it, and the PHP's
		// config('sso.scopes') order is what the console offers.
		"scopes_supported":                      config.ScopeOrder,
		"response_types_supported":              []string{"code"},
		"response_modes_supported":              []string{"query"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token", "client_credentials"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic", "none"},
		"code_challenge_methods_supported":      []string{"S256"},
		"claims_supported": []string{
			"sub", "iss", "aud", "exp", "iat", "nbf", "jti", "scope",
			"name", "preferred_username", "picture", "role",
		},
		"service_documentation": issuer + "/../docs/DESIGN.md",
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=600")
	writeJSONMap(w, document)
}

func (s *Server) jwks(w http.ResponseWriter, r *http.Request) {
	// Touch the active key first: on a brand new database the pair is generated
	// lazily, and the JWKS must never be empty while tokens exist.
	if _, err := s.Keys.Active(r.Context()); err != nil {
		s.serverError(w, r, err)
		return
	}
	keys, err := s.Keys.JWKS(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if keys == nil {
		keys = []secure.JWK{}
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=600")
	writeJSONMap(w, map[string]any{"keys": keys})
}

// ---- /oauth/authorize ----------------------------------------------------

// authorize is the authorization code flow with mandatory PKCE (S256).
//
// There is no interactive consent screen: clients are registered by an
// administrator, so the client registration itself is the consent.
func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.params(r)

	clientID := p.queryValue("client_id")
	client, err := s.Store.ClientByClientID(ctx, clientID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if client == nil || !client.Active {
		s.jsonOAuthError(w, service.InvalidRequest("Unknown or inactive client_id"))
		return
	}

	redirectURI := p.queryValue("redirect_uri")
	if redirectURI == "" && len(client.RedirectURIs) == 1 {
		redirectURI = client.RedirectURIs[0]
	}
	if !client.HasRedirectURI(redirectURI) {
		// Nothing may be echoed to an unvalidated redirect_uri.
		s.jsonOAuthError(w, service.InvalidRequest("redirect_uri is not registered for this client"))
		return
	}

	if p.queryValue("response_type") != "code" {
		s.redirectAuthorizeError(w, r, redirectURI, "unsupported_response_type", "Only response_type=code is supported")
		return
	}

	challenge, method := pkce(p)

	// A public client has no secret, so PKCE is the only thing binding the code
	// to the requester. Without it, anyone who can read the redirect can redeem
	// the code and take over the account (RFC 7636 §4.1 / RFC 9700).
	if client.IsPublic() && challenge == "" {
		s.redirectAuthorizeError(w, r, redirectURI, "invalid_request",
			"Public clients must send code_challenge with code_challenge_method=S256")
		return
	}

	scopes := client.GrantedScopes(requestedScopes(p.queryValue("scope")))
	if len(scopes) == 0 {
		s.redirectAuthorizeError(w, r, redirectURI, "invalid_scope", "No requestable scope is allowed for this client")
		return
	}

	parked := map[string]any{
		"response_type":         p.queryValue("response_type"),
		"client_id":             clientID,
		"redirect_uri":          redirectURI,
		"scope":                 p.queryValue("scope"),
		"state":                 p.queryValue("state"),
		"code_challenge":        p.queryValue("code_challenge"),
		"code_challenge_method": p.queryValue("code_challenge_method"),
		"nonce":                 p.queryValue("nonce"),
	}

	user := s.currentUser(r)
	if user == nil {
		if sess := sessionOf(r); sess != nil {
			sess.put("oauth.pending", parked)
			// The guest redirect remembers where to come back to, the way
			// redirect()->guest() did.
			sess.put("url.intended", s.absoluteURL(r))
		}
		// Name the requesting client on the sign-in page: the person may well
		// have a console session open, and that is deliberately not a client
		// identity.
		s.redirect(w, r, "/login?"+url.Values{"client": {client.Name}}.Encode(), http.StatusFound)
		return
	}

	if sess := sessionOf(r); sess != nil {
		// The request has been served: drop the parked copy, otherwise the next
		// plain sign-in would resume a stale client request instead of going home.
		sess.forget("oauth.pending")
		// …but remember it for two minutes: a sign-in form submitted twice lands
		// its second POST (419) while the browser is still on its way to the
		// client, and that request is what carries on.
		sess.put("oauth.last", map[string]any{"at": time.Now().Unix(), "params": parked})
	}

	plain := secure.Token("sso_c_")
	code := &store.AuthCode{
		CodeHash:    secure.SHA256Hex(plain),
		ClientID:    client.ClientID,
		UserID:      user.ID,
		RedirectURI: redirectURI,
		Scopes:      scopes,
		ExpiresAt:   store.FromTime(time.Now().UTC().Add(s.Cfg.AuthCodeTTL)),
	}
	if challenge != "" {
		code.CodeChallenge = &challenge
		code.CodeChallengeMethod = &method
	}
	if err := s.Store.InsertAuthCode(ctx, code); err != nil {
		s.serverError(w, r, err)
		return
	}

	s.Audit.Log(ctx, "authorize.granted", "user", itoa(user.ID), "client", client.ClientID, map[string]any{
		"scopes": scopes,
	}, s.requestMeta(r))

	s.redirectWith(w, r, redirectURI, map[string]string{"code": plain, "state": p.queryValue("state")})
}

func pkce(p *params) (string, string) {
	challenge := p.queryValue("code_challenge")
	method := strings.ToUpper(p.queryValue("code_challenge_method"))
	if method == "" {
		method = "S256"
	}
	if challenge == "" {
		return "", ""
	}
	// S256 only: "plain" gains nothing over sending nothing and invites
	// implementations that leak the verifier.
	if method != "S256" {
		return "", ""
	}
	return challenge, method
}

func requestedScopes(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return []string{"openid", "profile"}
	}
	seen := map[string]bool{}
	out := []string{}
	for _, scope := range strings.Fields(raw) {
		if !seen[scope] {
			seen[scope] = true
			out = append(out, scope)
		}
	}
	return out
}

func (s *Server) redirectAuthorizeError(w http.ResponseWriter, r *http.Request, redirectURI, code, description string) {
	s.Audit.Log(r.Context(), "authorize.denied", "", "", "", "", map[string]any{
		"error": code, "description": description, "client_id": r.URL.Query().Get("client_id"),
	}, s.requestMeta(r))

	s.redirectWith(w, r, redirectURI, map[string]string{
		"error":             code,
		"error_description": description,
		"state":             r.URL.Query().Get("state"),
	})
}

func (s *Server) redirectWith(w http.ResponseWriter, r *http.Request, uri string, params map[string]string) {
	values := url.Values{}
	for key, value := range params {
		if value != "" {
			values.Set(key, value)
		}
	}
	s.redirect(w, r, urlWith(uri, values), http.StatusFound)
}

// ---- /oauth/token --------------------------------------------------------

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.params(r)
	grantType := p.input("grant_type")

	clientID, secret := credentials(r, p)
	client, oerr := s.Clients.Authenticate(ctx, clientID, secret)
	if oerr == nil {
		var response *service.TokenResponse
		switch grantType {
		case "authorization_code":
			response, oerr = s.grantAuthorizationCode(r, client)
		case "refresh_token":
			response, oerr = s.grantRefreshToken(r, client)
		case "client_credentials":
			response, oerr = s.grantClientCredentials(r, client)
		default:
			oerr = service.UnsupportedGrantType("grant_type must be authorization_code, refresh_token or client_credentials")
		}
		if oerr == nil {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Pragma", "no-cache")
			s.json(w, http.StatusOK, response)
			return
		}
	}

	s.Audit.Log(ctx, "token.error", "", "", "", "", map[string]any{
		"error": oerr.Code, "description": oerr.Description, "grant_type": grantType,
	}, s.requestMeta(r))
	s.jsonOAuthError(w, oerr)
}

func (s *Server) grantAuthorizationCode(r *http.Request, client *store.Client) (*service.TokenResponse, *service.OAuthError) {
	ctx := r.Context()
	p := s.params(r)

	plain := p.input("code")
	if plain == "" {
		return nil, service.InvalidRequest("code is required")
	}

	code, err := s.Store.AuthCodeByHash(ctx, secure.SHA256Hex(plain))
	if err != nil {
		return nil, service.ServerError("could not read the authorization code")
	}
	if code == nil {
		return nil, service.InvalidGrant("Unknown authorization code")
	}
	if code.ClientID != client.ClientID {
		return nil, service.InvalidGrant("Authorization code was issued to another client")
	}
	if code.ConsumedAt.Valid {
		return nil, service.InvalidGrant("Authorization code already used")
	}
	if code.ExpiresAt.IsPast() {
		return nil, service.InvalidGrant("Authorization code expired")
	}

	if redirectURI := p.input("redirect_uri"); redirectURI != "" && redirectURI != code.RedirectURI {
		return nil, service.InvalidGrant("redirect_uri mismatch")
	}

	if code.CodeChallenge != nil {
		verifier := p.input("code_verifier")
		if verifier == "" {
			return nil, service.InvalidGrant("code_verifier is required for this authorization code")
		}
		if !secure.ConstantTimeEquals(*code.CodeChallenge, secure.PKCEChallenge(verifier)) {
			return nil, service.InvalidGrant("code_verifier does not match the code_challenge")
		}
	}

	user, err := s.Store.UserByID(ctx, code.UserID)
	if err != nil {
		return nil, service.ServerError("could not read the account")
	}
	if user == nil || !user.IsActive() {
		return nil, service.InvalidGrant("Account is not active")
	}

	if err := s.Store.ConsumeAuthCode(ctx, code.ID); err != nil {
		return nil, service.ServerError("could not consume the authorization code")
	}

	response, err := s.Tokens.IssueForUser(ctx, user, client.ClientID, code.Scopes, s.requestMeta(r), "")
	if err != nil {
		return nil, service.ServerError("could not issue a token")
	}
	return response, nil
}

func (s *Server) grantRefreshToken(r *http.Request, client *store.Client) (*service.TokenResponse, *service.OAuthError) {
	p := s.params(r)
	plain := p.input("refresh_token")
	if plain == "" {
		return nil, service.InvalidRequest("refresh_token is required")
	}
	response, err := s.Tokens.Refresh(r.Context(), plain, client, s.requestMeta(r))
	if err != nil {
		if oerr, ok := err.(*service.OAuthError); ok {
			return nil, oerr
		}
		return nil, service.ServerError("could not refresh the token")
	}
	return response, nil
}

func (s *Server) grantClientCredentials(r *http.Request, client *store.Client) (*service.TokenResponse, *service.OAuthError) {
	if client.IsPublic() {
		return nil, service.UnauthorizedClient("Public clients cannot use client_credentials")
	}

	p := s.params(r)
	requested := strings.TrimSpace(p.input("scope"))
	var scopes []string
	if requested == "" {
		scopes = client.GrantedScopes([]string{"db:read"})
	} else {
		scopes = client.GrantedScopes(strings.Fields(requested))
	}
	if len(scopes) == 0 {
		return nil, service.InvalidScope("None of the requested scopes is allowed for this client")
	}

	response, err := s.Tokens.IssueForClient(r.Context(), client, scopes, s.requestMeta(r))
	if err != nil {
		return nil, service.ServerError("could not issue a token")
	}
	return response, nil
}

// credentials reads client_secret_basic first (RFC 6749 §2.3.1: both parts are
// form-encoded before base64), then client_secret_post.
func credentials(r *http.Request, p *params) (string, string) {
	header := r.Header.Get("Authorization")
	if strings.HasPrefix(header, "Basic ") {
		decoded, err := decodeBasic(strings.TrimPrefix(header, "Basic "))
		if err == nil {
			if id, secret, ok := strings.Cut(decoded, ":"); ok {
				id, _ = url.QueryUnescape(id)
				secret, _ = url.QueryUnescape(secret)
				return id, secret
			}
		}
	}
	return p.input("client_id"), p.input("client_secret")
}

// ---- /oauth/userinfo -----------------------------------------------------

func (s *Server) userinfo(w http.ResponseWriter, r *http.Request) {
	plain := bearerToken(r)
	if plain == "" {
		s.userinfoUnauthorized(w, "Missing bearer token")
		return
	}

	record, err := s.Tokens.Resolve(r.Context(), plain)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if record == nil {
		s.userinfoUnauthorized(w, "Invalid or expired token")
		return
	}

	scopes := []string(record.Scopes)

	if record.SubjectType == store.SubjectClient {
		clientID := ""
		if record.ClientID != nil {
			clientID = *record.ClientID
		}
		s.json(w, http.StatusOK, map[string]any{
			"sub":          "client:" + clientID,
			"subject_type": "client",
			"scope":        strings.Join(scopes, " "),
		})
		return
	}

	var user *store.User
	if record.UserID != nil {
		user, err = s.Store.UserByID(r.Context(), *record.UserID)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
	}
	if user == nil {
		s.userinfoUnauthorized(w, "Unknown subject")
		return
	}

	body := map[string]any{
		"sub":          itoa(user.ID),
		"subject_type": "user",
		"scope":        strings.Join(scopes, " "),
	}
	if contains(scopes, "profile") {
		body["name"] = user.Name
		body["preferred_username"] = user.Username
		// Relying parties decide what a super administrator may do in their own
		// application.
		body["role"] = user.Role
		if user.CreatedAt.Valid {
			body["created_at"] = user.CreatedAt.Unix()
		}
		// A signed URL rather than a session-protected one: the relying party
		// reads this server-side and has no session to offer.
		if picture := user.AvatarURL(s.Cfg.Issuer, s.Cfg.AppKey); picture != nil {
			body["picture"] = *picture
		}
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	writeJSONMap(w, body)
}

func (s *Server) userinfoUnauthorized(w http.ResponseWriter, message string) {
	w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="`+message+`"`)
	s.json(w, http.StatusUnauthorized, map[string]string{
		"error":             "invalid_token",
		"error_description": message,
	})
}

// ---- introspection and revocation ---------------------------------------

func (s *Server) introspect(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.params(r)

	clientID, secret := credentials(r, p)
	client, oerr := s.Clients.Authenticate(ctx, clientID, secret)
	if oerr != nil {
		s.jsonOAuthError(w, oerr)
		return
	}

	token := p.input("token")
	var body *service.IntrospectionBody
	if token != "" {
		var err error
		body, err = s.Tokens.Introspect(ctx, token)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
	}

	w.Header().Set("Cache-Control", "no-store")
	if body == nil {
		s.json(w, http.StatusOK, map[string]any{"active": false})
		return
	}

	s.Audit.Log(ctx, "token.introspected", "client", client.ClientID, "token", body.JTI, map[string]any{
		"subject_type": body.SubjectType,
	}, s.requestMeta(r))

	s.json(w, http.StatusOK, body)
}

func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.params(r)

	clientID, secret := credentials(r, p)
	if _, oerr := s.Clients.Authenticate(ctx, clientID, secret); oerr != nil {
		s.jsonOAuthError(w, oerr)
		return
	}

	if token := p.input("token"); token != "" {
		if err := s.Tokens.Revoke(ctx, token); err != nil {
			s.serverError(w, r, err)
			return
		}
	}

	// RFC 7009 §2.2: always 200, even for unknown tokens.
	w.Header().Set("Cache-Control", "no-store")
	s.json(w, http.StatusOK, []any{})
}

// ---- health, static assets, pictures ------------------------------------

// healthz is liveness only. It deliberately does not touch the database: a
// brief outage should not restart-loop the proxy layer (DESIGN.md §9).
func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	s.json(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"service": "sso",
		"issuer":  s.Cfg.Issuer,
		"time":    time.Now().UTC().Format("2006-01-02T15:04:05+00:00"),
	})
}

func (s *Server) asset(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.PathValue("file"), "/")
	if name == "" || strings.Contains(name, "..") {
		http.NotFound(w, r)
		return
	}
	data, err := fs.ReadFile(s.Assets, name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", contentTypeFor(name))
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Server) robots(w http.ResponseWriter, r *http.Request) {
	data, err := fs.ReadFile(s.Assets, "robots.txt")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write(data)
}

func (s *Server) favicon(w http.ResponseWriter, r *http.Request) {
	data, err := fs.ReadFile(s.Assets, "favicon.ico")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "image/x-icon")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write(data)
}

func contentTypeFor(name string) string {
	switch {
	case strings.HasSuffix(name, ".css"):
		return "text/css; charset=utf-8"
	case strings.HasSuffix(name, ".js"):
		return "text/javascript; charset=utf-8"
	case strings.HasSuffix(name, ".ico"):
		return "image/x-icon"
	case strings.HasSuffix(name, ".txt"):
		return "text/plain; charset=utf-8"
	}
	return "application/octet-stream"
}

// avatar serves a profile picture.
//
// Anonymous by design, with an HMAC in the URL: another application reads this
// URL server-side from the `picture` claim and has no session to offer. The
// signature covers the user id and the version, so it is unguessable, changes
// when the picture changes, and can be cached forever.
func (s *Server) avatar(w http.ResponseWriter, r *http.Request) {
	id, ok := atoi(r.PathValue("user"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	version := r.PathValue("v")
	signature := r.URL.Query().Get("sig")

	if !secure.ConstantTimeEquals(store.AvatarSignature(s.Cfg.AppKey, id, version), signature) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	user, err := s.Store.UserByID(r.Context(), id)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if user == nil || !user.HasAvatar() {
		http.NotFound(w, r)
		return
	}

	absolute := filepath.Join(s.Cfg.ResolveStorageDir(), filepath.FromSlash(*user.AvatarPath))
	data, err := os.ReadFile(absolute)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	contentType := "application/octet-stream"
	if user.AvatarMime != nil && *user.AvatarMime != "" {
		contentType = *user.AvatarMime
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// ---- shared JSON helpers -------------------------------------------------

func (s *Server) jsonOAuthError(w http.ResponseWriter, e *service.OAuthError) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	body := map[string]any{"error": e.Code, "error_description": e.Description}
	if e.ErrorURI != "" {
		body["error_uri"] = e.ErrorURI
	}
	s.json(w, e.Status, body)
}

func writeJSONMap(w http.ResponseWriter, body map[string]any) {
	// Keys in a stable order: discovery output is compared by humans and by
	// caches, and Go's encoder would otherwise sort them alphabetically (which
	// is also fine, but a fixed order reads better in curl).
	keys := make([]string, 0, len(body))
	for key := range body {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	buf := strings.Builder{}
	buf.WriteByte('{')
	for i, key := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		encodedKey, _ := jsonMarshal(key)
		encodedValue, _ := jsonMarshal(body[key])
		buf.Write(encodedKey)
		buf.WriteByte(':')
		buf.Write(encodedValue)
	}
	buf.WriteByte('}')
	buf.WriteByte('\n')
	_, _ = w.Write([]byte(buf.String()))
}

func bearerToken(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if len(header) > 7 && strings.EqualFold(header[:7], "Bearer ") {
		token := strings.TrimSpace(header[7:])
		if token != "" && !strings.ContainsAny(token, " \t") {
			return token
		}
	}
	if value := r.URL.Query().Get("access_token"); value != "" {
		return value
	}
	if r.PostForm != nil {
		return r.PostForm.Get("access_token")
	}
	return ""
}
