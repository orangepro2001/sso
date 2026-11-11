package service

import (
	"context"
	"strings"
	"time"

	"sso/internal/secure"
	"sso/internal/store"
)

// TokenResponse is the /oauth/token answer. Fields that do not apply are
// omitted, never sent as null: Android's org.json reads a JSON null as the
// string "null", and AppAuth then tries to parse "null" as an ID token and
// refuses the sign-in (TokenController, 2026-11-06).
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope"`
	IDToken      string `json:"id_token,omitempty"`
}

// TokenService is the single place that mints, rotates, revokes and resolves
// tokens. Every access token is a row as well as a JWT: offline verification
// for the common case, instant revocation for the case that matters
// (DESIGN.md §3).
type TokenService struct {
	Store      *store.Store
	Keys       *SigningKeyService
	Audit      *AuditLogger
	Issuer     string
	AccessTTL  time.Duration
	RefreshTTL time.Duration
}

// IssueForUser mints an access JWT plus, when `offline_access` was granted, a
// rotating refresh token; `openid` adds an ID token.
func (t *TokenService) IssueForUser(ctx context.Context, user *store.User, clientID string, scopes []string, rm RequestMeta, familyID string) (*TokenResponse, error) {
	token, record, expiresAt, err := t.mintJWT(ctx, itoa(user.ID), store.SubjectUser, scopes, clientID, user, rm)
	if err != nil {
		return nil, err
	}

	response := &TokenResponse{
		AccessToken: token,
		TokenType:   "Bearer",
		ExpiresIn:   int(t.AccessTTL.Seconds()),
		Scope:       strings.Join(scopes, " "),
	}

	if contains(scopes, "offline_access") {
		refresh, err := t.issueRefreshToken(ctx, user, clientID, scopes, familyID)
		if err != nil {
			return nil, err
		}
		response.RefreshToken = refresh
	}

	if contains(scopes, "openid") {
		key, err := t.Keys.Active(ctx)
		if err != nil {
			return nil, err
		}
		claims := t.baseClaims(&user.ID, clientID, []string{"openid"}, rm)
		// OIDC Core 2: exp is required; a client reads a missing one as expired.
		claims["exp"] = expiresAt.Unix()
		for name, value := range t.identityClaims(user, scopes) {
			claims[name] = value
		}
		idToken, err := secure.Encode(claims, key.PrivatePEM, key.Kid)
		if err != nil {
			return nil, err
		}
		response.IDToken = idToken
	}

	t.Audit.Log(ctx, "token.issued", "user", itoa(user.ID), "token", record.JTI, map[string]any{
		"client_id": clientID, "scopes": scopes, "kind": "user",
	}, rm)

	return response, nil
}

// IssueForClient is client_credentials: the client itself is the subject and
// there is no refresh token.
func (t *TokenService) IssueForClient(ctx context.Context, client *store.Client, scopes []string, rm RequestMeta) (*TokenResponse, error) {
	token, record, _, err := t.mintJWT(ctx, client.ClientID, store.SubjectClient, scopes, client.ClientID, nil, rm)
	if err != nil {
		return nil, err
	}

	t.Audit.Log(ctx, "token.issued", "client", client.ClientID, "token", record.JTI, map[string]any{
		"client_id": client.ClientID, "scopes": scopes, "kind": "client_credentials",
	}, rm)

	return &TokenResponse{
		AccessToken: token,
		TokenType:   "Bearer",
		ExpiresIn:   int(t.AccessTTL.Seconds()),
		Scope:       strings.Join(scopes, " "),
	}, nil
}

// Refresh rotates a refresh token. Reuse of an already rotated token revokes
// the whole family: that is the classic stolen-token signal (DESIGN.md §4).
func (t *TokenService) Refresh(ctx context.Context, plain string, client *store.Client, rm RequestMeta) (*TokenResponse, error) {
	record, err := t.Store.RefreshTokenByHash(ctx, secure.SHA256Hex(plain))
	if err != nil {
		return nil, err
	}
	if record == nil {
		return nil, InvalidGrant("Unknown refresh token")
	}
	if record.ClientID != client.ClientID {
		return nil, InvalidGrant("Refresh token was issued to another client")
	}

	if record.RotatedAt.Valid {
		if _, err := t.Store.RevokeRefreshFamily(ctx, record.FamilyID); err != nil {
			return nil, err
		}
		t.Audit.Log(ctx, "token.reuse_detected", "user", itoa(record.UserID), "refresh_family", record.FamilyID, map[string]any{
			"client_id": client.ClientID,
		}, rm)
		t.auditFamilyRevoked(ctx, record.FamilyID, "refresh token reuse")
		return nil, InvalidGrant("Refresh token already used; the token family has been revoked")
	}

	if !record.IsUsable() {
		return nil, InvalidGrant("Refresh token expired or revoked")
	}

	user, err := t.Store.UserByID(ctx, record.UserID)
	if err != nil {
		return nil, err
	}
	if user == nil || !user.IsActive() {
		return nil, InvalidGrant("Account is not active")
	}

	if err := t.Store.RotateRefreshToken(ctx, record.ID); err != nil {
		return nil, err
	}

	// The rotated token stays in the same family, so a later replay of any
	// ancestor revokes everything descended from this login.
	return t.IssueForUser(ctx, user, client.ClientID, record.Scopes, rm, record.FamilyID)
}

// Resolve maps a bearer token to its stored record, or nil when it is unknown,
// expired, revoked, or belongs to a user who is no longer active.
func (t *TokenService) Resolve(ctx context.Context, plain string) (*store.AccessToken, error) {
	record, err := t.lookup(ctx, plain)
	if err != nil || record == nil {
		return nil, err
	}
	if !record.IsActive() {
		return nil, nil
	}
	if record.SubjectType == store.SubjectUser {
		if record.UserID == nil {
			return nil, nil
		}
		user, err := t.Store.UserByID(ctx, *record.UserID)
		if err != nil {
			return nil, err
		}
		if user == nil || !user.IsActive() {
			return nil, nil
		}
	}
	return record, nil
}

// Revoke ends a token immediately (RFC 7009 accepts anything, including
// tokens this service does not know).
func (t *TokenService) Revoke(ctx context.Context, plain string) error {
	record, err := t.lookup(ctx, plain)
	if err != nil || record == nil {
		return err
	}
	if record.RevokedAt.Valid {
		return nil
	}
	if err := t.Store.RevokeAccessToken(ctx, record.ID); err != nil {
		return err
	}
	t.Audit.Log(ctx, "token.revoked", "", "", "token", record.JTI, nil, RequestMeta{})
	return nil
}

// IntrospectionBody is the RFC 7662 answer (TokenService::introspect).
type IntrospectionBody struct {
	Active      bool   `json:"active"`
	TokenType   string `json:"token_type,omitempty"`
	Scope       string `json:"scope,omitempty"`
	ClientID    string `json:"client_id,omitempty"`
	Sub         string `json:"sub,omitempty"`
	Iss         string `json:"iss,omitempty"`
	Iat         int64  `json:"iat,omitempty"`
	Exp         int64  `json:"exp,omitempty"`
	JTI         string `json:"jti,omitempty"`
	TokenKind   string `json:"token_kind,omitempty"`
	SubjectType string `json:"subject_type,omitempty"`
	Username    string `json:"username,omitempty"`
	Name        string `json:"name,omitempty"`
}

func (t *TokenService) Introspect(ctx context.Context, plain string) (*IntrospectionBody, error) {
	record, err := t.Resolve(ctx, plain)
	if err != nil || record == nil {
		return nil, err
	}

	body := &IntrospectionBody{
		Active:      true,
		TokenType:   "Bearer",
		Scope:       strings.Join(record.Scopes, " "),
		Iss:         t.Issuer,
		Iat:         record.CreatedAt.Unix(),
		Exp:         record.ExpiresAt.Unix(),
		JTI:         record.JTI,
		TokenKind:   record.Kind,
		SubjectType: record.SubjectType,
	}
	if record.ClientID != nil {
		body.ClientID = *record.ClientID
	}
	if record.SubjectType == store.SubjectUser && record.UserID != nil {
		body.Sub = itoa(*record.UserID)
		user, err := t.Store.UserByID(ctx, *record.UserID)
		if err != nil {
			return nil, err
		}
		if user != nil {
			body.Username = user.Username
			body.Name = user.Name
		}
	} else if record.ClientID != nil {
		body.Sub = *record.ClientID
	}
	return body, nil
}

// DecodeUnverified checks the signature against the published key named in the
// header and returns the claims; no claim validation. nil for anything that is
// not a token this service signed.
func (t *TokenService) DecodeUnverified(ctx context.Context, plain string) map[string]any {
	kid := secure.HeaderKid(plain)
	if kid == "" {
		return nil
	}
	publicPEM, err := t.Keys.PublicKeyFor(ctx, kid)
	if err != nil || publicPEM == "" {
		return nil
	}
	claims, err := secure.Decode(plain, publicPEM)
	if err != nil {
		return nil
	}
	return claims
}

func (t *TokenService) lookup(ctx context.Context, plain string) (*store.AccessToken, error) {
	claims := t.DecodeUnverified(ctx, plain)
	if claims == nil {
		return nil, nil
	}
	jti, ok := claims["jti"].(string)
	if !ok || jti == "" {
		return nil, nil
	}
	return t.Store.AccessTokenByJTI(ctx, jti)
}

func (t *TokenService) mintJWT(ctx context.Context, subject, subjectType string, scopes []string, clientID string, user *store.User, rm RequestMeta) (string, *store.AccessToken, store.Timestamp, error) {
	key, err := t.Keys.Active(ctx)
	if err != nil {
		return "", nil, store.Timestamp{}, err
	}

	var userID *int64
	if user != nil {
		userID = &user.ID
	}

	jti := secure.UUID()
	expiresAt := store.FromTime(time.Now().UTC().Add(t.AccessTTL))

	claims := t.baseClaims(userID, clientID, scopes, rm)
	claims["sub"] = subject
	claims["jti"] = jti
	claims["exp"] = expiresAt.Unix()
	claims["subject_type"] = subjectType

	token, err := secure.Encode(claims, key.PrivatePEM, key.Kid)
	if err != nil {
		return "", nil, store.Timestamp{}, err
	}

	record := &store.AccessToken{
		Kind:        store.TokenKindJWT,
		JTI:         jti,
		SubjectType: subjectType,
		UserID:      userID,
		Scopes:      scopes,
		ExpiresAt:   expiresAt,
		IssuedIP:    optional(truncate(rm.IP, 45)),
		UserAgent:   optional(truncate(rm.UserAgent, 512)),
	}
	if clientID != "" {
		record.ClientID = &clientID
	}
	if err := t.Store.InsertAccessToken(ctx, record); err != nil {
		return "", nil, store.Timestamp{}, err
	}
	return token, record, expiresAt, nil
}

func (t *TokenService) baseClaims(userID *int64, clientID string, scopes []string, rm RequestMeta) map[string]any {
	now := time.Now().UTC().Unix()
	aud := clientID
	if aud == "" {
		aud = "sso"
	}
	claims := map[string]any{
		"iss":   t.Issuer,
		"aud":   aud,
		"iat":   now,
		"nbf":   now,
		"scope": strings.Join(scopes, " "),
	}
	if userID != nil {
		claims["uid"] = itoa(*userID)
	}
	return claims
}

func (t *TokenService) identityClaims(user *store.User, scopes []string) map[string]any {
	claims := map[string]any{"sub": itoa(user.ID)}
	if contains(scopes, "profile") {
		claims["name"] = user.Name
		claims["preferred_username"] = user.Username
		claims["role"] = user.Role
		if user.CreatedAt.Valid {
			claims["created_at"] = user.CreatedAt.Unix()
		}
	}
	return claims
}

func (t *TokenService) issueRefreshToken(ctx context.Context, user *store.User, clientID string, scopes []string, familyID string) (string, error) {
	plain := secure.Token("sso_r_")
	if familyID == "" {
		familyID = secure.UUID()
	}
	record := &store.RefreshToken{
		TokenHash: secure.SHA256Hex(plain),
		FamilyID:  familyID,
		UserID:    user.ID,
		ClientID:  clientID,
		Scopes:    scopes,
		ExpiresAt: store.FromTime(time.Now().UTC().Add(t.RefreshTTL)),
	}
	if err := t.Store.InsertRefreshToken(ctx, record); err != nil {
		return "", err
	}
	return plain, nil
}

func (t *TokenService) auditFamilyRevoked(ctx context.Context, familyID, reason string) {
	t.Audit.Log(ctx, "token.family_revoked", "", "", "refresh_family", familyID, map[string]any{"reason": reason}, RequestMeta{})
}

func contains(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

func itoa(v int64) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
