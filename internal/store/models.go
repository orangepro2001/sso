package store

import "strings"

// User is an SSO end user — and, via role, a console operator. One account
// space (DESIGN.md §2): the console is a user with role `super_admin`, not a
// second identity with its own password.
type User struct {
	ID              int64
	Name            string
	Username        string
	Role            string
	Password        string
	Status          string
	LastLoginAt     Timestamp
	LastLoginIP     *string
	CreatedBy       *int64
	Note            *string
	RememberToken   *string
	AvatarPath      *string
	AvatarMime      *string
	AvatarUpdatedAt Timestamp
	CreatedAt       Timestamp
	UpdatedAt       Timestamp
}

const (
	StatusActive   = "active"
	StatusDisabled = "disabled"

	RoleSuperAdmin = "super_admin"
	RoleUser       = "user"
)

var Roles = []string{RoleUser, RoleSuperAdmin}

func (u *User) IsSuperAdmin() bool { return u.Role == RoleSuperAdmin }
func (u *User) IsActive() bool     { return u.Status == StatusActive }
func (u *User) HasAvatar() bool    { return u.AvatarPath != nil && *u.AvatarPath != "" }

// SelfRegistered is the note the registration form writes; the console shows
// "본인 가입" instead of a missing creator for those rows.
func (u *User) SelfRegistered() bool { return u.Note != nil && *u.Note == "self-registered" }

// AvatarURL is the signed, cache-friendly picture URL (User::avatarUrl).
//
// Public on purpose: another application reads it server-side from the
// `picture` claim and cannot carry a session. The signature is what makes it
// safe, and it is built from the issuer rather than the request host so an
// internal call to userinfo cannot store a 127.0.0.1 URL as somebody's picture.
func (u *User) AvatarURL(issuer, appKey string) *string {
	if !u.HasAvatar() {
		return nil
	}
	version := "0"
	if u.AvatarUpdatedAt.Valid {
		version = itoa(u.AvatarUpdatedAt.Unix())
	}
	sig := AvatarSignature(appKey, u.ID, version)
	url := strings.TrimRight(issuer, "/") + "/avatar/" + itoa(u.ID) + "/" + version + "?sig=" + sig
	return &url
}

// Client is a registered OAuth application.
type Client struct {
	ID            int64
	ClientID      string
	Name          string
	Type          string
	SecretHash    *string
	RedirectURIs  JSONList
	HomeURL       *string
	SortOrder     int64
	InLauncher    bool
	AllowedScopes JSONList
	Active        bool
	CreatedBy     *int64
	Note          *string
	CreatedAt     Timestamp
	UpdatedAt     Timestamp
}

const (
	ClientTypePublic       = "public"
	ClientTypeConfidential = "confidential"
)

func (c *Client) IsPublic() bool { return c.Type == ClientTypePublic }

// HasRedirectURI is an exact match. No wildcards on purpose: an open redirect
// in an authorization server is a total compromise.
func (c *Client) HasRedirectURI(uri string) bool {
	for _, candidate := range c.RedirectURIs {
		if candidate == uri {
			return true
		}
	}
	return false
}

// GrantedScopes intersects what the client asked for with what the client is
// allowed; an empty intersection falls back to openid/profile when those are
// allowed (OauthClient::grantedScopes).
func (c *Client) GrantedScopes(requested []string) []string {
	allowed := make(map[string]bool, len(c.AllowedScopes))
	for _, scope := range c.AllowedScopes {
		allowed[scope] = true
	}

	granted := make([]string, 0, len(requested))
	seen := map[string]bool{}
	for _, scope := range requested {
		if allowed[scope] && !seen[scope] {
			seen[scope] = true
			granted = append(granted, scope)
		}
	}
	if len(granted) > 0 {
		return granted
	}

	for _, scope := range []string{"openid", "profile"} {
		if allowed[scope] {
			granted = append(granted, scope)
		}
	}
	return granted
}

type AuthCode struct {
	ID                  int64
	CodeHash            string
	ClientID            string
	UserID              int64
	RedirectURI         string
	Scopes              JSONList
	CodeChallenge       *string
	CodeChallengeMethod *string
	ExpiresAt           Timestamp
	ConsumedAt          Timestamp
	CreatedAt           Timestamp
	UpdatedAt           Timestamp
}

type AccessToken struct {
	ID          int64
	Kind        string
	JTI         string
	TokenHash   *string
	SubjectType string
	UserID      *int64
	ClientID    *string
	Scopes      JSONList
	ExpiresAt   Timestamp
	RevokedAt   Timestamp
	IssuedIP    *string
	UserAgent   *string
	CreatedAt   Timestamp
	UpdatedAt   Timestamp
}

const (
	TokenKindJWT    = "jwt"
	TokenKindOpaque = "opaque"

	SubjectUser   = "user"
	SubjectClient = "client"
)

// IsActive mirrors AccessToken::isActive.
func (t *AccessToken) IsActive() bool {
	if t.RevokedAt.Valid {
		return false
	}
	return !t.ExpiresAt.Valid || t.ExpiresAt.IsFuture()
}

type RefreshToken struct {
	ID        int64
	TokenHash string
	FamilyID  string
	UserID    int64
	ClientID  string
	Scopes    JSONList
	ExpiresAt Timestamp
	RevokedAt Timestamp
	RotatedAt Timestamp
	CreatedAt Timestamp
	UpdatedAt Timestamp
}

// IsUsable mirrors RefreshToken::isUsable.
func (t *RefreshToken) IsUsable() bool {
	return !t.RevokedAt.Valid && !t.RotatedAt.Valid && t.ExpiresAt.IsFuture()
}

type AuditLog struct {
	ID          int64
	Event       string
	ActorType   *string
	ActorID     *string
	SubjectType *string
	SubjectID   *string
	IP          *string
	UserAgent   *string
	Meta        Meta
	CreatedAt   Timestamp
}

type SigningKey struct {
	ID         int64
	Kid        string
	Alg        string
	PrivateKey string
	PublicKey  string
	Active     bool
	RetiredAt  Timestamp
	CreatedAt  Timestamp
	UpdatedAt  Timestamp
}

type PasswordReset struct {
	ID        int64
	UserID    int64
	TokenHash string
	CreatedBy *int64
	ExpiresAt Timestamp
	UsedAt    Timestamp
	UsedIP    *string
	RevokedAt Timestamp
	CreatedAt Timestamp
	UpdatedAt Timestamp
}

// IsUsable mirrors UserPasswordReset::isUsable.
func (r *PasswordReset) IsUsable() bool {
	return !r.UsedAt.Valid && !r.RevokedAt.Valid && r.ExpiresAt.IsFuture()
}

func itoa(v int64) string {
	// Small helper so the model file stays free of strconv noise.
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
