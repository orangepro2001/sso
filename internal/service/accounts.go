package service

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"sso/internal/secure"
	"sso/internal/store"
)

// AccountRuleError is a change the account rules forbid (UserAccounts):
// locking out the last super administrator, or an administrator disabling
// themselves. The message is shown as it is, so it is written in the console's
// language.
type AccountRuleError struct {
	Field   string
	Message string
}

func (e *AccountRuleError) Error() string { return e.Message }

// RevokedCounts is what "sign out everywhere" reports and audits.
type RevokedCounts struct {
	AccessTokens  int64 `json:"access_tokens"`
	RefreshTokens int64 `json:"refresh_tokens"`
	Sessions      int64 `json:"sessions"`
}

// PasswordResetService mints one-time password reset links and revokes the
// credentials a password change invalidates.
//
// There is no mail flow: users have no address, so the link is minted by an
// administrator and handed over out of band. Only the SHA-256 is stored.
type PasswordResetService struct {
	Store    *store.Store
	Audit    *AuditLogger
	Issuer   string
	TTL      time.Duration
	LogReset func(url string, user *store.User)
}

// Issue creates a link, revoking any earlier unused one first: a person
// following an old link must not be able to set a password behind the
// administrator's back.
func (p *PasswordResetService) Issue(ctx context.Context, user *store.User, adminID *int64) (string, *store.PasswordReset, error) {
	if err := p.Store.RevokeOpenPasswordResets(ctx, user.ID); err != nil {
		return "", nil, err
	}

	plain := secure.Token("sso_pw_")
	row := &store.PasswordReset{
		UserID:    user.ID,
		TokenHash: secure.SHA256Hex(plain),
		CreatedBy: adminID,
		ExpiresAt: store.FromTime(time.Now().UTC().Add(p.TTL)),
	}
	if err := p.Store.InsertPasswordReset(ctx, row); err != nil {
		return "", nil, err
	}
	return plain, row, nil
}

// URL is the public address a human can actually open, built from the issuer
// rather than the container's internal origin.
func (p *PasswordResetService) URL(plain string) string {
	return strings.TrimRight(p.Issuer, "/") + "/password/reset/" + plain
}

func (p *PasswordResetService) Find(ctx context.Context, plain string) (*store.PasswordReset, error) {
	return p.Store.PasswordResetByHash(ctx, secure.SHA256Hex(plain))
}

// Consume marks the link spent; called only after the password changed.
func (p *PasswordResetService) Consume(ctx context.Context, reset *store.PasswordReset, ip string) error {
	var ipPtr *string
	if ip != "" {
		trimmed := truncate(ip, 45)
		ipPtr = &trimmed
	}
	return p.Store.ConsumePasswordReset(ctx, reset.ID, ipPtr)
}

// RevokeCredentials ends every credential a password could have opened.
// keepJTI spares the access token an API client used to make the change.
func (p *PasswordResetService) RevokeCredentials(ctx context.Context, user *store.User, keepJTI string) (RevokedCounts, error) {
	access, err := p.Store.RevokeAccessTokensForUser(ctx, user.ID, keepJTI)
	if err != nil {
		return RevokedCounts{}, err
	}
	refresh, err := p.Store.RevokeRefreshTokensForUser(ctx, user.ID)
	if err != nil {
		return RevokedCounts{}, err
	}
	return RevokedCounts{AccessTokens: access, RefreshTokens: refresh}, nil
}

// UserAccounts holds every change to an account, whoever asks for it: the
// console, the account page and the JSON API all call this, so the rules and
// the audit trail are the same whichever door the change came through.
//
// Two rules exist only here:
//   - there is always at least one active super administrator, otherwise
//     nobody can reach the console again;
//   - an administrator cannot demote, disable or delete themselves.
type UserAccounts struct {
	Store     *store.Store
	Audit     *AuditLogger
	Resets    *PasswordResetService
	Storage   string
	HashCosts int
}

// CreateUserInput is what both the console dialog and POST /api/users accept.
type CreateUserInput struct {
	Name     string
	Username string
	Password *string
	Role     string
	Note     *string
}

// Create inserts a user and returns the generated password when the caller left
// the field blank (the only moment the plaintext exists).
func (u *UserAccounts) Create(ctx context.Context, in CreateUserInput, actor *store.User, rm RequestMeta) (*store.User, string, error) {
	plain := passwordOrGenerated(in.Password)

	hash, err := secure.HashPassword(plain, u.HashCosts)
	if err != nil {
		return nil, "", err
	}

	role := in.Role
	if role == "" {
		role = store.RoleUser
	}

	user := &store.User{
		Name:      strings.TrimSpace(in.Name),
		Username:  secure.NormalizeUsername(in.Username),
		Role:      role,
		Password:  hash,
		Status:    store.StatusActive,
		Note:      in.Note,
		CreatedBy: &actor.ID,
	}
	if err := u.Store.InsertUser(ctx, user); err != nil {
		return nil, "", err
	}

	u.Audit.Log(ctx, "admin.user.created", "admin", itoa(actor.ID), "user", itoa(user.ID), map[string]any{
		"username": user.Username, "role": user.Role,
	}, rm)

	if in.Password == nil || *in.Password == "" {
		return user, plain, nil
	}
	return user, "", nil
}

// UserChanges is any subset of name, username, note, role and status. The
// pointers say "present" the way array_intersect_key did in PHP.
type UserChanges struct {
	Name     *string
	Username *string
	Note     *string
	NoteSet  bool
	Role     *string
	Status   *string
}

func (u *UserAccounts) Update(ctx context.Context, user *store.User, changes UserChanges, actor *store.User, rm RequestMeta) (*store.User, error) {
	// The lock-out guard runs before anything is written, and notices both a
	// demotion and a disable: either one ends the same way if this is the last
	// administrator.
	wasSuperActive := user.IsSuperAdmin() && user.IsActive()
	demotes := changes.Role != nil && *changes.Role != store.RoleSuperAdmin
	disables := changes.Status != nil && *changes.Status != store.StatusActive
	if wasSuperActive && (demotes || disables) {
		field := "role"
		if disables {
			field = "status"
		}
		if err := u.guardAdminLoss(ctx, user, actor, field); err != nil {
			return nil, err
		}
	}

	before := map[string]any{}
	after := map[string]any{}

	if changes.Name != nil {
		before["name"] = user.Name
		user.Name = strings.TrimSpace(*changes.Name)
		after["name"] = user.Name
	}
	if changes.Username != nil {
		before["username"] = user.Username
		user.Username = secure.NormalizeUsername(*changes.Username)
		after["username"] = user.Username
	}
	if changes.NoteSet {
		before["note"] = derefOrEmpty(user.Note)
		user.Note = changes.Note
		after["note"] = derefOrEmpty(user.Note)
	}
	if changes.Role != nil {
		before["role"] = user.Role
		user.Role = *changes.Role
		after["role"] = user.Role
	}
	if changes.Status != nil {
		before["status"] = user.Status
		user.Status = *changes.Status
		after["status"] = user.Status
	}

	changed := make([]string, 0, len(before))
	for key := range before {
		if before[key] != after[key] {
			changed = append(changed, key)
		}
	}
	if len(changed) == 0 {
		return user, nil
	}
	sortStrings(changed)

	if err := u.Store.SaveUser(ctx, user); err != nil {
		return nil, err
	}

	// A disabled account must stop working everywhere at once, not when its
	// seven-day token runs out or its browser session expires.
	if changes.Status != nil && !user.IsActive() {
		if _, err := u.endEverySession(ctx, user, ""); err != nil {
			return nil, err
		}
	}

	from := map[string]any{}
	to := map[string]any{}
	for _, key := range changed {
		from[key] = before[key]
		to[key] = after[key]
	}

	u.Audit.Log(ctx, "admin.user.updated", "admin", itoa(actor.ID), "user", itoa(user.ID), map[string]any{
		"username": user.Username,
		"changed":  changed,
		"from":     from,
		"to":       to,
	}, rm)

	return user, nil
}

// UpdateOwnProfile is a person changing their own display name (and, with the
// current password, their username).
func (u *UserAccounts) UpdateOwnProfile(ctx context.Context, user *store.User, name string, username *string, rm RequestMeta) error {
	beforeName, beforeUsername := user.Name, user.Username

	user.Name = strings.TrimSpace(name)
	if username != nil && *username != "" {
		user.Username = secure.NormalizeUsername(*username)
	}
	if err := u.Store.SaveUser(ctx, user); err != nil {
		return err
	}

	if beforeName != user.Name || beforeUsername != user.Username {
		u.Audit.Log(ctx, "user.profile.updated", "user", itoa(user.ID), "user", itoa(user.ID), map[string]any{
			"from": map[string]any{"name": beforeName, "username": beforeUsername},
			"to":   map[string]any{"name": user.Name, "username": user.Username},
		}, rm)
	}
	return nil
}

// SetPassword sets a password (blank = generate one) and ends every credential
// the old one produced. keepJTI spares the token making an API call, so a
// client that changes the password is not signed out by its own request.
func (u *UserAccounts) SetPassword(ctx context.Context, user *store.User, typed *string, actor *store.User, rm RequestMeta, keepJTI string) (string, error) {
	plain := passwordOrGenerated(typed)
	hash, err := secure.HashPassword(plain, u.HashCosts)
	if err != nil {
		return "", err
	}
	user.Password = hash
	if err := u.Store.SaveUser(ctx, user); err != nil {
		return "", err
	}

	revoked, err := u.Resets.RevokeCredentials(ctx, user, keepJTI)
	if err != nil {
		return "", err
	}

	self := actor.ID == user.ID
	event, actorType := "admin.user.password_reset", "admin"
	if self {
		event, actorType = "user.password.changed", "user"
	}
	u.Audit.Log(ctx, event, actorType, itoa(actor.ID), "user", itoa(user.ID), map[string]any{
		"username": user.Username, "revoked": revoked,
	}, rm)

	return plain, nil
}

// ResetLink mints the one-time link and returns it with its expiry.
func (u *UserAccounts) ResetLink(ctx context.Context, user *store.User, actor *store.User, rm RequestMeta) (string, time.Time, error) {
	plain, row, err := u.Resets.Issue(ctx, user, &actor.ID)
	if err != nil {
		return "", time.Time{}, err
	}

	url := u.Resets.URL(plain)
	if u.Resets.LogReset != nil {
		u.Resets.LogReset(url, user)
	}

	u.Audit.Log(ctx, "admin.user.reset_link_created", "admin", itoa(actor.ID), "user", itoa(user.ID), map[string]any{
		"username":   user.Username,
		"expires_at": row.ExpiresAt.ISO(),
	}, rm)

	return url, row.ExpiresAt.Time, nil
}

// AvatarUpload is an already-read picture: the HTTP layer has no business in
// the account rules, so it hands over the bytes.
type AvatarUpload struct {
	MIME string
	Data []byte
}

// StoreAvatar replaces the picture; the old file is removed, not archived.
// Pictures are cropped and shrunk in the browser (public/assets/console.js), so
// the server stores exactly what it receives.
func (u *UserAccounts) StoreAvatar(ctx context.Context, user *store.User, upload AvatarUpload, actor *store.User, rm RequestMeta) error {
	extension := "jpg"
	switch upload.MIME {
	case "image/png":
		extension = "png"
	case "image/webp":
		extension = "webp"
	case "image/gif":
		extension = "gif"
	}

	path := "avatars/" + itoa(user.ID) + "/" + time.Now().UTC().Format("20060102150405") + "-" +
		strings.ToLower(secure.RandomString(6)) + "." + extension

	absolute := filepath.Join(u.Storage, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(absolute), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(absolute, upload.Data, 0o644); err != nil {
		return err
	}

	if user.AvatarPath != nil && *user.AvatarPath != path {
		_ = os.Remove(filepath.Join(u.Storage, filepath.FromSlash(*user.AvatarPath)))
	}

	user.AvatarPath = &path
	user.AvatarMime = &upload.MIME
	user.AvatarUpdatedAt = store.Now()
	if err := u.Store.SaveUser(ctx, user); err != nil {
		return err
	}

	self := actor.ID == user.ID
	event, actorType := "admin.user.avatar_updated", "admin"
	if self {
		event, actorType = "user.avatar.updated", "user"
	}
	u.Audit.Log(ctx, event, actorType, itoa(actor.ID), "user", itoa(user.ID), map[string]any{"path": path}, rm)
	return nil
}

func (u *UserAccounts) RemoveAvatar(ctx context.Context, user *store.User, actor *store.User, rm RequestMeta) error {
	if !user.HasAvatar() {
		return nil
	}

	_ = os.Remove(filepath.Join(u.Storage, filepath.FromSlash(*user.AvatarPath)))

	user.AvatarPath = nil
	user.AvatarMime = nil
	user.AvatarUpdatedAt = store.Timestamp{}
	if err := u.Store.SaveUser(ctx, user); err != nil {
		return err
	}

	self := actor.ID == user.ID
	event, actorType := "admin.user.avatar_removed", "admin"
	if self {
		event, actorType = "user.avatar.removed", "user"
	}
	u.Audit.Log(ctx, event, actorType, itoa(actor.ID), "user", itoa(user.ID), nil, rm)
	return nil
}

// SignOutEverywhere signs the user out of every application (tokens) and every
// browser (sessions), keeping the browser that asked when it is their own.
func (u *UserAccounts) SignOutEverywhere(ctx context.Context, user *store.User, actor *store.User, rm RequestMeta, keepSessionID string) (RevokedCounts, error) {
	if actor.ID != user.ID {
		keepSessionID = ""
	}
	counts, err := u.endEverySession(ctx, user, keepSessionID)
	if err != nil {
		return RevokedCounts{}, err
	}

	self := actor.ID == user.ID
	event, actorType := "admin.user.signed_out", "admin"
	if self {
		event, actorType = "user.tokens.revoked", "user"
	}
	u.Audit.Log(ctx, event, actorType, itoa(actor.ID), "user", itoa(user.ID), map[string]any{
		"access_tokens": counts.AccessTokens, "refresh_tokens": counts.RefreshTokens, "sessions": counts.Sessions,
	}, rm)

	return counts, nil
}

// Delete removes the account. Tokens, codes and reset links go with it
// (cascade); other applications keep whatever they hold under the old subject.
func (u *UserAccounts) Delete(ctx context.Context, user *store.User, actor *store.User, rm RequestMeta) error {
	if user.ID == actor.ID {
		return &AccountRuleError{Field: "user", Message: "자기 자신의 계정은 삭제할 수 없습니다."}
	}
	if user.IsSuperAdmin() && user.IsActive() {
		if err := u.guardAdminLoss(ctx, user, actor, "user"); err != nil {
			return err
		}
	}

	snapshot := map[string]any{
		"username": user.Username, "name": user.Name, "role": user.Role, "status": user.Status,
	}

	if _, err := u.Store.DeleteSessionsForUser(ctx, user.ID, ""); err != nil {
		return err
	}
	if user.AvatarPath != nil {
		_ = os.Remove(filepath.Join(u.Storage, filepath.FromSlash(*user.AvatarPath)))
	}
	if err := u.Store.DeleteUser(ctx, user.ID); err != nil {
		return err
	}

	u.Audit.Log(ctx, "admin.user.deleted", "admin", itoa(actor.ID), "user", itoa(user.ID), snapshot, rm)
	return nil
}

func (u *UserAccounts) guardAdminLoss(ctx context.Context, user *store.User, actor *store.User, field string) error {
	if user.ID == actor.ID {
		return &AccountRuleError{Field: field, Message: "자기 자신의 관리자 권한을 내리거나 계정을 비활성화할 수 없습니다. 다른 관리자에게 요청하세요."}
	}
	others, err := u.Store.OtherActiveAdmins(ctx, user.ID)
	if err != nil {
		return err
	}
	if !others {
		return &AccountRuleError{Field: field, Message: "마지막 관리자입니다. 다른 사람을 먼저 관리자로 지정하세요."}
	}
	return nil
}

func (u *UserAccounts) endEverySession(ctx context.Context, user *store.User, keepSessionID string) (RevokedCounts, error) {
	counts, err := u.Resets.RevokeCredentials(ctx, user, "")
	if err != nil {
		return RevokedCounts{}, err
	}
	sessions, err := u.Store.DeleteSessionsForUser(ctx, user.ID, keepSessionID)
	if err != nil {
		return RevokedCounts{}, err
	}
	counts.Sessions = sessions
	return counts, nil
}

// passwordOrGenerated makes a twelve-character password without look-alikes:
// read aloud or typed from a chat message, a generated password is copied by a
// person, not a machine.
func passwordOrGenerated(typed *string) string {
	if typed != nil && *typed != "" {
		return *typed
	}
	return secure.RandomFrom("abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789", 12)
}

func derefOrEmpty(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

func sortStrings(values []string) { sort.Strings(values) }
