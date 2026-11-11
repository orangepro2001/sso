package server

import (
	"context"
	"net/http"
	"strings"

	"sso/internal/secure"
	"sso/internal/service"
	"sso/internal/store"
)

type tokenContextKey struct{}

func tokenOf(r *http.Request) *store.AccessToken {
	if record, ok := r.Context().Value(tokenContextKey{}).(*store.AccessToken); ok {
		return record
	}
	return nil
}

func apiUserOf(r *http.Request) *store.User {
	if record := tokenOf(r); record != nil && record.UserID != nil {
		if user, ok := r.Context().Value(userContextKey{}).(*store.User); ok {
			return user
		}
	}
	return nil
}

type userContextKey struct{}

// apiToken is AuthenticateToken: the account API is called with the access
// token an application received at sign-in, never with a session.
//
// `""` means any active user holding a token with the `profile` scope;
// `"admin"` additionally a super administrator, the console's rule.
func (s *Server) apiToken(next http.HandlerFunc, level string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		plain := bearerToken(r)
		var record *store.AccessToken
		var err error
		if plain != "" {
			record, err = s.Tokens.Resolve(ctx, plain)
			if err != nil {
				s.serverError(w, r, err)
				return
			}
		}

		if record == nil || record.SubjectType != store.SubjectUser || record.UserID == nil {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			s.json(w, http.StatusUnauthorized, map[string]string{
				"error": "invalid_token", "message": "토큰이 없거나 만료되었습니다. 다시 로그인하세요.",
			})
			return
		}

		if !contains(record.Scopes, "profile") {
			s.json(w, http.StatusForbidden, map[string]string{
				"error": "insufficient_scope", "message": "이 토큰에는 profile 범위가 없습니다.",
			})
			return
		}

		user, err := s.Store.UserByID(ctx, *record.UserID)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		if user == nil || !user.IsActive() {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			s.json(w, http.StatusUnauthorized, map[string]string{
				"error": "invalid_token", "message": "토큰이 없거나 만료되었습니다. 다시 로그인하세요.",
			})
			return
		}

		if level == "admin" && !user.IsSuperAdmin() {
			s.json(w, http.StatusForbidden, map[string]string{
				"error": "forbidden", "message": "관리자만 사용할 수 있습니다.",
			})
			return
		}

		// Rate limits: 120 requests/minute on /api/me, 240 on /api/users.
		max := 120
		if level == "admin" {
			max = 240
		}
		key := "api:" + itoa(record.ID)
		if tooMany, _ := s.Limiter.tooMany(key, max); tooMany {
			s.json(w, http.StatusTooManyRequests, map[string]any{
				"message": "요청이 너무 많습니다.",
				"errors":  map[string][]string{},
			})
			return
		}
		s.Limiter.hit(key, minute)

		ctx = context.WithValue(ctx, tokenContextKey{}, record)
		ctx = context.WithValue(ctx, userContextKey{}, user)
		next(w, r.WithContext(ctx))
	}
}

// ---- the user object -----------------------------------------------------

// userResource is /api/me's account shape. The note, last sign-in address and
// creator are administrative detail and only reach a super administrator.
type userResource struct {
	ID          int64   `json:"id"`
	Username    string  `json:"username"`
	Name        string  `json:"name"`
	Role        string  `json:"role"`
	Status      string  `json:"status"`
	Picture     *string `json:"picture"`
	CreatedAt   *string `json:"created_at"`
	LastLoginAt *string `json:"last_login_at"`
}

type adminUserResource struct {
	userResource
	Note        *string `json:"note"`
	LastLoginIP *string `json:"last_login_ip"`
	CreatedBy   *int64  `json:"created_by"`
}

func (s *Server) resource(user, viewer *store.User) any {
	base := userResource{
		ID:       user.ID,
		Username: user.Username,
		Name:     user.Name,
		Role:     user.Role,
		Status:   user.Status,
		Picture:  user.AvatarURL(s.Cfg.Issuer, s.Cfg.AppKey),
	}
	if user.CreatedAt.Valid {
		iso := user.CreatedAt.ISO()
		base.CreatedAt = &iso
	}
	if user.LastLoginAt.Valid {
		iso := user.LastLoginAt.ISO()
		base.LastLoginAt = &iso
	}

	if viewer != nil && viewer.IsSuperAdmin() {
		return adminUserResource{
			userResource: base,
			Note:         user.Note,
			LastLoginIP:  user.LastLoginIP,
			CreatedBy:    user.CreatedBy,
		}
	}
	return base
}

// ---- /api/me -------------------------------------------------------------

func (s *Server) apiMeShow(w http.ResponseWriter, r *http.Request) {
	user := apiUserOf(r)
	s.json(w, http.StatusOK, s.resource(user, user))
}

func (s *Server) apiMeUpdate(w http.ResponseWriter, r *http.Request) {
	user := apiUserOf(r)
	p := s.params(r)

	name := strings.TrimSpace(p.input("name"))
	v := newValidation()
	if name == "" {
		v.add("name", msgRequired("name"))
	} else if len(name) > 120 {
		v.add("name", msgMaxString("name", 120))
	}
	if v.any() {
		s.validationFailed(w, v)
		return
	}

	if err := s.Accounts.UpdateOwnProfile(r.Context(), user, name, nil, s.requestMeta(r)); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, s.resource(user, user))
}

func (s *Server) apiMeAvatar(w http.ResponseWriter, r *http.Request) {
	user := apiUserOf(r)
	upload, fieldErr := s.readAvatar(r)
	if fieldErr != "" {
		v := newValidation()
		v.add("avatar", fieldErr)
		s.validationFailed(w, v)
		return
	}
	if err := s.Accounts.StoreAvatar(r.Context(), user, upload, user, s.requestMeta(r)); err != nil {
		s.serverError(w, r, err)
		return
	}
	fresh, _ := s.Store.UserByID(r.Context(), user.ID)
	if fresh == nil {
		fresh = user
	}
	s.json(w, http.StatusOK, s.resource(fresh, user))
}

func (s *Server) apiMeAvatarRemove(w http.ResponseWriter, r *http.Request) {
	user := apiUserOf(r)
	if err := s.Accounts.RemoveAvatar(r.Context(), user, user, s.requestMeta(r)); err != nil {
		s.serverError(w, r, err)
		return
	}
	fresh, _ := s.Store.UserByID(r.Context(), user.ID)
	if fresh == nil {
		fresh = user
	}
	s.json(w, http.StatusOK, s.resource(fresh, user))
}

func (s *Server) apiMePassword(w http.ResponseWriter, r *http.Request) {
	user := apiUserOf(r)
	p := s.params(r)

	current := p.input("current_password")
	password := p.input("password")

	v := newValidation()
	if current == "" {
		v.add("current_password", msgRequired("current_password"))
	}
	if password == "" {
		v.add("password", msgRequired("password"))
	} else if password == current {
		v.add("password", msgDifferent("password", "current_password"))
	}
	if v.any() {
		s.validationFailed(w, v)
		return
	}

	if !secure.CheckPassword(user.Password, current) {
		v.add("current_password", "현재 비밀번호가 맞지 않습니다.")
		s.validationFailed(w, v)
		return
	}

	// The username is not changeable here: it is what applications match on, and
	// a change needs the password, which an application should never see.
	record := tokenOf(r)
	keepJTI := ""
	if record != nil {
		keepJTI = record.JTI
	}
	if _, err := s.Accounts.SetPassword(r.Context(), user, &password, user, s.requestMeta(r), keepJTI); err != nil {
		s.serverError(w, r, err)
		return
	}

	s.json(w, http.StatusOK, map[string]string{"message": "비밀번호를 바꿨습니다. 다른 기기에서는 로그아웃됩니다."})
}

// ---- /api/users ----------------------------------------------------------

func (s *Server) apiUsersIndex(w http.ResponseWriter, r *http.Request) {
	viewer := apiUserOf(r)
	q := r.URL.Query()

	role := q.Get("role")
	status := q.Get("status")
	perPage := 50
	if raw := q.Get("per_page"); raw != "" {
		if n, ok := atoi(raw); ok && n >= 1 && n <= 200 {
			perPage = int(n)
		}
	}

	v := newValidation()
	if term := q.Get("q"); len(term) > 120 {
		v.add("q", msgMaxString("q", 120))
	}
	if role != "" && role != store.RoleUser && role != store.RoleSuperAdmin {
		v.add("role", msgIn("role"))
	}
	if status != "" && status != store.StatusActive && status != store.StatusDisabled {
		v.add("status", msgIn("status"))
	}
	if v.any() {
		s.validationFailed(w, v)
		return
	}

	page := 1
	if raw := q.Get("page"); raw != "" {
		if n, ok := atoi(raw); ok && n >= 1 {
			page = int(n)
		}
	}

	filter := store.UserFilter{Search: q.Get("q"), Role: role, Status: status, OrderBy: "name", Limit: perPage, Offset: (page - 1) * perPage}
	users, total, err := s.Store.ListUsers(r.Context(), filter)
	if err != nil {
		s.serverError(w, r, err)
		return
	}

	data := make([]any, 0, len(users))
	for _, user := range users {
		data = append(data, s.resource(user, viewer))
	}

	s.json(w, http.StatusOK, s.paginated(r, data, total, perPage, page))
}

func (s *Server) apiUsersShow(w http.ResponseWriter, r *http.Request) {
	user, ok := s.apiParamUser(w, r)
	if !ok {
		return
	}
	s.json(w, http.StatusOK, s.resource(user, apiUserOf(r)))
}

func (s *Server) apiUsersStore(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	viewer := apiUserOf(r)
	p := s.params(r)

	name := strings.TrimSpace(p.input("name"))
	username := secure.NormalizeUsername(p.input("username"))
	role := p.input("role")
	if role == "" {
		role = store.RoleUser
	}

	v := newValidation()
	if name == "" {
		v.add("name", msgRequired("name"))
	} else if len(name) > 120 {
		v.add("name", msgMaxString("name", 120))
	}
	v.addUsername(p, 0, false)
	if !v.Has("username") {
		if taken, err := s.Store.UsernameTaken(ctx, username, 0); err != nil {
			s.serverError(w, r, err)
			return
		} else if taken {
			v.add("username", msgUnique("username"))
		}
	}
	if role != store.RoleUser && role != store.RoleSuperAdmin {
		v.add("role", msgIn("role"))
	}
	if note := p.input("note"); len(note) > 2000 {
		v.add("note", msgMaxString("note", 2000))
	}
	if v.any() {
		s.validationFailed(w, v)
		return
	}

	user, generated, err := s.Accounts.Create(ctx, service.CreateUserInput{
		Name: name, Username: username, Password: optionalString(p.input("password")), Role: role,
		Note: optionalString(p.input("note")),
	}, viewer, s.requestMeta(r))
	if err != nil {
		s.serverError(w, r, err)
		return
	}

	body := s.resource(user, viewer)
	if generated != "" {
		// The only copy of the plaintext; the caller shows it once.
		body = withGeneratedPassword(body, generated)
	}
	s.json(w, http.StatusCreated, body)
}

func (s *Server) apiUsersUpdate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user, ok := s.apiParamUser(w, r)
	if !ok {
		return
	}
	viewer := apiUserOf(r)
	p := s.params(r)

	v := newValidation()
	changes := service.UserChanges{}

	if p.has("name") {
		name := strings.TrimSpace(p.input("name"))
		if name == "" {
			v.add("name", msgRequired("name"))
		} else if len(name) > 120 {
			v.add("name", msgMaxString("name", 120))
		}
		changes.Name = &name
	}
	if p.has("username") {
		username := secure.NormalizeUsername(p.input("username"))
		v.addUsername(p, user.ID, true)
		if !v.Has("username") {
			if taken, err := s.Store.UsernameTaken(ctx, username, user.ID); err != nil {
				s.serverError(w, r, err)
				return
			} else if taken {
				v.add("username", msgUnique("username"))
			}
		}
		changes.Username = &username
	}
	if p.has("role") {
		role := p.input("role")
		if role != store.RoleUser && role != store.RoleSuperAdmin {
			v.add("role", msgIn("role"))
		}
		changes.Role = &role
	}
	if p.has("status") {
		status := p.input("status")
		if status != store.StatusActive && status != store.StatusDisabled {
			v.add("status", msgIn("status"))
		}
		changes.Status = &status
	}
	if p.has("note") {
		note := p.input("note")
		if len(note) > 2000 {
			v.add("note", msgMaxString("note", 2000))
		}
		changes.Note = optionalString(note)
		changes.NoteSet = true
	}
	if v.any() {
		s.validationFailed(w, v)
		return
	}

	updated, err := s.Accounts.Update(ctx, user, changes, viewer, s.requestMeta(r))
	if err != nil {
		if s.accountRule(w, r, nil, err) {
			return
		}
		s.serverError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, s.resource(updated, viewer))
}

func (s *Server) apiUsersDestroy(w http.ResponseWriter, r *http.Request) {
	user, ok := s.apiParamUser(w, r)
	if !ok {
		return
	}
	if err := s.Accounts.Delete(r.Context(), user, apiUserOf(r), s.requestMeta(r)); err != nil {
		if s.accountRule(w, r, nil, err) {
			return
		}
		s.serverError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) apiUsersPassword(w http.ResponseWriter, r *http.Request) {
	user, ok := s.apiParamUser(w, r)
	if !ok {
		return
	}
	plain, err := s.Accounts.SetPassword(r.Context(), user, optionalString(s.params(r).input("password")),
		apiUserOf(r), s.requestMeta(r), "")
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, map[string]string{"password": plain})
}

func (s *Server) apiUsersResetLink(w http.ResponseWriter, r *http.Request) {
	user, ok := s.apiParamUser(w, r)
	if !ok {
		return
	}
	url, expiresAt, err := s.Accounts.ResetLink(r.Context(), user, apiUserOf(r), s.requestMeta(r))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, map[string]string{
		"url":        url,
		"expires_at": expiresAt.UTC().Format("2006-01-02T15:04:05+00:00"),
	})
}

func (s *Server) apiUsersAvatar(w http.ResponseWriter, r *http.Request) {
	user, ok := s.apiParamUser(w, r)
	if !ok {
		return
	}
	viewer := apiUserOf(r)
	upload, fieldErr := s.readAvatar(r)
	if fieldErr != "" {
		v := newValidation()
		v.add("avatar", fieldErr)
		s.validationFailed(w, v)
		return
	}
	if err := s.Accounts.StoreAvatar(r.Context(), user, upload, viewer, s.requestMeta(r)); err != nil {
		s.serverError(w, r, err)
		return
	}
	fresh, _ := s.Store.UserByID(r.Context(), user.ID)
	if fresh == nil {
		fresh = user
	}
	s.json(w, http.StatusOK, s.resource(fresh, viewer))
}

func (s *Server) apiUsersAvatarRemove(w http.ResponseWriter, r *http.Request) {
	user, ok := s.apiParamUser(w, r)
	if !ok {
		return
	}
	viewer := apiUserOf(r)
	if err := s.Accounts.RemoveAvatar(r.Context(), user, viewer, s.requestMeta(r)); err != nil {
		s.serverError(w, r, err)
		return
	}
	fresh, _ := s.Store.UserByID(r.Context(), user.ID)
	if fresh == nil {
		fresh = user
	}
	s.json(w, http.StatusOK, s.resource(fresh, viewer))
}

func (s *Server) apiUsersSignOut(w http.ResponseWriter, r *http.Request) {
	user, ok := s.apiParamUser(w, r)
	if !ok {
		return
	}
	counts, err := s.Accounts.SignOutEverywhere(r.Context(), user, apiUserOf(r), s.requestMeta(r), "")
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.json(w, http.StatusOK, counts)
}

func (s *Server) apiParamUser(w http.ResponseWriter, r *http.Request) (*store.User, bool) {
	id, ok := atoi(r.PathValue("user"))
	if !ok {
		s.apiNotFound(w)
		return nil, false
	}
	user, err := s.Store.UserByID(r.Context(), id)
	if err != nil {
		s.serverError(w, r, err)
		return nil, false
	}
	if user == nil {
		s.apiNotFound(w)
		return nil, false
	}
	return user, true
}

func (s *Server) apiNotFound(w http.ResponseWriter) {
	s.json(w, http.StatusNotFound, map[string]string{"message": "찾을 수 없습니다."})
}

// validationFailed is Laravel's 422: a message plus the field errors.
func (s *Server) validationFailed(w http.ResponseWriter, v *validation) {
	message := ""
	for _, field := range []string{"name", "username", "password", "current_password", "avatar", "role", "status", "note", "q", "confirm"} {
		if list := v.Errors[field]; len(list) > 0 {
			message = list[0]
			break
		}
	}
	if message == "" {
		for _, list := range v.Errors {
			if len(list) > 0 {
				message = list[0]
				break
			}
		}
	}
	s.json(w, http.StatusUnprocessableEntity, map[string]any{
		"message": message,
		"errors":  v.Errors,
	})
}

// paginated is the shape of an Eloquent resource collection: data, links, meta.
func (s *Server) paginated(r *http.Request, data []any, total, perPage, page int) map[string]any {
	last := (total + perPage - 1) / perPage
	if last < 1 {
		last = 1
	}
	path := s.publicBase(r) + r.URL.Path

	link := func(p int) any {
		if p < 1 || p > last {
			return nil
		}
		query := r.URL.Query()
		if p <= 1 {
			query.Del("page")
		} else {
			query.Set("page", itoa(int64(p)))
		}
		if encoded := query.Encode(); encoded != "" {
			return path + "?" + encoded
		}
		return path
	}

	from := (page-1)*perPage + 1
	to := page * perPage
	if to > total {
		to = total
	}
	if total == 0 {
		from, to = 0, 0
	}

	return map[string]any{
		"data": data,
		"links": map[string]any{
			"first": link(1),
			"last":  link(last),
			"prev":  link(page - 1),
			"next":  link(page + 1),
		},
		"meta": map[string]any{
			"current_page": page,
			"from":         from,
			"last_page":    last,
			"links":        []any{},
			"path":         path,
			"per_page":     perPage,
			"to":           to,
			"total":        total,
		},
	}
}

// withGeneratedPassword adds the one-time plaintext to a user object without
// disturbing the rest of the shape.
func withGeneratedPassword(body any, generated string) any {
	switch value := body.(type) {
	case userResource:
		return struct {
			userResource
			GeneratedPassword string `json:"generated_password"`
		}{value, generated}
	case adminUserResource:
		return struct {
			adminUserResource
			GeneratedPassword string `json:"generated_password"`
		}{value, generated}
	}
	return body
}
