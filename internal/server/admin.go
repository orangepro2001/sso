package server

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"sso/internal/config"
	"sso/internal/secure"
	"sso/internal/service"
	"sso/internal/store"
)

// adminGuard is AuthenticateAdmin: the console is for active users whose role
// is super_admin. There is one sign-in (the user one); this only checks the
// role. The signed-in user is the actor for every audit row here.
func (s *Server) adminGuard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := s.currentUser(r)
		if user == nil {
			if sess := sessionOf(r); sess != nil {
				sess.put("url.intended", s.absoluteURL(r))
			}
			s.redirect(w, r, "/login", http.StatusFound)
			return
		}
		if !user.IsActive() || !user.IsSuperAdmin() {
			s.forbidden(w, r, "The console is for super administrators.")
			return
		}
		next(w, r)
	}
}

// adminLogin is the old console sign-in address. The console has no sign-in of
// its own any more: it sends the visitor to the user sign-in and comes back.
func (s *Server) adminLogin(w http.ResponseWriter, r *http.Request) {
	if sess := sessionOf(r); sess != nil {
		sess.put("url.intended", s.publicBase(r)+"/admin")
	}
	s.redirect(w, r, "/login", http.StatusFound)
}

func (s *Server) adminLogout(w http.ResponseWriter, r *http.Request) {
	user := s.currentUser(r)
	actorID := ""
	if user != nil {
		actorID = itoa(user.ID)
	}
	s.Audit.Log(r.Context(), "user.logout", "user", actorID, "user", actorID, nil, s.requestMeta(r))
	if sess := sessionOf(r); sess != nil {
		sess.invalidate()
	}
	s.redirect(w, r, "/", http.StatusFound)
}

// adminDashboard opens the console on the people it manages; the old status
// board answered questions nobody here asks.
func (s *Server) adminDashboard(w http.ResponseWriter, r *http.Request) {
	s.redirect(w, r, "/admin/users", http.StatusFound)
}

// ---- users ---------------------------------------------------------------

func (s *Server) adminUsersIndex(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	search := strings.TrimSpace(r.URL.Query().Get("q"))
	filter := r.URL.Query().Get("filter")
	if filter == "" {
		filter = "all"
	}

	f := store.UserFilter{Search: search}
	switch filter {
	case "admin":
		f.Role = store.RoleSuperAdmin
	case "user":
		f.Role = store.RoleUser
	case "disabled":
		f.Status = store.StatusDisabled
	}

	page := pageParam(r)
	f.Limit = 50
	f.Offset = (page - 1) * 50

	users, total, err := s.Store.ListUsers(ctx, f)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	counts, err := s.Store.UserCounts(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}

	data := map[string]any{
		"Title":   "사용자",
		"Users":   users,
		"Search":  search,
		"Filter":  filter,
		"Counts":  counts,
		"Chips":   userChips(s.publicBase(r)+"/admin/users", search, filter, counts),
		"Pager":   s.pager(r, total, 50, page),
		"Main":    "",
		"OpenNow": r.URL.Query().Get("new") != "",
	}
	s.render(w, r, http.StatusOK, "admin/users/index", data)
}

type chip struct {
	Label  string
	Count  int
	URL    string
	Active bool
}

func userChips(base, search, filter string, counts map[string]int) []chip {
	order := []struct{ key, label string }{
		{"all", "전체"}, {"admin", "관리자"}, {"user", "일반"}, {"disabled", "비활성"},
	}
	out := make([]chip, 0, len(order))
	for _, item := range order {
		query := url.Values{}
		if item.key != "all" {
			query.Set("filter", item.key)
		}
		if search != "" {
			query.Set("q", search)
		}
		target := base
		if encoded := query.Encode(); encoded != "" {
			target += "?" + encoded
		}
		out = append(out, chip{Label: item.label, Count: counts[item.key], URL: target, Active: filter == item.key})
	}
	return out
}

func (s *Server) adminUsersCreate(w http.ResponseWriter, r *http.Request) {
	s.redirect(w, r, "/admin/users?new=1", http.StatusFound)
}

func (s *Server) adminUsersEdit(w http.ResponseWriter, r *http.Request) {
	user, ok := s.adminParamUser(w, r)
	if !ok {
		return
	}
	s.redirect(w, r, "/admin/users/"+itoa(user.ID), http.StatusFound)
}

func (s *Server) adminUsersStore(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	actor := s.currentUser(r)
	sess := sessionOf(r)
	p := s.params(r)

	name := strings.TrimSpace(p.input("name"))
	username := secure.NormalizeUsername(p.input("username"))

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
	role := p.input("role")
	if role == "" {
		role = store.RoleUser
	}
	if role != store.RoleUser && role != store.RoleSuperAdmin {
		v.add("role", msgIn("role"))
	}
	if note := p.input("note"); len(note) > 2000 {
		v.add("note", msgMaxString("note", 2000))
	}
	if v.any() {
		// A failed create reopens the dialog on the list: the errors belong to
		// the "create" bag in PHP, which is why they do not also flash above the
		// page.
		if sess != nil {
			sess.put("create_errors", v.Errors)
			sess.put("create_old", map[string]string{
				"name": name, "username": username, "role": role, "note": p.input("note"),
			})
			s.redirect(w, r, "/admin/users", http.StatusFound)
			return
		}
		s.validationFailed(w, v)
		return
	}

	note := optionalString(p.input("note"))
	password := optionalString(p.input("password"))
	user, generated, err := s.Accounts.Create(ctx, service.CreateUserInput{
		Name: name, Username: username, Password: password, Role: role, Note: note,
	}, actor, s.requestMeta(r))
	if err != nil {
		s.serverError(w, r, err)
		return
	}

	if sess != nil {
		sess.put("status", user.Name+" ("+user.Username+") 계정을 만들었습니다.")
		if generated != "" {
			sess.put("generated_password", map[string]string{user.Username: generated})
		}
	}
	s.redirect(w, r, "/admin/users/"+itoa(user.ID), http.StatusFound)
}

func (s *Server) adminUsersShow(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user, ok := s.adminParamUser(w, r)
	if !ok {
		return
	}
	actor := s.currentUser(r)

	activity, err := s.Store.AuditForUser(ctx, user.ID, 12)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	tokens, err := s.Store.ActiveTokensForUser(ctx, user.ID, 20)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	clients, err := s.Store.ClientNames(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}

	var creator *store.User
	if user.CreatedBy != nil {
		creator, _ = s.Store.UserByID(ctx, *user.CreatedBy)
	}

	s.render(w, r, http.StatusOK, "admin/users/show", map[string]any{
		"Title":    user.Name,
		"User":     user,
		"Self":     actor != nil && actor.ID == user.ID,
		"Tokens":   tokens,
		"Activity": activity,
		"Creator":  creator,
		"P":        &Presenter{People: s.People(ctx, activity), Clients: clients},
		"Main":     "",
	})
}

func (s *Server) adminUsersUpdate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user, ok := s.adminParamUser(w, r)
	if !ok {
		return
	}
	actor := s.currentUser(r)
	sess := sessionOf(r)
	p := s.params(r)

	name := strings.TrimSpace(p.input("name"))
	username := secure.NormalizeUsername(p.input("username"))

	v := newValidation()
	if name == "" {
		v.add("name", msgRequired("name"))
	} else if len(name) > 120 {
		v.add("name", msgMaxString("name", 120))
	}
	v.addUsername(p, user.ID, false)
	if !v.Has("username") {
		if taken, err := s.Store.UsernameTaken(ctx, username, user.ID); err != nil {
			s.serverError(w, r, err)
			return
		} else if taken {
			v.add("username", msgUnique("username"))
		}
	}
	if note := p.input("note"); len(note) > 2000 {
		v.add("note", msgMaxString("note", 2000))
	}
	if v.any() {
		s.failWith(w, r, sess, "/admin/users/"+itoa(user.ID), v, map[string]string{
			"name": name, "username": username, "note": p.input("note"),
		})
		return
	}

	changes := service.UserChanges{Name: &name, Username: &username, Note: optionalString(p.input("note")), NoteSet: p.has("note")}
	if _, err := s.Accounts.Update(ctx, user, changes, actor, s.requestMeta(r)); err != nil {
		if s.accountRule(w, r, sess, err) {
			return
		}
		s.serverError(w, r, err)
		return
	}

	if sess != nil {
		sess.put("status", "기본 정보를 저장했습니다.")
	}
	s.back(w, r)
}

func (s *Server) adminUsersRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user, ok := s.adminParamUser(w, r)
	if !ok {
		return
	}
	actor := s.currentUser(r)
	sess := sessionOf(r)
	role := s.params(r).input("role")

	v := newValidation()
	if role != store.RoleUser && role != store.RoleSuperAdmin {
		v.add("role", msgIn("role"))
		s.failWith(w, r, sess, "/admin/users/"+itoa(user.ID), v, map[string]string{})
		return
	}

	if _, err := s.Accounts.Update(ctx, user, service.UserChanges{Role: &role}, actor, s.requestMeta(r)); err != nil {
		if s.accountRule(w, r, sess, err) {
			return
		}
		s.serverError(w, r, err)
		return
	}

	if sess != nil {
		if user.IsSuperAdmin() {
			sess.put("status", user.Name+" 님을 관리자로 지정했습니다.")
		} else {
			sess.put("status", user.Name+" 님을 일반 사용자로 바꿨습니다.")
		}
	}
	s.back(w, r)
}

func (s *Server) adminUsersStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user, ok := s.adminParamUser(w, r)
	if !ok {
		return
	}
	actor := s.currentUser(r)
	sess := sessionOf(r)
	status := s.params(r).input("status")

	v := newValidation()
	if status != store.StatusActive && status != store.StatusDisabled {
		v.add("status", msgIn("status"))
		s.failWith(w, r, sess, "/admin/users/"+itoa(user.ID), v, map[string]string{})
		return
	}

	if _, err := s.Accounts.Update(ctx, user, service.UserChanges{Status: &status}, actor, s.requestMeta(r)); err != nil {
		if s.accountRule(w, r, sess, err) {
			return
		}
		s.serverError(w, r, err)
		return
	}

	if sess != nil {
		if user.IsActive() {
			sess.put("status", user.Name+" 님의 계정을 다시 활성화했습니다.")
		} else {
			sess.put("status", user.Name+" 님의 계정을 비활성화했습니다. 모든 앱과 브라우저에서 로그아웃됩니다.")
		}
	}
	s.back(w, r)
}

func (s *Server) adminUsersPassword(w http.ResponseWriter, r *http.Request) {
	user, ok := s.adminParamUser(w, r)
	if !ok {
		return
	}
	actor := s.currentUser(r)
	sess := sessionOf(r)

	plain, err := s.Accounts.SetPassword(r.Context(), user, optionalString(s.params(r).input("password")), actor, s.requestMeta(r), "")
	if err != nil {
		s.serverError(w, r, err)
		return
	}

	if sess != nil {
		sess.put("status", "비밀번호를 설정했습니다. 이 사용자는 모든 앱에서 로그아웃됩니다.")
		sess.put("generated_password", map[string]string{user.Username: plain})
	}
	s.redirect(w, r, "/admin/users/"+itoa(user.ID), http.StatusFound)
}

func (s *Server) adminUsersResetLink(w http.ResponseWriter, r *http.Request) {
	user, ok := s.adminParamUser(w, r)
	if !ok {
		return
	}
	actor := s.currentUser(r)
	sess := sessionOf(r)

	url, expiresAt, err := s.Accounts.ResetLink(r.Context(), user, actor, s.requestMeta(r))
	if err != nil {
		s.serverError(w, r, err)
		return
	}

	if sess != nil {
		sess.put("status", "비밀번호 재설정 링크를 만들었습니다.")
		sess.put("reset_url", url)
		// The PHP formatted this Carbon value without converting it, so the
		// console printed UTC here while every other time went through When::at.
		sess.put("reset_expires", expiresAt.UTC().Format("2006-01-02 15:04"))
	}
	s.redirect(w, r, "/admin/users/"+itoa(user.ID), http.StatusFound)
}

func (s *Server) adminUsersAvatar(w http.ResponseWriter, r *http.Request) {
	user, ok := s.adminParamUser(w, r)
	if !ok {
		return
	}
	actor := s.currentUser(r)
	upload, fieldErr := s.readAvatar(r)
	if fieldErr != "" {
		v := newValidation()
		v.add("avatar", fieldErr)
		s.failWith(w, r, sessionOf(r), "/admin/users/"+itoa(user.ID), v, map[string]string{})
		return
	}
	if err := s.Accounts.StoreAvatar(r.Context(), user, upload, actor, s.requestMeta(r)); err != nil {
		s.serverError(w, r, err)
		return
	}
	if sess := sessionOf(r); sess != nil {
		sess.put("status", "프로필 사진을 바꿨습니다.")
	}
	s.back(w, r)
}

func (s *Server) adminUsersAvatarRemove(w http.ResponseWriter, r *http.Request) {
	user, ok := s.adminParamUser(w, r)
	if !ok {
		return
	}
	if err := s.Accounts.RemoveAvatar(r.Context(), user, s.currentUser(r), s.requestMeta(r)); err != nil {
		s.serverError(w, r, err)
		return
	}
	if sess := sessionOf(r); sess != nil {
		sess.put("status", "프로필 사진을 지웠습니다.")
	}
	s.back(w, r)
}

func (s *Server) adminUsersSignOut(w http.ResponseWriter, r *http.Request) {
	user, ok := s.adminParamUser(w, r)
	if !ok {
		return
	}
	actor := s.currentUser(r)
	sess := sessionOf(r)
	keep := ""
	if sess != nil && actor != nil && actor.ID == user.ID {
		keep = sess.id
	}

	counts, err := s.Accounts.SignOutEverywhere(r.Context(), user, actor, s.requestMeta(r), keep)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if sess != nil {
		sess.put("status", "모든 곳에서 로그아웃시켰습니다 (앱 토큰 "+itoa(counts.AccessTokens)+"개, 브라우저 세션 "+itoa(counts.Sessions)+"개).")
	}
	s.back(w, r)
}

func (s *Server) adminUsersDestroy(w http.ResponseWriter, r *http.Request) {
	user, ok := s.adminParamUser(w, r)
	if !ok {
		return
	}
	actor := s.currentUser(r)
	sess := sessionOf(r)
	confirm := s.params(r).input("confirm")

	v := newValidation()
	switch {
	case confirm == "":
		v.add("confirm", "확인란에 아이디를 입력하세요.")
	case confirm != user.Username:
		v.add("confirm", "확인란에 아이디를 정확히 입력하세요.")
	}
	if v.any() {
		s.failWith(w, r, sess, "/admin/users/"+itoa(user.ID), v, map[string]string{})
		return
	}

	name, username := user.Name, user.Username
	if err := s.Accounts.Delete(r.Context(), user, actor, s.requestMeta(r)); err != nil {
		if s.accountRule(w, r, sess, err) {
			return
		}
		s.serverError(w, r, err)
		return
	}

	if sess != nil {
		sess.put("status", name+" ("+username+") 계정을 삭제했습니다.")
	}
	s.redirect(w, r, "/admin/users", http.StatusFound)
}

// adminParamUser loads {user} from the path and turns an unknown id into the
// 404 a missing Eloquent binding produced.
func (s *Server) adminParamUser(w http.ResponseWriter, r *http.Request) (*store.User, bool) {
	id, ok := atoi(r.PathValue("user"))
	if !ok {
		s.notFound(w, r)
		return nil, false
	}
	user, err := s.Store.UserByID(r.Context(), id)
	if err != nil {
		s.serverError(w, r, err)
		return nil, false
	}
	if user == nil {
		s.notFound(w, r)
		return nil, false
	}
	return user, true
}

// accountRule renders an AccountRuleException the way bootstrap/app.php did: a
// field message on the form, or a 422 for an API caller.
func (s *Server) accountRule(w http.ResponseWriter, r *http.Request, sess *session, err error) bool {
	rule, ok := err.(*service.AccountRuleError)
	if !ok {
		return false
	}
	if sess == nil {
		s.json(w, http.StatusUnprocessableEntity, map[string]any{
			"message": rule.Message,
			"errors":  map[string][]string{rule.Field: {rule.Message}},
		})
		return true
	}
	v := newValidation()
	v.add(rule.Field, rule.Message)
	s.failWith(w, r, sess, r.URL.Path, v, map[string]string{})
	return true
}

// ---- clients -------------------------------------------------------------

func (s *Server) adminClientsIndex(w http.ResponseWriter, r *http.Request) {
	page := pageParam(r)
	clients, total, err := s.Store.ListClients(r.Context(), 25, (page-1)*25)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "admin/clients/index", map[string]any{
		"Title":   "연결된 앱",
		"Clients": clients,
		"Pager":   s.pager(r, total, 25, page),
		"Main":    "",
	})
}

func (s *Server) adminClientsCreate(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "admin/clients/create", map[string]any{
		"Title":  "앱 연결",
		"Scopes": config.ScopeOrder,
		"Main":   "",
	})
}

func (s *Server) adminClientsStore(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	actor := s.currentUser(r)
	sess := sessionOf(r)
	p := s.params(r)

	v := newValidation()
	data := s.validateClient(p, v, true)
	if v.any() {
		s.failWith(w, r, sess, "/admin/clients/create", v, data.old)
		return
	}

	client := &store.Client{
		ClientID:      service.GenerateClientID(),
		Name:          data.name,
		Type:          data.clientType,
		RedirectURIs:  data.redirectURIs,
		AllowedScopes: data.allowedScopes,
		Active:        data.active,
		Note:          optionalString(p.input("note")),
		HomeURL:       optionalString(p.input("home_url")),
		SortOrder:     data.sortOrder,
		InLauncher:    data.inLauncher,
		CreatedBy:     &actor.ID,
	}

	var plainSecret string
	if data.clientType == store.ClientTypeConfidential {
		plainSecret = secure.RandomString(48)
		hash, err := secure.HashPassword(plainSecret, s.HashCosts)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		client.SecretHash = &hash
	}

	if err := s.Store.InsertClient(ctx, client); err != nil {
		s.serverError(w, r, err)
		return
	}

	s.Audit.Log(ctx, "admin.client.created", "admin", itoa(actor.ID), "client", client.ClientID, map[string]any{
		"type": data.clientType, "scopes": data.allowedScopes,
	}, s.requestMeta(r))

	if sess != nil {
		sess.put("status", "앱을 등록했습니다.")
		if plainSecret != "" {
			// The secret is shown exactly once, straight after creation.
			sess.put("client_secret", plainSecret)
		}
	}
	s.redirect(w, r, "/admin/clients/"+itoa(client.ID)+"/edit", http.StatusFound)
}

func (s *Server) adminClientsEdit(w http.ResponseWriter, r *http.Request) {
	client, ok := s.paramClient(w, r)
	if !ok {
		return
	}
	s.render(w, r, http.StatusOK, "admin/clients/edit", map[string]any{
		"Title":        client.Name,
		"Client":       client,
		"Scopes":       config.ScopeOrder,
		"FormDefaults": formDefaults{Scopes: []string(client.AllowedScopes)},
		"Main":         "",
	})
}

func (s *Server) adminClientsUpdate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	client, ok := s.paramClient(w, r)
	if !ok {
		return
	}
	actor := s.currentUser(r)
	sess := sessionOf(r)
	p := s.params(r)

	v := newValidation()
	data := s.validateClient(p, v, false)
	if v.any() {
		s.failWith(w, r, sess, "/admin/clients/"+itoa(client.ID)+"/edit", v, data.old)
		return
	}

	client.Name = data.name
	client.Type = data.clientType
	client.RedirectURIs = data.redirectURIs
	client.AllowedScopes = data.allowedScopes
	client.Active = data.active
	client.Note = optionalString(p.input("note"))
	client.HomeURL = optionalString(p.input("home_url"))
	client.SortOrder = data.sortOrder
	client.InLauncher = data.inLauncher

	plainSecret := ""
	if p.boolValue("rotate_secret") && client.Type == store.ClientTypeConfidential {
		plainSecret = secure.RandomString(48)
		hash, err := secure.HashPassword(plainSecret, s.HashCosts)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		client.SecretHash = &hash
	}

	if err := s.Store.SaveClient(ctx, client); err != nil {
		s.serverError(w, r, err)
		return
	}

	s.Audit.Log(ctx, "admin.client.updated", "admin", itoa(actor.ID), "client", client.ClientID, map[string]any{
		"active": client.Active, "secret_rotated": plainSecret != "",
	}, s.requestMeta(r))

	if sess != nil {
		sess.put("status", "앱 설정을 저장했습니다.")
		if plainSecret != "" {
			sess.put("client_secret", plainSecret)
		}
	}
	s.redirect(w, r, "/admin/clients/"+itoa(client.ID)+"/edit", http.StatusFound)
}

type clientForm struct {
	name          string
	clientType    string
	redirectURIs  store.JSONList
	allowedScopes store.JSONList
	active        bool
	sortOrder     int64
	inLauncher    bool
	old           map[string]string
}

func (s *Server) validateClient(p *params, v *validation, creating bool) clientForm {
	name := strings.TrimSpace(p.input("name"))
	clientType := p.input("type")
	redirectsRaw := p.input("redirect_uris")
	homeURL := strings.TrimSpace(p.input("home_url"))
	sortRaw := strings.TrimSpace(p.input("sort_order"))

	if name == "" {
		v.add("name", msgRequired("name"))
	} else if len(name) > 120 {
		v.add("name", msgMaxString("name", 120))
	}
	if clientType != store.ClientTypePublic && clientType != store.ClientTypeConfidential {
		v.add("type", msgIn("type"))
	}
	if len(redirectsRaw) > 4000 {
		v.add("redirect_uris", msgMaxString("redirect_uris", 4000))
	}
	if homeURL != "" && !validURL(homeURL) {
		v.add("home_url", msgURL("home_url"))
	}
	var sortOrder int64
	if sortRaw != "" {
		n, err := strconv.ParseInt(sortRaw, 10, 64)
		if err != nil || n < 0 || n > 999 {
			v.add("sort_order", "시작 화면 순서 항목은 0 이상 999 이하여야 합니다.")
		} else {
			sortOrder = n
		}
	}

	allowed := []string{}
	for _, scope := range p.all("allowed_scopes") {
		if contains(config.ScopeOrder, scope) {
			allowed = append(allowed, scope)
		}
	}

	return clientForm{
		name:          name,
		clientType:    clientType,
		redirectURIs:  splitURIs(redirectsRaw),
		allowedScopes: allowed,
		// A checkbox that is not sent means "not checked" on update, but on
		// create the PHP fell back to true (that is what `?? true` did), so a
		// new client is active and in the launcher unless the box was sent.
		active:     p.boolValue("active") || (creating && !p.has("active")),
		sortOrder:  sortOrder,
		inLauncher: p.boolValue("in_launcher") || (creating && !p.has("in_launcher")),
		old: map[string]string{
			"name": name, "type": clientType, "redirect_uris": redirectsRaw,
			"home_url": homeURL, "sort_order": sortRaw, "note": p.input("note"),
			"allowed_scopes": strings.Join(allowed, ","),
			"in_launcher":    boolString(p.boolValue("in_launcher")),
			"active":         boolString(p.boolValue("active")),
		},
	}
}

func boolString(v bool) string {
	if v {
		return "1"
	}
	return ""
}

// splitURIs is one URI per line, trimmed, fragments and blanks dropped: an
// authorization server only ever redirects to an exact pre-registered value.
func splitURIs(raw string) store.JSONList {
	out := store.JSONList{}
	for _, line := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.Contains(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

func validURL(value string) bool {
	lower := strings.ToLower(value)
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		return false
	}
	rest := value[strings.Index(value, "://")+3:]
	return rest != "" && !strings.HasPrefix(rest, "/")
}

func (s *Server) paramClient(w http.ResponseWriter, r *http.Request) (*store.Client, bool) {
	id, ok := atoi(r.PathValue("client"))
	if !ok {
		s.notFound(w, r)
		return nil, false
	}
	client, err := s.Store.ClientByID(r.Context(), id)
	if err != nil {
		s.serverError(w, r, err)
		return nil, false
	}
	if client == nil {
		s.notFound(w, r)
		return nil, false
	}
	return client, true
}

// ---- activity ------------------------------------------------------------

func (s *Server) adminAudit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	category := r.URL.Query().Get("kind")

	var prefixes []string
	for _, c := range AuditCategories {
		if c.Key == category {
			prefixes = c.Prefixes
		}
	}
	if prefixes == nil {
		category = ""
	}

	var person *store.User
	if raw := r.URL.Query().Get("user"); raw != "" {
		if id, ok := atoi(raw); ok {
			person, _ = s.Store.UserByID(ctx, id)
		}
	}

	filter := store.AuditFilter{Prefixes: prefixes, Limit: 50, Offset: (pageParam(r) - 1) * 50}
	if person != nil {
		filter.PersonID = person.ID
		filter.Username = person.Username
	}

	logs, total, err := s.Store.ListAudit(ctx, filter)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	clients, err := s.Store.ClientNames(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	everyone, err := s.Store.AllUsersBrief(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}

	var personID int64
	if person != nil {
		personID = person.ID
	}

	kindChips := make([]chip, 0, len(AuditCategories)+1)
	allQuery := url.Values{}
	if personID > 0 {
		allQuery.Set("user", itoa(personID))
	}
	allURL := s.publicBase(r) + "/admin/audit"
	if encoded := allQuery.Encode(); encoded != "" {
		allURL += "?" + encoded
	}
	kindChips = append(kindChips, chip{Label: "전체", URL: allURL, Active: category == ""})
	for _, c := range AuditCategories {
		query := url.Values{"kind": {c.Key}}
		if personID > 0 {
			query.Set("user", itoa(personID))
		}
		kindChips = append(kindChips, chip{
			Label:  c.Label,
			URL:    s.publicBase(r) + "/admin/audit?" + query.Encode(),
			Active: category == c.Key,
		})
	}

	s.render(w, r, http.StatusOK, "admin/audit", map[string]any{
		"Title":     "활동 기록",
		"Logs":      logs,
		"Kind":      category,
		"Person":    person,
		"Everyone":  everyone,
		"KindChips": kindChips,
		"P":         &Presenter{People: s.People(ctx, logs), Clients: clients},
		"Pager":     s.pager(r, total, 50, pageParam(r)),
		"PersonID":  personID,
		"Main":      "",
	})
}

// ---- paging --------------------------------------------------------------

// Pager is the dependency-free "‹ 이전 / page x of y / 다음 ›" block.
type Pager struct {
	HasPages bool
	OnFirst  bool
	Current  int
	Last     int
	PrevURL  string
	NextURL  string
}

func pageParam(r *http.Request) int {
	page, err := strconv.Atoi(r.URL.Query().Get("page"))
	if err != nil || page < 1 {
		return 1
	}
	return page
}

func (s *Server) pager(r *http.Request, total, perPage, page int) Pager {
	last := (total + perPage - 1) / perPage
	if last < 1 {
		last = 1
	}
	if page > last {
		page = last
	}
	pager := Pager{
		HasPages: last > 1,
		OnFirst:  page <= 1,
		Current:  page,
		Last:     last,
	}
	if !pager.OnFirst {
		pager.PrevURL = s.pageURL(r, page-1)
	}
	if page < last {
		pager.NextURL = s.pageURL(r, page+1)
	}
	return pager
}

func (s *Server) pageURL(r *http.Request, page int) string {
	query := r.URL.Query()
	if page <= 1 {
		query.Del("page")
	} else {
		query.Set("page", strconv.Itoa(page))
	}
	base := s.publicBase(r) + r.URL.Path
	if encoded := query.Encode(); encoded != "" {
		return base + "?" + encoded
	}
	return base
}

func optionalString(v string) *string {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	return &v
}
