package server

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"sso/internal/secure"
	"sso/internal/service"
	"sso/internal/store"
)

// ---- home ----------------------------------------------------------------

// home is the public front door. It used to be a status board — signing-key
// count, endpoint table — internal detail rendered to anyone on the internet
// and useful to nobody standing there. What a visitor needs is one thing: the
// way in. Clients read the endpoints from the discovery document.
func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	user := s.currentUser(r)

	var pending map[string][]string
	var apps []*store.Client
	if sess := sessionOf(r); sess != nil {
		if raw, ok := sess.get("oauth.pending"); ok {
			pending = toStringValues(raw)
		}
	}
	if user != nil {
		var err error
		apps, err = s.Store.LauncherClients(r.Context())
		if err != nil {
			s.serverError(w, r, err)
			return
		}
	}

	resume := ""
	if pending != nil {
		resume = s.publicBase(r) + "/oauth/authorize?" + url.Values(pending).Encode()
	}

	data := map[string]any{
		"User":      user,
		"Pending":   pending,
		"ResumeURL": resume,
		"Apps":      apps,
		"Main":      mainClass(user),
	}
	data["Title"] = "계정 센터"
	s.render(w, r, http.StatusOK, "home", data)
}

func mainClass(user *store.User) string {
	if user == nil {
		return "narrow"
	}
	return ""
}

// ---- sign-in -------------------------------------------------------------

// loginShow is outside the "guest" middleware on purpose: somebody arriving
// with ?next= while this session is still alive must be sent to `next`, not
// bounced to the home page.
func (s *Server) loginShow(w http.ResponseWriter, r *http.Request) {
	next := safeNext(r, r.URL.Query().Get("next"))

	if s.currentUser(r) != nil {
		if next != "" {
			s.redirect(w, r, s.absoluteNext(r, next), http.StatusFound)
			return
		}
		s.redirect(w, r, "/", http.StatusFound)
		return
	}

	if next != "" {
		if sess := sessionOf(r); sess != nil {
			sess.put("url.intended", s.absoluteNext(r, next))
		}
	}

	data := map[string]any{
		"Title":            "로그인",
		"Main":             "narrow",
		"RequestingClient": strings.TrimSpace(r.URL.Query().Get("client")),
		"Next":             next,
	}
	s.render(w, r, http.StatusOK, "auth/login", data)
}

func (s *Server) loginStore(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sess := sessionOf(r)

	// guest:web — somebody already signed in does not get a second session.
	if s.currentUser(r) != nil {
		s.redirectIntended(w, r, "/")
		return
	}

	if next := safeNext(r, r.URL.Query().Get("next")); next != "" && sess != nil {
		sess.put("url.intended", s.absoluteNext(r, next))
	}

	p := s.params(r)
	username := secure.NormalizeUsername(p.input("username"))
	password := p.input("password")

	v := newValidation()
	if username == "" {
		v.add("username", msgRequired("username"))
	}
	if len(username) > 64 {
		v.add("username", msgMaxString("username", 64))
	}
	if password == "" {
		v.add("password", msgRequired("password"))
	}
	if v.any() {
		s.failWith(w, r, sess, "/login", v, map[string]string{"username": username})
		return
	}

	key := "login:" + username + "|" + s.requestMeta(r).IP
	if tooMany, seconds := s.Limiter.tooMany(key, 10); tooMany {
		v.add("username", "시도가 너무 많습니다. "+itoa(int64(seconds))+"초 뒤에 다시 시도하세요.")
		s.failWith(w, r, sess, "/login", v, map[string]string{"username": username})
		return
	}

	user, err := s.Store.UserByUsername(ctx, username)
	if err != nil {
		s.serverError(w, r, err)
		return
	}

	if user == nil || !secure.CheckPassword(user.Password, password) {
		s.Limiter.hit(key, 5*time.Minute)
		s.Audit.Log(ctx, "login.failed", "anonymous", username, "user", username, map[string]any{"guard": "web"}, s.requestMeta(r))
		v.add("username", "아이디 또는 비밀번호가 맞지 않습니다.")
		s.failWith(w, r, sess, "/login", v, map[string]string{"username": username})
		return
	}

	if !user.IsActive() {
		s.Audit.Log(ctx, "login.denied", "user", itoa(user.ID), "user", itoa(user.ID), map[string]any{"reason": "disabled"}, s.requestMeta(r))
		v.add("username", "비활성화된 계정입니다. 관리자에게 문의하세요.")
		s.failWith(w, r, sess, "/login", v, map[string]string{"username": username})
		return
	}

	s.Limiter.clear(key)
	if sess != nil {
		sess.signIn(user)
	}

	user.LastLoginAt = store.Now()
	meta := s.requestMeta(r)
	if meta.IP != "" {
		user.LastLoginIP = &meta.IP
	}
	if err := s.Store.SaveUser(ctx, user); err != nil {
		s.serverError(w, r, err)
		return
	}

	s.Audit.Log(ctx, "login.succeeded", "user", itoa(user.ID), "user", itoa(user.ID), map[string]any{"guard": "web"}, meta)

	// Resume an interrupted authorization request, if there is one.
	if resume := s.resumeAuthorizeParams(sess); resume != nil {
		s.redirect(w, r, "/oauth/authorize?"+url.Values(resume).Encode(), http.StatusFound)
		return
	}
	s.redirectIntended(w, r, "/")
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	user := s.currentUser(r)
	actorID := ""
	if user != nil {
		actorID = itoa(user.ID)
	}
	s.Audit.Log(r.Context(), "logout", "user", actorID, "user", actorID, map[string]any{"guard": "web"}, s.requestMeta(r))

	if sess := sessionOf(r); sess != nil {
		sess.invalidate()
	}
	s.redirect(w, r, "/", http.StatusFound)
}

// redirectIntended honours url.intended, which is set by /oauth/authorize and
// by an explicit ?next=.
func (s *Server) redirectIntended(w http.ResponseWriter, r *http.Request, fallback string) {
	target := fallback
	if sess := sessionOf(r); sess != nil {
		if intended := sess.string("url.intended"); intended != "" {
			target = intended
			sess.forget("url.intended")
		}
	}
	http.Redirect(w, r, s.withBase(r, target), http.StatusFound)
}

func (s *Server) withBase(r *http.Request, target string) string {
	if strings.HasPrefix(target, "/") {
		return s.publicBase(r) + target
	}
	return target
}

// ---- registration --------------------------------------------------------

// registerShow is open self-registration. Old invite links (/register/{code})
// still land on the form; the code is ignored.
func (s *Server) registerShow(w http.ResponseWriter, r *http.Request) {
	if s.currentUser(r) != nil {
		s.redirect(w, r, "/", http.StatusFound)
		return
	}
	s.render(w, r, http.StatusOK, "auth/register", map[string]any{"Title": "가입", "Main": "narrow"})
}

func (s *Server) registerStore(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sess := sessionOf(r)

	if s.currentUser(r) != nil {
		s.redirect(w, r, "/", http.StatusFound)
		return
	}

	if tooMany, _ := s.Limiter.tooMany("register:"+s.requestMeta(r).IP, 10); tooMany {
		http.Error(w, "시도가 너무 많습니다. 잠시 뒤에 다시 시도하세요.", http.StatusTooManyRequests)
		return
	}
	s.Limiter.hit("register:"+s.requestMeta(r).IP, time.Minute)

	p := s.params(r)
	username := secure.NormalizeUsername(p.input("username"))
	name := strings.TrimSpace(p.input("name"))
	password := p.input("password")

	v := newValidation()
	if name == "" {
		v.add("name", msgRequired("name"))
	} else if len(name) > 120 {
		v.add("name", msgMaxString("name", 120))
	}
	v.addUsername(p, 0, false)
	if password == "" {
		v.add("password", msgRequired("password"))
	} else if p.input("password_confirmation") != password {
		v.add("password", msgConfirmed("password"))
	}

	if v.any() {
		s.failWith(w, r, sess, "/register", v, map[string]string{"name": name, "username": username})
		return
	}

	hash, err := secure.HashPassword(password, s.HashCosts)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	note := "self-registered"
	user := &store.User{
		Name:     name,
		Username: username,
		Role:     store.RoleUser,
		Password: hash,
		Status:   store.StatusActive,
		Note:     &note,
	}
	if err := s.Store.InsertUser(ctx, user); err != nil {
		s.serverError(w, r, err)
		return
	}

	s.Audit.Log(ctx, "user.register", "user", itoa(user.ID), "user", itoa(user.ID), map[string]any{"username": user.Username}, s.requestMeta(r))

	if sess != nil {
		sess.signIn(user)
	}

	// Same continuation as a normal sign-in: finish the authorization that sent
	// the person here, otherwise land on the home page.
	if resume := s.resumeAuthorizeParams(sess); resume != nil {
		s.redirect(w, r, "/oauth/authorize?"+url.Values(resume).Encode(), http.StatusFound)
		return
	}
	s.redirect(w, r, "/", http.StatusFound)
}

// addUsername applies UserAccounts::usernameRules: required, 3..64, the
// pattern, and unique (optionally ignoring the row being edited).
func (v *validation) addUsername(p *params, ignoreID int64, sometimes bool) {
	raw := p.input("username")
	if sometimes && !p.has("username") {
		return
	}
	value := secure.NormalizeUsername(raw)
	if value == "" {
		v.add("username", msgRequired("username"))
		return
	}
	if len(value) < 3 {
		v.add("username", msgMinString("username", 3))
		return
	}
	if len(value) > 64 {
		v.add("username", msgMaxString("username", 64))
		return
	}
	if !usernameValid(value) {
		v.add("username", "아이디는 영문 소문자·숫자로 시작하고 끝나며, 중간에 . _ - 를 쓸 수 있습니다 (3~64자).")
	}
}

// ---- password reset links ------------------------------------------------

func (s *Server) resetShow(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	token := r.PathValue("token")

	reset, err := s.Resets.Find(ctx, token)
	if err != nil {
		s.serverError(w, r, err)
		return
	}

	if reset == nil || !reset.IsUsable() {
		reason := "expired"
		if reset == nil {
			reason = "unknown"
		} else if reset.UsedAt.Valid {
			reason = "already used"
		} else if reset.RevokedAt.Valid {
			reason = "superseded"
		}
		// Audit rows must not contain a usable token, so only a short digest
		// prefix is recorded: enough to correlate two attempts, useless as a
		// credential.
		s.Audit.Log(ctx, "user.password_reset.rejected", "anonymous", "", "reset_link", secure.SHA256Hex(token)[:12],
			map[string]any{"reason": reason}, s.requestMeta(r))
		s.render(w, r, http.StatusOK, "auth/reset", map[string]any{"Title": "새 비밀번호", "Main": "narrow", "Invalid": true})
		return
	}

	user, err := s.Store.UserByID(ctx, reset.UserID)
	if err != nil || user == nil {
		s.render(w, r, http.StatusOK, "auth/reset", map[string]any{"Title": "새 비밀번호", "Main": "narrow", "Invalid": true})
		return
	}

	s.render(w, r, http.StatusOK, "auth/reset", map[string]any{
		"Title": "새 비밀번호", "Main": "narrow", "Invalid": false, "Token": token, "User": user,
	})
}

func (s *Server) resetUpdate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	token := r.PathValue("token")
	sess := sessionOf(r)

	if tooMany, _ := s.Limiter.tooMany("reset:"+s.requestMeta(r).IP, 10); tooMany {
		v := newValidation()
		v.add("password", "시도가 너무 많습니다. 잠시 뒤에 다시 시도하세요.")
		s.failWith(w, r, sess, "/password/reset/"+token, v, map[string]string{})
		return
	}
	s.Limiter.hit("reset:"+s.requestMeta(r).IP, time.Minute)

	reset, err := s.Resets.Find(ctx, token)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if reset == nil || !reset.IsUsable() {
		reason := "expired"
		if reset == nil {
			reason = "unknown"
		} else if reset.UsedAt.Valid {
			reason = "already used"
		} else if reset.RevokedAt.Valid {
			reason = "superseded"
		}
		s.Audit.Log(ctx, "user.password_reset.rejected", "anonymous", "", "reset_link", secure.SHA256Hex(token)[:12],
			map[string]any{"reason": reason}, s.requestMeta(r))
		s.render(w, r, http.StatusOK, "auth/reset", map[string]any{"Title": "새 비밀번호", "Main": "narrow", "Invalid": true})
		return
	}

	user, err := s.Store.UserByID(ctx, reset.UserID)
	if err != nil || user == nil {
		s.render(w, r, http.StatusOK, "auth/reset", map[string]any{"Title": "새 비밀번호", "Main": "narrow", "Invalid": true})
		return
	}

	p := s.params(r)
	password := p.input("password")
	v := newValidation()
	if password == "" {
		v.add("password", msgRequired("password"))
	} else if p.input("password_confirmation") != password {
		v.add("password", msgConfirmed("password"))
	}
	if v.any() {
		s.failWith(w, r, sess, "/password/reset/"+token, v, map[string]string{})
		return
	}

	hash, err := secure.HashPassword(password, s.HashCosts)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	user.Password = hash
	if err := s.Store.SaveUser(ctx, user); err != nil {
		s.serverError(w, r, err)
		return
	}

	if err := s.Resets.Consume(ctx, reset, s.requestMeta(r).IP); err != nil {
		s.serverError(w, r, err)
		return
	}
	revoked, err := s.Resets.RevokeCredentials(ctx, user, "")
	if err != nil {
		s.serverError(w, r, err)
		return
	}

	s.Audit.Log(ctx, "user.password_reset.completed", "user", itoa(user.ID), "user", itoa(user.ID), map[string]any{
		"username": user.Username, "revoked": revoked,
	}, s.requestMeta(r))

	if sess != nil {
		sess.put("status", "비밀번호를 바꿨습니다. 새 비밀번호로 로그인하세요.")
	}
	s.redirect(w, r, "/login", http.StatusFound)
}

// ---- the account a person owns ------------------------------------------

func (s *Server) accountShow(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireUser(w, r)
	if !ok {
		return
	}

	tokens, err := s.Store.ActiveTokensForUser(r.Context(), user.ID, 10)
	if err != nil {
		s.serverError(w, r, err)
		return
	}

	s.render(w, r, http.StatusOK, "auth/account", map[string]any{
		"Title":    "내 계정",
		"User":     user,
		"SignedIn": tokens,
		"Main":     "",
	})
}

func (s *Server) accountUpdate(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
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
	v.addUsername(p, user.ID, true)
	if v.any() {
		s.failWith(w, r, sess, "/account", v, map[string]string{"name": name, "username": username})
		return
	}

	usernameChanged := username != "" && username != user.Username
	if usernameChanged && !secure.CheckPassword(user.Password, p.input("current_password")) {
		v.add("current_password", "아이디를 바꾸려면 현재 비밀번호를 입력하세요.")
		s.failWith(w, r, sess, "/account", v, map[string]string{"name": name, "username": username})
		return
	}

	if err := s.Accounts.UpdateOwnProfile(ctx, user, name, &username, s.requestMeta(r)); err != nil {
		s.serverError(w, r, err)
		return
	}

	message := "저장했습니다."
	if usernameChanged {
		message = "저장했습니다. 다음 로그인부터 새 아이디를 쓰세요."
	}
	if sess != nil {
		sess.put("status", message)
	}
	s.back(w, r)
}

func (s *Server) accountPassword(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	sess := sessionOf(r)
	p := s.params(r)

	current := p.input("current_password")
	password := p.input("password")
	confirmation := p.input("password_confirmation")

	v := newValidation()
	if current == "" {
		v.add("current_password", msgRequired("current_password"))
	}
	if password == "" {
		v.add("password", msgRequired("password"))
	} else if confirmation != password {
		v.add("password", msgConfirmed("password"))
	} else if password == current {
		v.add("password", msgDifferent("password", "current_password"))
	}
	if v.any() {
		s.failWith(w, r, sess, "/account", v, map[string]string{})
		return
	}

	if !secure.CheckPassword(user.Password, current) {
		v.add("current_password", "현재 비밀번호가 맞지 않습니다.")
		s.failWith(w, r, sess, "/account", v, map[string]string{})
		return
	}

	// Every token the old password produced is revoked. This browser stays
	// signed in: the person at the keyboard just proved who they are.
	if _, err := s.Accounts.SetPassword(r.Context(), user, &password, user, s.requestMeta(r), ""); err != nil {
		s.serverError(w, r, err)
		return
	}

	if sess != nil {
		sess.put("status", "비밀번호를 바꿨습니다. 다른 기기와 앱에서는 로그아웃됩니다.")
	}
	s.back(w, r)
}

func (s *Server) accountRevokeTokens(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	sess := sessionOf(r)
	keep := ""
	if sess != nil {
		keep = sess.id
	}
	if _, err := s.Accounts.SignOutEverywhere(r.Context(), user, user, s.requestMeta(r), keep); err != nil {
		s.serverError(w, r, err)
		return
	}
	if sess != nil {
		sess.put("status", "모든 앱과 다른 브라우저에서 로그아웃했습니다.")
	}
	s.back(w, r)
}

func (s *Server) accountAvatar(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	upload, fieldErr := s.readAvatar(r)
	if fieldErr != "" {
		v := newValidation()
		v.add("avatar", fieldErr)
		s.failWith(w, r, sessionOf(r), "/account", v, map[string]string{})
		return
	}
	if err := s.Accounts.StoreAvatar(r.Context(), user, upload, user, s.requestMeta(r)); err != nil {
		s.serverError(w, r, err)
		return
	}
	if sess := sessionOf(r); sess != nil {
		sess.put("status", "프로필 사진을 바꿨습니다.")
	}
	s.back(w, r)
}

func (s *Server) accountAvatarRemove(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	if err := s.Accounts.RemoveAvatar(r.Context(), user, user, s.requestMeta(r)); err != nil {
		s.serverError(w, r, err)
		return
	}
	if sess := sessionOf(r); sess != nil {
		sess.put("status", "프로필 사진을 지웠습니다.")
	}
	s.back(w, r)
}

// requireUser is the auth:web middleware: anonymous visitors are sent to the
// sign-in page, with the address they wanted remembered.
func (s *Server) requireUser(w http.ResponseWriter, r *http.Request) (*store.User, bool) {
	user := s.currentUser(r)
	if user != nil {
		return user, true
	}
	if sess := sessionOf(r); sess != nil {
		sess.put("url.intended", s.absoluteURL(r))
	}
	s.redirect(w, r, "/login", http.StatusFound)
	return nil, false
}

// failWith flashes errors and the input and sends the browser back, which is
// what a failed Laravel validation did.
func (s *Server) failWith(w http.ResponseWriter, r *http.Request, sess *session, fallbackPath string, v *validation, old map[string]string) {
	if sess != nil {
		sess.put("errors", v.Errors)
		sess.put("_old", old)
		var target string
		if previous, ok := sess.get("url.previous"); ok {
			if text, ok := previous.(string); ok {
				target = text
			}
		}
		if target == "" {
			target = s.publicBase(r) + fallbackPath
		}
		http.Redirect(w, r, target, http.StatusFound)
		return
	}
	s.render(w, r, http.StatusUnprocessableEntity, "auth/login", map[string]any{
		"Title": "로그인", "Main": "narrow", "F": form{Old: old, Errors: v.Errors},
	})
}

// readAvatar validates and reads a picture: JPEG/PNG/WebP/GIF, at most 1 MB.
// The console crops and shrinks in the browser, so this only stops abuse.
func (s *Server) readAvatar(r *http.Request) (service.AvatarUpload, string) {
	if err := parseForm(r, 8<<20); err != nil {
		return service.AvatarUpload{}, msgRequired("avatar")
	}
	file, header, err := r.FormFile("avatar")
	if err != nil {
		return service.AvatarUpload{}, msgRequired("avatar")
	}
	defer file.Close()

	if header.Size > 1024*1024 {
		return service.AvatarUpload{}, msgFileMax("avatar", 1024)
	}

	data := make([]byte, 0, header.Size)
	buffer := make([]byte, 32*1024)
	for {
		n, readErr := file.Read(buffer)
		if n > 0 {
			data = append(data, buffer[:n]...)
			if len(data) > 1024*1024 {
				return service.AvatarUpload{}, msgFileMax("avatar", 1024)
			}
		}
		if readErr != nil {
			break
		}
	}
	if len(data) == 0 {
		return service.AvatarUpload{}, msgRequired("avatar")
	}

	mimeType := detectImageMIME(data)
	if mimeType == "" {
		return service.AvatarUpload{}, msgMime("avatar")
	}
	return service.AvatarUpload{MIME: mimeType, Data: data}, ""
}

func detectImageMIME(data []byte) string {
	sniffed := http.DetectContentType(data)
	switch sniffed {
	case "image/jpeg", "image/png", "image/gif":
		return sniffed
	case "image/webp":
		return sniffed
	}
	// Go's sniffer knows WebP; this fallback keeps an unusual header from
	// rejecting a valid file the browser produced.
	if len(data) > 12 && string(data[0:4]) == "RIFF" && string(data[8:12]) == "WEBP" {
		return "image/webp"
	}
	return ""
}
