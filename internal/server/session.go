package server

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"sso/internal/secure"
	"sso/internal/store"
)

type sessionKey struct{}

func sessionOf(r *http.Request) *session {
	if sess, ok := r.Context().Value(sessionKey{}).(*session); ok {
		return sess
	}
	return nil
}

// session is one browser session, stored as a row and carried by a cookie that
// only names it. Data is JSON — the PHP stored a PHP-serialised blob, and there
// is no reason to read that format back: sessions do not survive the switch,
// people simply sign in again.
type session struct {
	store *store.Store
	cfg   *configLike
	w     http.ResponseWriter
	r     *http.Request

	id         string
	previousID string
	isNew      bool
	// invalidated means the session was ended (logout): the row is deleted and
	// the cookie expires. A login is not that: it moves the session to a new id
	// and keeps the data.
	invalidated bool
	userID      *int64
	data        map[string]any
	dirty       bool
}

// configLike keeps this file free of a direct config import cycle in tests; it
// is the subset of config.Config the session needs.
type configLike struct {
	SessionPath     string
	SessionSecure   bool
	SessionSameSite string
	Lifetime        time.Duration
}

func (s *Server) loadSession(w http.ResponseWriter, r *http.Request) (*session, error) {
	sess := &session{
		store: s.Store,
		cfg: &configLike{
			SessionPath:     s.Cfg.SessionPath,
			SessionSecure:   s.Cfg.SessionSecure,
			SessionSameSite: s.Cfg.SessionSameSite,
			Lifetime:        s.Cfg.SessionLifetime,
		},
		w:    w,
		r:    r,
		data: map[string]any{},
	}

	var existing string
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		existing = cookie.Value
	}

	if existing != "" {
		row, err := s.Store.SessionByID(r.Context(), existing)
		if err != nil {
			return nil, err
		}
		if row != nil && time.Now().Unix()-row.LastActivity < int64(sess.cfg.Lifetime.Seconds()) {
			sess.id = row.ID
			sess.userID = row.UserID
			if row.Payload != "" {
				if err := json.Unmarshal([]byte(row.Payload), &sess.data); err != nil {
					sess.data = map[string]any{}
				}
			}
		}
	}

	if sess.id == "" {
		sess.id = secure.RandomString(40)
		sess.isNew = true
		sess.data = map[string]any{}
	}

	// Remember where this GET was, so a later validation failure can send the
	// browser back to the page it came from (Laravel's url.previous).
	if r.Method == http.MethodGet {
		sess.data["url.previous"] = s.absoluteURL(r)
		sess.dirty = true
	}

	return sess, nil
}

func (s *Server) absoluteURL(r *http.Request) string {
	return s.publicBase(r) + r.URL.RequestURI()
}

func (sess *session) get(key string) (any, bool) {
	value, ok := sess.data[key]
	return value, ok
}

func (sess *session) string(key string) string {
	value, _ := sess.data[key].(string)
	return value
}

func (sess *session) put(key string, value any) {
	sess.data[key] = value
	sess.dirty = true
}

func (sess *session) forget(key string) {
	delete(sess.data, key)
	sess.dirty = true
}

// regenerate moves the session to a new id, which is what Laravel's
// session()->regenerate() did at sign-in: the old row is deleted so a fixated
// cookie cannot be reused.
func (sess *session) regenerate() {
	if sess.id != "" {
		sess.previousID = sess.id
	}
	sess.id = secure.RandomString(40)
	sess.isNew = true
	sess.dirty = true
}

func (sess *session) invalidate() {
	sess.data = map[string]any{}
	sess.userID = nil
	sess.invalidated = true
	sess.dirty = true
}

func (sess *session) signIn(user *store.User) {
	userID := user.ID
	sess.userID = &userID
	sess.regenerate()
}

func (sess *session) signOut() {
	sess.userID = nil
	sess.dirty = true
}

func (sess *session) csrf() string {
	if token := sess.string("_token"); token != "" {
		return token
	}
	token := secure.RandomString(40)
	sess.put("_token", token)
	return token
}

func (sess *session) validCSRF(r *http.Request) bool {
	expected := sess.string("_token")
	if expected == "" {
		return false
	}
	given := r.PostFormValue("_token")
	if given == "" {
		given = r.Header.Get("X-CSRF-TOKEN")
	}
	if given == "" {
		given = r.Header.Get("X-XSRF-TOKEN")
	}
	return subtle.ConstantTimeCompare([]byte(given), []byte(expected)) == 1
}

func (sess *session) save() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if sess.previousID != "" {
		if err := sess.store.DeleteSession(ctx, sess.previousID); err != nil {
			log.Printf("session delete: %v", err)
		}
		sess.previousID = ""
	}

	if sess.invalidated {
		if err := sess.store.DeleteSession(ctx, sess.id); err != nil {
			log.Printf("session delete: %v", err)
		}
		sess.setCookie()
		return nil
	}

	if sess.data != nil {
		payload, err := json.Marshal(sess.data)
		if err != nil {
			return err
		}
		row := &store.SessionRow{
			ID:           sess.id,
			UserID:       sess.userID,
			IP:           optionalPtr(sess.clientIP()),
			UserAgent:    optionalPtr(truncate(sess.r.UserAgent(), 512)),
			Payload:      string(payload),
			LastActivity: time.Now().Unix(),
		}
		if err := sess.store.UpsertSession(ctx, row); err != nil {
			return err
		}
	}

	sess.setCookie()
	return nil
}

func (sess *session) setCookie() {
	maxAge := int(sess.cfg.Lifetime.Seconds())
	if sess.invalidated {
		maxAge = -1
	}
	cookie := &http.Cookie{
		Name:     sessionCookie,
		Value:    sess.id,
		Path:     sess.cfg.SessionPath,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   sess.cfg.SessionSecure,
		SameSite: sameSite(sess.cfg.SessionSameSite),
	}
	if sess.invalidated {
		cookie.Value = ""
	}
	http.SetCookie(sess.w, cookie)
}

func (sess *session) clientIP() string {
	ip := sess.r.RemoteAddr
	if forwarded := sess.r.Header.Get("X-Forwarded-For"); forwarded != "" {
		ip = strings.TrimSpace(strings.Split(forwarded, ",")[0])
	}
	if idx := strings.LastIndex(ip, ":"); idx > 0 && !strings.Contains(ip[idx:], "]") {
		ip = ip[:idx]
	}
	return ip
}

func sameSite(value string) http.SameSite {
	switch strings.ToLower(value) {
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode
	}
}

// handleCSRF is the 419 path from bootstrap/app.php. The sign-in form sent
// twice is the case that matters: the first submit signed in and regenerated
// the session, so the second carries a stale token. Signed in, carry on where
// the sign-in was going; not signed in, show the form again with a word on why.
func (s *Server) handleCSRF(w http.ResponseWriter, r *http.Request, sess *session) {
	if r.URL.Path == "/login" {
		if s.currentUser(r) != nil {
			if resume := s.resumeAuthorizeParams(sess); resume != nil {
				s.redirect(w, r, "/oauth/authorize?"+url.Values(resume).Encode(), http.StatusFound)
				return
			}
			s.redirect(w, r, "/", http.StatusFound)
			return
		}
		sess.put("errors", map[string][]string{"username": {"로그인 화면이 오래되었습니다. 다시 로그인하세요."}})
		s.redirect(w, r, "/login", http.StatusFound)
		return
	}
	http.Error(w, "페이지가 만료되었습니다. 다시 시도하세요.", 419)
}

func (s *Server) resumeAuthorizeParams(sess *session) map[string][]string {
	if sess == nil {
		return nil
	}
	if pending, ok := sess.get("oauth.pending"); ok {
		if values := toStringValues(pending); values != nil {
			return values
		}
	}
	last, ok := sess.get("oauth.last")
	if !ok {
		return nil
	}
	entry, ok := last.(map[string]any)
	if !ok {
		return nil
	}
	at, _ := entry["at"].(float64)
	if int64(at) <= time.Now().Unix()-120 {
		return nil
	}
	return toStringValues(entry["params"])
}

func toStringValues(value any) map[string][]string {
	raw, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	out := map[string][]string{}
	for key, v := range raw {
		if s, ok := v.(string); ok && s != "" {
			out[key] = []string{s}
		}
	}
	return out
}

// ---- presentation --------------------------------------------------------

// form is the one-request flash of invalid input and field errors, which is
// what $errors and old() gave every Blade view.
type form struct {
	Old    map[string]string
	Errors map[string][]string
	// Scopes is the checkbox state of the client form: nil means the create
	// page's defaults (openid + profile).
	Scopes []string
}

func (f form) Value(key, fallback string) string {
	if value, ok := f.Old[key]; ok && value != "" {
		return value
	}
	return fallback
}

func (f form) Has(key string) bool { return len(f.Errors[key]) > 0 }

func (f form) Err(key string) string {
	if len(f.Errors[key]) == 0 {
		return ""
	}
	return f.Errors[key][0]
}

// Checked is @checked(old(field, default)): the form body only carries checked
// boxes, so a missing key falls back to the default.
func (f form) Checked(key string, fallback bool) bool {
	value, ok := f.Old[key]
	if !ok {
		return fallback
	}
	switch strings.ToLower(value) {
	case "1", "true", "on", "yes", "":
		return value != ""
	}
	return false
}

// ScopeChecked is in_array($scope, old('allowed_scopes', …)).
func (f form) ScopeChecked(scope string) bool {
	if f.Scopes != nil {
		return contains(f.Scopes, scope)
	}
	if raw, ok := f.Old["allowed_scopes"]; ok {
		for _, item := range strings.Split(raw, ",") {
			if strings.TrimSpace(item) == scope {
				return true
			}
		}
		return false
	}
	return scope == "openid" || scope == "profile"
}

// formDefaults fills a page's initial field values into the flashed form,
// without replacing anything the person actually typed.
type formDefaults struct {
	Values map[string]string
	Scopes []string
}

type assetURLs struct {
	ThemeInit string
	Theme     string
	App       string
	Console   string
}

func (s *Server) assetURLs(base string) assetURLs {
	return assetURLs{
		ThemeInit: base + "/assets/theme-init.js",
		Theme:     base + "/assets/theme.css",
		App:       base + "/assets/app.css?v=" + s.AssetV,
		Console:   base + "/assets/console.js?v=" + s.AssetV,
	}
}

// baseData is what layouts/app.blade.php expects on every page: who is signed
// in, the flashes, the form state and the asset URLs.
func (s *Server) baseData(r *http.Request) map[string]any {
	base := s.publicBase(r)
	sess := sessionOf(r)
	me := s.currentUser(r)

	data := map[string]any{
		"Base":    base,
		"Issuer":  s.Cfg.Issuer,
		"AppName": s.Cfg.AppName,
		"A":       s.assetURLs(base),
		"Me":      me,
		"Nav":     navFor(r.URL.Path),
		"F":       form{Old: map[string]string{}, Errors: map[string][]string{}},
		"CF":      form{Old: map[string]string{}, Errors: map[string][]string{}},
		"CSRF":    "",
		"Now":     time.Now().UTC(),
	}

	if sess == nil {
		return data
	}

	data["CSRF"] = sess.csrf()

	// Flash values are read and cleared: they belong to this response only.
	f := form{Old: map[string]string{}, Errors: map[string][]string{}}
	if raw, ok := sess.get("errors"); ok {
		f.Errors = toErrorMap(raw)
		sess.forget("errors")
	}
	if raw, ok := sess.get("_old"); ok {
		if old, ok := raw.(map[string]any); ok {
			for key, value := range old {
				if text, ok := value.(string); ok {
					f.Old[key] = text
				}
			}
		}
		sess.forget("_old")
	}
	data["F"] = f

	// The console's "new user" dialog has its own error bag in PHP; keeping it
	// apart here means a failed create does not also flash above the page.
	cf := form{Old: map[string]string{}, Errors: map[string][]string{}}
	if raw, ok := sess.get("create_errors"); ok {
		cf.Errors = toErrorMap(raw)
		sess.forget("create_errors")
	}
	if raw, ok := sess.get("create_old"); ok {
		if old, ok := raw.(map[string]any); ok {
			for key, value := range old {
				if text, ok := value.(string); ok {
					cf.Old[key] = text
				}
			}
		}
		sess.forget("create_old")
	}
	data["CF"] = cf

	for _, key := range []string{"status", "reset_url", "reset_expires", "client_secret"} {
		if value, ok := sess.get(key); ok {
			if text, ok := value.(string); ok && text != "" {
				data[flashKey(key)] = text
			}
			sess.forget(key)
		}
	}

	if value, ok := sess.get("generated_password"); ok {
		switch v := value.(type) {
		case map[string]any:
			generated := []generatedSecret{}
			for username, plain := range v {
				if text, ok := plain.(string); ok {
					generated = append(generated, generatedSecret{Username: username, Password: text})
				}
			}
			sortSecrets(generated)
			data["Generated"] = generated
		case map[string]string:
			generated := []generatedSecret{}
			for username, plain := range v {
				generated = append(generated, generatedSecret{Username: username, Password: plain})
			}
			sortSecrets(generated)
			data["Generated"] = generated
		}
		sess.forget("generated_password")
	}

	return data
}

type generatedSecret struct {
	Username string
	Password string
}

func sortSecrets(list []generatedSecret) {
	for i := 1; i < len(list); i++ {
		for j := i; j > 0 && list[j].Username < list[j-1].Username; j-- {
			list[j], list[j-1] = list[j-1], list[j]
		}
	}
}

func flashKey(key string) string {
	switch key {
	case "status":
		return "Status"
	case "reset_url":
		return "ResetURL"
	case "reset_expires":
		return "ResetExpires"
	case "client_secret":
		return "ClientSecret"
	}
	return key
}

func navFor(path string) string {
	switch {
	case strings.HasPrefix(path, "/admin/users"):
		return "users"
	case strings.HasPrefix(path, "/admin/audit"):
		return "audit"
	case strings.HasPrefix(path, "/admin/clients"):
		return "clients"
	case strings.HasPrefix(path, "/account"):
		return "account"
	}
	return ""
}

func (s *Server) currentUser(r *http.Request) *store.User {
	sess := sessionOf(r)
	if sess == nil || sess.userID == nil {
		return nil
	}
	user, err := s.Store.UserByID(r.Context(), *sess.userID)
	if err != nil || user == nil || !user.IsActive() {
		// A user disabled while browsing loses the session at the next request,
		// which is what "disabled now" has to mean.
		if user == nil {
			sess.signOut()
		}
		return nil
	}
	return user
}

// render executes a parsed page into a buffer first: a template error must not
// leave a half-written page on the wire.
func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, page string, extra map[string]any) {
	tpl, ok := s.Templates[page]
	if !ok {
		s.serverError(w, r, errUnknownTemplate(page))
		return
	}

	data := s.baseData(r)
	for key, value := range extra {
		data[key] = value
	}

	// Page defaults (an edit form's current values) fill what the request did
	// not carry, exactly like old('name', $client->name).
	if defaults, ok := extra["FormDefaults"].(formDefaults); ok {
		if current, ok := data["F"].(form); ok {
			for key, value := range defaults.Values {
				if _, exists := current.Old[key]; !exists {
					current.Old[key] = value
				}
			}
			if current.Scopes == nil {
				current.Scopes = defaults.Scopes
			}
			data["F"] = current
		}
		delete(data, "FormDefaults")
	}

	var buf bytes.Buffer
	if err := tpl.ExecuteTemplate(&buf, "layouts/app.html", data); err != nil {
		log.Printf("render %s: %v", page, err)
		http.Error(w, "페이지를 표시할 수 없습니다.", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

type unknownTemplate string

func (u unknownTemplate) Error() string { return "unknown template " + string(u) }

func errUnknownTemplate(page string) error { return unknownTemplate(page) }

func optionalPtr(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}

func toErrorMap(raw any) map[string][]string {
	out := map[string][]string{}
	errorsMap, ok := raw.(map[string]any)
	if !ok {
		if typed, ok := raw.(map[string][]string); ok {
			return typed
		}
		return out
	}
	for field, list := range errorsMap {
		switch v := list.(type) {
		case []any:
			for _, item := range v {
				if text, ok := item.(string); ok {
					out[field] = append(out[field], text)
				}
			}
		case []string:
			out[field] = v
		case string:
			out[field] = []string{v}
		}
	}
	return out
}

func truncate(v string, n int) string {
	if len(v) <= n {
		return v
	}
	return v[:n]
}
