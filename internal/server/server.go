package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"sso/internal/config"
	"sso/internal/service"
	"sso/internal/store"
)

// Options is everything the server needs, handed over by main so the server
// package never reads the environment itself.
type Options struct {
	Config *config.Config
	Store  *store.Store
	// Files is the embedded tree rooted at the project root: web/templates and
	// web/assets live under it.
	Files     fs.FS
	HashCosts int
}

// Server is the whole HTTP surface: the console, the account pages, the OAuth
// endpoints and the account API. One value, no framework.
type Server struct {
	Cfg       *config.Config
	Store     *store.Store
	Keys      *service.SigningKeyService
	Tokens    *service.TokenService
	Accounts  *service.UserAccounts
	Resets    *service.PasswordResetService
	Audit     *service.AuditLogger
	Clients   *service.ClientAuthenticator
	Templates map[string]*template.Template
	Assets    fs.FS
	WebFiles  fs.FS
	AssetV    string
	Limiter   *Limiter
	HashCosts int

	mux *http.ServeMux
}

const sessionCookie = "sso-session"

// New wires the services and parses every page template once. A template error
// is a startup error: a page that cannot render is not worth serving.
func New(opts Options) (*Server, error) {
	if opts.HashCosts == 0 {
		opts.HashCosts = 12
	}

	s := &Server{
		Cfg:       opts.Config,
		Store:     opts.Store,
		HashCosts: opts.HashCosts,
		Limiter:   NewLimiter(),
	}

	s.Audit = service.NewAuditLogger(opts.Store)
	s.Keys = service.NewSigningKeyService(opts.Store, opts.Config.AppKey)
	s.Tokens = &service.TokenService{
		Store:      opts.Store,
		Keys:       s.Keys,
		Audit:      s.Audit,
		Issuer:     opts.Config.Issuer,
		AccessTTL:  opts.Config.AccessTokenTTL,
		RefreshTTL: opts.Config.RefreshTokenTTL,
	}
	s.Resets = &service.PasswordResetService{
		Store:  opts.Store,
		Audit:  s.Audit,
		Issuer: opts.Config.Issuer,
		TTL:    opts.Config.ResetLinkTTL,
		// There is no mail flow; the link is what an administrator hands over.
		// Logging it keeps "create a link from the shell" usable without mail.
		LogReset: func(link string, user *store.User) {
			log.Printf("password reset link for %s: %s", user.Username, link)
		},
	}
	s.Accounts = &service.UserAccounts{
		Store:     opts.Store,
		Audit:     s.Audit,
		Resets:    s.Resets,
		Storage:   opts.Config.ResolveStorageDir(),
		HashCosts: opts.HashCosts,
	}
	s.Clients = &service.ClientAuthenticator{Store: opts.Store}

	web, err := fs.Sub(opts.Files, "web")
	if err != nil {
		return nil, fmt.Errorf("embedded web files: %w", err)
	}
	s.WebFiles = web
	if assets, err := fs.Sub(web, "assets"); err == nil {
		s.Assets = assets
	}
	if data, err := fs.ReadFile(web, "assets/app.css"); err == nil {
		sum := sha256.Sum256(data)
		s.AssetV = hex.EncodeToString(sum[:4])
	}

	if err := s.parseTemplates(web); err != nil {
		return nil, err
	}
	s.routes()
	return s, nil
}

// pageTemplates are the pages a handler may render, parsed on top of the shared
// layout and partials. Parsing per page keeps each file's `{{define "title"}}`
// local to itself.
var pageTemplates = []string{
	"home.html",
	"auth/login.html",
	"auth/register.html",
	"auth/reset.html",
	"auth/account.html",
	"admin/users/index.html",
	"admin/users/show.html",
	"admin/clients/index.html",
	"admin/clients/create.html",
	"admin/clients/edit.html",
	"admin/audit.html",
	"errors/error.html",
}

func (s *Server) parseTemplates(web fs.FS) error {
	funcs := s.templateFuncs()

	shared := []string{"layouts/app.html"}
	for _, name := range []string{"partials/avatar.html", "partials/avatar-upload.html", "partials/pagination.html"} {
		shared = append(shared, name)
	}

	s.Templates = map[string]*template.Template{}
	for _, page := range pageTemplates {
		files := append(append([]string{}, shared...), page)
		parsed := template.New("root").Funcs(funcs)
		for _, file := range files {
			body, err := fs.ReadFile(web, path.Join("templates", file))
			if err != nil {
				return fmt.Errorf("template %s: %w", file, err)
			}
			// Each file gets its own root: text outside {{define}} (a leading
			// newline, a comment) would otherwise overwrite the layout parsed
			// before it, and the page would render as that whitespace.
			if _, err := parsed.New(file).Parse(string(body)); err != nil {
				return fmt.Errorf("template %s: %w", file, err)
			}
		}
		key := strings.TrimSuffix(page, ".html")
		s.Templates[key] = parsed
	}
	return nil
}

func (s *Server) routes() {
	m := http.NewServeMux()

	// Public pages
	m.HandleFunc("GET /{$}", s.home)
	m.HandleFunc("GET /login", s.loginShow)
	m.HandleFunc("POST /login", s.loginStore)
	m.HandleFunc("POST /logout", s.logout)
	m.HandleFunc("GET /register/{code}", s.registerShow)
	m.HandleFunc("GET /register", s.registerShow)
	m.HandleFunc("POST /register/{code}", s.registerStore)
	m.HandleFunc("POST /register", s.registerStore)
	m.HandleFunc("GET /password/reset/{token}", s.resetShow)
	m.HandleFunc("POST /password/reset/{token}", s.resetUpdate)

	// The account a person owns
	m.HandleFunc("GET /account", s.accountShow)
	m.HandleFunc("PUT /account", s.accountUpdate)
	m.HandleFunc("POST /account/password", s.accountPassword)
	m.HandleFunc("DELETE /account/tokens", s.accountRevokeTokens)
	m.HandleFunc("POST /account/avatar", s.accountAvatar)
	m.HandleFunc("DELETE /account/avatar", s.accountAvatarRemove)

	// OAuth 2.0 / OIDC
	m.HandleFunc("GET /.well-known/openid-configuration", s.discovery)
	m.HandleFunc("GET /.well-known/jwks.json", s.jwks)
	m.HandleFunc("GET /oauth/authorize", s.authorize)
	m.HandleFunc("POST /oauth/token", s.token)
	m.HandleFunc("POST /oauth/introspect", s.introspect)
	m.HandleFunc("POST /oauth/revoke", s.revoke)
	m.HandleFunc("GET /oauth/userinfo", s.userinfo)
	m.HandleFunc("POST /oauth/userinfo", s.userinfo)

	// Account API
	m.HandleFunc("GET /api/me", s.apiToken(s.apiMeShow, ""))
	m.HandleFunc("PATCH /api/me", s.apiToken(s.apiMeUpdate, ""))
	m.HandleFunc("POST /api/me/avatar", s.apiToken(s.apiMeAvatar, ""))
	m.HandleFunc("DELETE /api/me/avatar", s.apiToken(s.apiMeAvatarRemove, ""))
	m.HandleFunc("PUT /api/me/password", s.apiToken(s.apiMePassword, ""))
	m.HandleFunc("GET /api/users", s.apiToken(s.apiUsersIndex, "admin"))
	m.HandleFunc("POST /api/users", s.apiToken(s.apiUsersStore, "admin"))
	m.HandleFunc("GET /api/users/{user}", s.apiToken(s.apiUsersShow, "admin"))
	m.HandleFunc("PATCH /api/users/{user}", s.apiToken(s.apiUsersUpdate, "admin"))
	m.HandleFunc("DELETE /api/users/{user}", s.apiToken(s.apiUsersDestroy, "admin"))
	m.HandleFunc("POST /api/users/{user}/password", s.apiToken(s.apiUsersPassword, "admin"))
	m.HandleFunc("POST /api/users/{user}/reset-link", s.apiToken(s.apiUsersResetLink, "admin"))
	m.HandleFunc("POST /api/users/{user}/avatar", s.apiToken(s.apiUsersAvatar, "admin"))
	m.HandleFunc("DELETE /api/users/{user}/avatar", s.apiToken(s.apiUsersAvatarRemove, "admin"))
	m.HandleFunc("POST /api/users/{user}/sign-out", s.apiToken(s.apiUsersSignOut, "admin"))

	// Administration
	m.HandleFunc("GET /admin/login", s.adminLogin)
	m.HandleFunc("POST /admin/logout", s.adminGuard(s.adminLogout))
	m.HandleFunc("GET /admin", s.adminGuard(s.adminDashboard))
	m.HandleFunc("GET /admin/{$}", s.adminGuard(s.adminDashboard))
	m.HandleFunc("GET /admin/users", s.adminGuard(s.adminUsersIndex))
	m.HandleFunc("POST /admin/users", s.adminGuard(s.adminUsersStore))
	m.HandleFunc("GET /admin/users/create", s.adminGuard(s.adminUsersCreate))
	m.HandleFunc("GET /admin/users/{user}", s.adminGuard(s.adminUsersShow))
	m.HandleFunc("GET /admin/users/{user}/edit", s.adminGuard(s.adminUsersEdit))
	m.HandleFunc("PUT /admin/users/{user}", s.adminGuard(s.adminUsersUpdate))
	m.HandleFunc("DELETE /admin/users/{user}", s.adminGuard(s.adminUsersDestroy))
	m.HandleFunc("POST /admin/users/{user}/role", s.adminGuard(s.adminUsersRole))
	m.HandleFunc("POST /admin/users/{user}/status", s.adminGuard(s.adminUsersStatus))
	m.HandleFunc("POST /admin/users/{user}/password", s.adminGuard(s.adminUsersPassword))
	m.HandleFunc("POST /admin/users/{user}/reset-link", s.adminGuard(s.adminUsersResetLink))
	m.HandleFunc("POST /admin/users/{user}/avatar", s.adminGuard(s.adminUsersAvatar))
	m.HandleFunc("DELETE /admin/users/{user}/avatar", s.adminGuard(s.adminUsersAvatarRemove))
	m.HandleFunc("POST /admin/users/{user}/sign-out", s.adminGuard(s.adminUsersSignOut))
	m.HandleFunc("GET /admin/clients", s.adminGuard(s.adminClientsIndex))
	m.HandleFunc("GET /admin/clients/create", s.adminGuard(s.adminClientsCreate))
	m.HandleFunc("POST /admin/clients", s.adminGuard(s.adminClientsStore))
	m.HandleFunc("GET /admin/clients/{client}/edit", s.adminGuard(s.adminClientsEdit))
	m.HandleFunc("PUT /admin/clients/{client}", s.adminGuard(s.adminClientsUpdate))
	m.HandleFunc("GET /admin/audit", s.adminGuard(s.adminAudit))

	// Pictures, robots, favicon and the health probe
	m.HandleFunc("GET /avatar/{user}/{v}", s.avatar)
	m.HandleFunc("GET /healthz", s.healthz)
	m.HandleFunc("GET /robots.txt", s.robots)
	m.HandleFunc("GET /favicon.ico", s.favicon)
	m.HandleFunc("GET /assets/{file...}", s.asset)

	s.mux = m
}

// ServeHTTP is the whole middleware stack, in the one order that works:
// parse the body (so a form's _method can change the method the router sees),
// install the public base URL, start the session, check CSRF, dispatch, then
// save the session. The response is buffered until the session is saved:
// Set-Cookie has to reach the wire, and a handler that already wrote a redirect
// has already flushed the headers.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rec := newBufferedResponse()
	s.securityHeaders(rec, r)

	// A form cannot send DELETE/PUT; Blade's @method('delete') rides in the body
	// and Laravel's method override rewrites the verb before routing.
	if r.Method == http.MethodPost && r.URL.Path != "/oauth/token" && r.URL.Path != "/oauth/introspect" && r.URL.Path != "/oauth/revoke" {
		_ = parseForm(r, 8<<20)
		if override := r.PostFormValue("_method"); override != "" {
			upper := strings.ToUpper(override)
			switch upper {
			case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
				r.Method = upper
			}
		}
	}

	if s.needsSession(r.URL.Path) {
		sess, err := s.loadSession(rec, r)
		if err != nil {
			log.Printf("session: %v", err)
			http.Error(rec, "session unavailable", http.StatusInternalServerError)
			rec.flush(w)
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), sessionKey{}, sess))

		if isUnsafe(r.Method) && !csrfExempt(r.URL.Path) {
			if !sess.validCSRF(r) {
				s.handleCSRF(rec, r, sess)
				if err := sess.save(); err != nil {
					log.Printf("session save: %v", err)
				}
				rec.flush(w)
				return
			}
		}

		s.mux.ServeHTTP(rec, r)
		if err := sess.save(); err != nil {
			log.Printf("session save: %v", err)
		}
	} else {
		s.mux.ServeHTTP(rec, r)
	}

	if rec.status >= 500 {
		log.Printf("%s %s -> %d (%s)", r.Method, r.URL.Path, rec.status, time.Since(start))
	}
	rec.flush(w)
}

// needsSession decides where the session cookie is required. Everything that a
// person browses is a session request; the machine endpoints are stateless.
func (s *Server) needsSession(p string) bool {
	switch {
	case p == "/healthz", strings.HasPrefix(p, "/assets/"), strings.HasPrefix(p, "/avatar/"),
		p == "/robots.txt", p == "/favicon.ico",
		strings.HasPrefix(p, "/api/"), strings.HasPrefix(p, "/.well-known/"):
		return false
	case p == "/oauth/token", p == "/oauth/introspect", p == "/oauth/revoke":
		return false
	}
	return true
}

func csrfExempt(p string) bool {
	return p == "/oauth/token" || p == "/oauth/introspect" || p == "/oauth/revoke"
}

func isUnsafe(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	return true
}

// securityHeaders is SecurityHeaders: a small, boring set. HSTS is left to the
// TLS terminator so the service stays scheme agnostic.
func (s *Server) securityHeaders(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy",
		"default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; "+
			"form-action 'self'; frame-ancestors 'none'; base-uri 'none'")

	// Token endpoints never cache, and neither do authenticated pages: a console
	// page restored from the back/forward cache can carry links from an older
	// build, which is how a stale "/admin/devices" without the prefix reached a
	// browser once.
	p := r.URL.Path
	if strings.HasPrefix(p, "/oauth/") || strings.HasPrefix(p, "/.well-known/") || p == "/userinfo" ||
		strings.HasPrefix(p, "/api/") || strings.HasPrefix(p, "/admin") || p == "/login" || p == "/logout" {
		h.Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
		h.Set("Pragma", "no-cache")
	}
}

// publicBase is the root every generated URL starts with. The service is
// proxied under a mount point that the proxy strips, so the base is built from
// the forwarded host plus the configured prefix, never from the path the
// container sees (DESIGN.md §8).
func (s *Server) publicBase(r *http.Request) string {
	host := r.Host
	if forwarded := r.Header.Get("X-Forwarded-Host"); forwarded != "" {
		host = strings.TrimSpace(strings.Split(forwarded, ",")[0])
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = strings.TrimSpace(strings.Split(proto, ",")[0])
	}

	if s.Cfg.ForceRootURL {
		// Every value that leaves the service carries the canonical issuer, with
		// its own scheme and mount point (docs/DESIGN.md §8).
		return strings.TrimRight(s.Cfg.Issuer, "/")
	}
	return scheme + "://" + host
}

// ---- response helpers ----------------------------------------------------

// bufferedResponse holds a handler's response until the session has been
// saved: Set-Cookie is part of that response, and http.Redirect has already
// written the headers by the time a handler returns.
type bufferedResponse struct {
	header http.Header
	status int
	wrote  bool
	body   bytes.Buffer
}

func newBufferedResponse() *bufferedResponse {
	return &bufferedResponse{header: http.Header{}, status: http.StatusOK}
}

func (b *bufferedResponse) Header() http.Header { return b.header }

func (b *bufferedResponse) WriteHeader(status int) {
	if b.wrote {
		return
	}
	b.status = status
	b.wrote = true
}

func (b *bufferedResponse) Write(data []byte) (int, error) {
	if !b.wrote {
		b.WriteHeader(http.StatusOK)
	}
	return b.body.Write(data)
}

func (b *bufferedResponse) flush(w http.ResponseWriter) {
	for key, values := range b.header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	status := b.status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = w.Write(b.body.Bytes())
}

func (s *Server) json(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(body); err != nil {
		log.Printf("json: %v", err)
	}
}

func (s *Server) redirect(w http.ResponseWriter, r *http.Request, location string, status int) {
	// Laravel sends an absolute Location; clients and the tests read it that way.
	if strings.HasPrefix(location, "/") {
		location = s.publicBase(r) + location
	}
	http.Redirect(w, r, location, status)
}

func (s *Server) back(w http.ResponseWriter, r *http.Request) {
	target := s.publicBase(r) + r.URL.Path
	if sess := sessionOf(r); sess != nil {
		if previous := sess.string("url.previous"); previous != "" {
			target = previous
		}
	}
	http.Redirect(w, r, target, http.StatusFound)
}

// serverError is the catch-all: never a stack trace, always a readable status.
func (s *Server) serverError(w http.ResponseWriter, r *http.Request, err error) {
	log.Printf("error: %s %s: %v", r.Method, r.URL.Path, err)
	http.Error(w, "서버 오류가 발생했습니다.", http.StatusInternalServerError)
}

func (s *Server) notFound(w http.ResponseWriter, r *http.Request) {
	s.renderError(w, r, http.StatusNotFound, "찾을 수 없습니다", "주소가 바뀌었거나 삭제되었습니다.")
}

func (s *Server) forbidden(w http.ResponseWriter, r *http.Request, message string) {
	s.renderError(w, r, http.StatusForbidden, "접근할 수 없습니다", message)
}

func (s *Server) renderError(w http.ResponseWriter, r *http.Request, status int, title, message string) {
	data := s.baseData(r)
	data["Title"] = title
	data["Message"] = message
	data["Main"] = ""
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if tpl, ok := s.Templates["errors/error"]; ok {
		if err := tpl.ExecuteTemplate(w, "layouts/app.html", data); err != nil {
			log.Printf("render error page: %v", err)
		}
	}
}

// ---- small helpers -------------------------------------------------------

func (s *Server) requestMeta(r *http.Request) service.RequestMeta {
	ip := r.RemoteAddr
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		ip = strings.TrimSpace(strings.Split(forwarded, ",")[0])
	}
	if host, _, err := net.SplitHostPort(ip); err == nil {
		ip = host
	}
	return service.RequestMeta{IP: ip, UserAgent: r.UserAgent()}
}

func atoi(v string) (int64, bool) {
	n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

func urlWith(base string, params url.Values) string {
	if len(params) == 0 {
		return base
	}
	separator := "?"
	if strings.Contains(base, "?") {
		separator = "&"
	}
	return base + separator + params.Encode()
}

func dict(values ...any) map[string]any {
	out := map[string]any{}
	for i := 0; i+1 < len(values); i += 2 {
		key, ok := values[i].(string)
		if !ok {
			continue
		}
		out[key] = values[i+1]
	}
	return out
}
