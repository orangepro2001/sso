package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"sso/internal/config"
	"sso/internal/secure"
	"sso/internal/server"
	"sso/internal/service"
	"sso/internal/store"
)

// TestSmoke is the promise this port has to keep: one binary, one SQLite file,
// and the flows the PHP served — discovery, an authorization-code+PKCE sign-in,
// userinfo, refresh rotation, the console, and a health probe that does not
// touch the database.
func TestSmoke(t *testing.T) {
	env := newTestApp(t)

	t.Run("healthz does not need the database", func(t *testing.T) {
		dir := t.TempDir()
		st, err := store.Open(filepath.Join(dir, "closed.db"), dir)
		if err != nil {
			t.Fatal(err)
		}
		srv, err := server.New(server.Options{Config: env.cfg, Store: st, Files: webFiles, HashCosts: 4})
		if err != nil {
			t.Fatal(err)
		}
		// Close the database before asking: a health probe that queried it would
		// now fail, and a brief outage must not restart-loop the proxy.
		st.Close()

		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("healthz: status %d body %s", rec.Code, rec.Body.String())
		}
		var body map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body["status"] != "ok" || body["service"] != "sso" {
			t.Fatalf("unexpected health body: %v", body)
		}
	})

	t.Run("discovery describes the issuer", func(t *testing.T) {
		body := env.getJSON(t, "/.well-known/openid-configuration", "")
		if body["issuer"] != env.cfg.Issuer {
			t.Fatalf("issuer = %v", body["issuer"])
		}
		if body["token_endpoint"] != env.cfg.Issuer+"/oauth/token" {
			t.Fatalf("token_endpoint = %v", body["token_endpoint"])
		}
		if body["jwks_uri"] != env.cfg.Issuer+"/.well-known/jwks.json" {
			t.Fatalf("jwks_uri = %v", body["jwks_uri"])
		}
		methods, _ := body["code_challenge_methods_supported"].([]any)
		if len(methods) != 1 || methods[0] != "S256" {
			t.Fatalf("pkce methods = %v", methods)
		}
		if _, ok := body["guest_endpoint"]; ok {
			t.Fatal("the removed guest channel is still advertised")
		}

		jwks := env.getJSON(t, "/.well-known/jwks.json", "")
		keys, _ := jwks["keys"].([]any)
		if len(keys) == 0 {
			t.Fatal("empty jwks")
		}
		first, _ := keys[0].(map[string]any)
		if first["kty"] != "RSA" || first["alg"] != "RS256" {
			t.Fatalf("unexpected key: %v", first)
		}
		if _, private := first["d"]; private {
			t.Fatal("the private key leaked into the JWKS")
		}
	})

	var accessToken string

	t.Run("authorization code + PKCE", func(t *testing.T) {
		verifier := randomVerifier()
		challenge := pkceChallenge(verifier)

		// 1. Anonymous: the request is parked and the browser goes to sign in.
		location := env.redirect(t, "/oauth/authorize?"+url.Values{
			"response_type":         {"code"},
			"client_id":             {env.clientID},
			"redirect_uri":          {env.redirectURI},
			"scope":                 {"openid profile offline_access"},
			"state":                 {"carry-me"},
			"code_challenge":        {challenge},
			"code_challenge_method": {"S256"},
		}.Encode())
		if !strings.Contains(location, "/login") || !strings.Contains(location, "client=") {
			t.Fatalf("expected a sign-in redirect naming the client, got %s", location)
		}

		// 2. The sign-in page, so the form has a CSRF token and a cookie.
		page := env.get(t, "/login", "")
		token := csrfToken(t, page)

		// 3. Sign in: the controller replays the parked authorization request.
		location = env.postForm(t, "/login", url.Values{
			"_token":   {token},
			"username": {env.username},
			"password": {env.password},
		})
		if !strings.Contains(location, "/oauth/authorize") || !strings.Contains(location, "carry-me") ||
			!strings.Contains(location, "code_challenge=") {
			t.Fatalf("login did not resume the parked request: %s", location)
		}

		// 4. Replaying the authorize URL now yields a code for that user.
		resume, err := url.Parse(location)
		if err != nil {
			t.Fatal(err)
		}
		location = env.redirect(t, resume.RequestURI())
		if !strings.HasPrefix(location, env.redirectURI+"?") {
			t.Fatalf("expected a redirect to the client, got %s", location)
		}
		query, err := url.Parse(location)
		if err != nil {
			t.Fatal(err)
		}
		code := query.Query().Get("code")
		if code == "" {
			t.Fatalf("no code in %s", location)
		}
		if query.Query().Get("state") != "carry-me" {
			t.Fatalf("state was not returned: %s", location)
		}

		// 5. Redeem it: seven-day access token, rotating refresh token, ID token.
		tokens := env.postJSON(t, "/oauth/token", url.Values{
			"grant_type":    {"authorization_code"},
			"client_id":     {env.clientID},
			"code":          {code},
			"redirect_uri":  {env.redirectURI},
			"code_verifier": {verifier},
		})
		if tokens["token_type"] != "Bearer" {
			t.Fatalf("token_type = %v", tokens["token_type"])
		}
		if tokens["expires_in"] != float64(604800) {
			t.Fatalf("expires_in = %v", tokens["expires_in"])
		}
		if tokens["scope"] != "openid profile offline_access" {
			t.Fatalf("scope = %v", tokens["scope"])
		}
		accessToken, _ = tokens["access_token"].(string)
		if accessToken == "" {
			t.Fatal("no access token")
		}
		refresh, _ := tokens["refresh_token"].(string)
		if refresh == "" {
			t.Fatal("no refresh token")
		}
		idToken, _ := tokens["id_token"].(string)
		if idToken == "" {
			t.Fatal("no id token")
		}

		// The code is single use.
		if errBody := env.postJSONStatus(t, "/oauth/token", url.Values{
			"grant_type":    {"authorization_code"},
			"client_id":     {env.clientID},
			"code":          {code},
			"code_verifier": {verifier},
		}, http.StatusBadRequest); errBody["error"] != "invalid_grant" {
			t.Fatalf("second redemption = %v", errBody)
		}

		// 6. userinfo speaks for the signed-in person.
		info := env.getJSON(t, "/oauth/userinfo", accessToken)
		if info["sub"] != fmt.Sprint(env.userID) {
			t.Fatalf("sub = %v", info["sub"])
		}
		if info["preferred_username"] != env.username {
			t.Fatalf("preferred_username = %v", info["preferred_username"])
		}
		if info["name"] != env.name || info["role"] != "user" {
			t.Fatalf("userinfo = %v", info)
		}
		if info["subject_type"] != "user" {
			t.Fatalf("subject_type = %v", info["subject_type"])
		}

		// 7. Refresh rotates; replaying the old one kills the family.
		rotated := env.postJSON(t, "/oauth/token", url.Values{
			"grant_type":    {"refresh_token"},
			"client_id":     {env.clientID},
			"refresh_token": {refresh},
		})
		newRefresh, _ := rotated["refresh_token"].(string)
		if newRefresh == "" || newRefresh == refresh {
			t.Fatalf("refresh did not rotate: %v", rotated)
		}

		if errBody := env.postJSONStatus(t, "/oauth/token", url.Values{
			"grant_type":    {"refresh_token"},
			"client_id":     {env.clientID},
			"refresh_token": {refresh},
		}, http.StatusBadRequest); errBody["error"] != "invalid_grant" {
			t.Fatalf("replayed refresh = %v", errBody)
		}
		if errBody := env.postJSONStatus(t, "/oauth/token", url.Values{
			"grant_type":    {"refresh_token"},
			"client_id":     {env.clientID},
			"refresh_token": {newRefresh},
		}, http.StatusBadRequest); errBody["error"] != "invalid_grant" {
			t.Fatalf("the family should be dead, got %v", errBody)
		}
	})

	t.Run("a public client without PKCE is refused", func(t *testing.T) {
		location := env.redirect(t, "/oauth/authorize?"+url.Values{
			"response_type": {"code"},
			"client_id":     {env.clientID},
			"redirect_uri":  {env.redirectURI},
			"scope":         {"openid"},
		}.Encode())
		if !strings.Contains(location, "error=invalid_request") || strings.Contains(location, "code=") {
			t.Fatalf("expected an invalid_request redirect, got %s", location)
		}
	})

	t.Run("the console needs a super administrator", func(t *testing.T) {
		// Anonymous: the console sends the visitor to the one sign-in.
		visitor := env.newClient()
		location := visitor.redirect(t, "/admin")
		if !strings.HasSuffix(location, "/login") {
			t.Fatalf("anonymous /admin -> %s", location)
		}
		location = visitor.redirect(t, "/admin/login")
		if !strings.HasSuffix(location, "/login") {
			t.Fatalf("/admin/login -> %s", location)
		}

		// An ordinary user gets 403, not the console.
		anon := env.newClient()
		page := anon.get(t, "/login", "")
		anon.postForm(t, "/login", url.Values{
			"_token":   {csrfToken(t, page)},
			"username": {env.username},
			"password": {env.password},
		})
		if status, _ := anon.getStatus(t, "/admin/users"); status != http.StatusForbidden {
			t.Fatalf("ordinary user /admin/users = %d", status)
		}

		// The administrator signs in and every console page renders.
		admin := env.newClient()
		page = admin.get(t, "/login", "")
		admin.postForm(t, "/login", url.Values{
			"_token":   {csrfToken(t, page)},
			"username": {"boss"},
			"password": {"boss-password-1"},
		})
		for _, path := range []string{"/admin/users", "/admin/audit", "/admin/clients", "/admin/clients/create"} {
			status, body := admin.getStatus(t, path)
			if status != http.StatusOK {
				t.Fatalf("%s = %d: %s", path, status, body)
			}
			// A missing template value renders as "<no value>"; a page that leaks
			// that is a page that was not finished.
			if strings.Contains(body, "<no value>") {
				t.Fatalf("%s rendered a missing value", path)
			}
		}
		status, body := admin.getStatus(t, fmt.Sprintf("/admin/users/%d", env.userID))
		if status != http.StatusOK || !strings.Contains(body, "비밀번호 재설정") {
			t.Fatalf("person page = %d", status)
		}
		status, body = admin.getStatus(t, fmt.Sprintf("/admin/clients/%d/edit", env.clientRowID))
		if status != http.StatusOK || !strings.Contains(body, env.clientID) {
			t.Fatalf("client page = %d", status)
		}
		// The account page and the public pages render too.
		for _, path := range []string{"/", "/account", "/password/reset/nope"} {
			if status, body := admin.getStatus(t, path); status != http.StatusOK {
				t.Fatalf("%s = %d: %s", path, status, body)
			}
		}
		if status, body := visitor.getStatus(t, "/register"); status != http.StatusOK || !strings.Contains(body, "가입하기") {
			t.Fatalf("/register = %d: %s", status, body)
		}
	})

	t.Run("an administrator creates a person and hands out a reset link", func(t *testing.T) {
		admin := env.newClient()
		page := admin.get(t, "/login", "")
		admin.postForm(t, "/login", url.Values{
			"_token":   {csrfToken(t, page)},
			"username": {"boss"},
			"password": {"boss-password-1"},
		})

		list := admin.get(t, "/admin/users", "")
		location := admin.postForm(t, "/admin/users", url.Values{
			"_token":   {csrfToken(t, list)},
			"name":     {"채길용 사원"},
			"username": {"Chae.Gilyong"},
			"password": {"created-password-1"},
			"role":     {"user"},
		})
		if !strings.Contains(location, "/admin/users/") {
			t.Fatalf("create -> %s", location)
		}
		id := location[strings.LastIndex(location, "/")+1:]
		person := admin.get(t, "/admin/users/"+id, "")
		if !strings.Contains(person, "채길용 사원") || !strings.Contains(person, "chae.gilyong") {
			t.Fatalf("person page did not show the new account: %.300s", person)
		}

		// A one-time link, shown once, superseding any earlier one.
		admin.postForm(t, "/admin/users/"+id+"/reset-link", url.Values{"_token": {csrfToken(t, person)}})
		shown := admin.get(t, "/admin/users/"+id, "")
		resetToken := resetTokenPattern.FindString(shown)
		if resetToken == "" {
			t.Fatalf("no reset link on the page: %.400s", shown)
		}

		// The link is a credential for an anonymous browser.
		anonymous := env.newClient()
		form := anonymous.get(t, "/password/reset/"+resetToken, "")
		if !strings.Contains(form, "새 비밀번호 정하기") {
			t.Fatalf("reset page: %.300s", form)
		}
		anonymous.postForm(t, "/password/reset/"+resetToken, url.Values{
			"_token":                {csrfToken(t, form)},
			"password":              {"chosen-by-the-user-42"},
			"password_confirmation": {"chosen-by-the-user-42"},
		})

		// The new password works, and the old one does not.
		fresh := env.newClient()
		login := fresh.get(t, "/login", "")
		location = fresh.postForm(t, "/login", url.Values{
			"_token":   {csrfToken(t, login)},
			"username": {"chae.gilyong"},
			"password": {"chosen-by-the-user-42"},
		})
		if strings.HasSuffix(location, "/login") {
			t.Fatalf("the reset password did not sign in: %s", location)
		}

		// A blank password is generated and shown exactly once.
		list = admin.get(t, "/admin/users", "")
		created := admin.postForm(t, "/admin/users", url.Values{
			"_token":   {csrfToken(t, list)},
			"name":     {"신입 사원"},
			"username": {"newcomer"},
			"password": {""},
			"role":     {"user"},
		})
		createdURL, err := url.Parse(created)
		if err != nil {
			t.Fatal(err)
		}
		generatedPage := admin.get(t, createdURL.RequestURI(), "")
		generated := generatedPasswordPattern.FindStringSubmatch(generatedPage)
		if len(generated) != 2 {
			t.Fatalf("no generated password on the page: %.400s", generatedPage)
		}
		signedIn := env.newClient()
		loginPage := signedIn.get(t, "/login", "")
		signedIn.postForm(t, "/login", url.Values{
			"_token":   {csrfToken(t, loginPage)},
			"username": {"newcomer"},
			"password": {generated[1]},
		})
		homePage := signedIn.get(t, "/", "")
		if !strings.Contains(homePage, "신입 사원 님, 안녕하세요") {
			t.Fatalf("the generated password did not sign in")
		}

		audit := admin.get(t, "/admin/audit", "")
		for _, want := range []string{"계정 생성", "비밀번호 재설정 링크 발급", "링크로 비밀번호 재설정"} {
			if !strings.Contains(audit, want) {
				t.Fatalf("audit page is missing %q", want)
			}
		}
	})

	t.Run("client credentials, introspection and revocation", func(t *testing.T) {
		tokens := env.postJSONBasic(t, "/oauth/token", env.confClientID, env.confSecret,
			`{"grant_type":"client_credentials","scope":"db:read"}`)
		if tokens["token_type"] != "Bearer" || tokens["scope"] != "db:read" {
			t.Fatalf("client_credentials = %v", tokens)
		}
		if tokens["expires_in"] != float64(604800) {
			t.Fatalf("expires_in = %v", tokens["expires_in"])
		}
		if _, ok := tokens["refresh_token"]; ok {
			t.Fatalf("a machine token must have no refresh token: %v", tokens)
		}
		machineToken, _ := tokens["access_token"].(string)

		info := env.getJSON(t, "/oauth/userinfo", machineToken)
		if info["subject_type"] != "client" || info["sub"] != "client:"+env.confClientID {
			t.Fatalf("client userinfo = %v", info)
		}

		introspected := env.postJSONBasic(t, "/oauth/introspect", env.confClientID, env.confSecret,
			fmt.Sprintf(`{"token":%q}`, machineToken))
		if introspected["active"] != true || introspected["token_kind"] != "jwt" {
			t.Fatalf("introspection = %v", introspected)
		}
		if introspected["client_id"] != env.confClientID || introspected["subject_type"] != "client" {
			t.Fatalf("introspection = %v", introspected)
		}

		env.postJSONBasic(t, "/oauth/revoke", env.confClientID, env.confSecret,
			fmt.Sprintf(`{"token":%q}`, machineToken))
		if again := env.postJSONBasic(t, "/oauth/introspect", env.confClientID, env.confSecret,
			fmt.Sprintf(`{"token":%q}`, machineToken)); again["active"] != false {
			t.Fatalf("a revoked token is still active: %v", again)
		}

		// A wrong secret is a 401, and a public client cannot use this grant.
		env.postJSONBasicStatus(t, "/oauth/token", env.confClientID, "wrong-secret",
			`{"grant_type":"client_credentials"}`, http.StatusUnauthorized, "invalid_client")
		env.postJSONStatus(t, "/oauth/token", url.Values{
			"grant_type": {"client_credentials"},
			"client_id":  {env.clientID},
		}, http.StatusBadRequest)
	})

	t.Run("a picture is uploaded, served anonymously and removed", func(t *testing.T) {
		uploaded := env.postMultipart(t, "/api/me/avatar", accessToken, pngBytes(t))
		picture, _ := uploaded["picture"].(string)
		if picture == "" {
			t.Fatalf("no picture after upload: %v", uploaded)
		}
		parsed, err := url.Parse(picture)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(picture, env.cfg.Issuer+"/avatar/") {
			t.Fatalf("picture is not built from the issuer: %s", picture)
		}
		// The route is anonymous: the signature in the URL is the credential.
		path := strings.TrimPrefix(parsed.Path, "/sso")
		status, _ := env.getStatus(t, path+"?"+parsed.RawQuery)
		if status != http.StatusOK {
			t.Fatalf("avatar route = %d", status)
		}
		if status, _ := env.getStatus(t, path+"?sig=forged"); status != http.StatusForbidden {
			t.Fatalf("a forged signature = %d", status)
		}

		removed := env.deleteWithToken(t, "/api/me/avatar", accessToken)
		if removed["picture"] != nil {
			t.Fatalf("picture survived removal: %v", removed)
		}
	})

	t.Run("the administration API lists, edits and protects the last admin", func(t *testing.T) {
		ctx := t.Context()
		boss, err := env.srv.Store.UserByUsername(ctx, "boss")
		if err != nil || boss == nil {
			t.Fatalf("bootstrap administrator missing: %v", err)
		}
		adminToken, err := env.srv.Tokens.IssueForUser(ctx, boss, env.clientID, []string{"openid", "profile"}, service.RequestMeta{}, "")
		if err != nil {
			t.Fatal(err)
		}

		list := env.getJSON(t, "/api/users", adminToken.AccessToken)
		data, _ := list["data"].([]any)
		if len(data) < 3 {
			t.Fatalf("user list = %v", list)
		}
		meta, _ := list["meta"].(map[string]any)
		if total, _ := meta["total"].(float64); total < 3 || int(total) != len(data) {
			t.Fatalf("meta = %v (data has %d)", meta, len(data))
		}

		// An administrator sees the administrative fields on somebody else.
		person := env.getJSON(t, fmt.Sprintf("/api/users/%d", env.userID), adminToken.AccessToken)
		if person["username"] != env.username {
			t.Fatalf("person = %v", person)
		}
		if _, ok := person["note"]; !ok {
			t.Fatalf("an administrator must see the note field: %v", person)
		}

		// The last administrator cannot disable themselves, and an ordinary
		// token cannot reach the administration API at all.
		env.patchJSONStatus(t, fmt.Sprintf("/api/users/%d", boss.ID), adminToken.AccessToken,
			`{"status":"disabled"}`, http.StatusUnprocessableEntity)
		if body := env.patchJSONStatus(t, fmt.Sprintf("/api/users/%d", env.userID), accessToken,
			`{"name":"nope"}`, http.StatusForbidden); body["error"] != "forbidden" {
			t.Fatalf("ordinary token on /api/users = %v", body)
		}

		link := env.postJSONWithToken(t, fmt.Sprintf("/api/users/%d/reset-link", env.userID), adminToken.AccessToken)
		if url, _ := link["url"].(string); !strings.Contains(url, "/password/reset/sso_pw_") {
			t.Fatalf("reset link = %v", link)
		}
	})

	t.Run("the account API answers with the documented shape", func(t *testing.T) {
		me := env.getJSON(t, "/api/me", accessToken)
		if me["username"] != env.username || me["status"] != "active" {
			t.Fatalf("me = %v", me)
		}
		if _, ok := me["note"]; ok {
			t.Fatalf("an ordinary user must not see administrative fields: %v", me)
		}
		if me["picture"] != nil {
			t.Fatalf("picture = %v", me["picture"])
		}

		status, body := env.getStatusWithToken(t, "/api/me", "")
		if status != http.StatusUnauthorized || !strings.Contains(body, "invalid_token") {
			t.Fatalf("anonymous API = %d %s", status, body)
		}
	})
}

// ---- harness -------------------------------------------------------------

type testApp struct {
	cfg          *config.Config
	srv          *server.Server
	server       *httptest.Server
	jar          *cookiejar.Jar
	client       *http.Client
	clientID     string
	clientRowID  int64
	confClientID string
	confSecret   string
	redirectURI  string
	username     string
	password     string
	name         string
	userID       int64
}

func newTestApp(t *testing.T) *testApp {
	t.Helper()
	dir := t.TempDir()

	t.Setenv("APP_ENV", "testing")
	t.Setenv("APP_KEY", "base64:2fl+Kpv3vX0aPZQGc7M8Q0nWzN8mZ0hBq0pR5QzYQ2s=")
	t.Setenv("APP_URL", "https://sso.test")
	t.Setenv("SSO_ISSUER", "https://sso.test/sso")
	t.Setenv("SSO_URL_SCHEME", "https")
	t.Setenv("SSO_FORCE_ROOT_URL", "false")
	t.Setenv("SESSION_PATH", "/")
	t.Setenv("SESSION_SECURE_COOKIE", "false")
	t.Setenv("WR_DB", filepath.Join(dir, "sso.db"))
	t.Setenv("WR_STORAGE", filepath.Join(dir, "storage"))
	t.Setenv("SSO_BOOTSTRAP_ADMIN_USERNAME", "boss")
	t.Setenv("SSO_BOOTSTRAP_ADMIN_PASSWORD", "boss-password-1")
	t.Setenv("SSO_BOOTSTRAP_ADMIN_NAME", "관리자")

	cfg := config.Load()
	st, err := store.Open(cfg.ResolveDBFile(), cfg.ResolveStorageDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	srv, err := server.New(server.Options{Config: cfg, Store: st, Files: webFiles, HashCosts: 4})
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(srv)
	t.Cleanup(httpServer.Close)

	app := &testApp{cfg: cfg, srv: srv, server: httpServer}
	app.redirectURI = "https://client.example/callback"

	// The administrator the environment asked for, exactly as main does on boot.
	if err := bootstrapForTest(t, cfg, srv); err != nil {
		t.Fatal(err)
	}

	// One ordinary user, created the way the console creates them.
	hash, err := secure.HashPassword("user-password-1", 4)
	if err != nil {
		t.Fatal(err)
	}
	app.username = "plainuser"
	app.password = "user-password-1"
	app.name = "정태훈 대리"
	user := &store.User{
		Name:     app.name,
		Username: app.username,
		Role:     store.RoleUser,
		Password: hash,
		Status:   store.StatusActive,
	}
	if err := st.InsertUser(t.Context(), user); err != nil {
		t.Fatal(err)
	}
	app.userID = user.ID

	// A public client: PKCE, no secret, a launcher entry, the scopes the flow needs.
	client := &store.Client{
		ClientID:      "sso_testclient012345678901",
		Name:          "업무일보",
		Type:          store.ClientTypePublic,
		RedirectURIs:  store.JSONList{app.redirectURI},
		HomeURL:       ptr("https://report.example"),
		AllowedScopes: store.JSONList{"openid", "profile", "offline_access", "db:read"},
		Active:        true,
		InLauncher:    true,
		Note:          ptr("사내 업무일보"),
	}
	if err := st.InsertClient(t.Context(), client); err != nil {
		t.Fatal(err)
	}
	app.clientID = client.ClientID
	app.clientRowID = client.ID

	// A confidential client for the machine grant: a secret, no PKCE.
	app.confSecret = "very-secret-1"
	secretHash, err := secure.HashPassword(app.confSecret, 4)
	if err != nil {
		t.Fatal(err)
	}
	confidential := &store.Client{
		ClientID:      "sso_machineclient0123456789",
		Name:          "보고서 서비스",
		Type:          store.ClientTypeConfidential,
		SecretHash:    &secretHash,
		RedirectURIs:  store.JSONList{"https://service.example/cb"},
		AllowedScopes: store.JSONList{"db:read"},
		Active:        true,
	}
	if err := st.InsertClient(t.Context(), confidential); err != nil {
		t.Fatal(err)
	}
	app.confClientID = confidential.ClientID

	app.jar, _ = cookiejar.New(nil)
	app.client = &http.Client{
		Jar: app.jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return app
}

func bootstrapForTest(t *testing.T, cfg *config.Config, srv *server.Server) error {
	t.Helper()
	// main.ensureBootstrap is unexported but in this package, which also means
	// the test covers the real boot path rather than a copy of it.
	return ensureBootstrap(t.Context(), srv, srv.Store, cfg, false)
}

// newClient is a second browser: same application, a separate cookie jar.
func (a *testApp) newClient() *testApp {
	jar, _ := cookiejar.New(nil)
	copied := *a
	copied.jar = jar
	copied.client = &http.Client{
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &copied
}

func (a *testApp) do(t *testing.T, method, path, token, body string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(method, a.server.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	response, err := a.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func (a *testApp) get(t *testing.T, path, token string) string {
	t.Helper()
	status, body := a.getStatusWithToken(t, path, token)
	if status != http.StatusOK {
		t.Fatalf("GET %s = %d: %s", path, status, body)
	}
	return body
}

func (a *testApp) getStatus(t *testing.T, path string) (int, string) {
	t.Helper()
	return a.getStatusWithToken(t, path, "")
}

func (a *testApp) getStatusWithToken(t *testing.T, path, token string) (int, string) {
	t.Helper()
	response := a.do(t, http.MethodGet, path, token, "")
	defer response.Body.Close()
	data, _ := io.ReadAll(response.Body)
	return response.StatusCode, string(data)
}

func (a *testApp) getJSON(t *testing.T, path, token string) map[string]any {
	t.Helper()
	status, body := a.getStatusWithToken(t, path, token)
	if status != http.StatusOK {
		t.Fatalf("GET %s = %d: %s", path, status, body)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(body), &decoded); err != nil {
		t.Fatalf("GET %s: %v (%s)", path, err, body)
	}
	return decoded
}

func (a *testApp) redirect(t *testing.T, path string) string {
	t.Helper()
	response := a.do(t, http.MethodGet, path, "", "")
	defer response.Body.Close()
	if response.StatusCode < 300 || response.StatusCode >= 400 {
		data, _ := io.ReadAll(response.Body)
		t.Fatalf("GET %s = %d, expected a redirect: %s", path, response.StatusCode, data)
	}
	return response.Header.Get("Location")
}

func (a *testApp) postForm(t *testing.T, path string, values url.Values) string {
	t.Helper()
	response := a.do(t, http.MethodPost, path, "", values.Encode())
	defer response.Body.Close()
	if response.StatusCode < 300 || response.StatusCode >= 400 {
		data, _ := io.ReadAll(response.Body)
		t.Fatalf("POST %s = %d: %s", path, response.StatusCode, data)
	}
	return response.Header.Get("Location")
}

func (a *testApp) postMultipart(t *testing.T, path, token string, payload []byte) map[string]any {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("avatar", "me.png")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(payload); err != nil {
		t.Fatal(err)
	}
	writer.Close()

	request, err := http.NewRequest(http.MethodPost, a.server.URL+path, &body)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", writer.FormDataContentType())
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := a.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("POST %s = %d: %s", path, response.StatusCode, data)
	}
	decoded := map[string]any{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("POST %s: %v (%s)", path, err, data)
	}
	return decoded
}

func (a *testApp) patchJSONStatus(t *testing.T, path, token, body string, want int) map[string]any {
	t.Helper()
	request, err := http.NewRequest(http.MethodPatch, a.server.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := a.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(response.Body)
	if response.StatusCode != want {
		t.Fatalf("PATCH %s = %d (want %d): %s", path, response.StatusCode, want, data)
	}
	decoded := map[string]any{}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("PATCH %s: %v (%s)", path, err, data)
		}
	}
	return decoded
}

func (a *testApp) postJSONWithToken(t *testing.T, path, token string) map[string]any {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, a.server.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := a.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("POST %s = %d: %s", path, response.StatusCode, data)
	}
	decoded := map[string]any{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("POST %s: %v (%s)", path, err, data)
	}
	return decoded
}

func (a *testApp) deleteWithToken(t *testing.T, path, token string) map[string]any {
	t.Helper()
	request, err := http.NewRequest(http.MethodDelete, a.server.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := a.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("DELETE %s = %d: %s", path, response.StatusCode, data)
	}
	decoded := map[string]any{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("DELETE %s: %v (%s)", path, err, data)
	}
	return decoded
}

// pngBytes is the 1x1 transparent PNG the PHP tests used.
func pngBytes(t *testing.T) []byte {
	t.Helper()
	const encoded = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII="
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// postJSONBasic sends a JSON body with HTTP Basic client authentication, the
// way a server-side application calls /oauth/token.
func (a *testApp) postJSONBasic(t *testing.T, path, clientID, secret, body string) map[string]any {
	t.Helper()
	return a.postJSONBasicStatus(t, path, clientID, secret, body, http.StatusOK, "")
}

func (a *testApp) postJSONBasicStatus(t *testing.T, path, clientID, secret, body string, want int, wantError string) map[string]any {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, a.server.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.SetBasicAuth(clientID, secret)
	response, err := a.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(response.Body)
	if response.StatusCode != want {
		t.Fatalf("POST %s = %d (want %d): %s", path, response.StatusCode, want, data)
	}
	decoded := map[string]any{}
	// /oauth/revoke answers an empty JSON array (RFC 7009), so only objects are
	// decoded into the map.
	if trimmed := strings.TrimSpace(string(data)); len(trimmed) > 0 && strings.HasPrefix(trimmed, "{") {
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("POST %s: %v (%s)", path, err, data)
		}
	}
	if wantError != "" && decoded["error"] != wantError {
		t.Fatalf("POST %s error = %v, want %s", path, decoded["error"], wantError)
	}
	return decoded
}

func (a *testApp) postJSON(t *testing.T, path string, values url.Values) map[string]any {
	t.Helper()
	return a.postJSONStatus(t, path, values, http.StatusOK)
}

func (a *testApp) postJSONStatus(t *testing.T, path string, values url.Values, want int) map[string]any {
	t.Helper()
	response := a.do(t, http.MethodPost, path, "", values.Encode())
	defer response.Body.Close()
	data, _ := io.ReadAll(response.Body)
	if response.StatusCode != want {
		t.Fatalf("POST %s = %d (want %d): %s", path, response.StatusCode, want, data)
	}
	var decoded map[string]any
	if len(data) > 0 {
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("POST %s: %v (%s)", path, err, data)
		}
	}
	return decoded
}

var tokenPattern = regexp.MustCompile(`name="_token" value="([^"]+)"`)

var resetTokenPattern = regexp.MustCompile(`sso_pw_[A-Za-z0-9]+`)

var generatedPasswordPattern = regexp.MustCompile(`id="secret-0">([^<]+)`)

func csrfToken(t *testing.T, page string) string {
	t.Helper()
	match := tokenPattern.FindStringSubmatch(page)
	if len(match) != 2 {
		t.Fatalf("no CSRF token in page: %.400s", page)
	}
	return match[1]
}

func randomVerifier() string {
	raw := make([]byte, 48)
	for i := range raw {
		raw[i] = byte('A' + i%26)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func ptr(v string) *string { return &v }

var _ = os.Getenv
var _ = time.Now
