// Command sso is the authorization center: an OAuth 2.0 / OpenID Connect
// issuer and the console that manages the people who use it.
//
// One binary, one SQLite file, no web server, no database server, no PHP. The
// templates and assets ship inside the executable; the data file defaults to
// storage/sso.db next to the working directory. It cross-compiles for linux
// and windows with nothing installed.
//
// The flags are the operations the old deploy kept in artisan commands, plus
// the one-shot importer that carries production's PostgreSQL data over.
package main

import (
	"context"
	"embed"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"sso/internal/config"
	"sso/internal/secure"
	"sso/internal/server"
	"sso/internal/service"
	"sso/internal/store"
)

// The site ships in the binary: web/templates is html/template and web/assets
// is the CSS/JS copied verbatim from the PHP's public/.
//
//go:embed web/templates web/assets
var webFiles embed.FS

var version = "go-1"

func main() {
	var (
		addr      = flag.String("addr", "", "listen address (default SSO_LISTEN or 0.0.0.0:3550)")
		rotate    = flag.Bool("rotate-keys", false, "retire the active RS256 key and generate a new one")
		bootstrap = flag.Bool("bootstrap", false, "create the bootstrap super administrator from the environment")
		forceBoot = flag.Bool("force", false, "with -bootstrap: reset that administrator even if one exists")
		prune     = flag.Bool("prune", false, "delete expired tokens, spent codes and old audit rows")
		dryRun    = flag.Bool("dry-run", false, "with -prune: report what would be deleted")
		auditDays = flag.Int("audit-days", 90, "with -prune: audit retention in days")
		users     = flag.Bool("users", false, "list users (id, username, name, status, last login)")
		userPass  = flag.String("user-password", "", "set or generate a user's password")
		password  = flag.String("password", "", "with -user-password: use this password instead of generating one")
		disable   = flag.Bool("disable", false, "with -user-password: disable the account instead")
		role      = flag.String("role", "", "username whose role to show or set")
		newRole   = flag.String("set-role", "", "with -role: user | super_admin")
		importPG  = flag.String("import-postgres", "", "copy data from this PostgreSQL DSN into the SQLite file, then exit")
		pgTool    = flag.String("pgmigrate", "", "path to the sso-pgmigrate helper (default: beside this binary, then PATH)")
		backup    = flag.String("backup", "", "write a consistent copy of the database to this path and exit")
		showV     = flag.Bool("version", false, "print the version and exit")
	)
	flag.Parse()

	if *showV {
		fmt.Println(version)
		return
	}

	cfg := config.Load()
	if *addr != "" {
		cfg.Listen = *addr
	}

	st, err := store.Open(cfg.ResolveDBFile(), cfg.ResolveStorageDir())
	if err != nil {
		log.Fatalf("database: %v", err)
	}
	defer st.Close()

	if *backup != "" {
		if err := st.Backup(context.Background(), *backup); err != nil {
			log.Fatalf("backup: %v", err)
		}
		fmt.Println(*backup)
		return
	}

	srv, err := server.New(server.Options{Config: cfg, Store: st, Files: webFiles})
	if err != nil {
		log.Fatalf("templates: %v", err)
	}

	ctx := context.Background()

	switch {
	case *importPG != "":
		if err := runImporter(*importPG, st.Path, *pgTool); err != nil {
			log.Fatalf("import: %v", err)
		}
		return
	case *rotate:
		key, err := srv.Keys.Rotate(ctx)
		if err != nil {
			log.Fatalf("rotate: %v", err)
		}
		fmt.Printf("New active signing key: %s\n", key.Kid)
		return
	case *prune:
		counts, err := st.Prune(ctx, *auditDays, *dryRun)
		if err != nil {
			log.Fatalf("prune: %v", err)
		}
		verb := "deleted"
		if *dryRun {
			verb = "would delete"
		}
		fmt.Printf("%-26s %s\n", "what", verb)
		fmt.Printf("%-26s %d\n", "dead access tokens", counts.AccessTokens)
		fmt.Printf("%-26s %d\n", "dead refresh tokens", counts.RefreshTokens)
		fmt.Printf("%-26s %d\n", "spent authorization codes", counts.AuthCodes)
		fmt.Printf("%-26s %d\n", "old audit entries", counts.AuditLogs)
		if !*dryRun {
			srv.Audit.Log(ctx, "maintenance.pruned", "system", "cli", "", "", map[string]any{
				"dead access tokens":        counts.AccessTokens,
				"dead refresh tokens":       counts.RefreshTokens,
				"spent authorization codes": counts.AuthCodes,
				"old audit entries":         counts.AuditLogs,
			}, service.RequestMeta{})
		}
		return
	case *users:
		os.Exit(listUsers(ctx, st))
	case *userPass != "":
		os.Exit(userPassword(ctx, srv, st, *userPass, *password, *disable))
	case *role != "":
		os.Exit(showOrSetRole(ctx, srv, st, *role, *newRole))
	case *bootstrap:
		os.Exit(bootstrapAdmin(ctx, srv, st, cfg, *forceBoot))
	}

	// Every boot ensures there is an administrator, exactly as the container
	// entrypoint ran sso:bootstrap before supervisord. It is a no-op once one
	// exists, so a restart is always safe.
	if err := ensureBootstrap(ctx, srv, st, cfg, false); err != nil {
		log.Printf("bootstrap: %v", err)
	}

	runServer(cfg, srv)
}

func runServer(cfg *config.Config, srv *server.Server) {
	httpServer := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Sessions that outlived their lifetime are dead weight; the PHP swept them
	// with a lottery on every request, a timer is cheaper and quieter.
	vacuum := time.NewTicker(6 * time.Hour)
	defer vacuum.Stop()
	go func() {
		for range vacuum.C {
			if err := srv.Store.VacuumSessions(context.Background(),
				time.Now().Add(-cfg.SessionLifetime).Unix()); err != nil {
				log.Printf("session vacuum: %v", err)
			}
		}
	}()

	go func() {
		log.Printf("sso %s listening on %s (issuer %s)", version, cfg.Listen, cfg.Issuer)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("listen: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("shutdown: %v", err)
	}
}

// ensureBootstrap is sso:bootstrap: the first administrator comes from the
// environment and is only created when no active super administrator exists.
func ensureBootstrap(ctx context.Context, srv *server.Server, st *store.Store, cfg *config.Config, force bool) error {
	username := strings.ToLower(strings.TrimSpace(cfg.BootstrapUsername))
	if username == "" {
		return nil
	}

	existing, err := st.CountActiveAdmins(ctx)
	if err != nil {
		return err
	}
	if existing > 0 && !force {
		log.Printf("%d super administrator(s) already exist; nothing to do.", existing)
		return nil
	}

	passwordValue := bootstrapPassword(cfg)
	if passwordValue == "" {
		return fmt.Errorf("no bootstrap password: set SSO_BOOTSTRAP_ADMIN_PASSWORD or SSO_BOOTSTRAP_ADMIN_PASSWORD_FILE")
	}

	user, err := st.UserByUsername(ctx, username)
	if err != nil {
		return err
	}
	created := user == nil
	if user == nil {
		user = &store.User{
			Name:     cfg.BootstrapName,
			Username: username,
			Role:     store.RoleSuperAdmin,
			Status:   store.StatusActive,
		}
	}

	hash, err := secure.HashPassword(passwordValue, 12)
	if err != nil {
		return err
	}
	if user.Name == "" {
		user.Name = cfg.BootstrapName
	}
	user.Password = hash
	user.Role = store.RoleSuperAdmin
	user.Status = store.StatusActive

	if created {
		if err := st.InsertUser(ctx, user); err != nil {
			return err
		}
	} else if err := st.SaveUser(ctx, user); err != nil {
		return err
	}

	event := "admin.bootstrap.password_reset"
	if created {
		event = "admin.bootstrap.created"
	}
	srv.Audit.Log(ctx, event, "system", "bootstrap", "user", itoa(user.ID), map[string]any{
		"username": username,
	}, service.RequestMeta{})

	log.Printf("%s bootstrap super administrator %s.", map[bool]string{true: "Created", false: "Updated"}[created], username)
	return nil
}

func bootstrapPassword(cfg *config.Config) string {
	if cfg.BootstrapPassword != "" {
		return cfg.BootstrapPassword
	}
	if cfg.BootstrapPasswordFile != "" {
		data, err := os.ReadFile(cfg.BootstrapPasswordFile)
		if err == nil {
			return strings.TrimSpace(string(data))
		}
	}
	return ""
}

func bootstrapAdmin(ctx context.Context, srv *server.Server, st *store.Store, cfg *config.Config, force bool) int {
	if err := ensureBootstrap(ctx, srv, st, cfg, force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

// userPassword is sso:user-password. A password is stored hashed and shown
// once; if it was lost before it reached the person there is nothing to
// recover, and there is no mail flow to fall back on.
func userPassword(ctx context.Context, srv *server.Server, st *store.Store, username, password string, disable bool) int {
	user, err := st.UserByUsername(ctx, username)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if user == nil {
		fmt.Fprintf(os.Stderr, "No user with username %s.\n", username)
		return 1
	}

	if disable {
		user.Status = store.StatusDisabled
		if err := st.SaveUser(ctx, user); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		srv.Audit.Log(ctx, "admin.cli.user_disabled", "system", "cli", "user", itoa(user.ID),
			map[string]any{"username": user.Username}, service.RequestMeta{})
		fmt.Printf("Disabled %s.\n", user.Username)
		return 0
	}

	if password == "" {
		password = secure.RandomFrom("abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789", 20)
	}
	if len(password) < 12 {
		fmt.Fprintln(os.Stderr, "The password must be at least 12 characters.")
		return 1
	}

	hash, err := secure.HashPassword(password, 12)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	user.Password = hash
	if err := st.SaveUser(ctx, user); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	srv.Audit.Log(ctx, "admin.cli.user_password_reset", "system", "cli", "user", itoa(user.ID),
		map[string]any{"username": user.Username}, service.RequestMeta{})

	fmt.Printf("user      %s\n", user.Username)
	fmt.Printf("password  %s\n\n", password)
	fmt.Println("Shown once; it is stored hashed and cannot be read back.")
	return 0
}

// showOrSetRole is sso:role — the way back in if the last administrator
// demotes themselves.
func showOrSetRole(ctx context.Context, srv *server.Server, st *store.Store, username, role string) int {
	user, err := st.UserByUsername(ctx, username)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if user == nil {
		fmt.Fprintf(os.Stderr, "No user with username %s.\n", username)
		return 1
	}

	if role == "" {
		fmt.Println(user.Role)
		return 0
	}
	if role != store.RoleUser && role != store.RoleSuperAdmin {
		fmt.Fprintln(os.Stderr, "Role must be one of: user, super_admin.")
		return 1
	}

	from := user.Role
	user.Role = role
	if err := st.SaveUser(ctx, user); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	srv.Audit.Log(ctx, "admin.cli.user_role", "system", "cli", "user", itoa(user.ID),
		map[string]any{"username": user.Username, "from": from, "to": role}, service.RequestMeta{})
	fmt.Printf("%s: %s → %s.\n", user.Username, from, role)
	return 0
}

// runImporter runs the PostgreSQL importer.
//
// The importer is a separate module (tools/pgmigrate) with its own go.mod, so
// the shipped binary carries no pgx dependency. Keeping the two apart is the
// point: production data has to survive the switch, but a data file that runs
// with nothing installed must not grow a database driver for a job that runs
// once.
func runImporter(dsn, dbPath, explicit string) error {
	tool, err := findImporter(explicit)
	if err != nil {
		return err
	}
	cmd := exec.Command(tool, "-dsn", dsn, "-db", dbPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	return cmd.Run()
}

func findImporter(explicit string) (string, error) {
	candidates := []string{}
	if explicit != "" {
		candidates = append(candidates, explicit)
	}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(dir, "sso-pgmigrate"),
			filepath.Join(dir, "sso-pgmigrate.exe"),
		)
	}
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, nil
		}
	}
	if path, err := exec.LookPath("sso-pgmigrate"); err == nil {
		return path, nil
	}
	return "", errors.New("sso-pgmigrate not found: build it with `cd tools/pgmigrate && go build -o ../../sso-pgmigrate .` or pass -pgmigrate <path>. " +
		"The importer is a separate binary so this one needs no PostgreSQL driver")
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

// listUsers is the no-argument form of sso:user-password: a table of the
// accounts an operator can act on, because the command needs a username and
// nobody memorises them.
func listUsers(ctx context.Context, st *store.Store) int {
	all, err := st.AllUsersBrief(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if len(all) == 0 {
		fmt.Println("No users exist yet.")
		return 0
	}
	fmt.Printf("%-6s %-24s %-24s %-10s %s\n", "id", "username", "name", "status", "last login")
	for _, user := range all {
		full, err := st.UserByID(ctx, user.ID)
		if err != nil || full == nil {
			continue
		}
		last := "never"
		if full.LastLoginAt.Valid {
			last = full.LastLoginAt.Time.Format("2006-01-02 15:04:05")
		}
		fmt.Printf("%-6d %-24s %-24s %-10s %s\n", full.ID, full.Username, full.Name, full.Status, last)
	}
	return 0
}
