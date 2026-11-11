// Package config is the Go equivalent of config/sso.php plus the handful of
// Laravel settings (session, app key, listen address) this service actually
// reads. The vocabulary is deliberately the same as the PHP: same env names,
// same defaults, so an existing .env keeps working almost unchanged.
package config

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Scope labels, in the order the discovery document lists them (config/sso.php).
// A map would lose the order, and the console's checkbox list reads this slice.
var ScopeOrder = []string{"openid", "profile", "db:read", "db:write", "offline_access", "admin"}

type Config struct {
	AppName  string
	AppEnv   string
	AppDebug bool

	// AppKey is the raw APP_KEY value, exactly as written in the environment.
	//
	// It is the avatar HMAC key (User::avatarUrl hashes the string, so the
	// "base64:" prefix is part of the key) and the seed of the signing-key
	// encryption key. Keeping the raw string is what makes avatar URLs minted by
	// the PHP service keep working after the import.
	AppKey string

	// Issuer is SSO_ISSUER: the public base URL, including the mount point.
	Issuer string
	// AppURL is the internal origin; it is only used when no issuer is set.
	AppURL string

	Listen          string
	URLScheme       string
	ForceRootURL    bool
	SessionPath     string
	SessionSecure   bool
	SessionSameSite string
	SessionLifetime time.Duration

	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	AuthCodeTTL     time.Duration
	ResetLinkTTL    time.Duration

	DisplayTimezone string
	DisplayLocation *time.Location

	BootstrapUsername     string
	BootstrapName         string
	BootstrapPassword     string
	BootstrapPasswordFile string

	// DBFile is the single SQLite data file (WR_DB).
	DBFile string
	// StorageDir holds avatars (files are referenced from the database by the
	// same "avatars/<id>/<name>" path Laravel's local disk used).
	StorageDir string

	MailFrom string
	Mailer   string
}

// Load reads the environment. A .env file is optional; real environment
// variables always win, which is what a container or a systemd unit expects.
func Load() *Config {
	loadDotEnv(".env")

	c := &Config{
		AppName:         env("APP_NAME", "SSO"),
		AppEnv:          env("APP_ENV", "production"),
		AppDebug:        envBool("APP_DEBUG", false),
		AppKey:          env("APP_KEY", ""),
		AppURL:          env("APP_URL", "http://127.0.0.1:3550"),
		Listen:          env("SSO_LISTEN", "0.0.0.0:3550"),
		URLScheme:       env("SSO_URL_SCHEME", "https"),
		ForceRootURL:    envBool("SSO_FORCE_ROOT_URL", true),
		SessionPath:     env("SESSION_PATH", "/sso"),
		SessionSecure:   envBool("SESSION_SECURE_COOKIE", true),
		SessionSameSite: env("SESSION_SAME_SITE", "lax"),
		SessionLifetime: time.Duration(envInt("SESSION_LIFETIME", 720)) * time.Minute,

		AccessTokenTTL:  time.Duration(envInt("SSO_ACCESS_TOKEN_TTL", 604800)) * time.Second,
		RefreshTokenTTL: time.Duration(envInt("SSO_REFRESH_TOKEN_TTL", 2592000)) * time.Second,
		AuthCodeTTL:     time.Duration(envInt("SSO_AUTH_CODE_TTL", 300)) * time.Second,
		ResetLinkTTL:    time.Duration(envInt("SSO_RESET_LINK_TTL", 86400)) * time.Second,

		DisplayTimezone: env("SSO_DISPLAY_TIMEZONE", "Asia/Seoul"),

		BootstrapUsername:     env("SSO_BOOTSTRAP_ADMIN_USERNAME", ""),
		BootstrapName:         env("SSO_BOOTSTRAP_ADMIN_NAME", "admin"),
		BootstrapPassword:     env("SSO_BOOTSTRAP_ADMIN_PASSWORD", ""),
		BootstrapPasswordFile: env("SSO_BOOTSTRAP_ADMIN_PASSWORD_FILE", ""),

		DBFile:     env("WR_DB", env("SSO_DB", "storage/sso.db")),
		StorageDir: env("WR_STORAGE", "storage"),

		Mailer:   env("MAIL_MAILER", "log"),
		MailFrom: env("MAIL_FROM_ADDRESS", "sso@localhost"),
	}

	c.Issuer = strings.TrimRight(firstNonEmpty(env("SSO_ISSUER", ""), c.AppURL+"/sso"), "/")

	// The cookie path and generated links follow the issuer's own path, not a
	// leftover mount point: this deployment serves from its own origin, so the
	// old SESSION_PATH=/sso would scope the cookie to a path nobody serves.
	if v, ok := os.LookupEnv("SESSION_PATH"); ok {
		c.SessionPath = v
	} else if u, err := url.Parse(c.Issuer); err == nil {
		c.SessionPath = strings.TrimRight(u.Path, "/")
		if c.SessionPath == "" {
			c.SessionPath = "/"
		}
	}

	// A session cookie path must start with "/" or browsers ignore it.
	if c.SessionPath != "" && !strings.HasPrefix(c.SessionPath, "/") {
		c.SessionPath = "/" + c.SessionPath
	}

	if loc, err := time.LoadLocation(c.DisplayTimezone); err == nil {
		c.DisplayLocation = loc
	} else {
		c.DisplayLocation = time.UTC
	}

	return c
}

// PublicBase is the issuer. URLs that leave the service (iss claim, discovery,
// picture and reset links) are built from it, never from the request host:
// work-report calls userinfo over 127.0.0.1 and a URL built from that host was
// stored, broken, as somebody's picture (DESIGN.md §8).
func (c *Config) PublicBase() string { return c.Issuer }

// DataDir is the directory the SQLite file and the avatar tree live in.
func (c *Config) DataDir() string {
	if dir := filepath.Dir(c.DBFile); dir != "" {
		return dir
	}
	return "."
}

// ResolveDBFile makes a relative WR_DB absolute against the working directory,
// so the binary can be started from anywhere.
func (c *Config) ResolveDBFile() string {
	if filepath.IsAbs(c.DBFile) {
		return c.DBFile
	}
	abs, err := filepath.Abs(c.DBFile)
	if err != nil {
		return c.DBFile
	}
	return abs
}

// ResolveStorageDir is the root avatars are written under; the database keeps
// "avatars/<user>/<file>" so a PHP-era dump still points at the right files
// once they are copied to <storage>/avatars.
func (c *Config) ResolveStorageDir() string {
	dir := c.StorageDir
	if !filepath.IsAbs(dir) {
		if abs, err := filepath.Abs(dir); err == nil {
			dir = abs
		}
	}
	return dir
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func env(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return fallback
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return fallback
	}
	return n
}

// envBool accepts what Laravel's filter_var accepts for the values that appear
// in real .env files.
func envBool(key string, fallback bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return fallback
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "on", "yes":
		return true
	case "0", "false", "off", "no":
		return false
	}
	return fallback
}

// loadDotEnv reads KEY=VALUE lines without overriding anything already set.
// The parser is intentionally small: no interpolation, no quoting games beyond
// stripping one pair of quotes.
func loadDotEnv(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if len(value) >= 2 {
			if (value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'') {
				value = value[1 : len(value)-1]
			}
		}
		if _, exists := os.LookupEnv(key); !exists {
			_ = os.Setenv(key, value)
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "config: reading %s: %v\n", path, err)
	}
}
