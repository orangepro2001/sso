package server

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"sso/internal/store"
)

// templateFuncs is the Go answer to the Blade helpers the views used: the
// picture URL, the first letter of a name, the console's date formatting and
// Str::limit. Everything that depends on configuration is closed over here at
// parse time — the configuration does not change while the process runs.
func (s *Server) templateFuncs() map[string]any {
	return map[string]any{
		"picture": func(u *store.User) string {
			if u == nil {
				return ""
			}
			if url := u.AvatarURL(s.Cfg.Issuer, s.Cfg.AppKey); url != nil {
				return *url
			}
			return ""
		},
		// initial is mb_substr(trim(name) ?: username, 0, 1).
		"initial": func(u *store.User) string {
			if u == nil {
				return ""
			}
			name := strings.TrimSpace(u.Name)
			if name == "" {
				name = u.Username
			}
			for _, r := range name {
				return string(r)
			}
			return ""
		},
		"at":  atFunc(s),
		"ago": agoFunc(s),
		"limit": func(value string, n int) string {
			runes := []rune(value)
			if len(runes) <= n {
				return value
			}
			return string(runes[:n]) + "..."
		},
		"urlquery": url.QueryEscape,
		"deref": func(v *string) string {
			if v == nil {
				return ""
			}
			return *v
		},
		"itoa":  func(v int64) string { return itoa(v) },
		"label": Label,
		"tone":  Tone,
		"eqs":   func(a, b string) bool { return a == b },
		"join":  strings.Join,
		"dict":  dict,
		"bool":  func(v any) bool { b, _ := v.(bool); return b },
	}
}

// at renders a timestamp in SSO_DISPLAY_TIMEZONE; the stored clock stays UTC.
func atFunc(s *Server) func(store.Timestamp, string) string {
	return func(t store.Timestamp, layout string) string {
		if !t.Valid {
			return "—"
		}
		return t.Time.In(s.Cfg.DisplayLocation).Format(layout)
	}
}

// ago is Carbon's diffForHumans, in the console's language.
func agoFunc(s *Server) func(store.Timestamp, string) string {
	return func(t store.Timestamp, never string) string {
		if !t.Valid {
			return never
		}
		return humanAgo(time.Since(t.Time))
	}
}

func humanAgo(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d < 45*time.Second:
		return "방금 전"
	case d < 90*time.Second:
		return "1분 전"
	case d < 45*time.Minute:
		return fmt.Sprintf("%d분 전", int(d.Minutes()))
	case d < 90*time.Minute:
		return "1시간 전"
	case d < 22*time.Hour:
		return fmt.Sprintf("%d시간 전", int(d.Hours()))
	case d < 36*time.Hour:
		return "1일 전"
	case d < 25*24*time.Hour:
		return fmt.Sprintf("%d일 전", int(d.Hours()/24))
	case d < 45*24*time.Hour:
		return "1개월 전"
	case d < 345*24*time.Hour:
		return fmt.Sprintf("%d개월 전", int(d.Hours()/24/30))
	case d < 545*24*time.Hour:
		return "1년 전"
	}
	return fmt.Sprintf("%d년 전", int(d.Hours()/24/365))
}
