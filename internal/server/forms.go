package server

import (
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// parseForm reads an HTML form or a multipart upload, and leaves a JSON body
// for decodeJSON. Laravel's $request->input() accepted JSON too, which is why
// /oauth/token answers both form posts and JSON posts; the token endpoint uses
// decodeParams for that, this is for the browser forms.
func parseForm(r *http.Request, maxMemory int64) error {
	mediaType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	switch mediaType {
	case "multipart/form-data":
		return r.ParseMultipartForm(maxMemory)
	case "application/json":
		return nil
	}
	return r.ParseForm()
}

// decodeJSON decodes a JSON object body into a string map, the way Laravel's
// input() treated JSON requests.
func decodeJSON(r *http.Request) (map[string]string, bool) {
	var raw map[string]any
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 2<<20))
	if err := dec.Decode(&raw); err != nil {
		return nil, false
	}
	out := map[string]string{}
	for key, value := range raw {
		switch v := value.(type) {
		case string:
			out[key] = v
		case float64:
			out[key] = strconv.FormatFloat(v, 'f', -1, 64)
		case bool:
			out[key] = strconv.FormatBool(v)
		}
	}
	return out, true
}

// params merges the query string, the form body and a JSON body into one view,
// which is what $request->input() and $request->query() were doing separately.
type params struct {
	query url.Values
	post  url.Values
	json  map[string]string
}

func (s *Server) params(r *http.Request) *params {
	p := &params{query: r.URL.Query(), post: url.Values{}}

	mediaType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mediaType == "application/json" {
		if body, ok := decodeJSON(r); ok {
			p.json = body
		}
		return p
	}

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		if r.PostForm == nil {
			_ = parseForm(r, 8<<20)
		}
		p.post = r.PostForm
	}
	return p
}

func (p *params) input(key string) string {
	if p.post != nil {
		if v := p.post.Get(key); v != "" {
			return v
		}
	}
	if p.json != nil {
		return p.json[key]
	}
	return ""
}

func (p *params) has(key string) bool {
	if p.post != nil {
		if _, ok := p.post[key]; ok {
			return true
		}
	}
	if p.json != nil {
		_, ok := p.json[key]
		return ok
	}
	return false
}

func (p *params) queryValue(key string) string {
	if p.query == nil {
		return ""
	}
	return p.query.Get(key)
}

func (p *params) boolValue(key string) bool {
	value := p.input(key)
	switch strings.ToLower(value) {
	case "1", "true", "on", "yes":
		return true
	}
	return false
}

func (p *params) list(key string) []string {
	if p.post != nil {
		if values, ok := p.post[key]; ok {
			return values
		}
	}
	if p.json != nil {
		if value, ok := p.json[key]; ok {
			return strings.Fields(value)
		}
	}
	return nil
}

func (p *params) all(key string) []string {
	if p.post != nil {
		if values, ok := p.post[key]; ok {
			return values
		}
		if values, ok := p.post[key+"[]"]; ok {
			return values
		}
	}
	return nil
}

// ---- validation ----------------------------------------------------------

// validation collects field errors in the shape {"field": ["message"]}, which
// is what the JSON API documents and what the forms render.
type validation struct {
	Errors map[string][]string
}

func newValidation() *validation { return &validation{Errors: map[string][]string{}} }

func (v *validation) add(field, message string) {
	v.Errors[field] = append(v.Errors[field], message)
}

func (v *validation) any() bool { return len(v.Errors) > 0 }

func (v *validation) Has(field string) bool { return len(v.Errors[field]) > 0 }

const minute = time.Minute

// Labels are the Korean attribute names from lang/ko/validation.php.
var labels = map[string]string{
	"name":                  "이름",
	"username":              "아이디",
	"password":              "비밀번호",
	"password_confirmation": "비밀번호 확인",
	"current_password":      "현재 비밀번호",
	"avatar":                "사진",
	"role":                  "권한",
	"status":                "상태",
	"note":                  "메모",
	"confirm":               "확인",
	"redirect_uris":         "리디렉션 URI",
	"home_url":              "홈 주소",
	"type":                  "종류",
	"grant_type":            "grant_type",
}

func label(field string) string {
	if l, ok := labels[field]; ok {
		return l
	}
	return field
}

func msgRequired(field string) string {
	return label(field) + " 항목을 입력하세요."
}

func msgMaxString(field string, max int) string {
	return fmt.Sprintf("%s 항목은 %d자 이하여야 합니다.", label(field), max)
}

func msgMinString(field string, min int) string {
	return fmt.Sprintf("%s 항목은 %d자 이상이어야 합니다.", label(field), min)
}

func msgUnique(field string) string {
	return "이미 쓰이고 있는 " + label(field) + " 입니다."
}

func msgConfirmed(field string) string {
	return label(field) + " 확인이 일치하지 않습니다."
}

func msgDifferent(field, other string) string {
	return fmt.Sprintf("%s 항목은 %s 항목과 달라야 합니다.", label(field), label(other))
}

func msgIn(field string) string {
	return "선택한 " + label(field) + " 값이 올바르지 않습니다."
}

func msgURL(field string) string {
	return label(field) + " 항목은 올바른 주소여야 합니다."
}

func msgMime(field string) string {
	return label(field) + " 파일은 image/jpeg, image/png, image/webp, image/gif 형식이어야 합니다."
}

func msgFileMax(field string, kb int) string {
	return fmt.Sprintf("%s 파일은 %d KB 이하여야 합니다.", label(field), kb)
}

// UsernamePattern is User::USERNAME_PATTERN: lower-case letters, digits and
// . _ - , starting and ending with a letter or digit, 3 to 64 characters.
func usernameValid(value string) bool {
	if len(value) < 3 || len(value) > 64 {
		return false
	}
	start := value[0]
	end := value[len(value)-1]
	if !isAlnum(start) || !isAlnum(end) {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if !isAlnum(c) && c != '.' && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

func isAlnum(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
}

// ---- rate limiting -------------------------------------------------------

// Limiter is the throttle middleware, kept in memory: one process owns the
// counters, and an in-memory window survives exactly as long as it needs to.
type Limiter struct {
	mu      sync.Mutex
	entries map[string]*window
}

type window struct {
	count int
	reset time.Time
}

func NewLimiter() *Limiter { return &Limiter{entries: map[string]*window{}} }

func (l *Limiter) hit(key string, windowLength time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	entry, ok := l.entries[key]
	if !ok || now.After(entry.reset) {
		l.entries[key] = &window{count: 1, reset: now.Add(windowLength)}
		return
	}
	entry.count++
}

// tooMany reports whether the key has used up its allowance, and how long the
// caller has to wait — the "N초 뒤에 다시 시도하세요" message needs the number.
func (l *Limiter) tooMany(key string, max int) (bool, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	entry, ok := l.entries[key]
	if !ok || time.Now().After(entry.reset) {
		return false, 0
	}
	if entry.count < max {
		return false, 0
	}
	seconds := int(time.Until(entry.reset).Seconds())
	if seconds < 1 {
		seconds = 1
	}
	return true, seconds
}

func (l *Limiter) clear(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}

// ---- redirect safety -----------------------------------------------------

// safeNext is App\Support\SafeRedirect: only a single-slash path or an
// absolute URL on this host, because a login form that redirects wherever it
// is told is an open redirect.
func safeNext(r *http.Request, next string) string {
	next = strings.TrimSpace(next)
	if next == "" {
		return ""
	}
	if strings.HasPrefix(next, "/") && !strings.HasPrefix(next, "//") {
		return next
	}
	parsed, err := url.Parse(next)
	if err != nil || parsed.Host == "" {
		return ""
	}
	if !strings.EqualFold(parsed.Host, r.Host) {
		return ""
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https":
		return next
	}
	return ""
}

// absoluteNext turns a path into an absolute URL on this host. A next of
// /report means "at the root of this host": the applications live beside the
// mount point, so handing /report to the mounted redirector would produce
// /sso/report.
func (s *Server) absoluteNext(r *http.Request, next string) string {
	if strings.HasPrefix(next, "/") && !strings.HasPrefix(next, "//") {
		return s.publicBase(r) + next
	}
	return next
}
