package server

import (
	"context"
	"encoding/json"
	"strings"

	"sso/internal/store"
)

// Presenter turns audit rows into sentences a person can read: "정태훈 님이
// 로그인" instead of `login.succeeded user:6 user:6`. The raw event and metadata
// stay one click away on the activity page (App\Support\AuditPresenter).
type Presenter struct {
	People  map[string]string
	Clients map[string]string
}

var auditLabels = map[string]string{
	"login.succeeded":                "로그인",
	"login.failed":                   "로그인 실패",
	"login.denied":                   "로그인 거부 (비활성 계정)",
	"logout":                         "로그아웃",
	"user.logout":                    "로그아웃",
	"admin.login.succeeded":          "콘솔 로그인",
	"admin.login.failed":             "콘솔 로그인 실패",
	"user.register":                  "회원가입",
	"authorize.granted":              "앱에 로그인",
	"authorize.denied":               "앱 로그인 거부",
	"token.issued":                   "앱 토큰 발급",
	"token.revoked":                  "앱 토큰 폐기",
	"token.error":                    "토큰 요청 오류",
	"token.introspected":             "토큰 조회",
	"token.reuse_detected":           "갱신 토큰 재사용 감지",
	"token.family_revoked":           "갱신 토큰 묶음 폐기",
	"admin.user.created":             "계정 생성",
	"admin.user.updated":             "계정 정보 변경",
	"admin.user.password_reset":      "관리자가 비밀번호 설정",
	"admin.user.reset_link_created":  "비밀번호 재설정 링크 발급",
	"admin.user.avatar_updated":      "관리자가 사진 변경",
	"admin.user.avatar_removed":      "관리자가 사진 삭제",
	"admin.user.signed_out":          "관리자가 모든 곳에서 로그아웃",
	"admin.user.deleted":             "계정 삭제",
	"admin.cli.user_disabled":        "명령줄에서 계정 비활성화",
	"admin.cli.user_password_reset":  "명령줄에서 비밀번호 설정",
	"admin.cli.user_role":            "명령줄에서 권한 변경",
	"admin.bootstrap.created":        "최초 관리자 생성",
	"admin.bootstrap.password_reset": "최초 관리자 비밀번호 재설정",
	"admin.password_changed":         "비밀번호 변경",
	"user.profile.updated":           "프로필 변경",
	"user.avatar.updated":            "사진 변경",
	"user.avatar.removed":            "사진 삭제",
	"user.password.changed":          "비밀번호 변경",
	"user.password.change_rejected":  "비밀번호 변경 실패",
	"user.password_reset.completed":  "링크로 비밀번호 재설정",
	"user.password_reset.rejected":   "재설정 링크 거부",
	"user.tokens.revoked":            "모든 곳에서 로그아웃",
	"admin.client.created":           "앱 등록",
	"admin.client.updated":           "앱 설정 변경",
	"maintenance.pruned":             "만료 데이터 정리",
}

// AuditCategories are the filter chips: key, label, event prefixes.
var AuditCategories = []struct {
	Key      string
	Label    string
	Prefixes []string
}{
	{"login", "로그인", []string{"login.", "logout", "user.logout", "admin.login.", "authorize.", "user.register"}},
	{"account", "계정 변경", []string{"admin.user.", "admin.cli.", "user.profile.", "user.avatar.", "user.password", "user.tokens."}},
	{"token", "토큰", []string{"token."}},
	{"app", "앱 설정", []string{"admin.client."}},
}

var auditValues = map[string]string{
	store.RoleSuperAdmin: "관리자", store.RoleUser: "일반",
	store.StatusActive: "활성", store.StatusDisabled: "비활성",
}

var auditFields = map[string]string{"name": "이름", "username": "아이디", "note": "메모", "role": "권한", "status": "상태"}

func Label(event string) string {
	if label, ok := auditLabels[event]; ok {
		return label
	}
	return event
}

// Tone is ” | 'bad' | 'warn' — the badge colour of an event.
func Tone(event string) string {
	switch {
	case strings.Contains(event, "failed"), strings.Contains(event, "denied"),
		strings.Contains(event, "rejected"), strings.Contains(event, "error"),
		strings.Contains(event, "reuse"), event == "admin.user.deleted":
		return "bad"
	case strings.Contains(event, "password"), strings.Contains(event, "signed_out"),
		strings.Contains(event, "tokens.revoked"), strings.Contains(event, "disabled"):
		return "warn"
	}
	return ""
}

// People resolves the names for every user id mentioned as actor or subject of
// these rows, in one query.
func (s *Server) People(ctx context.Context, logs []*store.AuditLog) map[string]string {
	seen := map[int64]bool{}
	ids := []int64{}
	for _, log := range logs {
		if log.ActorType != nil && (*log.ActorType == "user" || *log.ActorType == "admin") && log.ActorID != nil {
			if id, ok := atoi(*log.ActorID); ok && !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
		if log.SubjectType != nil && *log.SubjectType == "user" && log.SubjectID != nil {
			if id, ok := atoi(*log.SubjectID); ok && !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}

	names, err := s.Store.UserNames(ctx, ids)
	if err != nil {
		return map[string]string{}
	}
	out := map[string]string{}
	for id, name := range names {
		out[itoa(id)] = name
	}
	return out
}

// Actor is who did it, in words.
func (p Presenter) Actor(log *store.AuditLog) string {
	actorType := deref(log.ActorType)
	actorID := deref(log.ActorID)
	switch actorType {
	case "user", "admin":
		if name, ok := p.People[actorID]; ok {
			return name
		}
		return "삭제된 사용자 #" + actorID
	case "anonymous":
		return "(로그인 전) " + actorID
	case "system":
		return "시스템"
	case "":
		return "—"
	}
	if actorID != "" {
		return actorType + ":" + actorID
	}
	return actorType
}

// Subject is whom it was done to, when that is not the actor.
func (p Presenter) Subject(log *store.AuditLog) string {
	subjectType := deref(log.SubjectType)
	subjectID := deref(log.SubjectID)

	if subjectType == "user" {
		actorType := deref(log.ActorType)
		if subjectID == deref(log.ActorID) && (actorType == "user" || actorType == "admin") {
			return ""
		}
		if name, ok := p.People[subjectID]; ok {
			return name
		}
		if username, ok := log.Meta["username"].(string); ok {
			return username
		}
		return "#" + subjectID
	}

	if subjectType == "client" {
		if name, ok := p.Clients[subjectID]; ok {
			return name
		}
		return subjectID
	}
	return ""
}

// Detail is one line from the metadata, or "" when there is nothing useful.
func (p Presenter) Detail(log *store.AuditLog) string {
	meta := log.Meta
	if meta == nil {
		return ""
	}

	if log.Event == "admin.user.updated" {
		if changed, ok := meta["changed"].([]any); ok {
			from, _ := meta["from"].(map[string]any)
			to, _ := meta["to"].(map[string]any)
			parts := []string{}
			for _, item := range changed {
				field, ok := item.(string)
				if !ok {
					continue
				}
				label := auditFields[field]
				if label == "" {
					label = field
				}
				if field == "note" {
					parts = append(parts, label)
					continue
				}
				parts = append(parts, label+" "+valueLabel(from[field])+" → "+valueLabel(to[field]))
			}
			return strings.Join(parts, ", ")
		}
	}

	if log.Event == "user.profile.updated" {
		from, _ := meta["from"].(map[string]any)
		to, _ := meta["to"].(map[string]any)
		parts := []string{}
		for _, field := range []string{"name", "username"} {
			if valueString(from[field]) != valueString(to[field]) {
				parts = append(parts, auditFields[field]+" "+valueString(from[field])+" → "+valueString(to[field]))
			}
		}
		return strings.Join(parts, ", ")
	}

	if clientID, ok := meta["client_id"].(string); ok {
		if name, ok := p.Clients[clientID]; ok {
			return name
		}
		return clientID
	}

	if role, ok := meta["role"].(string); ok && log.Event == "admin.user.created" {
		if label, ok := auditValues[role]; ok {
			return "권한 " + label
		}
		return "권한 " + role
	}

	if reason, ok := meta["reason"].(string); ok {
		return reason
	}

	return ""
}

// Raw is the pretty-printed JSON behind "one click away".
func (p Presenter) Raw(log *store.AuditLog) string {
	payload := map[string]any{}
	if log.ActorType != nil {
		payload["actor"] = deref(log.ActorType) + ":" + deref(log.ActorID)
	}
	if log.SubjectType != nil {
		payload["subject"] = deref(log.SubjectType) + ":" + deref(log.SubjectID)
	}
	if log.Meta != nil {
		payload["meta"] = map[string]any(log.Meta)
	}
	if log.UserAgent != nil {
		payload["agent"] = *log.UserAgent
	}
	encoded, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return ""
	}
	return string(encoded)
}

// Known reports whether a user id mentioned by a row still resolves to a name,
// which decides whether the activity table links the actor.
func (p Presenter) Known(actorID *string) bool {
	if actorID == nil {
		return false
	}
	_, ok := p.People[*actorID]
	return ok
}

// SubjectIfActor is the "→ someone" half of the person page: the subject, but
// only when this person was the actor. Empty otherwise.
func (p Presenter) SubjectIfActor(log *store.AuditLog, userID int64) string {
	if log.ActorID == nil || *log.ActorID != itoa(userID) {
		return ""
	}
	return p.Subject(log)
}

// ActorIfOther is the "by someone" half: who did it, when it was somebody else.
func (p Presenter) ActorIfOther(log *store.AuditLog, userID int64) string {
	if log.ActorID != nil && *log.ActorID == itoa(userID) {
		return ""
	}
	actorType := deref(log.ActorType)
	if actorType != "user" && actorType != "admin" {
		return ""
	}
	return p.Actor(log)
}

func valueLabel(v any) string {
	text := valueString(v)
	if label, ok := auditValues[text]; ok {
		return label
	}
	return text
}

func valueString(v any) string {
	switch value := v.(type) {
	case nil:
		return ""
	case string:
		return value
	case float64:
		return itoa(int64(value))
	case bool:
		if value {
			return "true"
		}
		return "false"
	}
	return ""
}

func deref(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}
