// Package service holds the rules: every account change, every token, every
// audit row goes through here whoever asks — console, account page or JSON API.
// The PHP kept these in app/Services for the same reason.
package service

import (
	"context"
	"log"

	"sso/internal/store"
)

// RequestMeta is what an audit row records about the caller. It is a small
// value instead of *http.Request so the services stay usable from the command
// line (sso:prune writes an audit row with system:cli).
type RequestMeta struct {
	IP        string
	UserAgent string
}

// AuditLogger is the append-only audit trail. An audit failure must never break
// the flow it was recording, but it is loud in the log.
type AuditLogger struct {
	Store *store.Store
}

func NewAuditLogger(st *store.Store) *AuditLogger { return &AuditLogger{Store: st} }

// Log mirrors AuditLogger::log. Empty actor/subject strings become NULL.
func (a *AuditLogger) Log(ctx context.Context, event, actorType, actorID, subjectType, subjectID string, meta map[string]any, rm RequestMeta) {
	row := &store.AuditLog{
		Event: event,
		Meta:  store.Meta(meta),
	}
	row.ActorType = optional(actorType)
	row.ActorID = optional(actorID)
	row.SubjectType = optional(subjectType)
	row.SubjectID = optional(subjectID)
	row.IP = optional(truncate(rm.IP, 45))
	row.UserAgent = optional(truncate(rm.UserAgent, 512))
	row.CreatedAt = store.Now()

	if len(meta) == 0 {
		row.Meta = nil
	}
	if err := a.Store.InsertAudit(ctx, row); err != nil {
		log.Printf("audit log write failed: event=%s error=%v", event, err)
	}
}

func optional(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}

func truncate(v string, n int) string {
	if len(v) <= n {
		return v
	}
	return v[:n]
}
