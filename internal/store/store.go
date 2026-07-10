// Package store persists tachyne-access state. The Store interface exists so
// the API layer is testable without Postgres; PG is the real implementation.
package store

import (
	"context"
	"time"

	"github.com/tachyne/tachyne-access/internal/policy"
)

// WhitelistEntry is one whitelist row.
type WhitelistEntry struct {
	Kind    string    `json:"kind"` // "uuid" | "name"
	Value   string    `json:"value"`
	AddedBy string    `json:"added_by"`
	AddedAt time.Time `json:"added_at"`
}

// BanRecord is one ban row as stored.
type BanRecord struct {
	ID        int64      `json:"id"`
	Kind      string     `json:"kind"` // "uuid" | "name" | "ip"
	Value     string     `json:"value"`
	Reason    string     `json:"reason"`
	IssuedBy  string     `json:"issued_by"`
	IssuedAt  time.Time  `json:"issued_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Revoked   bool       `json:"revoked"`
}

// IPRuleRecord is one firewall ACL row (lower priority evaluates first).
type IPRuleRecord struct {
	ID       int64     `json:"id"`
	Priority int       `json:"priority"`
	CIDR     string    `json:"cidr"`
	Action   string    `json:"action"` // "allow" | "deny"
	Note     string    `json:"note"`
	AddedBy  string    `json:"added_by"`
	AddedAt  time.Time `json:"added_at"`
}

// AuditEntry is one audit-log row.
type AuditEntry struct {
	ID      int64     `json:"id"`
	TS      time.Time `json:"ts"`
	Actor   string    `json:"actor"`
	Action  string    `json:"action"`
	Subject string    `json:"subject"`
	Detail  string    `json:"detail"`
}

// Principal is one known player.
type Principal struct {
	UUID      string    `json:"uuid"`
	Name      string    `json:"name"`
	Edition   string    `json:"edition"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// Store is everything the API needs. Every mutation takes the acting
// principal (actor) and writes an audit row.
type Store interface {
	// RulesFor gathers the rules bearing on one login request.
	RulesFor(ctx context.Context, name, uuid, ip string) (policy.Rules, error)
	// IPRulesFor gathers what bears on a bare source IP (the ingress edge check).
	IPRulesFor(ctx context.Context, ip string) (policy.IPRules, error)
	// TouchPrincipal upserts the principal directory from a login check.
	TouchPrincipal(ctx context.Context, uuid, name, edition string) error

	ListWhitelist(ctx context.Context) ([]WhitelistEntry, error)
	AddWhitelist(ctx context.Context, kind, value, actor string) error
	RemoveWhitelist(ctx context.Context, kind, value, actor string) error

	ListBans(ctx context.Context, includeInactive bool) ([]BanRecord, error)
	AddBan(ctx context.Context, kind, value, reason string, expiresAt *time.Time, actor string) (int64, error)
	RevokeBan(ctx context.Context, id int64, actor string) error

	// Firewall-style ordered IP ACL, evaluated at the ingress edge.
	ListIPRules(ctx context.Context) ([]IPRuleRecord, error)
	AddIPRule(ctx context.Context, priority int, cidr, action, note, actor string) (int64, error)
	RemoveIPRule(ctx context.Context, id int64, actor string) error

	ListRoles(ctx context.Context) (map[string][]string, error)
	UpsertRole(ctx context.Context, name string, permissions []string, actor string) error
	ListGrants(ctx context.Context, uuid string) ([]string, error)
	Grant(ctx context.Context, uuid, role, actor string) error
	RevokeGrant(ctx context.Context, uuid, role, actor string) error

	GetSetting(ctx context.Context, key string) (string, error)
	SetSetting(ctx context.Context, key, value, actor string) error

	SearchPrincipals(ctx context.Context, query string, limit int) ([]Principal, error)
	ListAudit(ctx context.Context, limit int) ([]AuditEntry, error)

	Healthy(ctx context.Context) error
}
