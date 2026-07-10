package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tachyne/tachyne-access/internal/policy"
)

// ErrNotFound is returned for lookups/mutations that matched no row.
var ErrNotFound = errors.New("store: not found")

// PG is the Postgres-backed Store.
type PG struct{ pool *pgxpool.Pool }

// OpenPG connects and applies the schema. url is a postgres:// conn string.
func OpenPG(ctx context.Context, url string) (*PG, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	p := &PG{pool: pool}
	if err := p.migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return p, nil
}

// Close releases the pool.
func (p *PG) Close() { p.pool.Close() }

// schema is idempotent — every statement is IF NOT EXISTS / ON CONFLICT.
var schema = []string{
	`CREATE TABLE IF NOT EXISTS principals (
		uuid       text PRIMARY KEY,
		name       text NOT NULL,
		edition    text NOT NULL DEFAULT 'java',
		first_seen timestamptz NOT NULL DEFAULT now(),
		last_seen  timestamptz NOT NULL DEFAULT now()
	)`,
	`CREATE TABLE IF NOT EXISTS roles (
		name        text PRIMARY KEY,
		permissions text[] NOT NULL DEFAULT '{}'
	)`,
	`CREATE TABLE IF NOT EXISTS grants (
		uuid       text NOT NULL,
		role       text NOT NULL REFERENCES roles(name) ON DELETE CASCADE,
		granted_by text NOT NULL,
		granted_at timestamptz NOT NULL DEFAULT now(),
		PRIMARY KEY (uuid, role)
	)`,
	`CREATE TABLE IF NOT EXISTS whitelist (
		kind     text NOT NULL CHECK (kind IN ('uuid','name')),
		value    text NOT NULL,
		added_by text NOT NULL,
		added_at timestamptz NOT NULL DEFAULT now(),
		PRIMARY KEY (kind, value)
	)`,
	`CREATE TABLE IF NOT EXISTS bans (
		id         bigserial PRIMARY KEY,
		kind       text NOT NULL CHECK (kind IN ('uuid','name','ip')),
		value      text NOT NULL,
		reason     text NOT NULL DEFAULT '',
		issued_by  text NOT NULL,
		issued_at  timestamptz NOT NULL DEFAULT now(),
		expires_at timestamptz,
		revoked    boolean NOT NULL DEFAULT false
	)`,
	`CREATE TABLE IF NOT EXISTS ip_rules (
		id       bigserial PRIMARY KEY,
		priority int NOT NULL,
		cidr     text NOT NULL,
		action   text NOT NULL CHECK (action IN ('allow','deny')),
		note     text NOT NULL DEFAULT '',
		added_by text NOT NULL,
		added_at timestamptz NOT NULL DEFAULT now()
	)`,
	`CREATE INDEX IF NOT EXISTS ip_rules_order ON ip_rules (priority, id)`,
	`CREATE TABLE IF NOT EXISTS settings (
		key   text PRIMARY KEY,
		value text NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS audit (
		id      bigserial PRIMARY KEY,
		ts      timestamptz NOT NULL DEFAULT now(),
		actor   text NOT NULL,
		action  text NOT NULL,
		subject text NOT NULL,
		detail  jsonb NOT NULL DEFAULT '{}'
	)`,
	`INSERT INTO roles (name, permissions) VALUES ('op', '{"*"}') ON CONFLICT DO NOTHING`,
	`INSERT INTO settings (key, value) VALUES ('whitelist_enforced', 'false') ON CONFLICT DO NOTHING`,
	// Default IP policy when no ACL rule matches. 'allow' = open (nothing
	// changes until rules are added); set 'deny' for allow-list-only mode.
	`INSERT INTO settings (key, value) VALUES ('ip_default', 'allow') ON CONFLICT DO NOTHING`,
}

func (p *PG) migrate(ctx context.Context) error {
	for _, stmt := range schema {
		if _, err := p.pool.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}
	return nil
}

// audit records one admin/system action. Failures are returned so callers
// notice — an access-control service with silent audit gaps is worse than one
// that errors loudly.
func (p *PG) audit(ctx context.Context, actor, action, subject string, detail any) error {
	js, err := json.Marshal(detail)
	if err != nil {
		js = []byte(`{}`)
	}
	_, err = p.pool.Exec(ctx,
		`INSERT INTO audit (actor, action, subject, detail) VALUES ($1, $2, $3, $4)`,
		actor, action, subject, js)
	return err
}

func (p *PG) RulesFor(ctx context.Context, name, uuid, ip string) (policy.Rules, error) {
	var r policy.Rules

	var enforced string
	err := p.pool.QueryRow(ctx, `SELECT value FROM settings WHERE key = 'whitelist_enforced'`).Scan(&enforced)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return r, err
	}
	r.WhitelistEnforced = enforced == "true"

	err = p.pool.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM whitelist
		WHERE (kind = 'uuid' AND lower(value) = lower($1))
		   OR (kind = 'name' AND lower(value) = lower($2)))`, uuid, name).Scan(&r.Whitelisted)
	if err != nil {
		return r, err
	}

	rows, err := p.pool.Query(ctx, `SELECT kind, value, reason, expires_at, revoked FROM bans
		WHERE NOT revoked AND (expires_at IS NULL OR expires_at > now())
		  AND (kind = 'ip'
		       OR (kind = 'uuid' AND lower(value) = lower($1))
		       OR (kind = 'name' AND lower(value) = lower($2)))`, uuid, name)
	if err != nil {
		return r, err
	}
	defer rows.Close()
	for rows.Next() {
		var b policy.Ban
		if err := rows.Scan(&b.Kind, &b.Value, &b.Reason, &b.ExpiresAt, &b.Revoked); err != nil {
			return r, err
		}
		r.Bans = append(r.Bans, b)
	}
	if err := rows.Err(); err != nil {
		return r, err
	}

	r.Roles, err = p.ListGrants(ctx, uuid)
	return r, err
}

func (p *PG) TouchPrincipal(ctx context.Context, uuid, name, edition string) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO principals (uuid, name, edition)
		VALUES ($1, $2, $3)
		ON CONFLICT (uuid) DO UPDATE SET name = $2, edition = $3, last_seen = now()`,
		uuid, name, edition)
	return err
}

func (p *PG) ListWhitelist(ctx context.Context) ([]WhitelistEntry, error) {
	rows, err := p.pool.Query(ctx, `SELECT kind, value, added_by, added_at FROM whitelist ORDER BY added_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []WhitelistEntry{}
	for rows.Next() {
		var e WhitelistEntry
		if err := rows.Scan(&e.Kind, &e.Value, &e.AddedBy, &e.AddedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (p *PG) AddWhitelist(ctx context.Context, kind, value, actor string) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO whitelist (kind, value, added_by)
		VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, kind, value, actor)
	if err != nil {
		return err
	}
	return p.audit(ctx, actor, "whitelist.add", kind+":"+value, nil)
}

func (p *PG) RemoveWhitelist(ctx context.Context, kind, value, actor string) error {
	tag, err := p.pool.Exec(ctx, `DELETE FROM whitelist WHERE kind = $1 AND lower(value) = lower($2)`, kind, value)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return p.audit(ctx, actor, "whitelist.remove", kind+":"+value, nil)
}

func (p *PG) ListBans(ctx context.Context, includeInactive bool) ([]BanRecord, error) {
	q := `SELECT id, kind, value, reason, issued_by, issued_at, expires_at, revoked FROM bans`
	if !includeInactive {
		q += ` WHERE NOT revoked AND (expires_at IS NULL OR expires_at > now())`
	}
	q += ` ORDER BY id`
	rows, err := p.pool.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []BanRecord{}
	for rows.Next() {
		var b BanRecord
		if err := rows.Scan(&b.ID, &b.Kind, &b.Value, &b.Reason, &b.IssuedBy, &b.IssuedAt, &b.ExpiresAt, &b.Revoked); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (p *PG) AddBan(ctx context.Context, kind, value, reason string, expiresAt *time.Time, actor string) (int64, error) {
	var id int64
	err := p.pool.QueryRow(ctx, `INSERT INTO bans (kind, value, reason, issued_by, expires_at)
		VALUES ($1, $2, $3, $4, $5) RETURNING id`, kind, value, reason, actor, expiresAt).Scan(&id)
	if err != nil {
		return 0, err
	}
	return id, p.audit(ctx, actor, "ban.add", kind+":"+value, map[string]any{"id": id, "reason": reason, "expires_at": expiresAt})
}

func (p *PG) RevokeBan(ctx context.Context, id int64, actor string) error {
	tag, err := p.pool.Exec(ctx, `UPDATE bans SET revoked = true WHERE id = $1 AND NOT revoked`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return p.audit(ctx, actor, "ban.revoke", fmt.Sprint(id), nil)
}

// IPRulesFor gathers the edge ACL for a bare source IP: active ip-bans, the
// ordered rules, and the default action.
func (p *PG) IPRulesFor(ctx context.Context, ip string) (policy.IPRules, error) {
	var r policy.IPRules

	def, err := p.GetSetting(ctx, "ip_default")
	if errors.Is(err, ErrNotFound) {
		def = "allow"
	} else if err != nil {
		return r, err
	}
	r.Default = def

	banRows, err := p.pool.Query(ctx, `SELECT kind, value, reason, expires_at, revoked FROM bans
		WHERE kind = 'ip' AND NOT revoked AND (expires_at IS NULL OR expires_at > now())`)
	if err != nil {
		return r, err
	}
	defer banRows.Close()
	for banRows.Next() {
		var b policy.Ban
		if err := banRows.Scan(&b.Kind, &b.Value, &b.Reason, &b.ExpiresAt, &b.Revoked); err != nil {
			return r, err
		}
		r.Bans = append(r.Bans, b)
	}
	if err := banRows.Err(); err != nil {
		return r, err
	}

	ruleRows, err := p.pool.Query(ctx, `SELECT cidr, action FROM ip_rules ORDER BY priority, id`)
	if err != nil {
		return r, err
	}
	defer ruleRows.Close()
	for ruleRows.Next() {
		var rule policy.IPRule
		if err := ruleRows.Scan(&rule.CIDR, &rule.Action); err != nil {
			return r, err
		}
		r.Rules = append(r.Rules, rule)
	}
	return r, ruleRows.Err()
}

func (p *PG) ListIPRules(ctx context.Context) ([]IPRuleRecord, error) {
	rows, err := p.pool.Query(ctx, `SELECT id, priority, cidr, action, note, added_by, added_at
		FROM ip_rules ORDER BY priority, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []IPRuleRecord{}
	for rows.Next() {
		var e IPRuleRecord
		if err := rows.Scan(&e.ID, &e.Priority, &e.CIDR, &e.Action, &e.Note, &e.AddedBy, &e.AddedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (p *PG) AddIPRule(ctx context.Context, priority int, cidr, action, note, actor string) (int64, error) {
	var id int64
	err := p.pool.QueryRow(ctx, `INSERT INTO ip_rules (priority, cidr, action, note, added_by)
		VALUES ($1, $2, $3, $4, $5) RETURNING id`, priority, cidr, action, note, actor).Scan(&id)
	if err != nil {
		return 0, err
	}
	return id, p.audit(ctx, actor, "ip_rule.add", cidr, map[string]any{"id": id, "priority": priority, "action": action, "note": note})
}

func (p *PG) RemoveIPRule(ctx context.Context, id int64, actor string) error {
	tag, err := p.pool.Exec(ctx, `DELETE FROM ip_rules WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return p.audit(ctx, actor, "ip_rule.remove", fmt.Sprint(id), nil)
}

func (p *PG) ListRoles(ctx context.Context) (map[string][]string, error) {
	rows, err := p.pool.Query(ctx, `SELECT name, permissions FROM roles ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var name string
		var perms []string
		if err := rows.Scan(&name, &perms); err != nil {
			return nil, err
		}
		out[name] = perms
	}
	return out, rows.Err()
}

func (p *PG) UpsertRole(ctx context.Context, name string, permissions []string, actor string) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO roles (name, permissions) VALUES ($1, $2)
		ON CONFLICT (name) DO UPDATE SET permissions = $2`, name, permissions)
	if err != nil {
		return err
	}
	return p.audit(ctx, actor, "role.upsert", name, map[string]any{"permissions": permissions})
}

func (p *PG) ListGrants(ctx context.Context, uuid string) ([]string, error) {
	rows, err := p.pool.Query(ctx, `SELECT role FROM grants WHERE uuid = $1 ORDER BY role`, uuid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			return nil, err
		}
		out = append(out, role)
	}
	return out, rows.Err()
}

func (p *PG) Grant(ctx context.Context, uuid, role, actor string) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO grants (uuid, role, granted_by)
		VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, uuid, role, actor)
	if err != nil {
		return err
	}
	return p.audit(ctx, actor, "grant.add", uuid, map[string]any{"role": role})
}

func (p *PG) RevokeGrant(ctx context.Context, uuid, role, actor string) error {
	tag, err := p.pool.Exec(ctx, `DELETE FROM grants WHERE uuid = $1 AND role = $2`, uuid, role)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return p.audit(ctx, actor, "grant.revoke", uuid, map[string]any{"role": role})
}

func (p *PG) GetSetting(ctx context.Context, key string) (string, error) {
	var v string
	err := p.pool.QueryRow(ctx, `SELECT value FROM settings WHERE key = $1`, key).Scan(&v)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	return v, err
}

func (p *PG) SetSetting(ctx context.Context, key, value, actor string) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO settings (key, value) VALUES ($1, $2)
		ON CONFLICT (key) DO UPDATE SET value = $2`, key, value)
	if err != nil {
		return err
	}
	return p.audit(ctx, actor, "setting.set", key, map[string]any{"value": value})
}

func (p *PG) SearchPrincipals(ctx context.Context, query string, limit int) ([]Principal, error) {
	rows, err := p.pool.Query(ctx, `SELECT uuid, name, edition, first_seen, last_seen FROM principals
		WHERE $1 = '' OR uuid = $1 OR name ILIKE '%' || $1 || '%'
		ORDER BY last_seen DESC LIMIT $2`, query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Principal{}
	for rows.Next() {
		var pr Principal
		if err := rows.Scan(&pr.UUID, &pr.Name, &pr.Edition, &pr.FirstSeen, &pr.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, pr)
	}
	return out, rows.Err()
}

func (p *PG) ListAudit(ctx context.Context, limit int) ([]AuditEntry, error) {
	rows, err := p.pool.Query(ctx, `SELECT id, ts, actor, action, subject, detail::text FROM audit
		ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditEntry{}
	for rows.Next() {
		var a AuditEntry
		if err := rows.Scan(&a.ID, &a.TS, &a.Actor, &a.Action, &a.Subject, &a.Detail); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (p *PG) Healthy(ctx context.Context) error { return p.pool.Ping(ctx) }
