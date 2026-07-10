package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tachyne/tachyne-access/internal/policy"
	"github.com/tachyne/tachyne-access/internal/store"
)

// fake is an in-memory Store covering what the tests exercise.
type fake struct {
	whitelistEnforced bool
	whitelist         map[string]bool // kind:value (lowered)
	bans              []store.BanRecord
	ipRules           []store.IPRuleRecord
	grants            map[string][]string
	audit             []store.AuditEntry
	nextBan           int64
}

func newFake() *fake {
	return &fake{whitelist: map[string]bool{}, grants: map[string][]string{}, nextBan: 1}
}

func key(kind, value string) string { return kind + ":" + strings.ToLower(value) }

func (f *fake) RulesFor(_ context.Context, name, uuid, ip string) (policy.Rules, error) {
	r := policy.Rules{
		WhitelistEnforced: f.whitelistEnforced,
		Whitelisted:       f.whitelist[key("uuid", uuid)] || f.whitelist[key("name", name)],
		Roles:             f.grants[uuid],
	}
	for _, b := range f.bans {
		r.Bans = append(r.Bans, policy.Ban{Kind: b.Kind, Value: b.Value, Reason: b.Reason, ExpiresAt: b.ExpiresAt, Revoked: b.Revoked})
	}
	return r, nil
}

func (f *fake) TouchPrincipal(context.Context, string, string, string) error { return nil }

func (f *fake) ListWhitelist(context.Context) ([]store.WhitelistEntry, error) {
	out := []store.WhitelistEntry{}
	for k := range f.whitelist {
		kind, value, _ := strings.Cut(k, ":")
		out = append(out, store.WhitelistEntry{Kind: kind, Value: value})
	}
	return out, nil
}

func (f *fake) AddWhitelist(_ context.Context, kind, value, actor string) error {
	f.whitelist[key(kind, value)] = true
	f.audit = append(f.audit, store.AuditEntry{Actor: actor, Action: "whitelist.add"})
	return nil
}

func (f *fake) RemoveWhitelist(_ context.Context, kind, value, _ string) error {
	k := key(kind, value)
	if !f.whitelist[k] {
		return store.ErrNotFound
	}
	delete(f.whitelist, k)
	return nil
}

func (f *fake) ListBans(context.Context, bool) ([]store.BanRecord, error) { return f.bans, nil }

func (f *fake) AddBan(_ context.Context, kind, value, reason string, expiresAt *time.Time, _ string) (int64, error) {
	id := f.nextBan
	f.nextBan++
	f.bans = append(f.bans, store.BanRecord{ID: id, Kind: kind, Value: value, Reason: reason, ExpiresAt: expiresAt})
	return id, nil
}

func (f *fake) RevokeBan(_ context.Context, id int64, _ string) error {
	for i := range f.bans {
		if f.bans[i].ID == id && !f.bans[i].Revoked {
			f.bans[i].Revoked = true
			return nil
		}
	}
	return store.ErrNotFound
}

func (f *fake) IPRulesFor(_ context.Context, ip string) (policy.IPRules, error) {
	r := policy.IPRules{Default: "allow"}
	for _, ir := range f.ipRules {
		r.Rules = append(r.Rules, policy.IPRule{CIDR: ir.CIDR, Action: ir.Action})
	}
	for _, b := range f.bans {
		if b.Kind == "ip" {
			r.Bans = append(r.Bans, policy.Ban{Kind: b.Kind, Value: b.Value, Reason: b.Reason, ExpiresAt: b.ExpiresAt, Revoked: b.Revoked})
		}
	}
	return r, nil
}
func (f *fake) ListIPRules(context.Context) ([]store.IPRuleRecord, error) { return f.ipRules, nil }
func (f *fake) AddIPRule(_ context.Context, priority int, cidr, action, note, _ string) (int64, error) {
	id := f.nextBan
	f.nextBan++
	f.ipRules = append(f.ipRules, store.IPRuleRecord{ID: id, Priority: priority, CIDR: cidr, Action: action, Note: note})
	return id, nil
}
func (f *fake) RemoveIPRule(_ context.Context, id int64, _ string) error {
	for i := range f.ipRules {
		if f.ipRules[i].ID == id {
			f.ipRules = append(f.ipRules[:i], f.ipRules[i+1:]...)
			return nil
		}
	}
	return store.ErrNotFound
}

func (f *fake) ListRoles(context.Context) (map[string][]string, error) { return nil, nil }
func (f *fake) UpsertRole(context.Context, string, []string, string) error {
	return nil
}
func (f *fake) ListGrants(_ context.Context, uuid string) ([]string, error) {
	return f.grants[uuid], nil
}
func (f *fake) Grant(_ context.Context, uuid, role, _ string) error {
	f.grants[uuid] = append(f.grants[uuid], role)
	return nil
}
func (f *fake) RevokeGrant(context.Context, string, string, string) error { return nil }
func (f *fake) GetSetting(context.Context, string) (string, error)        { return "", store.ErrNotFound }
func (f *fake) SetSetting(_ context.Context, key, value, _ string) error {
	if key == "whitelist_enforced" {
		f.whitelistEnforced = value == "true"
	}
	return nil
}
func (f *fake) SearchPrincipals(context.Context, string, int) ([]store.Principal, error) {
	return nil, nil
}
func (f *fake) ListAudit(context.Context, int) ([]store.AuditEntry, error) { return f.audit, nil }
func (f *fake) Healthy(context.Context) error                              { return nil }

const token = "test-token"

func serve(t *testing.T, f *fake) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer((&Server{Store: f, Token: token}).Handler())
	t.Cleanup(ts.Close)
	return ts
}

func call(t *testing.T, method, url string, body any, auth bool) (*http.Response, []byte) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		json.NewEncoder(&buf).Encode(body)
	}
	req, err := http.NewRequest(method, url, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if auth {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out bytes.Buffer
	out.ReadFrom(resp.Body)
	return resp, out.Bytes()
}

func TestAuthRequired(t *testing.T) {
	ts := serve(t, newFake())
	resp, _ := call(t, "GET", ts.URL+"/v1/whitelist", nil, false)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated request: want 401 got %d", resp.StatusCode)
	}
	resp, _ = call(t, "GET", ts.URL+"/healthz", nil, false)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz must not need auth: got %d", resp.StatusCode)
	}
}

func checkVerdict(t *testing.T, ts *httptest.Server, req policy.Request) policy.Verdict {
	t.Helper()
	resp, body := call(t, "POST", ts.URL+"/v1/check", req, true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("check: status %d: %s", resp.StatusCode, body)
	}
	var v policy.Verdict
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestCheckFlow(t *testing.T) {
	f := newFake()
	ts := serve(t, f)
	player := policy.Request{Name: "wesley", UUID: "u-1", IP: "203.0.113.50", Edition: "java"}

	if v := checkVerdict(t, ts, player); !v.Allow {
		t.Fatalf("open server should allow: %+v", v)
	}

	// Enforce the whitelist: now denied.
	call(t, "PUT", ts.URL+"/v1/settings/whitelist_enforced", map[string]string{"value": "true"}, true)
	if v := checkVerdict(t, ts, player); v.Allow {
		t.Fatalf("unlisted player should be denied: %+v", v)
	}

	// Whitelist by name: allowed again.
	call(t, "POST", ts.URL+"/v1/whitelist", map[string]string{"kind": "name", "value": "Wesley"}, true)
	if v := checkVerdict(t, ts, player); !v.Allow {
		t.Fatalf("whitelisted player should be allowed: %+v", v)
	}

	// Ban beats whitelist.
	resp, body := call(t, "POST", ts.URL+"/v1/bans", map[string]string{"kind": "uuid", "value": "u-1", "reason": "testing"}, true)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("add ban: status %d: %s", resp.StatusCode, body)
	}
	if v := checkVerdict(t, ts, player); v.Allow || !strings.Contains(v.Reason, "testing") {
		t.Fatalf("banned player should be denied with reason: %+v", v)
	}

	// Revoke the ban: allowed again.
	call(t, "DELETE", ts.URL+"/v1/bans/1", nil, true)
	if v := checkVerdict(t, ts, player); !v.Allow {
		t.Fatalf("player should be allowed after ban revoked: %+v", v)
	}
}

func TestGrantRolesInVerdict(t *testing.T) {
	f := newFake()
	ts := serve(t, f)
	call(t, "POST", ts.URL+"/v1/principals/u-9/roles", map[string]string{"role": "op"}, true)
	v := checkVerdict(t, ts, policy.Request{Name: "admin", UUID: "u-9"})
	if !v.Allow || len(v.Roles) != 1 || v.Roles[0] != "op" {
		t.Fatalf("verdict should carry granted roles: %+v", v)
	}
}

func TestBadInputRejected(t *testing.T) {
	ts := serve(t, newFake())
	resp, _ := call(t, "POST", ts.URL+"/v1/whitelist", map[string]string{"kind": "ip", "value": "1.2.3.4"}, true)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("ip whitelist entries are invalid: want 400 got %d", resp.StatusCode)
	}
	resp, _ = call(t, "POST", ts.URL+"/v1/check", map[string]string{"edition": "java"}, true)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("check without name/uuid: want 400 got %d", resp.StatusCode)
	}
}
