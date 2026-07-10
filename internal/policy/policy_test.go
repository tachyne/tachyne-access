package policy

import (
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)

func req() Request {
	return Request{Name: "Wesley", UUID: "11111111-2222-3333-4444-555555555555", IP: "203.0.113.50", Edition: "java"}
}

func TestOpenServerAllows(t *testing.T) {
	v := Decide(now, req(), Rules{})
	if !v.Allow || v.Roles == nil {
		t.Fatalf("open server should allow with non-nil roles: %+v", v)
	}
}

func TestBanByUUIDCaseInsensitive(t *testing.T) {
	r := Rules{Bans: []Ban{{Kind: "uuid", Value: strings.ToUpper(req().UUID), Reason: "griefing"}}}
	v := Decide(now, req(), r)
	if v.Allow || !strings.Contains(v.Reason, "griefing") {
		t.Fatalf("uuid ban should deny with reason: %+v", v)
	}
}

func TestBanByName(t *testing.T) {
	v := Decide(now, req(), Rules{Bans: []Ban{{Kind: "name", Value: "wesley"}}})
	if v.Allow {
		t.Fatalf("name ban should deny: %+v", v)
	}
}

func TestBanByCIDR(t *testing.T) {
	v := Decide(now, req(), Rules{Bans: []Ban{{Kind: "ip", Value: "203.0.113.0/24"}}})
	if v.Allow {
		t.Fatalf("cidr ban should deny: %+v", v)
	}
	v = Decide(now, req(), Rules{Bans: []Ban{{Kind: "ip", Value: "10.0.0.0/8"}}})
	if !v.Allow {
		t.Fatalf("non-matching cidr should allow: %+v", v)
	}
}

func TestExpiredAndRevokedBansIgnored(t *testing.T) {
	past := now.Add(-time.Hour)
	r := Rules{Bans: []Ban{
		{Kind: "name", Value: "wesley", ExpiresAt: &past},
		{Kind: "name", Value: "wesley", Revoked: true},
	}}
	if v := Decide(now, req(), r); !v.Allow {
		t.Fatalf("expired/revoked bans should not deny: %+v", v)
	}
}

func TestTemporaryBanMentionsExpiry(t *testing.T) {
	until := now.Add(24 * time.Hour)
	v := Decide(now, req(), Rules{Bans: []Ban{{Kind: "name", Value: "wesley", ExpiresAt: &until}}})
	if v.Allow || !strings.Contains(v.Reason, "until") {
		t.Fatalf("temp ban should deny and mention expiry: %+v", v)
	}
}

func TestWhitelistEnforced(t *testing.T) {
	if v := Decide(now, req(), Rules{WhitelistEnforced: true}); v.Allow {
		t.Fatalf("unlisted player should be denied under whitelist: %+v", v)
	}
	if v := Decide(now, req(), Rules{WhitelistEnforced: true, Whitelisted: true}); !v.Allow {
		t.Fatalf("whitelisted player should be allowed: %+v", v)
	}
	// Role holders bypass the whitelist.
	v := Decide(now, req(), Rules{WhitelistEnforced: true, Roles: []string{"op"}})
	if !v.Allow || len(v.Roles) != 1 {
		t.Fatalf("role holder should bypass whitelist and keep roles: %+v", v)
	}
}

func TestBanBeatsWhitelist(t *testing.T) {
	r := Rules{
		WhitelistEnforced: true,
		Whitelisted:       true,
		Roles:             []string{"op"},
		Bans:              []Ban{{Kind: "uuid", Value: req().UUID}},
	}
	if v := Decide(now, req(), r); v.Allow {
		t.Fatalf("ban must beat whitelist and roles: %+v", v)
	}
}

func TestDecideIPOrderedFirstMatch(t *testing.T) {
	// The firewall example: allow the LAN, deny everything else. Order matters —
	// the allow must be evaluated before the catch-all deny.
	acl := IPRules{
		Rules: []IPRule{
			{CIDR: "192.168.0.0/24", Action: "allow"},
			{CIDR: "0.0.0.0/0", Action: "deny"},
		},
		Default: "allow",
	}
	if v := DecideIP(now, "192.168.0.42", acl); !v.Allow {
		t.Fatalf("LAN IP should match the allow rule first: %+v", v)
	}
	if v := DecideIP(now, "8.8.8.8", acl); v.Allow {
		t.Fatalf("outside IP should hit the catch-all deny: %+v", v)
	}
	// Reversing the order flips the LAN verdict — proving order is honored.
	reversed := IPRules{Rules: []IPRule{{CIDR: "0.0.0.0/0", Action: "deny"}, {CIDR: "192.168.0.0/24", Action: "allow"}}}
	if v := DecideIP(now, "192.168.0.42", reversed); v.Allow {
		t.Fatalf("with deny-all first, the LAN IP must be blocked: %+v", v)
	}
	// An active ip-ban outranks any allow rule.
	banned := IPRules{Bans: []Ban{{Kind: "ip", Value: "192.168.0.0/24"}}, Rules: []IPRule{{CIDR: "192.168.0.0/24", Action: "allow"}}}
	if v := DecideIP(now, "192.168.0.42", banned); v.Allow {
		t.Fatalf("an ip-ban must outrank an allow rule: %+v", v)
	}
	// Default deny with no matching rule blocks.
	if v := DecideIP(now, "8.8.8.8", IPRules{Default: "deny"}); v.Allow {
		t.Fatalf("default-deny with no match should block: %+v", v)
	}
}
