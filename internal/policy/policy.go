// Package policy is the pure decision engine for tachyne-access: given a
// login request and the rules that apply to it, produce a verdict. No I/O —
// the store gathers rules, this package only decides. Precedence: active ban
// beats everything; the whitelist (when enforced) admits whitelisted
// principals and role holders; everything else is allowed through.
package policy

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// Request describes a login attempt as the gateway saw it.
type Request struct {
	Name    string `json:"name"`
	UUID    string `json:"uuid"`
	IP      string `json:"ip"`
	Edition string `json:"edition"` // "java" | "bedrock"
}

// Verdict is the decision handed back to the gateway.
type Verdict struct {
	Allow  bool     `json:"allow"`
	Reason string   `json:"reason,omitempty"` // shown to the player on deny
	Roles  []string `json:"roles"`
}

// Ban is one ban row. Value is a UUID, a (case-insensitive) name, or an
// IP/CIDR depending on Kind.
type Ban struct {
	Kind      string // "uuid" | "name" | "ip"
	Value     string
	Reason    string
	ExpiresAt *time.Time
	Revoked   bool
}

// Active reports whether the ban is in force at t.
func (b Ban) Active(t time.Time) bool {
	return !b.Revoked && (b.ExpiresAt == nil || b.ExpiresAt.After(t))
}

// Matches reports whether the ban applies to the request.
func (b Ban) Matches(req Request) bool {
	switch b.Kind {
	case "uuid":
		return strings.EqualFold(b.Value, req.UUID)
	case "name":
		return strings.EqualFold(b.Value, req.Name)
	case "ip":
		ip := net.ParseIP(req.IP)
		if ip == nil {
			return false
		}
		if _, cidr, err := net.ParseCIDR(b.Value); err == nil {
			return cidr.Contains(ip)
		}
		if banned := net.ParseIP(b.Value); banned != nil {
			return banned.Equal(ip)
		}
		return false
	}
	return false
}

// Rules is everything the store gathered that bears on one request.
type Rules struct {
	WhitelistEnforced bool
	Whitelisted       bool // request matched a whitelist entry (uuid or name)
	Bans              []Ban
	Roles             []string // roles granted to this principal
}

// ipMatch reports whether an IP/CIDR pattern covers ip.
func ipMatch(pattern string, ip net.IP) bool {
	if ip == nil {
		return false
	}
	if _, cidr, err := net.ParseCIDR(pattern); err == nil {
		return cidr.Contains(ip)
	}
	if p := net.ParseIP(pattern); p != nil {
		return p.Equal(ip)
	}
	return false
}

// IPRule is one firewall-style ACL entry. Rules are evaluated in order and the
// FIRST match wins, so "allow 192.168.0.0/24" placed before "deny 0.0.0.0/0"
// admits the LAN and blocks everything else — order is the whole point.
type IPRule struct {
	CIDR   string `json:"cidr"`   // an IP or CIDR
	Action string `json:"action"` // "allow" | "deny"
}

// IPRules is the edge ACL for a bare source IP — the only thing the ingress can
// see before any login/encryption. No identity here. Active ip-bans are checked
// first and always deny (a ban is authoritative and outranks the ACL); then the
// ordered rules first-match; then the default when nothing matched.
type IPRules struct {
	Bans    []Ban    // active ip-kind bans (checked first, always deny)
	Rules   []IPRule // ordered; first match wins
	Default string   // "allow" | "deny" when nothing matches (default "allow")
}

// DecideIP produces the edge verdict for a bare source IP.
func DecideIP(now time.Time, ip string, r IPRules) Verdict {
	pip := net.ParseIP(ip)
	for _, b := range r.Bans {
		if b.Active(now) && b.Kind == "ip" && ipMatch(b.Value, pip) {
			reason := "Your network is banned from this server."
			if b.Reason != "" {
				reason = fmt.Sprintf("Banned: %s", b.Reason)
			}
			return Verdict{Allow: false, Reason: reason, Roles: []string{}}
		}
	}
	for _, rule := range r.Rules {
		if ipMatch(rule.CIDR, pip) {
			if rule.Action == "deny" {
				return Verdict{Allow: false, Reason: "Your network is blocked by an ingress rule.", Roles: []string{}}
			}
			return Verdict{Allow: true, Roles: []string{}}
		}
	}
	if r.Default == "deny" {
		return Verdict{Allow: false, Reason: "Your network is not permitted by ingress policy.", Roles: []string{}}
	}
	return Verdict{Allow: true, Roles: []string{}}
}

// Decide produces the verdict for req under rules.
func Decide(now time.Time, req Request, rules Rules) Verdict {
	for _, b := range rules.Bans {
		if b.Active(now) && b.Matches(req) {
			reason := "You are banned from this server."
			if b.Reason != "" {
				reason = fmt.Sprintf("Banned: %s", b.Reason)
			}
			if b.ExpiresAt != nil {
				reason += fmt.Sprintf(" (until %s)", b.ExpiresAt.UTC().Format("2006-01-02 15:04 MST"))
			}
			return Verdict{Allow: false, Reason: reason, Roles: []string{}}
		}
	}
	if rules.WhitelistEnforced && !rules.Whitelisted && len(rules.Roles) == 0 {
		return Verdict{Allow: false, Reason: "You are not whitelisted on this server.", Roles: []string{}}
	}
	roles := rules.Roles
	if roles == nil {
		roles = []string{}
	}
	return Verdict{Allow: true, Roles: roles}
}
