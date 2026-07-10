// Package api is the HTTP surface of tachyne-access. JSON in, JSON out.
// Everything except /healthz requires the shared bearer token; the acting
// principal for audit rows comes from the optional X-Actor header.
package api

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/tachyne/tachyne-access/internal/policy"
	"github.com/tachyne/tachyne-access/internal/store"
)

// Server serves the access API.
type Server struct {
	Store store.Store
	Token string // shared bearer token; empty disables auth (tests only)
}

// Handler builds the routed, auth-wrapped handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.healthz)

	mux.HandleFunc("POST /v1/check", s.check)
	mux.HandleFunc("POST /v1/check-ip", s.checkIP)

	mux.HandleFunc("GET /v1/ip-rules", s.listIPRules)
	mux.HandleFunc("POST /v1/ip-rules", s.addIPRule)
	mux.HandleFunc("DELETE /v1/ip-rules/{id}", s.removeIPRule)

	mux.HandleFunc("GET /v1/whitelist", s.listWhitelist)
	mux.HandleFunc("POST /v1/whitelist", s.addWhitelist)
	mux.HandleFunc("DELETE /v1/whitelist", s.removeWhitelist)

	mux.HandleFunc("GET /v1/bans", s.listBans)
	mux.HandleFunc("POST /v1/bans", s.addBan)
	mux.HandleFunc("DELETE /v1/bans/{id}", s.revokeBan)

	mux.HandleFunc("GET /v1/roles", s.listRoles)
	mux.HandleFunc("PUT /v1/roles/{name}", s.upsertRole)

	mux.HandleFunc("GET /v1/principals", s.searchPrincipals)
	mux.HandleFunc("GET /v1/principals/{uuid}/roles", s.listGrants)
	mux.HandleFunc("POST /v1/principals/{uuid}/roles", s.grant)
	mux.HandleFunc("DELETE /v1/principals/{uuid}/roles/{role}", s.revokeGrant)

	mux.HandleFunc("GET /v1/settings/{key}", s.getSetting)
	mux.HandleFunc("PUT /v1/settings/{key}", s.setSetting)

	mux.HandleFunc("GET /v1/audit", s.listAudit)

	return s.auth(mux)
}

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || s.Token == "" {
			next.ServeHTTP(w, r)
			return
		}
		want := "Bearer " + s.Token
		got := r.Header.Get("Authorization")
		if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			jsonError(w, http.StatusUnauthorized, "missing or invalid bearer token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func actor(r *http.Request) string {
	if a := r.Header.Get("X-Actor"); a != "" {
		return a
	}
	return "admin"
}

func jsonWrite(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func jsonError(w http.ResponseWriter, code int, msg string) {
	jsonWrite(w, code, map[string]string{"error": msg})
}

// storeErr maps store errors onto HTTP codes.
func storeErr(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrNotFound) {
		jsonError(w, http.StatusNotFound, "not found")
		return
	}
	log.Printf("store error: %v", err)
	jsonError(w, http.StatusInternalServerError, "storage error")
}

func decode[T any](w http.ResponseWriter, r *http.Request) (T, bool) {
	var v T
	if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
		jsonError(w, http.StatusBadRequest, "bad JSON: "+err.Error())
		return v, false
	}
	return v, true
}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	if err := s.Store.Healthy(r.Context()); err != nil {
		jsonError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	jsonWrite(w, http.StatusOK, map[string]string{"status": "ok"})
}

// check is THE endpoint gateways call on every login attempt.
func (s *Server) check(w http.ResponseWriter, r *http.Request) {
	req, ok := decode[policy.Request](w, r)
	if !ok {
		return
	}
	if req.Name == "" && req.UUID == "" {
		jsonError(w, http.StatusBadRequest, "need at least one of name, uuid")
		return
	}
	rules, err := s.Store.RulesFor(r.Context(), req.Name, req.UUID, req.IP)
	if err != nil {
		// Fail CLOSED: a gateway that cannot get a verdict must not admit.
		storeErr(w, err)
		return
	}
	v := policy.Decide(time.Now(), req, rules)
	if req.UUID != "" {
		if err := s.Store.TouchPrincipal(r.Context(), req.UUID, req.Name, req.Edition); err != nil {
			log.Printf("touch principal %s: %v", req.UUID, err) // directory upkeep is best-effort
		}
	}
	jsonWrite(w, http.StatusOK, v)
}

// checkIP is the edge endpoint the ingress calls with only a source IP — before
// any login, so no identity is available (and for Bedrock, cannot be).
func (s *Server) checkIP(w http.ResponseWriter, r *http.Request) {
	req, ok := decode[struct {
		IP string `json:"ip"`
	}](w, r)
	if !ok {
		return
	}
	if net.ParseIP(req.IP) == nil {
		jsonError(w, http.StatusBadRequest, "need a valid ip")
		return
	}
	rules, err := s.Store.IPRulesFor(r.Context(), req.IP)
	if err != nil {
		storeErr(w, err)
		return
	}
	jsonWrite(w, http.StatusOK, policy.DecideIP(time.Now(), req.IP, rules))
}

func (s *Server) listIPRules(w http.ResponseWriter, r *http.Request) {
	rules, err := s.Store.ListIPRules(r.Context())
	if err != nil {
		storeErr(w, err)
		return
	}
	jsonWrite(w, http.StatusOK, rules)
}

func (s *Server) addIPRule(w http.ResponseWriter, r *http.Request) {
	req, ok := decode[struct {
		Priority int    `json:"priority"`
		CIDR     string `json:"cidr"`
		Action   string `json:"action"`
		Note     string `json:"note"`
	}](w, r)
	if !ok {
		return
	}
	if req.Action != "allow" && req.Action != "deny" {
		jsonError(w, http.StatusBadRequest, `action must be "allow" or "deny"`)
		return
	}
	if net.ParseIP(req.CIDR) == nil {
		if _, _, err := net.ParseCIDR(req.CIDR); err != nil {
			jsonError(w, http.StatusBadRequest, "cidr must be an IP or CIDR")
			return
		}
	}
	id, err := s.Store.AddIPRule(r.Context(), req.Priority, req.CIDR, req.Action, req.Note, actor(r))
	if err != nil {
		storeErr(w, err)
		return
	}
	jsonWrite(w, http.StatusCreated, map[string]int64{"id": id})
}

func (s *Server) removeIPRule(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "bad rule id")
		return
	}
	if err := s.Store.RemoveIPRule(r.Context(), id, actor(r)); err != nil {
		storeErr(w, err)
		return
	}
	jsonWrite(w, http.StatusOK, map[string]int64{"removed": id})
}

func (s *Server) listWhitelist(w http.ResponseWriter, r *http.Request) {
	entries, err := s.Store.ListWhitelist(r.Context())
	if err != nil {
		storeErr(w, err)
		return
	}
	jsonWrite(w, http.StatusOK, entries)
}

type kindValue struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

func (kv kindValue) validFor(kinds ...string) bool {
	if kv.Value == "" {
		return false
	}
	for _, k := range kinds {
		if kv.Kind == k {
			return true
		}
	}
	return false
}

func (s *Server) addWhitelist(w http.ResponseWriter, r *http.Request) {
	kv, ok := decode[kindValue](w, r)
	if !ok {
		return
	}
	if !kv.validFor("uuid", "name") {
		jsonError(w, http.StatusBadRequest, `kind must be "uuid" or "name", value non-empty`)
		return
	}
	if err := s.Store.AddWhitelist(r.Context(), kv.Kind, kv.Value, actor(r)); err != nil {
		storeErr(w, err)
		return
	}
	jsonWrite(w, http.StatusCreated, kv)
}

func (s *Server) removeWhitelist(w http.ResponseWriter, r *http.Request) {
	kv := kindValue{Kind: r.URL.Query().Get("kind"), Value: r.URL.Query().Get("value")}
	if !kv.validFor("uuid", "name") {
		jsonError(w, http.StatusBadRequest, "need kind and value query params")
		return
	}
	if err := s.Store.RemoveWhitelist(r.Context(), kv.Kind, kv.Value, actor(r)); err != nil {
		storeErr(w, err)
		return
	}
	jsonWrite(w, http.StatusOK, kv)
}

func (s *Server) listBans(w http.ResponseWriter, r *http.Request) {
	bans, err := s.Store.ListBans(r.Context(), r.URL.Query().Get("all") == "true")
	if err != nil {
		storeErr(w, err)
		return
	}
	jsonWrite(w, http.StatusOK, bans)
}

func (s *Server) addBan(w http.ResponseWriter, r *http.Request) {
	req, ok := decode[struct {
		kindValue
		Reason    string     `json:"reason"`
		ExpiresAt *time.Time `json:"expires_at"`
	}](w, r)
	if !ok {
		return
	}
	if !req.validFor("uuid", "name", "ip") {
		jsonError(w, http.StatusBadRequest, `kind must be "uuid", "name" or "ip", value non-empty`)
		return
	}
	id, err := s.Store.AddBan(r.Context(), req.Kind, req.Value, req.Reason, req.ExpiresAt, actor(r))
	if err != nil {
		storeErr(w, err)
		return
	}
	jsonWrite(w, http.StatusCreated, map[string]int64{"id": id})
}

func (s *Server) revokeBan(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "bad ban id")
		return
	}
	if err := s.Store.RevokeBan(r.Context(), id, actor(r)); err != nil {
		storeErr(w, err)
		return
	}
	jsonWrite(w, http.StatusOK, map[string]int64{"revoked": id})
}

func (s *Server) listRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := s.Store.ListRoles(r.Context())
	if err != nil {
		storeErr(w, err)
		return
	}
	jsonWrite(w, http.StatusOK, roles)
}

func (s *Server) upsertRole(w http.ResponseWriter, r *http.Request) {
	req, ok := decode[struct {
		Permissions []string `json:"permissions"`
	}](w, r)
	if !ok {
		return
	}
	name := r.PathValue("name")
	if err := s.Store.UpsertRole(r.Context(), name, req.Permissions, actor(r)); err != nil {
		storeErr(w, err)
		return
	}
	jsonWrite(w, http.StatusOK, map[string]any{"name": name, "permissions": req.Permissions})
}

func (s *Server) searchPrincipals(w http.ResponseWriter, r *http.Request) {
	principals, err := s.Store.SearchPrincipals(r.Context(), r.URL.Query().Get("q"), 100)
	if err != nil {
		storeErr(w, err)
		return
	}
	jsonWrite(w, http.StatusOK, principals)
}

func (s *Server) listGrants(w http.ResponseWriter, r *http.Request) {
	roles, err := s.Store.ListGrants(r.Context(), r.PathValue("uuid"))
	if err != nil {
		storeErr(w, err)
		return
	}
	jsonWrite(w, http.StatusOK, roles)
}

func (s *Server) grant(w http.ResponseWriter, r *http.Request) {
	req, ok := decode[struct {
		Role string `json:"role"`
	}](w, r)
	if !ok {
		return
	}
	if req.Role == "" {
		jsonError(w, http.StatusBadRequest, "need role")
		return
	}
	if err := s.Store.Grant(r.Context(), r.PathValue("uuid"), req.Role, actor(r)); err != nil {
		storeErr(w, err)
		return
	}
	jsonWrite(w, http.StatusCreated, map[string]string{"uuid": r.PathValue("uuid"), "role": req.Role})
}

func (s *Server) revokeGrant(w http.ResponseWriter, r *http.Request) {
	if err := s.Store.RevokeGrant(r.Context(), r.PathValue("uuid"), r.PathValue("role"), actor(r)); err != nil {
		storeErr(w, err)
		return
	}
	jsonWrite(w, http.StatusOK, map[string]string{"uuid": r.PathValue("uuid"), "role": r.PathValue("role")})
}

func (s *Server) getSetting(w http.ResponseWriter, r *http.Request) {
	v, err := s.Store.GetSetting(r.Context(), r.PathValue("key"))
	if err != nil {
		storeErr(w, err)
		return
	}
	jsonWrite(w, http.StatusOK, map[string]string{"key": r.PathValue("key"), "value": v})
}

func (s *Server) setSetting(w http.ResponseWriter, r *http.Request) {
	req, ok := decode[struct {
		Value string `json:"value"`
	}](w, r)
	if !ok {
		return
	}
	if err := s.Store.SetSetting(r.Context(), r.PathValue("key"), req.Value, actor(r)); err != nil {
		storeErr(w, err)
		return
	}
	jsonWrite(w, http.StatusOK, map[string]string{"key": r.PathValue("key"), "value": req.Value})
}

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 1000 {
		limit = n
	}
	entries, err := s.Store.ListAudit(r.Context(), limit)
	if err != nil {
		storeErr(w, err)
		return
	}
	jsonWrite(w, http.StatusOK, entries)
}
