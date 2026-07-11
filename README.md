# tachyne-access

> tachyne is an unofficial fan project, not affiliated with Mojang,
> Microsoft, or Minecraft's developer/publisher in any way. See the
> Disclaimer at the bottom.

## Project status

**Work in progress.** tachyne is young and moving fast: a full survival game
runs today, but expect rough edges, missing vanilla features, and breaking
changes between updates. **Bug reports are genuinely useful** — please open a
GitHub Issue with your client version/edition and what you saw. Contributions
are welcome too: see [CONTRIBUTING.md](CONTRIBUTING.md).

**Just want to run a server?** The [quickstart repo](https://github.com/tachyne/tachyne)
brings up the whole stack in one command — Docker Compose or Kubernetes,
classic infinite survival by default, real-Cape-Town earth mode as a variant.

**What's implemented?** Gameplay features live in the world engine, not the
gateways — see [tachyne-world's feature matrix](https://github.com/tachyne/tachyne-world#what-to-expect-vanilla-parity-at-a-glance)
for what to expect (implemented / partial / missing) as a player.




Authorization + identity policy for the tachyne Minecraft cluster: whitelist,
blacklist/bans, roles/permissions, a firewall-style IP ACL, principal
directory, audit log. Two enforcement points call this one policy store:
**gateways** call `POST /v1/check` on every login (identity: name/UUID/XUID),
and **tachyne-ingress** calls `POST /v1/check-ip` at the network edge (bare
source IP, before any login). Gateways enforce **fail closed**: no verdict, no
entry. Worlds never call this service; sessions arrive there with
gateway-stamped claims.

Why two points: the ingress is L4 and can't see player identity (Bedrock's
login is encrypted inside RakNet), so IP-level policy is enforced there while
identity policy stays at the gateways where a decrypted identity exists.

Deliberately NOT here: authentication mechanics (Mojang/Xbox handshakes are
protocol work → gateways), and game state (world pods). This service decides
*policy*; it never speaks Minecraft protocol.

**Status: gateway integration LIVE (2026-07-06)** — Postgres-backed policy
engine + HTTP API, deployed; both gateways (`tachyne-gw-java-770`/`-776`)
call `/v1/check` on every login (name + vanilla offline UUID + real client IP
via ingress's PROXY v1), cache verdicts 30 s, and **fail closed** (verified
by scaling this service to 0). Whitelist/ban/version-gate paths verified.
`whitelist_enforced` is still `false` — flip via
`PUT /v1/settings/whitelist_enforced` to lock the door to the whitelist.
Remaining M2 scope: NATS revocation events so bans kick LIVE sessions
(today a ban takes effect on next login).

## API (bearer token; `X-Actor` header names the audit actor)

```
POST   /v1/check                              {name,uuid,ip,edition} → {allow,reason,roles}
POST   /v1/check-ip                           {ip} → {allow,reason}   (the ingress edge check)
GET    /v1/whitelist                          POST {kind:uuid|name, value}   DELETE ?kind=&value=
GET    /v1/bans[?all=true]                    POST {kind:uuid|name|ip, value, reason, expires_at?}
DELETE /v1/bans/{id}                          (revoke)
GET    /v1/ip-rules                           POST {priority,cidr,action:allow|deny,note}
DELETE /v1/ip-rules/{id}                       (remove)
GET    /v1/roles                              PUT /v1/roles/{name} {permissions:[...]}
GET    /v1/principals?q=                      (directory, populated by checks)
GET    /v1/principals/{uuid}/roles            POST {role}   DELETE /v1/principals/{uuid}/roles/{role}
GET    /v1/settings/{key}                     PUT {value}   (whitelist_enforced, ip_default: "allow"/"deny")
GET    /v1/audit?limit=
GET    /healthz                               (no auth)
```

Identity precedence (`/v1/check`): active ban > whitelist; role holders bypass
the whitelist; open server (whitelist_enforced=false) allows anyone not banned.

**IP ACL (`/v1/check-ip`) — a firewall, order matters.** Rules are evaluated by
ascending `priority` (then id) and the **FIRST match wins**, so an
`allow 192.168.0.0/24` at priority 10 placed before a `deny 0.0.0.0/0` at
priority 100 admits the LAN and blocks everything else. Active ip-bans are
checked first and always deny (a ban outranks the ACL); `ip_default`
(allow|deny, default `allow`) is the verdict when nothing matches. The ingress
caches these verdicts per pod (denies for 5 min) so repeat offenders don't
hammer this service.

## Storage

CNPG Postgres (`pg-rw.databases.svc:5432`), database `tachyne`, schema
`access` owned by role `tachyne_access` (search_path set on the role).
Secrets: `tachyne-access-pg-cred` (username/password),
`tachyne-access-token` (API bearer token) — both in namespace `tachyne`.
Schema is applied idempotently at startup.

## Build / test / deploy

```bash
go test ./...
kubectl apply -f deploy/
# admin access:
kubectl port-forward svc/tachyne-access 8080:8080
TOKEN=$(kubectl get secret tachyne-access-token -o jsonpath='{.data.token}' | base64 -d)
curl -H "Authorization: Bearer $TOKEN" localhost:8080/v1/whitelist
```

## Deployment

`Dockerfile` builds a static Go binary into a minimal image. `deploy/` holds
working Kubernetes manifests (the ones this project actually runs) — treat
them as examples: substitute your own image registry, hostnames, namespaces
and secrets before applying them to your cluster.

## Credits

- **[jackc/pgx](https://github.com/jackc/pgx)** — PostgreSQL driver (MIT).

## Development transparency

tachyne is built by its maintainer working with an AI coding agent
(Anthropic's Claude): substantial portions of the implementation were written
by the model under human direction, and every change is reviewed, tested and
deployed by the maintainer. The project's engineering discipline is designed
for exactly this workflow — byte-oracle tests pin the wire format, full test
suites gate every image build, and real-client verification signs off
gameplay. Disclosed here for transparency; judge the code on its behavior.

## License

Licensed under the **Apache License, Version 2.0** — see [LICENSE](LICENSE)
and [NOTICE](NOTICE). Note §6: the license grants no rights to the tachyne
name or any trademarks.

## Disclaimer

tachyne is an unofficial, independent project. It is **not** affiliated with,
endorsed, sponsored, or approved by Mojang Studios, Mojang Synergies AB,
Microsoft Corporation, or any of their subsidiaries — the developer and
publisher of Minecraft have no involvement with this project. "Minecraft" is
a trademark of Mojang Synergies AB. This project contains no Minecraft game
code; all game behavior is independently reimplemented, and data tables are
built from openly licensed community datasets (see Credits).
