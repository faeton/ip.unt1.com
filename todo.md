# todo

Roadmap for ip.unt1.com. Tracked here so the next session has the same picture.

## Status legend

- `[ ]` planned
- `[~]` in progress
- `[x]` done
- `[-]` deferred (with reason)

---

## v1 (shipped)

- [x] Go HTTP service replacing static Caddy block
- [x] Topology: CF orange-cloud → Caddy on de1 → 127.0.0.1:8080 (systemd hardened unit)
- [x] Routes: `/`, `/json`, `/vpn`, `/headers`, `/all`, `/ua`, `/reverse`, `/health`
- [x] Content negotiation: plain for curl, HTML for browsers
- [x] ASN resolution via Team Cymru DNS whois (no MaxMind license)
- [x] VPN detection from official server lists: Mullvad, NordVPN, iVPN, AirVPN, Tor exits (~14k IPs total)
- [x] Datacenter-ASN fallback for ExpressVPN/ProtonVPN/Surfshark/PIA etc.
- [x] WebRTC leak check on the browser page (parsed by SDP grammar, classifies public/private/mDNS)
- [x] CF Colo tile (parsed from CF-Ray suffix)
- [x] Public GitHub repo (faeton/ip.unt1.com, MIT)

---

## v1.1 — cheap wins (this batch)

- [ ] **`/trace` endpoint** — Cloudflare-style key=value plain text. Universal, scriptable.
- [ ] **Arbitrary IP lookup** — `/ip/{addr}` path + `?ip=addr` query on `/json`, `/vpn`, `/all`, `/trace`. Reuses ASN/VPN/reverse for any IP.
- [ ] **Cymru: extract more fields** — RIR, allocation date, announced prefix, RIR-registered country (Cymru returns these; we currently throw them away).
- [ ] **Sec-CH-UA parsing** — Show "Chrome 142 on macOS" instead of just the raw UA string. Server-side parse.
- [ ] **iCloud Private Relay detection** — Apple's published egress range CSV (`https://mask-api.icloud.com/egress-ip-ranges.csv`). CIDR matcher in vpn.go. Major source of "IP ≠ user location" today.
- [ ] **Output format negotiation** — `?format=yaml|hosts` on `/json`. Two formats is enough to demonstrate the pattern.
- [-] **Peer port** — defer. Cloudflare doesn't pass the client source port by default; needs a CF Transform Rule adding e.g. `CF-Connecting-Port`. Without it we'd be reporting the CF→Caddy edge port, which is misleading.
- [-] **TLS + HTTP version tiles** — defer. Same reason: CF terminates TLS at the edge and doesn't forward client-side TLS version / HTTP version by default. Needs a CF Transform Rule (or Worker) to surface `cf.tls_version` and `cf.http_version`.

---

## v1.2 — medium effort

- [ ] **City / region / postal / lat-lng / timezone** via MaxMind GeoLite2-City DB
  - Free with signup; ~70MB; 30-day update cron
  - Massive payoff — currently we only have country-level
  - Bundled lookup in-process via `oschwald/maxminddb-golang`
- [ ] **Mobile / hosting / business / residential classification**
  - GeoLite2-ASN includes a network-type field
  - Or synthesize from ASN org name + datacenter list
- [ ] **DNS leak test**
  - Wildcard DNS: `*.dnstest.unt1.com` pointing to a small UDP listener that logs resolver IPs
  - Page fetches a random subdomain via `<img>` or `fetch`, then queries `/dns-leak/<token>` to retrieve the resolver(s) we saw
  - True diagnostic, on par with dnsleaktest.com
- [~] **IPv4 + IPv6 dual display**
  - [-] Separate `ip4.` / `ip6.` hostnames — declined, no new subdomains.
  - [x] Derive instead of measure: relay records now carry the exit's
    hostname/city/country and both address families, so an IPv6 arrival gets
    its PoP and the relay's IPv4 without a second hostname (`pop*` fields).
  - [x] `country_source` makes the v4/v6 country disagreement legible.
  - [ ] Remaining gap: for non-VPN clients the other family is still
    unknowable from one hostname. Options are a v4-only host, a v4-only
    third party for address discovery only (`ipv4.icanhazip.com` is v4-only
    and CORS-open), or a client that pins the family itself.
- [ ] **DNSBL check** — Spamhaus ZEN, SORBS, etc. (DNS queries)
- [ ] **Clock skew** — client posts `Date.now()`, server compares; surface drift
- [ ] **Cloudflare WARP detection** — needs published egress list (or Worker hint via `cf.warp_proxy`); CF doesn't make this clean for non-Worker origins

---

## v1.3 — heavier

- [ ] **TLS fingerprint (JA4)** — needs custom listener bypassing Caddy or a tightly-configured `tls_connection_policies` that exposes handshake details
- [ ] **HTTP/2 fingerprint (Akamai)** — same architectural concern
- [ ] **Reverse-connect probe** — server attempts back-connection to detect open ports / NAT type. Mild abuse-vector concern; rate-limit
- [ ] **Anycast detection** — measure CF colo variance per-request from the same client over time
- [ ] **Speed test / RTT graph via WebSocket** — niche, bandwidth burden on de1

---

## What we deliberately won't build

- Canvas / WebGL / font / audio fingerprinting — privacy-aggressive, browserleaks.com already does this exhaustively
- Full bandwidth speed test — wrong scope, would dominate de1's bandwidth
- Persistent visit history / cookies — privacy concern, no real benefit
- Paid-tier features (premium GeoIP, abuse contact databases, etc.) — keeps the project free + self-hosted

---

## Operational notes

- Caddy backup before swap: `/etc/caddy/Caddyfile.bak.pre-go-swap-20260506T201030Z` on on1
- Re-deploy: `make deploy` (cross-compile, scp, systemctl restart)
- VPN list refresh: every 6h, on startup; logged at INFO level
- ASN cache TTL: 12h (in-process, atomic-swap)
- systemd unit hardening: DynamicUser, ProtectSystem=strict, MemoryDenyWriteExecute, full SystemCallFilter

## Performance / memory

- [x] iCloud Private Relay range list (~288k /27-/31 prefixes) is no longer
  linear-scanned. Prefixes are converted to ranges, sorted and merged at
  refresh time: 287,807 prefixes collapse to 6,873 disjoint ranges, and
  lookup is a binary search. Benchmarked 974,000 ns → 89 ns.
- The CIDR probe is also skipped entirely when an exact server-list hit has
  already classified the address.
- Memory: bumped systemd limits to MemoryHigh=256M / MemoryMax=512M after first deploy hit the previous 128M ceiling.

## Known precision tradeoffs

- [x] AS15169 (Google) and the other hyperscalers now report `hosting: true`
  with `vpn: false`, and render as "Hosting" rather than "VPN".
- Surfshark / ExpressVPN / ProtonVPN: caught via ASN only (they don't publish IPs cleanly). False negative possible if they rent from an ASN we don't flag.
