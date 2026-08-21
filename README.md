# ip.unt1.com

Tiny IP-echo + VPN/proxy detection service. Curl-friendly, browser-friendly,
single static Go binary. Currently deployed to `de1` behind Caddy + Cloudflare.

## Surface

| Path        | curl                           | browser (Accept: text/html)        |
|-------------|--------------------------------|------------------------------------|
| `/`         | plain IP, trailing newline     | full diagnostics page              |
| `/json`     | full JSON (IP, ASN, VPN, …)    | same                               |
| `/country`  | `IP COUNTRY`, JSON with `Accept: application/json` | same              |
| `/vpn`      | JSON: `{vpn, tor, provider, reasons, source}` | same             |
| `/headers`  | selected request headers       | same                               |
| `/all`      | all fields, plain text         | same                               |
| `/ua`       | User-Agent only                | same                               |
| `/reverse`  | reverse-DNS PTR or `-`         | same                               |
| `/health`   | `ok` (liveness)                | same                               |
| `/ready`    | `ready`, or 503 until the detection lists load | same            |

## Address family and exit identity

A single hostname carries both A and AAAA records, so the client picks the
family at connect time and we only ever see the one it chose. There is no way
to report the other side from here — that needs a family-specific hostname, or
a client that can pin the family itself (`NWProtocolIP.Options.version` in
Network.framework; `URLSession` has no equivalent).

What we *can* do is stop the IPv6 path from being the poorer answer. Provider
feeds publish full relay records, so when an address belongs to a known exit
we report it directly instead of depending on reverse DNS:

- `pop` / `pop_city` / `pop_country` / `pop_host` — the exit's identity, from
  the operator's own record. Most relay IPv6 addresses have no PTR, which is
  why the IPv6 view used to lose the PoP entirely.
- `pop_v4` / `pop_v6` — that relay's endpoints in both families. It is the
  relay's other address, not necessarily yours.
- `country_source` — `cf` (Cloudflare edge, and therefore specific to the path
  this request took), `rir` (registration for the announced prefix), or
  `relay` (the operator's record). The IPv4 and IPv6 answers for one client
  routinely disagree; this says which one you are looking at.

Pairing is complete for Mullvad and AirVPN, partial for NordVPN (`ipv6_station`
is usually empty), and unavailable for iVPN (no published IPv6 egress).

## VPN detection

Combines published server-IP lists with ASN-level datacenter detection:

- **Mullvad** — `https://api.mullvad.net/www/relays/all/`
- **NordVPN** — `https://api.nordvpn.com/v1/servers?limit=10000`
- **iVPN** — `https://api.ivpn.net/v5/servers.json`
- **AirVPN** — `https://airvpn.org/api/status/`
- **Tor exits** — `https://check.torproject.org/torbulkexitlist`
- **Datacenter ASNs** — curated list in `vpn.go`, split into two tiers.
  *VPN-rental* hosters (M247, Datapacket, Choopa, …) catch ExpressVPN,
  ProtonVPN, Surfshark, PIA and CyberGhost, which don't publish addresses;
  those report `vpn: true`. *Hyperscalers* (AWS, GCP, Azure, Cloudflare,
  Google) report `hosting: true` with `vpn: false` — they're datacenters, but
  calling them VPNs buried real detections under ordinary cloud traffic.

Lists refresh on startup and every 6 hours. A source that fails or returns an
empty payload keeps its previous data rather than disappearing from the
snapshot, and `vpn.ready` / `/ready` report whether anything has loaded at all
— before the first refresh every address would otherwise look clean.

ASN lookups use Team Cymru's public DNS whois (`origin.asn.cymru.com`) with a
bounded 12h cache; failures are cached for 60s only, so a DNS blip doesn't
mask an address for half a day. WHOIS runs only for VPN-rental ASNs, is keyed
by announced prefix, and is capped at 4 concurrent port-43 connections.

Third-party lookups (`/ip/{addr}`, `?ip=`) are rate-limited per requester;
lookups of your own address are not. Malformed or non-routable targets return
400 rather than silently echoing your own address.

## Topology

```
client → Cloudflare (orange-cloud) → Caddy on de1 → 127.0.0.1:8080 (this binary)
```

`CF-Connecting-IP` and `CF-IPCountry` ride through; the binary trusts them
when `-trust-cf=true` (the default).

## Local dev

```sh
make dev          # offline mode — skips VPN provider fetches
curl localhost:8080/json
curl -H 'Accept: text/html' localhost:8080/ | less
```

## Deploy to de1

```sh
make linux           # cross-compile to dist/ipunt1-linux-amd64
make install-systemd # one-time: install the service unit
make deploy          # scp + systemctl restart
make reload-caddy    # after replacing the ip.unt1.com block
```

The systemd unit (`deploy/ipunt1.service`) runs the binary as a `DynamicUser`
on `127.0.0.1:8080`, with `MemoryDenyWriteExecute`, `ProtectSystem=strict`,
and other modern hardening flags enabled.

## Why Go (not a Cloudflare Worker)

Earlier draft was a Worker. Pivoted to Go so the same binary runs on `de1`
behind the existing Caddy + Cloudflare topology, with no additional
runtime dependencies. CF Workers would have given us `request.cf` (rich
ASN/country/colo metadata) for free, but tied us to one host; the Cymru
DNS lookup gives us ASN data on any host.

## License

MIT.
