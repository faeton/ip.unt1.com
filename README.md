# ip.unt1.com

Tiny IP-echo + VPN/proxy detection service. Curl-friendly, browser-friendly,
single static Go binary. Currently deployed to `on1` behind Caddy + Cloudflare.

## Surface

| Path        | curl                           | browser (Accept: text/html)        |
|-------------|--------------------------------|------------------------------------|
| `/`         | plain IP, trailing newline     | full diagnostics page              |
| `/json`     | full JSON (IP, ASN, VPN, …)    | same                               |
| `/vpn`      | JSON: `{vpn, tor, provider, reasons, source}` | same             |
| `/headers`  | selected request headers       | same                               |
| `/all`      | all fields, plain text         | same                               |
| `/ua`       | User-Agent only                | same                               |
| `/reverse`  | reverse-DNS PTR or `-`         | same                               |
| `/health`   | `ok`                           | same                               |

## VPN detection

Combines published server-IP lists with ASN-level datacenter detection:

- **Mullvad** — `https://api.mullvad.net/www/relays/all/`
- **NordVPN** — `https://api.nordvpn.com/v1/servers?limit=10000`
- **iVPN** — `https://api.ivpn.net/v5/servers.json`
- **AirVPN** — `https://airvpn.org/api/status/`
- **Tor exits** — `https://check.torproject.org/torbulkexitlist`
- **Datacenter ASNs** — curated list in `vpn.go`. Catches ExpressVPN,
  ProtonVPN, Surfshark, PIA, CyberGhost, etc., which don't publish IPs
  but rent from a small set of hosters (M247, Datapacket, Choopa, …).

Lists refresh on startup and every 6 hours. ASN lookups use Team Cymru's
public DNS whois (`origin.asn.cymru.com`) with a 12h in-process cache.

## Topology

```
client → Cloudflare (orange-cloud) → Caddy on on1 → 127.0.0.1:8080 (this binary)
```

`CF-Connecting-IP` and `CF-IPCountry` ride through; the binary trusts them
when `-trust-cf=true` (the default).

## Local dev

```sh
make dev          # offline mode — skips VPN provider fetches
curl localhost:8080/json
curl -H 'Accept: text/html' localhost:8080/ | less
```

## Deploy to on1

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

Earlier draft was a Worker. Pivoted to Go so the same binary runs on `on1`
behind the existing Caddy + Cloudflare topology, with no additional
runtime dependencies. CF Workers would have given us `request.cf` (rich
ASN/country/colo metadata) for free, but tied us to one host; the Cymru
DNS lookup gives us ASN data on any host.

## License

MIT.
