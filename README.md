# whois-engine

Universal Domain Intelligence Engine — high-performance RDAP/WHOIS hybrid lookup for any TLD. Self-hosted, no paid API, no AI.

## Features

**V1 — core engine**
- Single + bulk lookup (RDAP → WHOIS fallback)
- IANA RDAP bootstrap → automatic coverage for every TLD with RDAP support
- IANA WHOIS referral chain → universal ccTLD coverage (no hardcoded TLD map)
- Availability + lifecycle detection (ACTIVE / EXPIRED / REDEMPTION / PENDING_DELETE / AVAILABLE)
- DNSSEC detection
- CSV / JSON / NDJSON export
- Worker-pool concurrency

**V2 — intelligence layer**
- File-based cache with adaptive TTL (short for availability, long for stable)
- DNS probe (A/AAAA/MX/NS/CNAME/TXT) with NS provider + hosting hint detection
- Expiry monitoring with WARN / CRITICAL thresholds
- Diff engine: compare two NDJSON snapshots
- Watch mode: periodic re-scan with change detection
- TLD intelligence (`tld-info`)
- Cache management (`cache clear|purge|path`)

**V3 — roadmap**
- REST API server
- Historical snapshots (SQLite/PostgreSQL)
- Domain categorization (regex + keyword)
- Rate limiter per-registry
- Webhook on watch changes

## Build

```bash
go build -o bin/whoisctl ./cmd/whoisctl
```

## Usage

### Single lookup
```bash
whoisctl lookup example.com
whoisctl lookup example.com --json
whoisctl lookup example.com --dns          # include DNS probe
whoisctl lookup example.id --rdap-only      # skip WHOIS fallback
whoisctl lookup example.id --whois-only     # skip RDAP
whoisctl lookup example.com --no-cache
```

### Bulk lookup
```bash
whoisctl bulk domains.txt --format csv --concurrency 64 > out.csv
whoisctl bulk domains.txt --format ndjson > snapshot.ndjson
cat domains.txt | whoisctl bulk - --format json
whoisctl bulk domains.txt --dns             # include DNS for each
```

### Keyword × TLD availability
```bash
whoisctl check mybrand --tlds=com,io,ai,id,dev,co,xyz
```

### Expiry monitoring
```bash
whoisctl expiry portfolio.txt --warn-days 30 --critical-days 7
whoisctl expiry portfolio.txt --format csv > expiry-report.csv
whoisctl expiry portfolio.txt --format json
```

### Diff two snapshots
```bash
whoisctl diff yesterday.ndjson today.ndjson
whoisctl diff before.ndjson after.ndjson --format json
```

### Watch mode (continuous monitoring)
```bash
whoisctl watch portfolio.txt --interval 30m
whoisctl watch portfolio.txt --once         # single scan, useful for cron
```

### TLD intelligence
```bash
whoisctl tld-info ai
# TLD:           .ai
# RDAP support:  true
# RDAP endpoint: https://rdap.identitydigital.services/rdap
```

### Cache management
```bash
whoisctl cache path     # show cache directory
whoisctl cache purge    # remove expired entries
whoisctl cache clear    # remove all cached lookups
```

## Architecture

```
                 ┌─────────────┐
  whoisctl ───▶  │ lookup.Engine
                 └──────┬──────┘
                        │
        ┌───────────────┼───────────────────┐
        │               │                   │
   ┌────▼─────┐  ┌──────▼────────┐  ┌──────▼─────┐
   │ cache    │  │ RDAP          │  │ DNS probe  │
   │ (file)   │  │ IANA bootstrap│  │ NS hint    │
   └──────────┘  └──────┬────────┘  └────────────┘
                        │ fallback
                 ┌──────▼────────┐
                 │ WHOIS         │
                 │ whois.iana.org│
                 │ → referral    │
                 └──────┬────────┘
                        │
                 ┌──────▼────────┐
                 │ normalize     │
                 │ DomainInfo    │
                 └───────────────┘
```

**No hardcoded TLD map.** IANA RDAP bootstrap (`data.iana.org/rdap/dns.json`) covers all delegated TLDs with RDAP support automatically. WHOIS fallback uses IANA's referral mechanism (`whois.iana.org` → authoritative server → registrar) so any ccTLD or niche TLD that publishes WHOIS works out of the box.

## Output schema

```json
{
  "domain": "example.com",
  "available": false,
  "registrar": "RESERVED-Internet Assigned Numbers Authority",
  "created_at": "1995-08-14T04:00:00Z",
  "expires_at": "2026-08-13T04:00:00Z",
  "updated_at": "2026-01-16T...",
  "nameservers": ["a.iana-servers.net", "b.iana-servers.net"],
  "status": ["client delete prohibited"],
  "dnssec": true,
  "source": "rdap",
  "lookup_ms": 312,
  "dns": {
    "a": ["..."],
    "ns": ["..."],
    "ns_provider": "Cloudflare",
    "hosting_hint": "Cloudflare proxy",
    "has_dns": true
  }
}
```

## Project layout

```
whois-engine/
├── cmd/whoisctl/        CLI entrypoint
└── internal/
    ├── rdap/            RDAP client + IANA bootstrap
    ├── whois/           WHOIS TCP/43 + parser + referral chain
    ├── dnsx/            DNS probe + NS provider/hosting detection
    ├── normalize/       unified DomainInfo + lifecycle
    ├── cache/           file-based cache with adaptive TTL
    ├── lookup/          orchestrator
    ├── bulk/            worker pool + writers (CSV/JSON/NDJSON)
    ├── diff/            snapshot comparison engine
    └── watch/           periodic polling + change detection
```

## License

MIT
