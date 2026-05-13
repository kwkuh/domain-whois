# whois-engine

Universal Domain Intelligence Engine — high-performance RDAP/WHOIS hybrid lookup for any TLD. Self-hosted, no paid API, no AI.

## Status: MVP V1

- [x] Single lookup (RDAP → WHOIS fallback)
- [x] Bulk lookup with worker pool
- [x] Availability detection
- [x] Lifecycle classification (ACTIVE / EXPIRED / REDEMPTION / PENDING_DELETE / AVAILABLE)
- [x] CSV / JSON / NDJSON export
- [x] IANA RDAP bootstrap (auto-coverage all modern gTLDs)
- [x] IANA WHOIS referral chain (universal ccTLD coverage)
- [x] DNSSEC detection
- [x] Bulk keyword × TLD availability check
- [ ] V2: cache, DNS layer, watch mode
- [ ] V3: diff engine, REST API, historical snapshots

## Build

```bash
go build -o bin/whoisctl ./cmd/whoisctl
```

## Usage

```bash
# Single lookup (human-readable)
whoisctl lookup example.com

# Single lookup (JSON)
whoisctl lookup example.com --json

# Force RDAP only or WHOIS only
whoisctl lookup example.id --rdap-only
whoisctl lookup example.id --whois-only

# Bulk from file (NDJSON to stdout, progress to stderr)
whoisctl bulk domains.txt --concurrency 64 > out.ndjson

# Bulk CSV
whoisctl bulk domains.txt --format csv > out.csv

# Bulk from stdin
cat domains.txt | whoisctl bulk - --format csv

# Keyword availability across TLDs
whoisctl check mybrand --tlds=com,io,ai,id,dev,co
```

## Architecture

```
                 ┌─────────────┐
  whoisctl ───▶  │  lookup.Engine
                 └──────┬──────┘
                        │
              ┌─────────▼──────────┐
              │ RDAP (IANA bootstrap)
              │ data.iana.org/rdap/dns.json
              └─────────┬──────────┘
                        │ fallback
              ┌─────────▼──────────┐
              │ WHOIS (whois.iana.org → referral)
              └─────────┬──────────┘
                        │
              ┌─────────▼──────────┐
              │ normalize.DomainInfo
              └────────────────────┘
```

**No hardcoded TLD map.** IANA RDAP bootstrap covers all delegated TLDs with RDAP support automatically. WHOIS fallback uses IANA's referral mechanism (`whois.iana.org` → authoritative server → registrar) so any ccTLD or niche TLD that publishes WHOIS works out of the box.

## Output schema

```json
{
  "domain": "example.com",
  "available": false,
  "registrar": "...",
  "created_at": "1995-08-14T04:00:00Z",
  "expires_at": "2026-08-13T04:00:00Z",
  "updated_at": "2026-01-16T...",
  "nameservers": ["a.iana-servers.net", "b.iana-servers.net"],
  "status": ["client delete prohibited"],
  "dnssec": true,
  "source": "rdap",
  "lookup_ms": 312
}
```

## Project layout

```
whois-engine/
├── cmd/whoisctl/        # CLI entrypoint
└── internal/
    ├── rdap/            # RDAP client + IANA bootstrap
    ├── whois/           # WHOIS TCP/43 + parser + referral chain
    ├── normalize/       # unified DomainInfo + lifecycle
    ├── lookup/          # orchestrator
    └── bulk/            # worker pool + CSV/JSON/NDJSON writer
```
