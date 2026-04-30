# Observer — Observable Enrichment Tool
## Claude Code Build Specification

---

## Overview

Build a cross-platform observable enrichment tool called **Observer** in Go.
It consists of two interfaces sharing a single core library:

1. **CLI** — a native binary for Windows/macOS/Linux
2. **Web** — a self-hosted HTTP server with REST API and a browser-based UI

The tool accepts an observable (IP, domain, URL, or file hash), fans out to multiple
enrichment sources in parallel, and returns normalized, structured results.

---

## Project Structure

```
observer/
├── cmd/
│   ├── observer/        # CLI entrypoint (main.go)
│   └── server/          # Web server entrypoint (main.go)
├── internal/
│   ├── detect/          # Observable type detection
│   ├── enricher/        # Enricher interface + all source implementations
│   │   ├── enricher.go  # Interface definition
│   │   ├── shodan.go
│   │   ├── virustotal.go
│   │   ├── abuseipdb.go
│   │   ├── whois.go
│   │   ├── otx.go
│   │   ├── ipinfo.go
│   │   └── greynoise.go
│   ├── model/           # Shared data structures (Result, Finding, ObservableType)
│   ├── runner/          # Parallel fan-out logic
│   └── render/          # Output renderers: table, JSON, Markdown, CSV
├── web/
│   ├── handler.go       # HTTP handlers (thin wrapper around runner)
│   ├── middleware.go    # API key auth middleware
│   └── static/
│       └── index.html   # Single-file SPA (vanilla HTML/CSS/JS, no framework)
├── config/
│   └── config.go        # Config loading from .env / environment variables
├── .env.example
├── go.mod
├── go.sum
├── Makefile             # Build targets: build-cli, build-server, build-all, cross-compile
└── README.md
```

---

## Language & Runtime

- **Language:** Go 1.22+
- **HTTP framework:** `net/http` stdlib only for the server (no Gin/Echo — keep deps minimal)
- **CLI framework:** `github.com/spf13/cobra` for subcommands and flags
- **Terminal output:** `github.com/charmbracelet/lipgloss` + `github.com/charmbracelet/bubbletea`
  for colored, formatted table output in the CLI. Fall back to plain text if not a TTY.
- **Config:** `github.com/joho/godotenv` to load `.env`; all values also readable from
  environment variables (useful for container deployments)
- **HTTP client:** stdlib `net/http` with a shared client (timeout: 10s per request)

---

## Observable Types & Auto-Detection

The `detect` package must correctly identify the observable type from a raw string input:

| Type | Detection Logic |
|---|---|
| `IPv4` | Regex: valid IPv4 address |
| `IPv6` | Regex: valid IPv6 address |
| `Domain` | Regex: valid FQDN, no path or scheme |
| `URL` | Has scheme (`http://`, `https://`, `ftp://`) |
| `MD5` | 32 hex chars |
| `SHA1` | 40 hex chars |
| `SHA256` | 64 hex chars |

Unknown types must return a typed error that both CLI and web handle gracefully.

---

## Enricher Interface

Every source implements this interface in `internal/enricher/enricher.go`:

```go
type Enricher interface {
    Name() string
    SupportedTypes() []detect.ObservableType
    Enrich(ctx context.Context, observable string, oType detect.ObservableType) (*model.SourceResult, error)
}
```

Each enricher is responsible for:
- Returning `ErrUnsupportedType` if the observable type is not in `SupportedTypes()`
- Returning a partial result with `Status: "error"` and an `ErrorMessage` field on API failure
- Returning a partial result with `Status: "rate_limited"` on HTTP 429

---

## Data Model (`internal/model`)

```go
type EnrichmentResult struct {
    Observable  string                    `json:"observable"`
    Type        string                    `json:"type"`
    Timestamp   time.Time                 `json:"timestamp"`
    Sources     map[string]*SourceResult  `json:"sources"`
}

type SourceResult struct {
    Name         string         `json:"name"`
    Status       string         `json:"status"` // "ok", "error", "rate_limited", "unsupported"
    ErrorMessage string         `json:"error_message,omitempty"`
    Data         map[string]any `json:"data"`
    RawURL       string         `json:"raw_url,omitempty"` // link to source for UI
}
```

The `Data` map uses consistent keys across sources where possible (see Source Specs below).

---

## Sources & Field Mapping

### Source Routing by Observable Type

| Source | IP | Domain | URL | Hash |
|---|---|---|---|---|
| Shodan | ✅ | ✅ (resolve first) | ❌ | ❌ |
| VirusTotal | ✅ | ✅ | ✅ | ✅ |
| AbuseIPDB | ✅ | ❌ | ❌ | ❌ |
| WHOIS | ✅ (rDNS) | ✅ | ✅ (extract domain) | ❌ |
| AlienVault OTX | ✅ | ✅ | ✅ | ✅ |
| ipinfo.io | ✅ | ✅ (resolve first) | ❌ | ❌ |
| GreyNoise | ✅ | ❌ | ❌ | ❌ |

### Shodan (`api.shodan.io`)
- **API:** `GET /shodan/host/{ip}` (free API key required)
- **Key fields to extract:**
  - `ip_str`, `org`, `isp`, `asn`
  - `country_name`, `city`, `region_code`
  - `ports` (array of open ports)
  - `hostnames`
  - `tags` (look for: `vpn`, `tor`, `cloud`, `cdn`, `honeypot`)
  - `vulns` (CVE keys if present)
  - `last_update`
- **Domain handling:** Resolve to IP first using `net.LookupHost`, then query that IP.

### VirusTotal (`www.virustotal.com/api/v3`)
- **Free API key required**
- **IP:** `GET /ip_addresses/{ip}`
- **Domain:** `GET /domains/{domain}`
- **URL:** `POST /urls` to submit, then `GET /analyses/{id}` (handle async)
  OR use `GET /urls/{base64_encoded_url}` for cached results first — prefer cached.
- **Hash:** `GET /files/{hash}`
- **Key fields:**
  - `last_analysis_stats` → `malicious`, `suspicious`, `harmless`, `undetected`
  - `last_analysis_date`
  - `reputation`
  - `tags`
  - `categories` (domain/URL)
  - For files: `meaningful_name`, `type_description`, `size`, `names`

### AbuseIPDB (`api.abuseipdb.com/api/v2`)
- **Free API key required**
- **Endpoint:** `GET /check?ipAddress={ip}&maxAgeInDays=90&verbose`
- **Key fields:**
  - `abuseConfidenceScore`
  - `totalReports`
  - `numDistinctUsers`
  - `lastReportedAt`
  - `usageType` (e.g., "Data Center/Web Hosting", "VPN", "Tor Exit Node")
  - `isp`, `domain`, `countryCode`
  - `isWhitelisted`

### WHOIS
- **Library:** Use `github.com/likexian/whois` + `github.com/likexian/whois-parser`
  (pure Go, no external binary dependency)
- **Key fields:**
  - `registrar`
  - `created_date`, `updated_date`, `expiration_date`
  - `name_servers`
  - `status`
  - `registrant_organization` (often redacted — return "Redacted" if so)
- **For IP:** Perform rDNS lookup (`net.LookupAddr`) and return PTR records.
  Also attempt WHOIS on the IP for ASN/org info.

### AlienVault OTX (`otx.alienvault.com/api/v1`)
- **Free API key required**
- **Endpoints:**
  - IP: `GET /indicators/IPv4/{ip}/general` + `/reputation`
  - Domain: `GET /indicators/domain/{domain}/general`
  - URL: `GET /indicators/url/{url}/general`
  - Hash: `GET /indicators/file/{hash}/general`
- **Key fields:**
  - `pulse_info.count` (number of pulses referencing this indicator)
  - `pulse_info.pulses` → extract `name`, `tags`, `malware_families` from first 5 pulses
  - `reputation` (for IPs)
  - `type_title`

### ipinfo.io (`ipinfo.io`)
- **Free tier: 50,000 requests/month — no key required for basic, key for privacy object**
- **Endpoint:** `GET /{ip}/json` or `GET /{ip}` with `Authorization: Bearer {token}`
- **Key fields:**
  - `ip`, `hostname`, `city`, `region`, `country`
  - `org` (ASN + org name)
  - `privacy` object (requires token):
    - `vpn` (bool), `proxy` (bool), `tor` (bool), `relay` (bool), `hosting` (bool)
    - `service` (name of VPN service if identified)
- **This is the primary source for VPN/TOR/proxy classification.** If no token configured,
  return basic geo only and note privacy data unavailable.

### GreyNoise (`api.greynoise.io/v3`)
- **Free community API key required**
- **Endpoint:** `GET /community/{ip}` (community tier)
- **Key fields:**
  - `noise` (bool — is this IP observed scanning the internet?)
  - `riot` (bool — is this a known benign service like Google/AWS?)
  - `classification` ("malicious", "benign", "unknown")
  - `name` (if RIOT — e.g., "Google LLC")
  - `link` (URL to GreyNoise UI for this IP)
- **Only supports IPv4** — return `Status: "unsupported"` for all other types.

---

## Runner (`internal/runner`)

```go
func Run(ctx context.Context, observable string, cfg *config.Config) (*model.EnrichmentResult, error)
```

- Auto-detect observable type
- Build list of enrichers that support this type AND have an API key configured
- Fan out all enricher calls concurrently using `sync.WaitGroup` or `errgroup`
- Use a per-enricher context with 15s timeout
- Collect all results; partial failures are included in output with `Status: "error"`
- Never fail the whole run because one source failed
- Return `EnrichmentResult` with all source results

---

## CLI (`cmd/observer`)

### Commands

```
observer <observable>                    # enrich a single observable, pretty table output
observer <observable> --format json      # JSON output
observer <observable> --format markdown  # Markdown output
observer <observable> --format csv       # CSV output
observer <observable> --sources vt,shodan  # run subset of sources
observer bulk <file>                     # enrich all observables in a file (one per line)
observer bulk --stdin                    # read from stdin (pipe-friendly)
observer version                         # print version
observer config                          # validate config and show which sources are active
```

### Output — Pretty Table (default)

Use `lipgloss` for colors. Group output into sections:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  OBSERVER  │  1.2.3.4  (IPv4)  │  2025-04-29 14:32
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

CLASSIFICATION
  VPN          YES  (ipinfo: ExpressVPN)
  TOR          No
  Proxy        No
  Hosting/DC   YES  (Hetzner Online GmbH)
  GN Noise     YES — malicious (scanning observed)
  GN RIOT      No

GEO & NETWORK
  Location     Frankfurt, DE  (Hesse)
  ASN/Org      AS24940 — Hetzner Online GmbH
  Ports        22, 80, 443, 8080
  Hostnames    mail.example.com
  PTR          mail.example.com

REPUTATION
  VirusTotal   4 / 94 engines  [last: 2025-04-01]
  AbuseIPDB    87% confidence  │  142 reports  │  last: 2025-04-28
  OTX          8 pulses  →  Malware C2, Phishing, Scanner

WHOIS (IP)
  Registrar    RIPE NCC
  Org          Hetzner Online GmbH

SOURCES  ✅ shodan  ✅ virustotal  ✅ abuseipdb  ✅ whois  ✅ otx  ✅ ipinfo  ⚠️ greynoise [rate limited]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

- Green = benign, Red = malicious, Yellow = suspicious, Grey = unknown
- Source status line at the bottom: ✅ ok, ⚠️ rate_limited, ❌ error, — unsupported
- If not a TTY (piped), strip all color/formatting automatically

### Output — Markdown

Produce clean Markdown tables suitable for pasting into DFIR-IRIS case notes or a report.
No ANSI codes. Include a header with the observable and timestamp.

### Output — JSON

Pretty-printed JSON matching the `EnrichmentResult` model exactly. Machine-readable.

### Output — CSV

For bulk use. Columns: `observable,type,source,field,value`. Flat format.

### Bulk Mode

- Read newline-delimited file or stdin
- Skip blank lines and `#` comments
- Process concurrently (max 5 goroutines to avoid rate limiting)
- Output one result block per observable (table/markdown) or a single combined JSON array
- Print a summary at the end: N processed, N errors

---

## Web Server (`cmd/server`)

### Startup

```
observer-server --port 8080 --config .env
```

Or via environment variables only (for container use).

### API Endpoints

```
GET  /api/health                    # health check, returns {"status":"ok","version":"x.y.z"}
GET  /api/enrich?q={observable}     # single enrichment
GET  /api/enrich?q={observable}&sources=vt,shodan  # subset of sources
POST /api/enrich/bulk               # body: {"observables": ["1.2.3.4", "evil.com"]}
GET  /api/sources                   # list configured sources and their status
```

All API responses are JSON (`Content-Type: application/json`).

Error response format:
```json
{
  "error": "unsupported observable type",
  "code": "UNSUPPORTED_TYPE"
}
```

### Authentication Middleware

- Read `OBSERVER_API_KEY` from config
- If set: require `X-API-Key: {value}` header on all `/api/*` routes
- If not set: auth is disabled (log a warning on startup: "API key not configured — auth disabled")
- `/api/health` is always unauthenticated
- Static file routes (`/`) are always unauthenticated
- Return `401 Unauthorized` with JSON error on missing/wrong key

### Static UI (`web/static/index.html`)

Single HTML file, no build step, no framework. Embed it into the binary using Go's
`//go:embed` directive so the server binary is self-contained.

UI requirements:
- Clean, dark-themed, professional appearance (security tool aesthetic)
- Single search input, auto-detects observable type on input with a small type badge
- "Enrich" button + Enter key submits
- Bulk input toggle: switch between single input and a textarea for multiple observables
- Results displayed as structured cards — one card per source, showing status clearly
- Classification section at the top (VPN, TOR, Proxy, Hosting flags) with colored badges
- Source status indicators (ok / error / rate_limited / unsupported) per card
- Copy buttons: copy result as JSON, Markdown, or plaintext
- Loading state with spinner while enrichment is running
- Error state if API call fails
- No external CDN dependencies — all CSS/JS inline or in the single file
- Responsive for desktop use (minimum 1024px width target, doesn't need to be mobile-first)

**History (design for, implement later):**
- Add a `// TODO: history` comment in the handler where results would be persisted
- Keep handler thin so dropping in a SQLite store later is a 1-file addition
- Design the UI with a collapsible sidebar placeholder for history (hidden by default, noted as "coming soon")

---

## Configuration

All configuration via environment variables or `.env` file in the working directory.

```env
# API Keys — omit a key to disable that source
SHODAN_API_KEY=
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
OTX_API_KEY=
IPINFO_TOKEN=
GREYNOISE_API_KEY=

# Server config
OBSERVER_API_KEY=          # leave empty to disable auth (local use)
OBSERVER_PORT=8080
OBSERVER_LOG_LEVEL=info    # debug, info, warn, error

# Timeouts
ENRICHER_TIMEOUT_SECONDS=15
BULK_CONCURRENCY=5
```

Provide `.env.example` with all keys listed and commented.

The `observer config` CLI command must:
- Load config
- Print a table showing each source, whether its key is configured, and whether it's active
- Exit non-zero if no sources are configured

---

## Cross-Compilation & Build

Provide a `Makefile` with these targets:

```makefile
build-cli:          # build CLI for host OS
build-server:       # build server for host OS
build-all:          # build both for host OS
cross-compile:      # build all binaries for Windows/macOS/Linux (amd64 + arm64)
clean:
test:
lint:               # golangci-lint if available
```

Cross-compile output:
```
dist/
  observer-linux-amd64
  observer-linux-arm64
  observer-darwin-amd64
  observer-darwin-arm64
  observer-windows-amd64.exe
  observer-server-linux-amd64
  observer-server-linux-arm64
  observer-server-darwin-amd64
  observer-server-darwin-arm64
  observer-server-windows-amd64.exe
```

Embed version string at build time via `-ldflags`:
```
-ldflags "-X main.Version=$(git describe --tags --always --dirty)"
```

---

## Error Handling Conventions

- All enrichers return `(*SourceResult, error)` — never panic
- Network errors → `Status: "error"`, `ErrorMessage: "connection failed: ..."`
- HTTP 429 → `Status: "rate_limited"`, `ErrorMessage: "rate limited by {source}"`
- HTTP 4xx (e.g., not found) → `Status: "ok"` with empty/null data fields (observable not found is a valid result)
- HTTP 5xx → `Status: "error"`
- Unsupported type → `Status: "unsupported"` (not an error — silently skipped in pretty output)
- All errors logged at `warn` level with source name; `debug` level for full response bodies

---

## Testing

- Unit tests for `detect` package covering all observable types and edge cases
- Unit tests for each enricher using `httptest.NewServer` to mock API responses
- Integration test flag: `--tags integration` to run live API tests (skipped by default)
- At least one table-driven test for the runner covering partial failure scenarios

---

## README Requirements

Include:
1. What it is and why (one paragraph)
2. Installation options: download binary, or `go install`
3. Quick start: config, then `observer 1.2.3.4`
4. All CLI flags documented
5. Server setup and how to run
6. API reference (endpoints, auth header, example curl)
7. Source coverage table (which sources support which observable types)
8. How to add a new enricher (point to the interface + add to runner)
9. API key signup links for each source

---

## Out of Scope (for initial build)

These are explicitly deferred — do not implement, but design so they can be added:

- Database persistence / query history (stub in comments)
- User accounts / multi-tenant auth
- Webhook notifications
- Scheduled/recurring enrichment
- IRIS/TheHive integration connector
- Rate limit queuing / retry with backoff (use simple fail-fast for now)
- Caching layer (noted as a future middleware in handler.go)
