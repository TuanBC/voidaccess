# VoidAccess × ScrapingAnt Integration — Solutions Architect Briefing

**Audience:** Solutions architect
**Scope:** Full integration as built across Phase 1 → Phase 4 (corrected per architect review against the official docs)
**Repository:** `C:\void.access\voidaccess`
**Target release:** v1.6.0
**Date:** 2026-07-02

---

## 1. Executive Summary

VoidAccess is integrated with [ScrapingAnt](https://scrapingant.com/?ref=mzliyzh) as the optional clearnet transport for paste-site and RSS-feed scraping. The integration:

- **Routes two specific clearnet sources** through ScrapingAnt: the 4 paste sites (Pastebin, dpaste, paste.ee, Rentry) and the 20 curated RSS security feeds.
- **Does not touch Tor / .onion traffic** under any configuration. Dark web scraping is permanently isolated.
- **Does not touch GitHub / GitLab** traffic either, because both scrapers carry auth tokens that must never transit a third-party proxy.
- **Fails silently to direct** on any proxy error (timeout, 5xx, auth, malformed response). The pipeline never crashes.
- **Picks ONE transport per request** based on configuration:
  - **Direct** (default, no env vars set)
  - **REST API transport** — `VOIDACCESS_USE_PROXIES=true` routes through ScrapingAnt's Web Scraping API (POST the URL to `api.scrapingant.com/v2/general`)
  - **Proxy Mode transport** — `VOIDACCESS_USE_PROXY=true` routes through ScrapingAnt's HTTP CONNECT endpoint at `proxy.scrapingant.com:8080`
- **The two transports are mutually exclusive alternates**, not independently combinable. Per the [docs](https://docs.scrapingant.com/proxy-mode): "The proxy mode is a light front-end for the scraping API and has all the same functionality and performance as sending requests to the API endpoint." Therefore no chained mode exists. If both env vars are set, Proxy Mode wins with a one-shot info log.
- **Entirely optional and off by default.**

---

## 2. Architecture (corrected per docs)

### 2.1 Single chokepoint pattern

All clearnet scraping flows through **one function**: `clearnet_fetch()` in `sources/proxy_client.py`. Both `sources/paste_scraper.py` and `sources/rss_scraper.py` were refactored to call this chokepoint instead of `self._session.get()` directly.

```
┌──────────────────────────────────────────────────────────────────────┐
│  Paste scrapers (4 sites)         RSS scrapers (20 feeds)            │
│  ┌────────────────────────┐       ┌──────────────────────────┐        │
│  │ sources/paste_scraper  │       │ sources/rss_scraper      │        │
│  └──────────┬─────────────┘       └──────────┬───────────────┘        │
└─────────────┼──────────────────────────────────┼─────────────────────┘
              │                                  │
              └─────────────┬────────────────────┘
                            ▼
              ┌────────────────────────────┐
              │ sources/proxy_client.py    │
              │   clearnet_fetch()         │ ◄── HARD .onion guard first
              │                            │
              │   select_transport() picks:│
              │   ┌──────────────────────┐ │
              │   │ "proxy" if VOIDACCESS │ │ → Proxy Mode (HTTP CONNECT)
              │   │  _USE_PROXY=true     │ │
              │   │ "api" if VOIDACCESS  │ │ → REST API (POST)
              │   │  _USE_PROXIES=true   │ │
              │   │ "direct" otherwise   │ │ → direct (v1.5.0 behavior)
              │   └──────────────────────┘ │
              │                            │
              │   On any failure from the  │
              │   selected transport:      │
              │   silent fallback to direct│
              └────────────────────────────┘
                            │
                            ▼
              ┌────────────────────────────┐
              │  Pastebin / dpaste /       │
              │  paste.ee / Rentry /       │
              │  RSS feeds (clearnet)      │
              └────────────────────────────┘
```

**Hard rules:**
- `.onion` URLs are refused *unconditionally* at the very first line of `clearnet_fetch()`, before any transport check, before any env read. Raises `ValueError`.
- GitHub / GitLab scrapers are **permanently excluded** — they carry `Authorization: Bearer ${GITHUB_TOKEN}` / `PRIVATE-TOKEN: ${GITLAB_TOKEN}`.
- Browser rendering is **always off** on both transports. On the REST API path via `browser=false` query param; on Proxy Mode via `browser=false` in the username string per docs.

### 2.2 Single-transport selection table

| `VOIDACCESS_USE_PROXY` | `VOIDACCESS_USE_PROXIES` | Selected transport |
|---|---|---|
| `true` (and key set) | (anything) | **Proxy Mode** |
| (anything) | `true` (and key set) | **REST API** |
| `true` | `true` | **Proxy Mode** (proxy wins; one-shot info log) |
| `false` | `false` | **direct** |
| `true` but no key | (anything) | **direct** (proxy can't activate) |
| (anything) | `true` but no key | **direct** (REST API can't activate) |

When a transport is selected but its required credential (`SCRAPINGANT_API_KEY`) is absent, the chokepoint silently skips that transport and falls through to direct. No errors.

### 2.3 What architect review changed (corrections applied)

The initial Phase 2/3 implementation included three things that did not match the official documentation:

| Original claim | Architect review verdict | Correction |
|---|---|---|
| `SCRAPINGANT_PROXY_USERNAME` is a per-customer credential (the `customer-XXXX` prefix from the dashboard). | **Wrong.** Per [docs §Integration details](https://docs.scrapingant.com/proxy-mode): "Username: scrapingant + API parameters separated by & delimiter. Password: YOUR-API-KEY." The username is the literal constant `scrapingant` with optional parameters appended. No per-customer credential exists. | **Removed entirely.** Removed from `ENRICHMENT_KEYS`, `OPTIONAL_KEYS`, `ALLOWED_KEY_NAMES`, `KEYS_WITH_DEDICATED_STEP`, wizard prompts, setup.sh prompts, `.env.example`, top-level `config.py`, and tests. |
| Two proxy hostnames: `residential.scrapingant.com` and `datacenter.scrapingant.com` (selected via `SCRAPINGANT_PROXY_TYPE`). | **Wrong.** Per docs: "HTTP address: proxy.scrapingant.com:8080" — one hostname, two ports. Pool type is passed as `proxy_type=` parameter in the username. | **Replaced with single `SCRAPINGANT_PROXY_HOST = "proxy.scrapingant.com"`.** `SCRAPINGANT_PROXY_TYPE` now flows into the username string as `proxy_type=residential\|datacenter` per docs §Proxy Mode parameters. |
| Two independent gates that can be chained (`use_proxy` + `use_scraping_api` = both at once). | **Wrong.** Per docs §Introduction: "The proxy mode is a light front-end for the scraping API and has all the same functionality and performance as sending requests to the API endpoint." Same backend, alternate transport — never chained. | **Removed chained mode.** Gates are now mutually exclusive alternates. If both env vars are set, Proxy Mode wins with a one-shot info log. |

---

## 3. Phased Rollout (corrected)

### Phase 1 — Baseline clearnet proxy

**Goal:** Add the optional Web Scraping API path with safe defaults.

- Created `sources/proxy_client.py` (~640 lines) with `clearnet_fetch()` chokepoint and `_fetch_via_scrapingant()` helper.
- Refactored `sources/paste_scraper.py` to route through `clearnet_fetch()`.
- Refactored `sources/rss_scraper.py` to route through `clearnet_fetch()` with `.onion` guard.
- Added CLI surface: `voidaccess configure proxy` subcommand, `--use-proxies` flag on `voidaccess investigate`.
- Added env var: `SCRAPINGANT_API_KEY`, `VOIDACCESS_USE_PROXIES`.
- Silent fallback to direct on any failure.

### Phase 2 — Proxy username + pool type (REMOVED per architect review)

The initial Phase 2 added `SCRAPINGANT_PROXY_USERNAME` (per-customer credential) and `SCRAPINGANT_PROXY_TYPE` plus two separate hosts. **This phase was reverted** when architect review confirmed:

- The proxy username is the literal constant `scrapingant` per docs.
- There is only one proxy host (`proxy.scrapingant.com:8080`); pool type is a username parameter.
- The two "gates" are not independently combinable.

What Phase 2 retained after correction:
- `SCRAPINGANT_PROXY_TYPE` env var (`residential` | `datacenter`)
- `VOIDACCESS_USE_PROXY` env var (selects Proxy Mode transport)
- `SCRAPINGANT_PROXY_TYPE` is the ONLY optional config for Proxy Mode besides the API key

### Phase 3 — Two-gate independence + chained mode (REMOVED per architect review)

The initial Phase 3 made the API gate and proxy gate "independent" and added a "chained mode" where the residential proxy becomes transport for the API call. **This was reverted** because:

- Per docs §Introduction: "Proxy Mode is a light front-end for the scraping API." Chaining would double-charge the same request without adding capability.
- The gates are now **mutually exclusive alternates**; `select_transport()` picks exactly one.

What Phase 3 retained after correction:
- `select_transport()` function with explicit `direct | api | proxy` selection
- One-shot info log when both env vars are set (proxy wins, logged)
- `clearnet_fetch()` simplified to single-transport dispatch (was 4-combination matrix)

### Phase 4 — Docs + Referral + Partner banner

**Goal:** Document the integration in user-facing surfaces; apply the referral link everywhere; promote ScrapingAnt as a partner.

- **CHANGELOG.md** — Rewrote `[1.6.0]` entry: drop `SCRAPINGANT_PROXY_USERNAME`, drop 2-gate/chained-mode framing, document mutual-exclusion transports per docs.
- **README.md** — Added "What's New in v1.6.0" block; rewrote "Optional: Clearnet Scraping Proxy" section for mutually-exclusive transports with per-transport credentials.
- **TECHNICAL_REFERENCE.md** — Rewrote §3.2 with single-host design, username-from-docs construction, mutual-exclusion transport selection; rewrote §13.5 env-var table.
- **Referral link applied everywhere:** `https://scrapingant.com/?ref=mzliyzh` in README, TECHNICAL_REFERENCE, .env.example, setup.sh, configure.py, settings.py.
- **CLI banner** — Added 3 lines: `━━━ Partnered with ScrapingAnt ━━━` / `Web Scraping with Rotating Proxies` / `https://scrapingant.com/?ref=mzliyzh` (clickable via Rich `[link=]`).
- **Setup wizard** — Group F header has partnership banner with referral URL.

---

## 4. Full File Change Manifest (post-correction)

```
13 files changed (re-corrected from original Phase 1-4):
  .env.example                              +28/-4   Phase 4: referral + Phase 3 corrected: 2 mutually-exclusive transports
  CHANGELOG.md                              +78      Phase 4: full v1.6.0 entry (corrected: no SCRAPINGANT_PROXY_USERNAME)
  README.md                                 +50/-4   Phase 4: v1.6.0 block + corrected proxy section
  TECHNICAL_REFERENCE.md                    +60/-8   Phase 4: §3.2 + §13.5 (corrected)
  api/routes/settings.py                    +20/-30  Phase 3 corrected: SCRAPINGANT_PROXY_USERNAME removed from ALLOWED_KEY_NAMES
  config.py                                 +5/-8    Phase 3 corrected: SCRAPINGANT_PROXY_USERNAME removed
  setup.sh                                  +90/-30  Phase 3 corrected: username prompt removed; Group F rewritten
  sources/paste_scraper.py                  -53      Phase 1: route through clearnet_fetch (verified correct, untouched)
  sources/rss_scraper.py                    +83      Phase 1: route through clearnet_fetch + onion guard (verified correct, untouched)
  voidaccess_cli/commands/configure.py      +200/-60 Phase 3 corrected: username prompt removed, --show rewritten
  voidaccess_cli/commands/investigate.py    +35      Phase 1: --use-proxies flag (verified correct, untouched)
  voidaccess_cli/config.py                  +30/-25  Phase 3 corrected: SCRAPINGANT_PROXY_USERNAME removed; features renamed use_residential_proxy → use_proxy
  voidaccess_cli/main.py                    +36      Phase 4: partner banner lines

NEW FILE:
  sources/proxy_client.py                   ~620     Phase 1+2+3 corrected: clearnet_fetch, select_transport, single-host, username-from-docs
```

---

## 5. Environment Variables Reference (corrected)

### Credentials

| Variable | Required for | Storage (web) | Storage (CLI) | Storage (.env) |
|---|---|---|---|---|
| `SCRAPINGANT_API_KEY` | REST API transport, Proxy Mode transport | Fernet AES-128 via `UserApiKey` | plaintext in `~/.voidaccess/config.json` | plaintext in `.env` |

> **There is exactly ONE credential** for the entire ScrapingAnt integration: `SCRAPINGANT_API_KEY`. There is no per-customer proxy username.

### Routing toggles (mutually exclusive)

| Variable | Default | Selects transport | Independent? |
|---|---|---|---|
| `VOIDACCESS_USE_PROXIES` | `false` | **REST API** (`POST api.scrapingant.com/v2/general`) | Yes (mutually exclusive at runtime; proxy wins if both set) |
| `VOIDACCESS_USE_PROXY` | `false` | **Proxy Mode** (HTTP CONNECT through `proxy.scrapingant.com:8080`) | Yes (mutually exclusive at runtime) |

### Pool config

| Variable | Default | Values | Effect |
|---|---|---|---|
| `SCRAPINGANT_PROXY_TYPE` | `residential` | `residential` \| `datacenter` | Passed as `proxy_type=` parameter in the Proxy Mode username string per docs. Single host (`proxy.scrapingant.com:8080`) regardless of pool type. |

### Internal API endpoints (do not change — these are not signup links)

| Constant | Value | Source |
|---|---|---|
| `SCRAPINGANT_BASE_URL` | `https://api.scrapingant.com/v2/general` | REST API transport endpoint (referenced as "general endpoint" in docs) |
| `SCRAPINGANT_PROXY_HOST` | `proxy.scrapingant.com` | Single documented Proxy Mode host (HTTP port 8080; HTTPS 443) |
| `SCRAPINGANT_PROXY_PORT` | `8080` | HTTP port |

### Transport predicates (in `sources/proxy_client.py`)

```python
is_api_transport_enabled()        # API_KEY set AND VOIDACCESS_USE_PROXIES=true
is_proxy_transport_enabled()      # API_KEY set AND VOIDACCESS_USE_PROXY=true
select_transport()                # Returns "direct" | "api" | "proxy" (proxy wins on conflict)
```

---

## 6. Proxy Mode username string construction

Per [docs.scrapingant.com/proxy-mode §Proxy Mode parameters](https://docs.scrapingant.com/proxy-mode):

> "ScrapingAnt Proxy Mode uses the same request structure as the general endpoint. To enable extra functionality whilst using the API in proxy mode, you can pass parameters to the API by adding them to username, separated by ampersand."

Example from docs:
```
scrapingant&browser=false&proxy_type=residential
```

The username string is built at connection time by `_build_proxy_username()`:

```python
f"scrapingant&browser=false&proxy_type={SCRAPINGANT_PROXY_TYPE}"
```

Resulting in:
- `scrapingant&browser=false&proxy_type=residential` (default)
- `scrapingant&browser=false&proxy_type=datacenter` (when `SCRAPINGANT_PROXY_TYPE=datacenter`)

The username is URL-encoded when placed in the proxy URL (so `&` becomes `%26`, `=` becomes `%3D`) to prevent URL parser confusion. The password is `SCRAPINGANT_API_KEY` (URL-encoded defensively).

Resulting proxy URL:
```
http://scrapingant%26browser%3Dfalse%26proxy_type%3Dresidential:<API_KEY>@proxy.scrapingant.com:8080
```

---

## 7. CLI Surfaces (corrected)

### `voidaccess configure proxy`

| Flag | Behavior |
|---|---|
| (no flags) | Interactive prompt — key, pool type, asks about each transport separately |
| `--enable / --disable` | REST API transport toggle (legacy v1.5.0 flag) |
| `--enable-proxy / --disable-proxy` | Proxy Mode transport toggle (v1.6.0+) |
| `--show` | Print masked key (`abcd…5678`), pool type, both transport states. **No username row** — there is no such credential. Short credentials render as `set` to avoid substring leakage. |

### `voidaccess investigate`

| Flag | Behavior |
|---|---|
| `--use-proxies` | One-shot override — sets `VOIDACCESS_USE_PROXIES=true` for current process only (REST API transport only). |

### `voidaccess configure keys`

Includes the dedicated ScrapingAnt step alongside other enrichment keys.

### `voidaccess configure` (full wizard)

Includes the dedicated ScrapingAnt step inside the "Add enrichment API keys now?" branch.

### `voidaccess status`

Displays the active transport ("direct" / "api" / "proxy") so the user can tell at a glance which is in effect.

### CLI banner

Triggered on every `voidaccess <subcommand>` invocation (skippable with `--no-banner`). Phase 4 added:

```
                                  ░░░░░█░░░░░
                               ░░█████████████░░
                                  (existing circle banner)
                                dark web osint intelligence
                                ━━━ Partnered with ScrapingAnt ━━━
                                Web Scraping with Rotating Proxies
                                https://scrapingant.com/?ref=mzliyzh
```

The URL is a clickable Rich hyperlink in supporting terminals (Windows Terminal, iTerm, modern gnome-terminal).

---

## 8. Storage Model (corrected)

| Field | CLI path | Docker/web settings | `.env` |
|---|---|---|---|
| `SCRAPINGANT_API_KEY` | plaintext in `~/.voidaccess/config.json::enrichment_keys` | Fernet AES-128 via `UserApiKey` (registered in `ALLOWED_KEY_NAMES`) | plaintext in `.env` |
| `SCRAPINGANT_PROXY_TYPE` | plaintext in `~/.voidaccess/config.json::enrichment_keys` | env-var-only (it's a value, not a secret) | plaintext in `.env` |
| `features.use_proxies` (REST API toggle) | plaintext in `~/.voidaccess/config.json::features` | n/a (toggle, not a credential) | n/a |
| `features.use_proxy` (Proxy Mode toggle) | plaintext in `~/.voidaccess/config.json::features` | n/a | n/a |

`SCRAPINGANT_PROXY_USERNAME` is intentionally **NOT** registered in `ALLOWED_KEY_NAMES`, **NOT** in `ENRICHMENT_KEYS`, **NOT** in `.env.example`, **NOT** in `OPTIONAL_KEYS`. Per the docs there is no such credential.

---

## 9. Test Coverage (corrected)

```
tests/test_cli_proxy_config.py   ~50 tests (corrected: no username tests, no chained-mode tests)
tests/test_proxy_client.py       ~50 tests (corrected: 4-dispatch table → 3-transport selection)
tests/test_paste_scraper.py      19 passed (regression-clean post-migration; untouched in correction)
tests/test_rss_scraper.py        27 passed (regression-clean post-migration; untouched in correction)
Total                           ~150 tests
```

Key invariants pinned by tests:
- `select_transport()` returns exactly one of `"direct" | "api" | "proxy"`. Proxy wins on conflict.
- `.onion` URLs raise `ValueError` unconditionally, before any transport check, before any env read.
- Missing `SCRAPINGANT_API_KEY` → both transports inactive → direct.
- On any failure from the selected transport → silent fallback to direct. No exception propagates.
- Single host: `proxy.scrapingant.com:8080`. Pool type does NOT change the host.
- Username string built per docs: `scrapingant&browser=false&proxy_type=residential|datacenter`.
- `browser=false` is hardcoded on the REST API path; included in Proxy Mode username.
- No `SCRAPINGANT_PROXY_USERNAME` constant, `_get_proxy_username` function, `SCRAPINGANT_PROXY_HOST_RESIDENTIAL`/`_DATACENTER` constants, `is_residential_proxy_enabled` predicate, or `is_scraping_api_enabled` predicate. (A negative-coverage test asserts this.)
- `use_residential_proxy` feature flag is NOT in `DEFAULT_CONFIG` (renamed to `use_proxy`).

---

## 10. Design Constraints (locked, do not revisit)

1. **Scope is paste sites + RSS feeds only.** `paste_scraper.py` and `rss_scraper.py` are the only callers of `clearnet_fetch()`.
2. **GitHub / GitLab are permanently excluded** — they carry auth tokens that must never transit a third-party proxy.
3. **Tor / `.onion` traffic is permanently isolated.** The chokepoint refuses `.onion` URLs at the first line.
4. **Browser rendering is always off** on both transports (REST API: query param `browser=false`; Proxy Mode: `browser=false` in username string per docs).
5. **Single API key.** `SCRAPINGANT_API_KEY` covers both transports. No second credential.
6. **Silent failure.** The proxy path never raises to the scraper. Every failure mode falls back to direct.
7. **Single host.** Only `proxy.scrapingant.com:8080` (HTTP) or `:443` (HTTPS) — pool type is a username parameter.
8. **Single transport per request.** Proxy Mode and REST API are mutually exclusive alternates (per docs); the chokepoint picks one. No chained mode.
9. **`sources/scraper` firewall preserved.** No imports from `scraper/` into `sources/`. `MAX_RESPONSE_BYTES = 1_000_000` mirrors `scraper/scrape.py::MAX_DOWNLOAD_BYTES`.

---

## 11. Verification Status (corrections not committed)

```
git status --short
 M .env.example
 M CHANGELOG.md
 M README.md
 M TECHNICAL_REFERENCE.md
 M api/routes/settings.py
 M config.py
 M setup.sh
 M sources/proxy_client.py          (rewritten in correction pass)
 M voidaccess_cli/commands/configure.py
 M voidaccess_cli/config.py
 M voidaccess_cli/main.py
 M tests/test_cli_proxy_config.py   (rewritten in correction pass)
 M tests/test_proxy_client.py       (rewritten in correction pass)
?? docs/SCRAPINGANT_INTEGRATION_BRIEFING.md
?? sources/proxy_client.py          (originally untracked; now rewritten)
```

All modifications + new file are pending codex/claude review per the "verify before commit" workflow. Nothing committed yet.

---

## 12. Quick Reference — How to Turn It On

| Surface | How |
|---|---|
| CLI configure wizard | `voidaccess configure` → `voidaccess configure keys` — paste sites and RSS feeds are flagged with their honest "never Tor" description before any field is asked for |
| CLI proxy subcommand | `voidaccess configure proxy` (interactive) — covers key + pool type, asks about each transport separately |
| CLI non-interactive | `voidaccess configure proxy --enable --enable-proxy` (or `--disable` either) — sets toggles non-interactively |
| CLI one-shot | `voidaccess investigate "query" --use-proxies` — REST API transport only, current process only |
| Docker install | `bash setup.sh` — Group F in the Enrichment Keys step; prompts for key + pool type, asks about each transport toggle separately |
| Docker env | Set `SCRAPINGANT_API_KEY`, optionally `VOIDACCESS_USE_PROXIES=true` OR `VOIDACCESS_USE_PROXY=true`, optionally `SCRAPINGANT_PROXY_TYPE=datacenter` |
| Web settings | Settings → API Keys → ScrapingAnt (encrypted at rest via `UserApiKey`) |

---

**Referral signup:** [https://scrapingant.com/?ref=mzliyzh](https://scrapingant.com/?ref=mzliyzh)
**Partnership banner** appears in the CLI banner (every invocation) and in `setup.sh` Group F (Docker install).

---

## Appendix: Sources cited

- [https://docs.scrapingant.com/proxy-mode](https://docs.scrapingant.com/proxy-mode) — primary documentation for Proxy Mode (architecture, username, host, ports, parameters, browser=false recommendation)
- [https://proxydocs.scrapingant.com/](https://proxydocs.scrapingant.com/) — separate residential/datacenter proxy product documentation (linked but not used for the integration, since per docs the integration only uses the proxy mode endpoint at `proxy.scrapingant.com`)