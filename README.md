# TPRM Platform

Internal third-party cyber risk management and external attack surface monitoring
platform — a focused, lower-cost alternative to UpGuard/BitSight for vendor risk
management, passive external risk monitoring, typosquatting detection, security
posture scoring, and executive reporting.

This is **Phase 1 + 2** of a phased build. See the full roadmap below. Nothing
here performs active scanning of third-party infrastructure — passive-mode
scanning (DNS/email security, RDAP, crt.sh, Subfinder) is the only mode with
real code behind it, and no active-scan provider exists yet at all (see
Phase 6).

## Stack

- **Backend:** Python, FastAPI, SQLAlchemy, Pydantic, Alembic
- **Database:** PostgreSQL
- **Jobs:** Celery + Redis
- **Frontend:** Next.js (App Router) + TypeScript
- **Deployment:** Docker Compose

## Running it

```bash
cp .env.example .env
docker compose up --build
```

- API: http://localhost:8000/docs (OpenAPI/Swagger UI)
- Frontend: http://localhost:3000
- Postgres: localhost:5432 (only bound to 127.0.0.1)
- Redis: localhost:6379 (only bound to 127.0.0.1)

The `backend` service runs `alembic upgrade head` automatically on startup before
starting uvicorn, so the schema is always current.

## Running tests

```bash
cd backend
pip install -e ".[dev]"
pytest
```

Tests are split by dependency:
- `tests/unit` — pure Python, no database required. Includes
  `test_scan_authorization.py`, which verifies the authorized-active-scan
  authorization gate — the single most safety-critical check in this codebase —
  with zero infrastructure dependency.
- `tests/api` — integration tests against a real Postgres (`TEST_DATABASE_URL`,
  defaults to `postgresql+psycopg://tprm:changeme@localhost:5432/tprm_test`).
  These skip automatically (not fail) if no Postgres is reachable. A couple also
  need the Celery broker (Redis) and skip independently if that's unreachable.

## Architecture

```
Next.js (TS) frontend  <--REST-->  FastAPI backend  <-->  PostgreSQL
                                          |
                                    enqueues Scan
                                          v
                                    Celery worker (Redis broker)
```

- **Provider adapter pattern** (`backend/app/providers/`): every external
  intelligence source (DNS, RDAP, crt.sh, Subfinder, Shodan InternetDB, NVD, CISA
  KEV, typosquat generation) implements one of the interfaces in
  `providers/base.py`. The scan orchestrator depends only on these interfaces, so
  swapping or adding a source is a new adapter class, not an application change.
  DNS/RDAP/crt.sh/Subfinder are real implementations as of Phase 2; the rest
  (Shodan InternetDB, NVD, CISA KEV, typosquat generation) are still typed stubs
  (`NotImplementedError`, with a `TODO(Phase N)` docstring) — see the roadmap
  below for when each lands.

- **Passive vs. authorized-active scanning** is enforced at the data model
  (`Vendor.active_scan_authorized`, default `False`) and the service layer
  (`app/services/scan_orchestrator.py` rejects any `authorized_active` scan
  request unless that flag is set) — independent of anything the frontend sends.
  No provider capable of active scanning exists in the codebase yet (that's
  Phase 6), so this is defense-in-depth from day one, not a retrofit.

- **Risk scoring is config-driven**, not hardcoded — weights and per-finding-type
  deductions live in the `risk_scoring_config` table (see
  `app/models/risk_score.py` and `app/services/risk_engine/`), so tuning them
  doesn't require a code deploy. Every `RiskScore` row is append-only and stores
  the full category/finding breakdown behind the number. (Scoring logic lands in
  Phase 3 — see roadmap.)

- **Governance/TPRM data is kept separate** from the external technical score
  (`GovernanceProfile` model) and is never blended into it automatically.

- **Asset attribution is a first-class concern**: every `Asset` row carries an
  `ownership_confidence` (confirmed/high/medium/low/unverified) and a `source`.
  Only sufficiently attributed assets are meant to significantly affect scoring.

## Roadmap

- **Phase 1 (done):** repo scaffold, Docker Compose, all core models + Alembic
  migration, CRUD/read APIs, dashboard summary endpoint, minimal frontend
  (vendor list/detail, scan history, findings, asset/score tabs).
- **Phase 2 (done):** real DNS/SPF/DMARC/MTA-STS/TLS-RPT/MX evaluation
  (`app/providers/dns_provider.py`), RDAP (`rdap_provider.py`), crt.sh
  Certificate Transparency subdomain discovery (`crtsh_provider.py`), and a
  Subfinder subprocess adapter (`subfinder_provider.py`) — all wired into
  `app/services/scan_ingest.py`, which the Celery task
  (`app/workers/tasks.py::run_scan`) calls to upsert real `Asset`/`Finding`
  rows with evidence. Findings from a still-detected condition update in
  place; a still-`OPEN` finding whose condition clears on a later scan is
  auto-transitioned to `remediated` — findings an analyst already triaged
  (accepted/false_positive/investigating) are never silently reopened or
  auto-closed. One provider failing (e.g. crt.sh timing out) is logged to
  `Scan.scan_metadata.provider_errors` and doesn't fail the whole scan.
- **Phase 3 (done):** the risk engine — `app/services/risk_engine/scorer.py`
  computes a weighted, config-driven 0-100 score per vendor every time a scan
  completes, appending a `RiskScore` row (never mutated in place) with a full
  category/finding deduction trail. Config is seeded via
  `alembic/versions/0002_seed_risk_scoring_config.py` (the same weights
  documented in this README) and can be re-tuned by editing the active
  `risk_scoring_config` row — no deploy required. `false_positive` and
  `remediated` findings, currently-suppressed findings, low-confidence
  findings, and findings tied to a low/unverified-confidence asset are all
  excluded from scoring; `accepted`-risk findings deliberately still count,
  since accepting a risk doesn't change what's externally visible. The Score
  History tab on a vendor's detail page now shows the deduction trail
  directly, not just a bare number.
- **Phase 4 (done):** typosquatting — `app/providers/typosquat_provider.py`
  generates ~80-150 lookalike-domain candidates per vendor (omission,
  repetition, transposition, keyboard-adjacent substitution/insertion,
  homoglyph substitution, phishing-style prefixes/suffixes, alt-TLD swap; pure
  Python, no `dnstwist` subprocess dependency), then checks each candidate's
  DNS resolution and MX presence with conservative concurrency (8 at a time,
  no retries — this is a sweep over 100+ candidates, not a single lookup).
  Only candidates that actually resolve are ever reported. A resolving
  candidate with mail configured is `typosquat_active_mail` (high severity);
  resolving-but-no-mail is `typosquat_domain_resolves` (low severity) — both
  feed the risk score (`0003_expand_typosquat_scoring.py`) via
  per-instance-keyed findings, so multiple lookalike domains each deduct
  independently instead of collapsing into one row.
- **Phase 5 (vulnerability intelligence done; web/TLS still open):** each
  discovered hostname is now resolved to IPs (`dns_provider.resolve_ips`), each
  unique IP is looked up in Shodan's free passive index
  (`shodan_internetdb_provider.py`), and any CVE it reports is cross-referenced
  against the CISA KEV catalog (`cisa_kev_provider.py`). A KEV match becomes a
  critical `kev_exposure_confirmed` finding at HIGH confidence — never
  CONFIRMED, since KEV proves the CVE is exploited *somewhere* and Shodan only
  associates it with the host by observed banner/version, neither of which
  confirms this host is actually vulnerable. A non-KEV CVE becomes a LOW
  confidence `shodan_known_vulnerability` (and LOW-confidence findings are
  excluded from scoring by design). Notable open ports (RDP/SSH/Telnet/SMB/
  databases) become `exposed_service_passive`. All of these are linked to the
  specific `Asset` they were found on, so the scorer's low-attribution
  discount applies. **Auto-remediation deliberately does not apply to these** —
  a missing Shodan result can mean "not rescanned yet," not "fixed," and the
  spec is explicit that absence of evidence is not proof of security.
  Still open in this phase: HTTPS/TLS certificate and security-header
  evaluation (HTTPx/TLSx-style).
- **Phase 6:** Authorized active-scan framework (Nmap/Naabu/Nuclei adapters) —
  gated on `active_scan_authorized`, not started until the authorization
  plumbing above is proven in tests (it already is, as of Phase 1).

## Security notes

- No hardcoded secrets — see `.env.example`; a real `.env` is gitignored.
- `app/schemas/vendor.py::validate_domain` normalizes and strictly validates any
  domain before it can reach a provider or (in later phases) a subprocess call.
- All future subprocess-based providers (Subfinder, etc.) must use argument
  lists, never `shell=True` or f-string-built commands, and a hard timeout.
- RBAC roles (`admin`, `security_analyst`, `read_only`, `executive`) and a
  `get_current_user` dependency exist from Phase 1 (`app/core/security.py`) even
  though real authentication (OAuth/SSO) isn't wired in yet — every route already
  depends on it so wiring in real auth later won't require touching route
  signatures. **The current stub treats every request as an authenticated admin
  — do not expose this deployment beyond a trusted internal network as-is.**
- Docker Compose binds every service to `127.0.0.1` only.
