# OpenClaw Secure Stack — Project Index

**Version:** 1.1.0
**Python:** >=3.12
**License:** See LICENSE

A security-hardened Docker deployment wrapper for the OpenClaw AI agent. Interposes a FastAPI reverse proxy between clients and the OpenClaw gateway, providing authentication, prompt injection defense, AST-based skill scanning, quarantine management, and a full pre-execution governance layer with human-in-the-loop approval.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Module Reference](#module-reference)
3. [Configuration Reference](#configuration-reference)
4. [Infrastructure](#infrastructure)
5. [CLI Tools](#cli-tools)
6. [Test Suite](#test-suite)
7. [Security Model](#security-model)
8. [Data Flow](#data-flow)
9. [Dependency Graph](#dependency-graph)

---

## Architecture Overview

```text
                     ┌──────────────────────────────────────────────┐
                     │              Docker Compose Stack            │
Client ──8080──►┌────┴────┐    internal    ┌──────────┐            │
  (Bearer)      │  Proxy  │──────────────►│ OpenClaw  │            │
                │ FastAPI │   :3000        │ Gateway   │            │
                └────┬────┘                └─────┬─────┘            │
                     │                           │                  │
                ┌────┴────┐               ┌──────┴─────┐            │
                │  Audit  │               │ Egress DNS │◄─172.28.0.10
                │  Logger │               │  CoreDNS   │            │
                └─────────┘               └────────────┘            │
                                                                    │
                ┌─────────┐                                         │
  :8443 ──────►│  Caddy   │  TLS termination for Control UI        │
                └─────────┘                                         │
                     └──────────────────────────────────────────────┘

Network topology:
  - "internal" (172.28.0.0/16): proxy <-> openclaw <-> egress-dns <-> caddy
  - "egress": openclaw <-> egress-dns -> internet (DNS-filtered)
  - Only proxy(:8080) and caddy(:8443) publish ports to host
```

**Key design principles:**

- Fail-closed: missing scanner rules -> refuse to approve skills
- Defense-in-depth: auth -> sanitization -> scanning -> governance -> quarantine
- Least privilege: all containers run read-only, non-root, all capabilities dropped
- Tamper-evident: append-only audit log with SHA-256 hash chain

---

## Module Reference

### `src/proxy/` — Reverse Proxy (334 LOC)

| File | Lines | Purpose |
|------|-------|---------|
| `app.py` | 249 | FastAPI app factory; routes all `/{path}` to upstream OpenClaw; handles streaming (SSE) and non-streaming responses; applies request sanitization and response scanning |
| `auth_middleware.py` | 85 | ASGI middleware; Bearer token validation with constant-time `hmac.compare_digest`; public paths bypass: `/health`, `/healthz`, `/ready`, `/__openclaw__/canvas*` |

**Request lifecycle:**

1. `AuthMiddleware` validates Bearer token
2. `_sanitize_body()` recursively strips/rejects prompt injection patterns
3. Quarantine check for `skills/*` paths
4. Forward to upstream with gateway token injection
5. Response scanning for indirect injection (non-streaming: header, streaming: audit event)

### `src/scanner/` — Skill Scanner (624 LOC)

| File | Lines | Purpose |
|------|-------|---------|
| `scanner.py` | 307 | Core orchestrator: `SkillScanner.scan()` runs all rules against JS/TS files using tree-sitter; `PatternScanRule` for string matching; pin verification via SHA-256 checksums |
| `cli.py` | 92 | Click CLI: `scan`, `quarantine list`, `quarantine override` commands |
| `trust_score.py` | 46 | 0-100 trust score: author reputation (40%), downloads (20%), reviews (20%), recency (20%) |
| `rules/base.py` | 78 | `ASTScanRule` base class: tree-sitter AST traversal, `_walk()` / `_walk_children()` / `_make_finding()` helpers |
| `rules/dangerous_api.py` | 71 | Detects dynamic code evaluation, `Function()` constructor, `child_process` imports via AST |
| `rules/fs_abuse.py` | 91 | Detects `writeFile*`, `unlink*`, `rmdir*` calls via AST |
| `rules/network_exfil.py` | 90 | Detects `fetch()`, `XMLHttpRequest`, `http`/`https` module imports via AST |

**Scanner rule types:**

- **PatternScanRule**: string-in-line matching (loaded from `scanner-rules.json`)
- **ASTScanRule**: tree-sitter AST walk (built-in: `DangerousAPIRule`, `FSAbuseRule`, `NetworkExfilRule`)

**Pin verification flow:**

1. Compute SHA-256 of skill directory
2. Compare against `config/skill-pins.json`
3. Mismatch -> CRITICAL finding, auto-quarantine, skip AST scan

### `src/sanitizer/` — Prompt Injection Defense (86 LOC)

| File | Lines | Purpose |
|------|-------|---------|
| `sanitizer.py` | 86 | `PromptSanitizer`: loads regex rules from JSON; `sanitize()` strips or rejects matches; `scan()` detect-only mode for response scanning |

**Actions:**

- `"strip"`: remove matched content, continue
- `"reject"`: raise `PromptInjectionError` -> HTTP 400

### `src/audit/` — Audit Logging (114 LOC)

| File | Lines | Purpose |
|------|-------|---------|
| `logger.py` | 114 | Append-only JSON Lines logger with SHA-256 hash chain; file locking via `fcntl`; rotation with configurable `max_bytes` and `backup_count`; `validate_audit_chain()` for integrity checking |

**Hash chain:** each line includes `prev_hash = sha256(previous_line)`. First entry has `prev_hash: null`.

### `src/quarantine/` — Quarantine System (218 LOC)

| File | Lines | Purpose |
|------|-------|---------|
| `manager.py` | 133 | `QuarantineManager`: moves flagged skills to quarantine directory; enforces quarantine at proxy level; supports admin override with acknowledgment; rescan capability |
| `db.py` | 85 | `QuarantineDB`: SQLite storage for `skill_metadata` table; upsert, status tracking, override metadata |

**Quarantine lifecycle:**

```text
Scan findings -> quarantine(move + DB upsert) -> enforce_quarantine(block HTTP 403)
                                                     |
                                              force_override(admin ack) -> overridden status
```

### `src/governance/` — Pre-Execution Governance Layer (2,750 LOC)

The governance layer implements a full security pipeline for LLM tool execution.

| File | Lines | Purpose |
|------|-------|---------|
| `models.py` | 233 | Pydantic models: `IntentCategory`, `ToolCall`, `Intent`, `ExecutionPlan`, `PlannedAction`, `RiskAssessment`, `PolicyRule`, `PolicyViolation`, `ValidationResult`, `ApprovalRequest`, `Session`, `PlanToken` |
| `classifier.py` | 269 | `IntentClassifier`: extracts tool calls from OpenAI-compatible format; maps tools to `IntentCategory` via config; analyzes arguments for sensitive paths/URLs |
| `planner.py` | 294 | `PlanGenerator`: builds `PlannedAction` sequences; extracts file/URL resources; calculates risk scores with configurable multipliers; produces `RiskAssessment` |
| `validator.py` | 325 | `PolicyValidator`: evaluates plans against 4 policy types — action (category-based), resource (path/URL pattern), sequence (forbidden patterns), rate (session limits) |
| `approver.py` | 348 | `ApprovalGate`: human-in-the-loop approval with timeout; atomic approve/reject with race condition protection; self-approval validation |
| `enforcer.py` | 194 | `GovernanceEnforcer`: runtime enforcement; verifies HMAC-signed tokens; validates tool calls against approved plans; tracks action sequence completion |
| `session.py` | 209 | `SessionManager`: multi-turn conversation tracking; action recording with RETURNING clause for TOCTOU prevention; TTL-based cleanup |
| `store.py` | 556 | `PlanStore`: SQLite persistence for plans; HMAC-SHA256 token signing/verification; atomic sequence advancement via compare-and-swap; pending/active plan lifecycle |
| `db.py` | 203 | `GovernanceDB`: SQLite wrapper with WAL mode; parameterized queries; 4 tables: `governance_plans`, `governance_approvals`, `governance_sessions`, `governance_action_history` |
| `middleware.py` | 357 | `GovernanceMiddleware`: pipeline orchestrator; `evaluate()` classifies intent, generates plan, validates policy, issues token or requests approval; `enforce()` for runtime checks; context manager with safe cleanup |

**Governance pipeline:**

```text
Request -> IntentClassifier.classify()
              |
        PlanGenerator.generate()
              |
        PolicyValidator.validate()
              |
        +---------------------+
        | ALLOW -> store plan,|     +----------------------+
        |   issue HMAC token  |     | REQUIRE_APPROVAL ->  |
        +---------------------+     |   store pending plan,|
                                    |   create approval    |
        +---------------------+     |   request            |
        | BLOCK -> reject with|     +----------------------+
        |   violations list   |
        +---------------------+

At execution time:
  GovernanceEnforcer.enforce_action(plan_id, token, tool_call)
    -> verify HMAC token -> match tool call to plan -> check sequence
```

### `src/models.py` — Shared Data Models (139 LOC)

Pydantic models used across all modules:

| Model | Fields |
|-------|--------|
| `Severity` | Enum: `critical`, `high`, `medium`, `low` |
| `AuditEventType` | Enum: `auth_success`, `auth_failure`, `skill_scan`, `skill_quarantine`, `skill_override`, `prompt_injection`, `indirect_injection`, `egress_blocked` |
| `RiskLevel` | Enum: `critical`, `high`, `medium`, `low`, `info` |
| `PinResult` | `status` (verified/mismatch/unpinned), `expected`, `actual` |
| `ScanFinding` | `rule_id`, `rule_name`, `severity`, `file`, `line`, `column`, `snippet`, `message` |
| `TrustScore` | `overall` (0-100), `author_reputation`, `download_count`, `community_reviews`, `last_update_days` |
| `ScanReport` | `skill_name`, `skill_path`, `checksum` (SHA-256), `findings`, `trust_score`, `scanned_at`, `duration_ms` |
| `QuarantinedSkill` | `name`, `original_path`, `quarantined_at`, `reason`, `findings`, `overridden`, `overridden_by`, `overridden_at` |
| `SanitizeResult` | `clean`, `injection_detected`, `patterns` |
| `SanitizationRule` | `id`, `name`, `pattern`, `action` (strip/reject), `description` |
| `AuditEvent` | `timestamp`, `event_type`, `source_ip`, `user_id`, `action`, `result`, `risk_level`, `details` |

---

## Configuration Reference

### `config/scanner-rules.json`

Pattern-based scanner rules loaded at startup. Each rule has `id`, `name`, `severity`, `patterns[]`, and `description`. Works alongside built-in AST rules.

### `config/skill-pins.json`

SHA-256 hashes of approved skills. Format: `{ "skill-name": { "sha256": "..." } }`. Pin mismatch triggers auto-quarantine.

### `config/prompt-rules.json`

Prompt injection detection rules (6 rules):

- PI-001: "Ignore previous instructions" (strip)
- PI-002: Role switching (strip)
- PI-003: System prompt extraction (reject)
- PI-004: Delimiter injection (strip)
- PI-005: Disregard rules (strip)
- PI-006: Developer/jailbreak mode (reject)

### `config/indirect-injection-rules.json`

Same format as prompt-rules.json, applied to response scanning for indirect prompt injection defense.

### `config/governance-policies.json`

Governance policy rules (8 policies):

- GOV-001: Block file deletion (action/deny, priority 100)
- GOV-002: Require approval for code execution (action/require_approval, priority 90)
- GOV-003: Block sensitive paths `/etc/`, `passwd`, `shadow`, `secret` (resource/deny, priority 100)
- GOV-004: Require approval for external URLs (resource/require_approval, priority 80)
- GOV-005: Rate limit 100 actions/session (rate/deny, priority 50)
- GOV-006: Flag read-then-exfiltrate sequence (sequence/require_approval, priority 85)
- GOV-007: Require approval for system commands (action/require_approval, priority 90)
- GOV-008: Allow localhost URLs (resource/allow, priority 90)

### `config/intent-patterns.json`

Tool-to-category mapping and risk configuration:

- `tool_categories`: maps tool names to `IntentCategory` values
- `argument_patterns`: regexes for sensitive paths (`/etc/`, `.pem`, `.key`, `.env`) and external URLs
- `risk_multipliers`: per-category multipliers (code_execution: 4.0x, system_command: 4.0x, file_write: 2.0x, etc.)

### `config/egress-allowlist.conf`

Domain allowlist for CoreDNS egress filtering. `install.sh` generates `docker/egress/Corefile` from this file (allowed domains forward to Cloudflare; all others get NXDOMAIN).

### `.env.example` -> `.env`

| Variable | Purpose |
|----------|---------|
| `OPENCLAW_TOKEN` | Bearer token for proxy auth (auto-generated) |
| `UPSTREAM_URL` | Internal OpenClaw gateway URL |
| `AUDIT_LOG_PATH` | Audit log file path |
| `DB_PATH` | SQLite quarantine DB path |
| `SKILLS_DIR` | Skills directory path |
| `QUARANTINE_DIR` | Quarantine directory path |
| `OPENAI_API_KEY` | OpenAI API key (passthrough) |
| `ANTHROPIC_API_KEY` | Anthropic API key (passthrough) |

---

## Infrastructure

### Docker Compose Services

| Service | Image | Ports | Purpose |
|---------|-------|-------|---------|
| `proxy` | Built from `Dockerfile` | 8080 (host) | FastAPI reverse proxy |
| `openclaw` | `ghcr.io/openclaw/openclaw:latest` | none (internal only) | AI gateway |
| `caddy` | `caddy:2-alpine` | 8443 (HTTPS) | TLS termination for Control UI |
| `egress-dns` | Built from `docker/egress/` | none (172.28.0.10) | CoreDNS egress filter |

### Container Hardening

All services:

- `read_only: true` — immutable filesystem
- `cap_drop: ALL` — no Linux capabilities
- `security_opt: no-new-privileges:true` — prevent privilege escalation
- `user: "65534"` (nobody) or distroless nonroot
- `tmpfs` for temporary storage with size limits

### Dockerfile (Multi-stage)

1. **Builder stage**: `python:3.12-slim` + `uv` — installs frozen dependencies
2. **Runtime stage**: `gcr.io/distroless/python3-debian12:nonroot` — no shell, no package manager, minimal attack surface

### Networks

- `internal` (172.28.0.0/16): bridge, `internal: true` — no direct internet
- `egress`: bridge — filtered internet access via CoreDNS

---

## CLI Tools

### `openclaw-scanner` (entrypoint: `src.scanner.cli:cli`)

```bash
# Scan a skill
openclaw-scanner scan <skill-path> [--quarantine]

# List quarantined skills
openclaw-scanner quarantine list

# Override quarantine (admin)
openclaw-scanner quarantine override <skill-name> --ack "reason" [--user admin]
```

### `scripts/audit.py`

OWASP-aligned security audit script:

```bash
python scripts/audit.py [--format json|text]
```

Checks: container hardening, network isolation, secret management, log integrity (hash chain), skill security, documentation completeness, performance (latency p95, startup time).

### `build.sh`

Auto-detects Docker/Podman and builds the proxy image:

```bash
./build.sh [tag]
```

### `install.sh`

Full installation wizard:

1. Detects Docker/Podman
2. Generates `.env` with random token
3. Generates CoreDNS Corefile from egress allowlist
4. Interactive LLM auth setup (API key or OAuth)
5. Builds containers
6. Validates image hardening
7. Runs OpenClaw onboarding
8. Starts all services

---

## Test Suite

**371 test functions** across 32 test files organized in 3 tiers:

### `tests/unit/` (27 files)

| File | Covers |
|------|--------|
| `test_approver.py` | `ApprovalGate` — create, approve, reject, expiration, self-approval |
| `test_audit_logger.py` | `AuditLogger` — logging, rotation, hash chain |
| `test_audit_script.py` | `scripts/audit.py` — all security checks |
| `test_auth_middleware.py` | `AuthMiddleware` — token validation, public paths |
| `test_classifier.py` | `IntentClassifier` — tool extraction, categorization, argument analysis |
| `test_cli.py` | Scanner CLI — scan, quarantine commands |
| `test_config_loading.py` | Configuration file loading and validation |
| `test_enforcer.py` | `GovernanceEnforcer` — token verification, action enforcement |
| `test_governance_db.py` | `GovernanceDB` — schema, CRUD, WAL mode |
| `test_governance_models.py` | Pydantic model validation |
| `test_indirect_injection_rules.py` | Indirect injection rule detection |
| `test_middleware.py` | `GovernanceMiddleware` — full pipeline |
| `test_models.py` | Shared Pydantic models |
| `test_planner.py` | `PlanGenerator` — plan generation, risk assessment |
| `test_proxy_streaming.py` | SSE streaming response handling |
| `test_quarantine.py` | `QuarantineManager` — lifecycle |
| `test_quarantine_db.py` | `QuarantineDB` — SQLite operations |
| `test_response_scanning.py` | Response-side injection scanning |
| `test_rules_dangerous_api.py` | `DangerousAPIRule` detection |
| `test_rules_fs_abuse.py` | `FSAbuseRule` detection |
| `test_rules_network_exfil.py` | `NetworkExfilRule` detection |
| `test_sanitizer.py` | `PromptSanitizer` — strip/reject actions |
| `test_scanner.py` | `SkillScanner` — orchestration, pin verification |
| `test_session.py` | `SessionManager` — CRUD, action recording, cleanup |
| `test_store.py` | `PlanStore` — storage, tokens, sequence, retry |
| `test_trust_score.py` | Trust score computation |
| `test_validator.py` | `PolicyValidator` — all 4 policy types |

### `tests/integration/` (3 files)

| File | Covers |
|------|--------|
| `test_proxy_auth.py` | End-to-end auth flow through proxy |
| `test_proxy_quarantine.py` | Quarantine enforcement through proxy |
| `test_scan_quarantine.py` | Scan -> quarantine -> enforce pipeline |

### `tests/security/` (1 file)

| File | Covers |
|------|--------|
| `test_malicious_skills.py` | Real-world malicious skill samples |

### Configuration

- **Framework**: pytest + pytest-asyncio + pytest-httpx
- **Coverage target**: 90% (`fail_under = 90`)
- **Async mode**: auto
- **Markers**: `slow`, `security`

---

## Security Model

### Layer 1: Network Isolation

- Internal Docker network prevents direct internet access
- CoreDNS egress filtering: only allowlisted domains resolve
- Only proxy and caddy expose ports to host

### Layer 2: Authentication

- Bearer token with constant-time comparison (`hmac.compare_digest`)
- Auto-generated 32-byte base64 token
- Audit logging of all auth events (success and failure with reason)

### Layer 3: Prompt Injection Defense

- **Request-side**: regex-based detection and neutralization (strip or reject)
- **Response-side**: indirect injection scanning with audit logging
- 6 detection rules: instruction override, role switching, prompt extraction, delimiter injection, rule disregard, jailbreak mode

### Layer 4: Skill Scanning

- Tree-sitter AST analysis for JavaScript/TypeScript
- Pattern-based string matching from configuration
- SHA-256 pin verification for known-good skills
- Automatic quarantine on findings or pin mismatch

### Layer 5: Governance

- Intent classification of tool calls
- Execution plan generation with risk scoring
- Policy validation (action, resource, sequence, rate)
- Human-in-the-loop approval for medium-risk operations
- HMAC-signed plan tokens for execution-time enforcement
- Session-based rate limiting

### Layer 6: Audit Trail

- Append-only JSON Lines with SHA-256 hash chain
- File locking for concurrent access safety
- Log rotation with configurable size and backup count
- `validate_audit_chain()` for tamper detection

### Layer 7: Container Hardening

- Distroless runtime image (no shell, no package manager)
- Read-only filesystem with size-limited tmpfs
- All capabilities dropped, no-new-privileges
- Non-root user (nobody/65534 or distroless nonroot/65532)

---

## Data Flow

### Inbound Request Flow

```text
Client
  | POST /v1/chat/completions
  | Authorization: Bearer <token>
  v
AuthMiddleware
  | hmac.compare_digest(token)
  | audit: auth_success / auth_failure
  v
Proxy Route Handler
  | 1. Check quarantine (skills/* paths)
  | 2. Parse JSON body
  | 3. Sanitize all string fields recursively
  | 4. Inject gateway token
  v
httpx.AsyncClient -> OpenClaw Gateway (:3000)
  |
  v
Response
  | Non-streaming: scan full body, set X-Prompt-Guard header
  | Streaming: scan chunks, log audit events
  v
Client
```

### Skill Scan Flow

```text
openclaw-scanner scan <path>
  |
  v
SkillScanner.scan()
  +- Compute SHA-256 checksum
  +- Verify pin (if pin file loaded)
  |   +- Mismatch -> CRITICAL finding, return early
  +- Find .js/.ts/.mjs/.cjs files
  +- Parse each file with tree-sitter
  +- Run all rules (Pattern + AST)
      +- PatternScanRule.detect() — string matching
      +- DangerousAPIRule._walk() — dynamic code, Function, child_process
      +- NetworkExfilRule._walk() — fetch, http module
      +- FSAbuseRule._walk() — writeFile, unlink, rmdir
  |
  v
ScanReport
  | findings -> QuarantineManager.quarantine()
  |              +- Move skill to quarantine dir
  |              +- Upsert DB record
  |              +- Audit log
  v
Runtime: enforce_quarantine() -> HTTP 403
```

---

## Dependency Graph

### Python Dependencies (production)

| Package | Version | Purpose |
|---------|---------|---------|
| FastAPI | >=0.115.0 | Web framework for proxy |
| uvicorn[standard] | >=0.32.0 | ASGI server |
| httpx | >=0.28.0 | Async HTTP client for upstream requests |
| pydantic | >=2.10.0 | Data validation and models |
| click | >=8.1.0 | CLI framework for scanner |
| tree-sitter | >=0.24.0 | Parser generator for AST analysis |
| tree-sitter-javascript | >=0.23.0 | JavaScript grammar |
| tree-sitter-typescript | >=0.23.0 | TypeScript grammar |

### Dev Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| pytest | >=8.0.0 | Test framework |
| pytest-asyncio | >=0.24.0 | Async test support |
| pytest-cov | >=6.0.0 | Coverage reporting |
| pytest-httpx | >=0.34.0 | httpx mocking |
| ruff | >=0.8.0 | Linter and formatter |
| mypy | >=1.13.0 | Static type checking (strict mode) |

### Internal Module Dependencies

```text
src/models.py          <- used by all modules
  ^
src/audit/logger.py    <- used by proxy, scanner, quarantine
  ^
src/sanitizer/         <- used by proxy
src/scanner/           <- used by proxy (via quarantine), CLI
  ^
src/quarantine/        <- used by proxy, CLI
  ^
src/governance/        <- standalone (middleware orchestrator)
  +-- classifier.py    <- uses models
  +-- planner.py       <- uses models, classifier output
  +-- validator.py     <- uses models, planner output
  +-- approver.py      <- uses db, models
  +-- enforcer.py      <- uses store
  +-- session.py       <- uses db, models
  +-- store.py         <- uses db, models
  +-- db.py            <- SQLite wrapper
  +-- middleware.py     <- orchestrates all above
```

---

## File Tree (source only)

```text
src/
+-- __init__.py
+-- models.py                          # Shared Pydantic models (139 LOC)
+-- audit/
|   +-- __init__.py
|   +-- logger.py                      # Hash-chained JSON Lines logger (114 LOC)
+-- governance/
|   +-- __init__.py
|   +-- approver.py                    # Human-in-the-loop approval gate (348 LOC)
|   +-- classifier.py                  # Intent classification (269 LOC)
|   +-- db.py                          # SQLite + WAL wrapper (203 LOC)
|   +-- enforcer.py                    # Runtime plan enforcement (194 LOC)
|   +-- middleware.py                  # Pipeline orchestrator (357 LOC)
|   +-- models.py                      # Governance Pydantic models (233 LOC)
|   +-- planner.py                     # Execution plan generator (294 LOC)
|   +-- session.py                     # Session management (209 LOC)
|   +-- store.py                       # HMAC-signed plan storage (556 LOC)
|   +-- validator.py                   # Policy validation engine (325 LOC)
+-- proxy/
|   +-- __init__.py
|   +-- app.py                         # FastAPI reverse proxy (249 LOC)
|   +-- auth_middleware.py             # Bearer token auth (85 LOC)
+-- quarantine/
|   +-- __init__.py
|   +-- db.py                          # SQLite quarantine DB (85 LOC)
|   +-- manager.py                     # Quarantine lifecycle (133 LOC)
+-- sanitizer/
|   +-- __init__.py
|   +-- sanitizer.py                   # Prompt injection sanitizer (86 LOC)
+-- scanner/
    +-- __init__.py
    +-- cli.py                         # Click CLI (92 LOC)
    +-- scanner.py                     # Skill scanner orchestrator (307 LOC)
    +-- trust_score.py                 # Trust score computation (46 LOC)
    +-- rules/
        +-- __init__.py
        +-- base.py                    # ASTScanRule base class (78 LOC)
        +-- dangerous_api.py           # Dynamic code / Function / child_process (71 LOC)
        +-- fs_abuse.py                # writeFile / unlink / rmdir (91 LOC)
        +-- network_exfil.py           # fetch / http module (90 LOC)

Total: ~4,754 LOC (source) | 371 tests | 32 test files
```
