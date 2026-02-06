# Design: openclaw-secure-stack

## Overview

A security wrapper around OpenClaw deployed via Docker Compose. The system is structured as a set of containers and host-side scripts that add security layers **around** OpenClaw without modifying its source. The core components are: (1) an authentication reverse proxy, (2) a skills scanner CLI/service, (3) an egress-filtering DNS/firewall sidecar, (4) a prompt sanitization middleware, and (5) an audit logger. All orchestrated by `docker-compose.yml` and bootstrapped by `install.sh`.

## Architecture Pattern

**Sidecar / Reverse-Proxy pattern** — each security concern runs as a separate container or layer composed around the unmodified OpenClaw container. This satisfies the constraint of not modifying OpenClaw core code while keeping each security domain isolated and independently testable.

```text
                    ┌────────────────────────────────────────────────┐
                    │           Docker Compose Stack                 │
                    │                                                │
  User ──HTTPS──▶   │  ┌──────────────┐      ┌───────────────────┐   │
                    │  │ Auth Proxy   │─────▶│    OpenClaw       │   │
                    │  │ (port 443)   │      │  (internal only)  │   │
                    │  └─────┬────────┘      └────────┬──────────┘   │
                    │        │                        │              │
                    │        │ prompt sanitizer       │ skill load   │
                    │        │ (middleware)           ▼              │
                    │        │              ┌───────────────┐        │
                    │        │              │ Skill Scanner │        │
                    │        │              │ + Quarantine  │        │
                    │        │              └───────────────┘        │
                    │        │                                       │
                    │        ▼                                       │
                    │  ┌──────────────┐   ┌───────────────────────┐  │
                    │  │ Audit Logger │   │ Egress Firewall       │  │
                    │  │ (JSON Lines) │   │ (DNS + iptables)      │  │
                    │  └──────────────┘   └───────────────────────┘  │
                    │                                                │
                    └────────────────────────────────────────────────┘
```

## Technology Decisions

| Concern | Technology | Rationale |
|---------|-----------|-----------|
| Language | Python 3.12+ | Smaller image, rich security tooling, stdlib SQLite/CLI |
| Auth Proxy | FastAPI + `httpx` (async reverse proxy) | High-performance async, Pydantic validation built-in |
| Container base | `gcr.io/distroless/python3-debian12` | No shell, ~50MB, minimal attack surface |
| Scanner | `tree-sitter` + `tree-sitter-javascript` | Accurate AST parsing of JS/TS skills from Python |
| Egress filter | CoreDNS sidecar + iptables rules | DNS-level allowlist, no app changes needed |
| Audit log | Append-only JSON Lines file on named volume | Simple, SIEM-compatible, no DB needed |
| Database | SQLite via stdlib `sqlite3` | Zero dependencies, skill metadata + quarantine state |
| Data models | Pydantic v2 | Runtime validation, serialization, config parsing |
| CLI | `click` | Clean CLI for scanner, quarantine management |
| Testing | `pytest` + `pytest-asyncio` + `httpx` | Mature, async support, fixtures |
| Build | Multi-stage Dockerfile | Small images, layer caching, ARM64 support |
| Packaging | `uv` (lockfile) + `pyproject.toml` | Fast, reproducible, modern Python packaging |

---

## Components

### 1. Auth Proxy (`src/proxy/`)

**Type:** Service (container)

**Purpose:** Reverse proxy that authenticates all inbound requests before forwarding to OpenClaw.

**Responsibilities:**

- Validate Bearer token on every request
- Forward authenticated requests to OpenClaw container
- Inject prompt sanitization on LLM-bound request bodies
- Return 401/403 for invalid auth

**Interface:**

```python
from pydantic import BaseModel

class SanitizeResult(BaseModel):
    clean: str
    injection_detected: bool
    patterns: list[str]

class AuthMiddleware:
    """ASGI middleware for Bearer token validation."""
    def __init__(self, token: str, audit_logger: "AuditLogger") -> None: ...
    def validate_token(self, token: str) -> bool: ...

class ProxyApp:
    """FastAPI application that proxies to OpenClaw."""
    def __init__(
        self,
        upstream_url: str,
        sanitizer: "PromptSanitizer",
        audit_logger: "AuditLogger",
    ) -> None: ...
```

**Dependencies:**

- `PromptSanitizer` — for FR-8
- `AuditLogger` — for FR-10
- Environment variable `API_TOKEN` — for FR-6

**Error Handling:**

- Missing/invalid token → 401/403, logged as audit event
- Upstream OpenClaw unreachable → 502, logged as ERROR
- Prompt injection detected → configurable: strip or reject (400)

---

### 2. Skill Scanner (`src/scanner/`)

**Type:** Service (CLI + library)

**Purpose:** Static analysis of skill source code to detect malicious patterns. Runs on skill install/load and on-demand via CLI.

**Responsibilities:**

- Parse skill source files into AST via `tree-sitter`
- Match against configurable rule set (FR-3)
- Compute trust score (FR-3 AC-7)
- Verify skill checksums for pinning (FR-3 AC-6)
- Output structured scan report

**Interface:**

```python
from abc import ABC, abstractmethod
from enum import Enum
from pydantic import BaseModel

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class ScanFinding(BaseModel):
    rule_id: str
    rule_name: str
    severity: Severity
    file: str
    line: int
    column: int
    snippet: str
    message: str

class TrustScore(BaseModel):
    overall: int  # 0-100
    author_reputation: int
    download_count: int
    community_reviews: int
    last_update_days: int

class ScanReport(BaseModel):
    skill_name: str
    skill_path: str
    checksum: str  # SHA-256
    findings: list[ScanFinding]
    trust_score: TrustScore | None
    scanned_at: str  # ISO8601
    duration_ms: int

class ScanRule(ABC):
    """Base class for scanner rules. Loaded from config + built-in rules."""
    id: str
    name: str
    severity: Severity

    @abstractmethod
    def detect(self, tree: "tree_sitter.Tree", source: bytes) -> list[ScanFinding]: ...

class SkillScanner:
    def __init__(self, rules: list[ScanRule], audit_logger: "AuditLogger") -> None: ...
    def scan(self, skill_path: str) -> ScanReport: ...
    def scan_all(self, skills_dir: str) -> list[ScanReport]: ...
```

**Dependencies:**

- `QuarantineManager` — moves flagged skills
- `AuditLogger` — logs scan events
- Scanner rules config file (`config/scanner-rules.json`)

**Error Handling:**

- Unparseable file → log warning, treat as suspicious (high severity finding)
- Rule config missing → fail-closed, refuse to approve any skill

---

### 3. Quarantine Manager (`src/quarantine/`)

**Type:** Service (library)

**Purpose:** Manages the lifecycle of flagged skills — quarantine, override, re-scan.

**Responsibilities:**

- Move flagged skills to quarantine directory
- Prevent quarantined skills from loading
- Handle force-override with acknowledgment
- Track quarantine state in SQLite

**Interface:**

```python
from pydantic import BaseModel

class QuarantinedSkill(BaseModel):
    name: str
    original_path: str
    quarantined_at: str  # ISO8601
    reason: str
    findings: list[ScanFinding]
    overridden: bool
    overridden_by: str | None = None
    overridden_at: str | None = None

class QuarantineManager:
    def __init__(
        self,
        db_path: str,
        quarantine_dir: str,
        scanner: SkillScanner,
        audit_logger: "AuditLogger",
    ) -> None: ...

    def quarantine(self, skill_path: str, report: ScanReport) -> None: ...
    def is_quarantined(self, skill_name: str) -> bool: ...
    def force_override(self, skill_name: str, user_id: str, ack: str) -> None: ...
    def get_quarantined(self) -> list[QuarantinedSkill]: ...
    def rescan(self, skill_name: str) -> ScanReport: ...
```

**Dependencies:**

- `SkillScanner` — for re-scan
- `AuditLogger` — logs quarantine/override events
- SQLite database for state

---

### 4. Prompt Sanitizer (`src/sanitizer/`)

**Type:** Library (used by Auth Proxy)

**Purpose:** Detect and neutralize prompt injection patterns in user input before it reaches the LLM.

**Responsibilities:**

- Pattern-match against configurable injection rules
- Strip or reject detected injections
- Preserve legitimate input unchanged

**Interface:**

```python
from pydantic import BaseModel

class SanitizationRule(BaseModel):
    id: str
    name: str
    pattern: str  # regex pattern
    action: str   # "strip" or "reject"
    description: str

class PromptSanitizer:
    def __init__(self, rules_path: str, audit_logger: "AuditLogger") -> None: ...
    def load_rules(self, rules_path: str) -> None: ...
    def sanitize(self, input_text: str) -> SanitizeResult: ...
```

**Dependencies:**

- Rules config file (`config/prompt-rules.json`)
- `AuditLogger` — logs injection detections

---

### 5. Audit Logger (`src/audit/`)

**Type:** Library (shared)

**Purpose:** Append-only structured logging for all security events.

**Interface:**

```python
from enum import Enum
from pydantic import BaseModel

class AuditEventType(str, Enum):
    AUTH_SUCCESS = "auth_success"
    AUTH_FAILURE = "auth_failure"
    SKILL_SCAN = "skill_scan"
    SKILL_QUARANTINE = "skill_quarantine"
    SKILL_OVERRIDE = "skill_override"
    PROMPT_INJECTION = "prompt_injection"
    EGRESS_BLOCKED = "egress_blocked"

class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class AuditEvent(BaseModel):
    timestamp: str         # ISO8601, auto-generated
    event_type: AuditEventType
    source_ip: str | None = None
    user_id: str | None = None
    action: str
    result: str            # "success" | "failure" | "blocked"
    risk_level: RiskLevel
    details: dict | None = None

class AuditLogger:
    def __init__(self, log_path: str) -> None: ...
    def log(self, event: AuditEvent) -> None: ...
```

**Dependencies:**

- Named Docker volume for log persistence
- Log rotation config

---

### 6. Egress Firewall (`docker/egress/`)

**Type:** Container (sidecar)

**Purpose:** DNS-level filtering that blocks all outbound traffic except allowlisted domains.

**Implementation:** CoreDNS container configured to resolve only allowlisted domains, combined with iptables rules in the Docker network that restrict outbound connections to resolved IPs.

**Config file:** `config/egress-allowlist.conf`

```text
# One domain per line
api.openai.com
api.anthropic.com
```

**No application code** — purely configuration-driven via Docker networking and CoreDNS.

---

### 7. Install Script (`install.sh`)

**Type:** Shell script (host-side)

**Purpose:** One-click bootstrap: prereq check, token generation, env setup, stack launch.

**Flow:**

1. Check Docker >= 20.10 and docker-compose >= 2.0
2. Check available disk space and architecture (amd64/arm64)
3. Generate 32-byte cryptographic random token (base64-encoded)
4. Copy `.env.example` to `.env` (skip if exists), inject token
5. Build images (`docker-compose build`)
6. Launch stack (`docker-compose up -d`)
7. Health check — wait for proxy to respond
8. Print access info (URL, token location)

---

## Data Models

### SkillMetadata (SQLite)

| Column | Type | Description |
|--------|------|-------------|
| name | TEXT PK | Skill identifier |
| path | TEXT | Original filesystem path |
| checksum | TEXT | SHA-256 of skill contents |
| status | TEXT | `active` / `quarantined` / `overridden` |
| last_scanned | TEXT | ISO8601 timestamp |
| trust_score | INTEGER | 0-100 or NULL |
| findings_json | TEXT | JSON array of ScanFinding |
| override_user | TEXT | User who overrode (nullable) |
| override_ack | TEXT | Acknowledgment text (nullable) |
| override_at | TEXT | Override timestamp (nullable) |

### ScannerRule (config file, not DB)

```json
{
  "id": "DANGEROUS_API_EVAL",
  "name": "Dynamic code evaluation",
  "severity": "critical",
  "ast_query": "(call_expression function: (identifier) @fn (#eq? @fn \"eval\"))",
  "description": "Detects dynamic evaluation calls that can run arbitrary code"
}
```

Note: `ast_query` uses tree-sitter S-expression query syntax for precise AST matching.

---

## File Structure

```text
openclaw-secure-stack/
├── docker-compose.yml          # Stack orchestration
├── install.sh                  # One-click setup (FR-5)
├── .env.example                # Config template (FR-7)
├── .gitignore                  # Includes .env
├── Dockerfile                  # Multi-stage build for proxy+scanner
├── pyproject.toml              # Python project config (deps, tools)
├── uv.lock                     # Locked dependencies
├── config/
│   ├── scanner-rules.json      # Malicious pattern rules (FR-3)
│   ├── prompt-rules.json       # Injection patterns (FR-8)
│   └── egress-allowlist.conf   # Permitted domains (FR-9)
├── src/
│   ├── __init__.py
│   ├── proxy/
│   │   ├── __init__.py
│   │   ├── app.py              # FastAPI reverse proxy entry point
│   │   └── auth_middleware.py  # Token validation (FR-6)
│   ├── scanner/
│   │   ├── __init__.py
│   │   ├── scanner.py          # Core scanner logic (FR-3)
│   │   ├── rules/              # Built-in rule implementations
│   │   │   ├── __init__.py
│   │   │   ├── dangerous_api.py
│   │   │   ├── network_exfil.py
│   │   │   └── fs_abuse.py
│   │   ├── trust_score.py      # Trust score computation
│   │   └── cli.py              # Click CLI interface
│   ├── quarantine/
│   │   ├── __init__.py
│   │   ├── manager.py          # Quarantine logic (FR-4)
│   │   └── db.py               # SQLite operations
│   ├── sanitizer/
│   │   ├── __init__.py
│   │   └── sanitizer.py        # Prompt injection filter (FR-8)
│   └── audit/
│       ├── __init__.py
│       └── logger.py           # Audit logging (FR-10)
├── docker/
│   └── egress/
│       ├── Corefile             # CoreDNS config (FR-2)
│       └── Dockerfile           # Egress sidecar image
├── scripts/
│   └── audit.py                # Security audit script (NFR-2)
├── tests/
│   ├── conftest.py             # Shared fixtures
│   ├── unit/
│   │   ├── test_scanner.py
│   │   ├── test_quarantine.py
│   │   ├── test_sanitizer.py
│   │   ├── test_auth_middleware.py
│   │   └── test_audit_logger.py
│   ├── integration/
│   │   ├── test_proxy_auth.py
│   │   ├── test_scan_quarantine.py
│   │   └── test_egress_filter.py
│   └── security/
│       ├── malicious_skills/    # Test suite of 50+ samples
│       ├── prompt_injections/   # Known injection test cases
│       └── test_container_audit.py
└── .spec/                       # SDD workflow files
```

---

## Docker Compose Design

```yaml
services:
  proxy:
    build: .
    ports: ["443:8000"]
    read_only: true
    security_opt: ["no-new-privileges:true"]
    cap_drop: ["ALL"]
    user: "1000:1000"
    depends_on: [openclaw]
    networks: [internal]
    environment:
      - API_TOKEN=${API_TOKEN}
      - UPSTREAM_URL=http://openclaw:3000
    volumes:
      - audit-logs:/var/log/audit
      - ./config:/app/config:ro
      - sqlite-data:/app/data

  openclaw:
    image: openclaw/openclaw:latest
    read_only: true
    security_opt: ["no-new-privileges:true"]
    cap_drop: ["ALL"]
    user: "1000:1000"
    networks: [internal]
    volumes:
      - skills:/app/skills
      - quarantine:/app/quarantine
      - openclaw-data:/app/data

  egress-dns:
    build: docker/egress
    networks: [internal]
    cap_drop: ["ALL"]
    cap_add: ["NET_BIND_SERVICE"]

networks:
  internal:
    driver: bridge
    internal: true  # No external access by default

volumes:
  audit-logs:
  skills:
  quarantine:
  openclaw-data:
  sqlite-data:
```

The `internal: true` network setting blocks all egress by default. The egress-dns sidecar selectively resolves allowlisted domains, and iptables rules (applied via Docker network config) allow only those resolved IPs outbound.

---

## Security Considerations

| Concern | Approach | FR/NFR |
|---------|----------|--------|
| Authentication | Constant-time token comparison via `hmac.compare_digest` | FR-6 |
| Secret storage | `.env` only, never in source | FR-7 |
| Container hardening | Distroless Python, non-root, read-only fs, no caps | FR-1 |
| Network isolation | Internal-only Docker network + DNS allowlist | FR-2, FR-9 |
| Supply chain | tree-sitter AST scanner + quarantine + pinning | FR-3, FR-4 |
| Prompt injection | Configurable regex + heuristic sanitizer | FR-8 |
| Audit trail | Append-only JSON Lines, read-only to app | FR-10 |
| SSRF | Egress allowlist prevents arbitrary outbound | FR-2 |

---

## Requirement Traceability

| Requirement | Component(s) |
|-------------|-------------|
| FR-1 | `docker-compose.yml`, `Dockerfile` |
| FR-2 | `docker-compose.yml`, `docker/egress/` |
| FR-3 | `src/scanner/` |
| FR-4 | `src/quarantine/` |
| FR-5 | `install.sh` |
| FR-6 | `src/proxy/auth_middleware.py` |
| FR-7 | `.env.example`, `.gitignore`, `install.sh` |
| FR-8 | `src/sanitizer/` |
| FR-9 | `config/egress-allowlist.conf`, `docker/egress/` |
| FR-10 | `src/audit/` |
| NFR-1 | Multi-stage Dockerfile, scanner performance targets |
| NFR-2 | `scripts/audit.py`, `tests/security/`, Trivy in CI |
| NFR-3 | `install.sh`, README |
| NFR-4 | Config-driven rules, multi-stage Dockerfile, CI |

---

## Testing Strategy

| Level | Scope | Coverage Target |
|-------|-------|----------------|
| Unit | Scanner rules, sanitizer, auth middleware, quarantine logic, audit logger | 90%+ |
| Integration | Proxy-to-OpenClaw flow, scan-to-quarantine flow, egress filtering | All happy + error paths |
| Security | 50+ malicious skill samples, prompt injection corpus, CIS Docker Benchmark, OWASP ZAP | 100% detection on test suite |
| E2E | `install.sh` to running stack, authenticated request, skill scan | Full workflow |

### Key Testing Tools

- `pytest` + `pytest-asyncio` for all Python tests
- `httpx.AsyncClient` for integration testing the FastAPI proxy
- `testcontainers-python` for Docker-based integration tests
- `trivy` for container image CVE scanning in CI
