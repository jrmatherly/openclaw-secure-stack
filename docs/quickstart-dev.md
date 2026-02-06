# Developer Quick Start

Contributor guide for local development and extending OpenClaw Secure Stack.

## Local Dev Setup (Without Docker)

```bash
# Install dependencies
uv sync

# Set required environment variables
export UPSTREAM_URL=http://localhost:3000
export OPENCLAW_TOKEN=dev-token-for-testing
export AUDIT_LOG_PATH=/tmp/audit.jsonl

# Start the proxy in dev mode
uv run uvicorn src.proxy.app:create_app_from_env --factory --reload
```

The proxy listens on `http://localhost:8000` by default (uvicorn default).

## Running Tests

The test suite has 371 tests across three categories:

```bash
# All tests
uv run pytest tests/ -q

# Unit tests only (~70% of suite)
uv run pytest tests/unit/ -q

# Integration tests (~20%)
uv run pytest tests/integration/ -q

# Security/adversarial tests (~10%)
uv run pytest tests/security/ -q

# With coverage
uv run pytest tests/ --cov=src --cov-report=term-missing
```

## Type Checking and Linting

```bash
# Lint
uv run ruff check src/ tests/

# Lint with auto-fix
uv run ruff check --fix src/ tests/

# Type check
uv run mypy src/
```

## Scanner Rules

Rules are defined in `config/scanner-rules.json` and implemented as AST walkers in `src/scanner/rules/`.

### 3 Categories, 7 Rules

| Category | Rule ID | What It Detects |
|----------|---------|-----------------|
| **Dangerous API** | DANGEROUS_EVAL | Dynamic code execution via eval |
| | DANGEROUS_FUNCTION_CTOR | Function constructor abuse |
| | DANGEROUS_CHILD_PROCESS | Process spawning and execution APIs |
| **Network Exfiltration** | NETWORK_FETCH | Outbound fetch, XMLHttpRequest, axios |
| | NETWORK_HTTP_MODULE | Node http/https/net/dgram imports |
| **Filesystem Abuse** | FS_WRITE | writeFileSync, appendFile, createWriteStream |
| | FS_DELETE | unlink, rmdir, rmSync |

The scanner uses tree-sitter to parse JS/TS into an AST before applying rules. Domains `api.openai.com` and `api.anthropic.com` are allowlisted by default in the network exfiltration scanner rules.

### Adding a New Scanner Rule

1. Create a rule file in `src/scanner/rules/` (e.g., `crypto_abuse.py`)
2. Implement an AST walker that returns `ScanFinding` objects
3. Add the rule definition to `config/scanner-rules.json` with an ID, name, severity, and patterns
4. Add tests in `tests/unit/test_rules_<category>.py`
5. The scanner engine (`src/scanner/scanner.py`) loads rules from config at startup

## Prompt Injection Rules

Rules are defined in `config/prompt-rules.json` and applied by `src/sanitizer/sanitizer.py`.

### 6 Rules, 2 Actions

| Rule ID | Name | Action |
|---------|------|--------|
| PI-001 | Ignore previous instructions | strip |
| PI-002 | Role switching | strip |
| PI-003 | System prompt extraction | reject |
| PI-004 | Delimiter injection | strip |
| PI-005 | Disregard rules | strip |
| PI-006 | Developer mode | reject |

- **strip**: removes the matched pattern from the prompt, forwards the cleaned version
- **reject**: blocks the entire request with HTTP 400

### Adding a New Prompt Injection Rule

1. Add a rule entry to `config/prompt-rules.json`:

   ```json
   {
     "id": "PI-007",
     "name": "Your rule name",
     "pattern": "regex_pattern_here",
     "action": "strip",
     "description": "What this rule catches"
   }
   ```

2. Add tests in `tests/unit/test_sanitizer.py`
3. The sanitizer loads rules from the JSON file at startup — no code changes needed for new patterns

## Project Layout

```text
src/
├── models.py              # Shared Pydantic models (frozen): ScanFinding, AuditEvent, etc.
├── proxy/
│   ├── app.py             # FastAPI app factory (create_app_from_env reads env vars)
│   └── auth_middleware.py  # ASGI middleware: Bearer token auth (constant-time compare)
├── scanner/
│   ├── scanner.py         # Core engine: loads rules from JSON, scans files via tree-sitter
│   ├── cli.py             # Click CLI: scan, quarantine list/override
│   ├── trust_score.py     # Trust score computation for skills
│   └── rules/
│       ├── dangerous_api.py   # AST rule: eval, Function constructor
│       ├── network_exfil.py   # AST rule: fetch, http modules (with domain allowlist)
│       └── fs_abuse.py        # AST rule: writeFile, unlink, rmSync
├── quarantine/
│   ├── db.py              # SQLite database for quarantine state
│   └── manager.py         # Quarantine lifecycle: quarantine, override, rescan
├── sanitizer/
│   └── sanitizer.py       # Prompt injection detection: regex strip/reject
├── governance/
│   ├── middleware.py       # Orchestrator: evaluate, enforce, approve, reject
│   ├── classifier.py      # IntentClassifier: tool call extraction & categorization
│   ├── planner.py         # PlanGenerator: execution plans with risk assessment
│   ├── validator.py       # PolicyValidator: action/resource/sequence/rate policies
│   ├── approver.py        # ApprovalGate: human-in-the-loop with timeout
│   ├── enforcer.py        # GovernanceEnforcer: HMAC token verification
│   ├── session.py         # SessionManager: multi-turn tracking, rate limiting
│   ├── store.py           # PlanStore: HMAC-signed tokens, atomic operations
│   ├── db.py              # GovernanceDB: SQLite WAL wrapper, 4 tables
│   └── models.py          # Pydantic models for governance types
└── audit/
    └── logger.py          # Append-only JSON Lines logger (file-locked writes)

config/
├── scanner-rules.json     # Scanner rule definitions (loaded at startup)
├── skill-pins.json        # SHA-256 hashes for approved skills
├── prompt-rules.json      # Prompt injection regex rules (loaded at startup)
├── indirect-injection-rules.json  # Response-side injection scanning rules
├── governance-policies.json       # Governance policies (action/resource/sequence/rate)
├── intent-patterns.json           # Tool-to-category mapping, risk multipliers
└── egress-allowlist.conf  # Allowed external domains (one per line)

tests/
├── conftest.py            # Shared fixtures
├── unit/                  # 27 test files — one per module
├── integration/           # 3 integration test files
└── security/              # Adversarial skill tests
```

## SDD Workflow for New Features

This project uses Spec-Driven Development. For non-trivial features:

```text
sdd-init → /sdd-requirements → /sdd-design → /sdd-tasks → /sdd-implement
```

Each phase requires approval before proceeding. For small changes, use `/simple-task` instead.

See [CLAUDE.md](../CLAUDE.md) for the full workflow reference.
