# Design: requirements-audit

## Overview

This design addresses the 6 functional and 3 non-functional gaps identified in the traceability matrix. The approach is **incremental hardening** — each change strengthens the existing architecture without restructuring it. No new services are introduced; changes land in existing files or a single new script (`scripts/audit.py`).

## Architecture Pattern

Same as the existing stack: **layered sidecar / reverse-proxy** around unmodified OpenClaw. This design adds validation and enforcement layers to components that already exist.

## Component Map

```text
┌─────────────────────────────────────────────────┐
│                 Changes by FR                    │
├──────────┬──────────────────────────────────────┤
│  FR-1    │  Dockerfile, install.sh              │
│  FR-2    │  docker-compose.yml, docs            │
│  FR-3    │  scanner/scanner.py, quarantine/db   │
│  FR-4    │  quarantine/manager.py               │
│  FR-5    │  audit/logger.py, config             │
│  FR-6    │  scripts/audit.py (new)              │
│  NFR-1   │  scripts/audit.py, tests             │
│  NFR-2   │  Dockerfile, docs                    │
│  NFR-3   │  README.md                           │
└──────────┴──────────────────────────────────────┘
```

---

## Detailed Design per Requirement

### FR-1: Container Hardening

**Files**: `Dockerfile`, `install.sh`

**Current state**: Runtime stage uses `python:3.12-slim` with manual purge of apt/dpkg/perl. Reasonable but lacks formal hardening validation (SUID removal, digest pinning).

**Design**:

1. **Dockerfile** — Pin base image by digest (not `:latest`). Keep the manual-purge approach since true distroless lacks pip/venv support for Python. Add explicit checks:
   - Remove `/bin/sh` symlink in runtime stage (keep `/bin/dash` only if uvicorn needs it; test)
   - Remove all SUID/SGID binaries: `RUN find / -perm /6000 -type f -exec chmod a-s {} +`
   - Verify non-root: already `USER 65534`, no change needed

2. **install.sh** — Add `validate_image_hardening()` function after build step:

   ```bash
   validate_image_hardening() {
     local image="$1"
     # Check: runs as non-root
     local user; user=$($RUNTIME inspect --format '{{.Config.User}}' "$image")
     [ "$user" = "65534" ] || fail "Image runs as root"
     # Check: no SUID binaries
     $RUNTIME run --rm --entrypoint="" "$image" \
       find / -perm /6000 -type f 2>/dev/null | grep -q . && fail "SUID binaries found"
     # Check: no shell (optional, warn only)
     $RUNTIME run --rm --entrypoint="" "$image" \
       ls /bin/sh 2>/dev/null && warn "Shell present in image"
   }
   ```

**Interface**: No new Python interfaces. Shell function only.

---

### FR-2: Network Isolation

**Files**: `docker-compose.yml`, `README.md`

**Current state**: OpenClaw publishes port 3000 to host. Egress policy is partially documented.

**Design**:

1. **docker-compose.yml** — Remove `ports: ["3000:3000"]` from `openclaw` service. Traffic reaches OpenClaw only through the proxy on the `internal` network. If operators need direct access, they add it via `docker-compose.override.yml`.

2. **Documentation** — Add `docs/network-policy.md` (or a section in README) with:
   - Network topology diagram (internal + egress networks)
   - Egress allowlist location and format
   - How to add/remove allowed domains
   - Port exposure policy: only proxy (8080) and caddy (8443) are host-facing

3. **Audit script** (FR-6) validates no unexpected published ports.

**Interface**: No code changes beyond compose file.

---

### FR-3: Skill Pinning & Trust Score

**Files**: `src/scanner/scanner.py`, `src/quarantine/db.py`, `config/scanner-rules.json`

**Current state**: Scanner detects patterns; `trust_score` column exists in DB but is computed transiently and not persisted after scan.

**Design**:

1. **Skill manifest** — Introduce `config/skill-pins.json`:

   ```json
   {
     "skill-name": {
       "sha256": "abc123...",
       "pinned_at": "2026-02-01T00:00:00Z"
     }
   }
   ```

   Optional file. If absent, pinning is skipped (fail-open for unpinned skills, but audit log warns).

2. **scanner.py** — Add hash verification step before AST scan:

   ```python
   def _verify_pin(self, skill_path: Path, skill_name: str) -> PinResult:
       """Compare SHA-256 of skill file against pinned hash."""
       actual = hashlib.sha256(skill_path.read_bytes()).hexdigest()
       expected = self._pins.get(skill_name, {}).get("sha256")
       if expected is None:
           return PinResult(status="unpinned")  # logged as warning
       if actual != expected:
           return PinResult(status="mismatch", expected=expected, actual=actual)
       return PinResult(status="verified")
   ```

   A `mismatch` result triggers immediate quarantine without further scanning.

3. **db.py** — `upsert_skill()` already accepts `trust_score`. Ensure `scanner.py` passes the computed score from `trust_score.py` into the upsert call. Currently the score is computed but discarded — wire it through.

**Data model addition**:

```python
class PinResult(BaseModel, frozen=True):
    status: Literal["verified", "mismatch", "unpinned"]
    expected: str | None = None
    actual: str | None = None
```

---

### FR-4: Quarantine Runtime Enforcement

**Files**: `src/quarantine/manager.py`, `src/proxy/app.py` (or wherever skill invocation is routed)

**Current state**: `is_quarantined()` exists but is not called on the execution path.

**Design**:

1. **manager.py** — Add `enforce_quarantine(skill_name: str) -> None`:

   ```python
   def enforce_quarantine(self, skill_name: str) -> None:
       """Raise if skill is quarantined. Called before skill execution."""
       skill = self._db.get_skill(skill_name)
       if skill and skill["status"] == "quarantined":
           self._audit.log(AuditEvent(
               event_type=EventType.SKILL_QUARANTINE,
               action=f"Blocked execution of quarantined skill: {skill_name}",
               result="blocked",
               risk_level=RiskLevel.HIGH,
           ))
           raise QuarantineBlockedError(skill_name)
   ```

2. **QuarantineBlockedError** — New exception in `src/quarantine/manager.py`:

   ```python
   class QuarantineBlockedError(Exception):
       def __init__(self, skill_name: str):
           super().__init__(f"Skill '{skill_name}' is quarantined and cannot execute")
           self.skill_name = skill_name
   ```

3. **Integration point** — The proxy or skill-loading path calls `enforce_quarantine()` before forwarding a skill invocation request. The exact hook depends on how OpenClaw invokes skills (likely a proxy route or middleware check). If skill invocation goes through the proxy as a regular HTTP request, add a middleware/dependency that inspects the request path for skill references.

---

### FR-5: Audit Log Hardening

**Files**: `src/audit/logger.py`, config (env vars or `config/audit.json`)

**Current state**: Logger opens file in append mode (`"a"`) with `fcntl.LOCK_EX`. No rotation, retention, or tamper detection.

**Design**:

1. **Rotation & retention** — Use Python's `logging.handlers.RotatingFileHandler` pattern or implement simply:

   ```python
   class AuditLogger:
       def __init__(self, path: Path, max_bytes: int = 10_485_760, backup_count: int = 5):
           self._path = path
           self._max_bytes = max_bytes      # default 10MB
           self._backup_count = backup_count # default 5 files

       def _maybe_rotate(self) -> None:
           if self._path.stat().st_size >= self._max_bytes:
               # Rotate: audit.jsonl -> audit.jsonl.1 -> ... -> audit.jsonl.5 (delete oldest)
               for i in range(self._backup_count, 0, -1):
                   src = self._path.with_suffix(f".jsonl.{i}") if i > 0 else self._path
                   ...
   ```

   Config via env vars: `AUDIT_LOG_MAX_BYTES`, `AUDIT_LOG_BACKUP_COUNT`.

2. **Tamper detection** — After each write, compute a rolling SHA-256 chain:

   ```python
   # Each log line includes prev_hash for chain integrity
   {"timestamp": "...", "event_type": "...", ..., "prev_hash": "sha256-of-previous-line"}
   ```

   The audit script (FR-6) validates the chain on each run. If a line's `prev_hash` doesn't match the SHA-256 of the previous line, the chain is broken → tamper alert.

3. **Alerting** — Tamper detection is passive: `scripts/audit.py` validates the hash chain and reports a `critical` finding on breakage. Real-time alerting (webhook/email) is out of scope for v0.1.

---

### FR-6: Security Audit Script

**Files**: `scripts/audit.py` (new)

**Design**: A standalone Python script (no framework dependencies beyond stdlib + existing project deps) that validates security posture.

```text
scripts/audit.py
├── Check: container_hardening()
│   ├── Non-root user
│   ├── Read-only filesystem
│   ├── Dropped capabilities
│   └── No SUID binaries
├── Check: network_isolation()
│   ├── No unexpected published ports
│   ├── Internal network is truly internal
│   └── Egress allowlist matches docs
├── Check: secret_management()
│   ├── No secrets in compose file
│   ├── .env not committed to git
│   └── Token entropy >= 128 bits
├── Check: log_integrity()
│   ├── Audit log exists
│   ├── Hash chain is valid
│   └── Rotation config is set
├── Check: skill_security()
│   ├── Scanner rules loaded
│   ├── Quarantine DB accessible
│   └── No quarantined skills bypassing enforcement
└── Check: documentation()
    ├── Network policy documented
    ├── Troubleshooting section exists
    └── Rebuild strategy documented
```

**Interface**:

```python
def main() -> int:
    """Run all checks. Return 0 if all pass, 1 if any fail."""
    checks = [
        container_hardening,
        network_isolation,
        secret_management,
        log_integrity,
        skill_security,
        documentation,
    ]
    findings: list[Finding] = []
    for check in checks:
        findings.extend(check())

    print_report(findings)
    return 0 if not findings else 1
```

**Data model**:

```python
@dataclass
class Finding:
    check: str          # e.g., "container_hardening"
    severity: str       # critical, high, medium, low
    message: str        # human-readable description
    remediation: str    # how to fix
```

Output: human-readable table + JSON (for CI parsing) controlled by `--format` flag.

---

### NFR-1: Performance Validation

**Files**: `scripts/audit.py` (extend), `tests/integration/`

**Design**:

1. **Startup time** — `audit.py` includes a `performance()` check:
   - Run `docker compose up -d`, measure time until health check passes
   - Compare against `AUDIT_STARTUP_THRESHOLD_SECONDS` (default 60)

2. **Latency** — Send 10 HTTP requests to proxy health endpoint, measure p95:
   - Compare against `AUDIT_LATENCY_P95_MS` (default 500)

3. These are informational checks (severity: `low`) unless thresholds are breached.

---

### NFR-2: CI / Maintainability

**Files**: `Dockerfile`, `docker/egress/Dockerfile`, docs

**Design**:

1. **Pin base images** — Replace:

   ```dockerfile
   FROM python:3.12-slim
   ```

   with:

   ```dockerfile
   FROM python:3.12-slim@sha256:<digest>
   ```

   Same for CoreDNS image. Document the digest update process.

2. **Rebuild strategy** — Add section to README:
   - When to rebuild: monthly, or when base image CVE is published
   - How: `docker compose build --no-cache`
   - CI hook: `audit.py` warns if image is older than 30 days

---

### NFR-3: Usability / Documentation

**Files**: `README.md`

**Design**: Add troubleshooting section covering:

| Symptom | Cause | Resolution |
|---------|-------|------------|
| Stack won't start | Docker not running / wrong version | Check `docker --version` ≥ 20.10 |
| 401 on all requests | Token mismatch | Regenerate token in `.env`, restart |
| DNS resolution fails | CoreDNS not healthy | Check `docker logs egress-dns` |
| Certificate errors | Caddy can't issue cert | Verify domain DNS, check Caddy logs |
| Skill quarantined unexpectedly | Scanner false positive | Review findings, use `override` command |
| Audit log not writing | Volume permissions | Check `audit-data` volume mount |

---

## Error Handling

| Component | Error | Handling |
|-----------|-------|----------|
| Pin verification | Hash mismatch | Quarantine immediately, log `SKILL_QUARANTINE` |
| Pin verification | Missing pin file | Warn in audit log, continue (fail-open) |
| Quarantine enforcement | Blocked skill | Return clear error message, log event |
| Audit rotation | Disk full | Log to stderr, continue operation |
| Audit tamper detection | Broken chain | `audit.py` reports as `critical` finding |
| Audit script | Docker not running | Exit with code 2 (prerequisite failure) |

---

## Security Considerations

- **Hash pinning** uses SHA-256 (collision-resistant for integrity checking)
- **Audit chain** prevents silent log deletion/modification
- **Quarantine enforcement** is fail-closed: if DB is unreachable, skill execution is blocked
- **Audit script** runs with read-only access to containers (inspect, no exec with write)
- **No new network exposure**: no new ports, services, or external dependencies

---

## Testing Strategy

| Requirement | Test Type | Description |
|-------------|-----------|-------------|
| FR-1 | Integration | Build image, inspect for SUID, verify non-root |
| FR-2 | Integration | Start stack, verify no host ports except proxy/caddy |
| FR-3 | Unit | Test `_verify_pin()` with matching, mismatching, and missing hashes |
| FR-3 | Unit | Test trust score persistence in DB after scan |
| FR-4 | Unit | Test `enforce_quarantine()` raises for quarantined skill |
| FR-4 | Integration | Attempt skill invocation while quarantined, verify rejection |
| FR-5 | Unit | Test rotation triggers at threshold, test hash chain validation |
| FR-6 | Integration | Run `audit.py` against healthy stack, expect exit 0 |
| FR-6 | Integration | Introduce a violation, expect non-zero exit |
| NFR-1 | Integration | Measure startup time, verify under threshold |

---

## Files Changed Summary

| File | Action | FR/NFR |
|------|--------|--------|
| `Dockerfile` | Edit (pin digest, remove SUID) | FR-1, NFR-2 |
| `docker/egress/Dockerfile` | Edit (pin digest) | NFR-2 |
| `docker-compose.yml` | Edit (remove openclaw port 3000) | FR-2 |
| `install.sh` | Edit (add `validate_image_hardening`) | FR-1 |
| `src/scanner/scanner.py` | Edit (add `_verify_pin`, wire trust score) | FR-3 |
| `src/quarantine/db.py` | No change (schema already supports trust_score) | — |
| `src/quarantine/manager.py` | Edit (add `enforce_quarantine`, exception) | FR-4 |
| `src/audit/logger.py` | Edit (add rotation, hash chain) | FR-5 |
| `src/models.py` | Edit (add `PinResult`) | FR-3 |
| `scripts/audit.py` | **New** | FR-6, NFR-1 |
| `config/skill-pins.json` | **New** (optional config) | FR-3 |
| `README.md` | Edit (troubleshooting, rebuild, network policy) | FR-2, NFR-2, NFR-3 |

## Dependencies

- **External**: None new. All changes use stdlib (`hashlib`, `json`, `subprocess`, `dataclasses`).
- **Internal**: `scripts/audit.py` imports from `src/` for shared models (optional — can be standalone).

## Out of Scope for This Design

- Real-time tamper alerting (webhook/email). Passive detection via audit script is sufficient for v0.1.
- Automated CI pipeline creation. Document the strategy; operators wire it into their CI.
- Skill pinning UI. Pins are managed via JSON file.
