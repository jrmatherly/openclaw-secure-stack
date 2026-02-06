# Tasks: requirements-audit

## Overview

12 files, 9 requirements. Tasks are ordered by dependency: data models first, then core logic, then integration points, then the audit script that validates everything, and finally documentation.

## Implementation Order

```text
[1.1 PinResult model] ──> [2.1 Skill pinning] ──> [2.2 Trust score wiring]
                                                         │
[3.1 QuarantineBlockedError] ──> [3.2 enforce_quarantine] ──> [3.3 Proxy integration]
                                                         │
[4.1 Log rotation] ──> [4.2 Hash chain] ────────────────┐│
                                                         ││
[5.1 Container hardening] ──> [5.2 install.sh validation]││
                                                         ││
[5.3 Network isolation] ────────────────────────────────>├┘
                                                         │
                                                    [6.1 audit.py]
                                                         │
                                                    [7.1 Docs]
```

---

## Task Group 1: Data Models (FR-3)

### 1.1 Add PinResult model

**Size:** S | **Type:** Unit | **FR:** FR-3

**TDD Steps:**

1. **RED:** Write test in `tests/unit/test_models.py`:

   ```python
   def test_pin_result_verified():
       r = PinResult(status="verified")
       assert r.status == "verified"
       assert r.expected is None

   def test_pin_result_mismatch():
       r = PinResult(status="mismatch", expected="aaa", actual="bbb")
       assert r.expected == "aaa"

   def test_pin_result_is_frozen():
       r = PinResult(status="verified")
       with pytest.raises(ValidationError):
           r.status = "mismatch"
   ```

2. **GREEN:** Add `PinResult` to `src/models.py`:

   ```python
   class PinResult(BaseModel, frozen=True):
       status: Literal["verified", "mismatch", "unpinned"]
       expected: str | None = None
       actual: str | None = None
   ```

3. **REFACTOR:** None expected — simple value object.

**Acceptance Criteria:**

- [ ] `PinResult` is importable from `src.models`
- [ ] Frozen (immutable)
- [ ] All three status values accepted

---

## Task Group 2: Skill Pinning & Trust Score (FR-3)

### 2.1 Add hash verification to scanner

**Size:** M | **Type:** Unit | **Dependencies:** 1.1 | **FR:** FR-3

**TDD Steps:**

1. **RED:** Write tests in `tests/unit/test_scanner.py`:

   ```python
   def test_verify_pin_matching_hash(tmp_path):
       skill = tmp_path / "skill.js"
       skill.write_text("console.log('hi')")
       digest = hashlib.sha256(skill.read_bytes()).hexdigest()
       pins = {"skill.js": {"sha256": digest}}
       scanner = SkillScanner(pin_data=pins)
       result = scanner._verify_pin(skill, "skill.js")
       assert result.status == "verified"

   def test_verify_pin_mismatch(tmp_path):
       skill = tmp_path / "skill.js"
       skill.write_text("console.log('hi')")
       pins = {"skill.js": {"sha256": "wrong"}}
       scanner = SkillScanner(pin_data=pins)
       result = scanner._verify_pin(skill, "skill.js")
       assert result.status == "mismatch"

   def test_verify_pin_unpinned(tmp_path):
       skill = tmp_path / "skill.js"
       skill.write_text("console.log('hi')")
       scanner = SkillScanner(pin_data={})
       result = scanner._verify_pin(skill, "skill.js")
       assert result.status == "unpinned"

   def test_scan_quarantines_on_pin_mismatch(tmp_path):
       # Full scan with mismatched pin should quarantine immediately
       ...
   ```

2. **GREEN:** Add `_verify_pin()` method to `SkillScanner`. Load `config/skill-pins.json` in `__init__` (optional file, empty dict if missing). Call `_verify_pin()` at the start of `scan()` — if mismatch, quarantine immediately and skip AST scan.
3. **REFACTOR:** Extract pin loading into a helper if needed.

**Acceptance Criteria:**

- [ ] Matching hash → scan proceeds normally
- [ ] Mismatched hash → immediate quarantine, no AST scan
- [ ] Missing pin file → scan proceeds with `unpinned` warning in audit log
- [ ] Missing pin for specific skill → `unpinned` status

---

### 2.2 Wire trust score persistence

**Size:** S | **Type:** Unit | **Dependencies:** 2.1 | **FR:** FR-3

**TDD Steps:**

1. **RED:** Test in `tests/unit/test_scanner.py`:

   ```python
   def test_scan_persists_trust_score(tmp_path, mock_db):
       # After scan, verify trust_score was passed to db.upsert_skill()
       scanner = SkillScanner(db=mock_db, ...)
       scanner.scan(skill_path)
       call_args = mock_db.upsert_skill.call_args
       assert call_args.kwargs["trust_score"] is not None
   ```

2. **GREEN:** In `scanner.py`, after computing trust score via `compute_trust_score()`, pass it to `self._db.upsert_skill(..., trust_score=score)`.
3. **REFACTOR:** None.

**Acceptance Criteria:**

- [ ] `upsert_skill` receives `trust_score` parameter after every scan
- [ ] Score is an integer 0–100

---

## Task Group 3: Quarantine Runtime Enforcement (FR-4)

### 3.1 Add QuarantineBlockedError

**Size:** S | **Type:** Unit | **FR:** FR-4

**TDD Steps:**

1. **RED:**

   ```python
   def test_quarantine_blocked_error():
       err = QuarantineBlockedError("my-skill")
       assert "my-skill" in str(err)
       assert err.skill_name == "my-skill"
   ```

2. **GREEN:** Add exception class to `src/quarantine/manager.py`.
3. **REFACTOR:** None.

---

### 3.2 Add enforce_quarantine method

**Size:** M | **Type:** Unit | **Dependencies:** 3.1 | **FR:** FR-4

**TDD Steps:**

1. **RED:**

   ```python
   def test_enforce_quarantine_blocks_quarantined_skill(mock_db, mock_audit):
       mock_db.get_skill.return_value = {"name": "evil", "status": "quarantined"}
       mgr = QuarantineManager(db=mock_db, audit_logger=mock_audit)
       with pytest.raises(QuarantineBlockedError):
           mgr.enforce_quarantine("evil")
       mock_audit.log.assert_called_once()

   def test_enforce_quarantine_allows_active_skill(mock_db):
       mock_db.get_skill.return_value = {"name": "good", "status": "active"}
       mgr = QuarantineManager(db=mock_db)
       mgr.enforce_quarantine("good")  # should not raise

   def test_enforce_quarantine_allows_unknown_skill(mock_db):
       mock_db.get_skill.return_value = None
       mgr = QuarantineManager(db=mock_db)
       mgr.enforce_quarantine("unknown")  # should not raise

   def test_enforce_quarantine_allows_overridden_skill(mock_db):
       mock_db.get_skill.return_value = {"name": "risky", "status": "overridden"}
       mgr = QuarantineManager(db=mock_db)
       mgr.enforce_quarantine("risky")  # should not raise
   ```

2. **GREEN:** Implement `enforce_quarantine()` in `QuarantineManager`.
3. **REFACTOR:** None.

**Acceptance Criteria:**

- [ ] Quarantined → raises `QuarantineBlockedError`, logs audit event
- [ ] Active / overridden / unknown → no exception

---

### 3.3 Integrate enforcement into proxy

**Size:** M | **Type:** Integration | **Dependencies:** 3.2 | **FR:** FR-4

**TDD Steps:**

1. **RED:** Integration test in `tests/integration/`:

   ```python
   async def test_proxy_blocks_quarantined_skill(client, quarantine_db):
       quarantine_db.upsert_skill(name="blocked-skill", status="quarantined", ...)
       response = await client.post("/skills/blocked-skill/invoke", ...)
       assert response.status_code == 403
       assert "quarantined" in response.json()["error"]["message"].lower()
   ```

2. **GREEN:** Add middleware or dependency in proxy that extracts skill name from request path and calls `enforce_quarantine()`. Catch `QuarantineBlockedError` → return 403.
3. **REFACTOR:** Ensure the check is in a reusable dependency, not inline.

**Acceptance Criteria:**

- [ ] Proxy returns 403 for quarantined skill invocations
- [ ] Non-skill requests are unaffected
- [ ] Audit event logged on block

---

## Task Group 4: Audit Log Hardening (FR-5)

### 4.1 Add log rotation

**Size:** M | **Type:** Unit | **FR:** FR-5

**TDD Steps:**

1. **RED:**

   ```python
   def test_rotation_triggers_at_threshold(tmp_path):
       logger = AuditLogger(path=tmp_path / "audit.jsonl", max_bytes=100, backup_count=3)
       for i in range(20):
           logger.log(make_event(f"event-{i}"))
       assert (tmp_path / "audit.jsonl.1").exists()

   def test_rotation_deletes_oldest(tmp_path):
       logger = AuditLogger(path=tmp_path / "audit.jsonl", max_bytes=50, backup_count=2)
       for i in range(50):
           logger.log(make_event(f"event-{i}"))
       assert not (tmp_path / "audit.jsonl.3").exists()

   def test_rotation_configurable_via_env(monkeypatch, tmp_path):
       monkeypatch.setenv("AUDIT_LOG_MAX_BYTES", "500")
       monkeypatch.setenv("AUDIT_LOG_BACKUP_COUNT", "7")
       logger = AuditLogger.from_env(tmp_path / "audit.jsonl")
       assert logger._max_bytes == 500
       assert logger._backup_count == 7
   ```

2. **GREEN:** Add `max_bytes` and `backup_count` to `AuditLogger.__init__`. Implement `_maybe_rotate()` called before each write.
3. **REFACTOR:** Extract rotation logic into a private method.

**Acceptance Criteria:**

- [ ] Rotation triggers when file exceeds `max_bytes`
- [ ] Old files are numbered `.1`, `.2`, etc.
- [ ] Oldest beyond `backup_count` is deleted
- [ ] Configurable via env vars

---

### 4.2 Add hash chain tamper detection

**Size:** M | **Type:** Unit | **Dependencies:** 4.1 | **FR:** FR-5

**TDD Steps:**

1. **RED:**

   ```python
   def test_log_entries_include_prev_hash(tmp_path):
       logger = AuditLogger(path=tmp_path / "audit.jsonl")
       logger.log(make_event("first"))
       logger.log(make_event("second"))
       lines = (tmp_path / "audit.jsonl").read_text().strip().split("\n")
       first = json.loads(lines[0])
       second = json.loads(lines[1])
       assert "prev_hash" in second
       expected = hashlib.sha256(lines[0].encode()).hexdigest()
       assert second["prev_hash"] == expected

   def test_first_entry_has_null_prev_hash(tmp_path):
       logger = AuditLogger(path=tmp_path / "audit.jsonl")
       logger.log(make_event("first"))
       entry = json.loads((tmp_path / "audit.jsonl").read_text().strip())
       assert entry["prev_hash"] is None

   def test_validate_chain_detects_tampering(tmp_path):
       logger = AuditLogger(path=tmp_path / "audit.jsonl")
       for i in range(5):
           logger.log(make_event(f"event-{i}"))
       lines = (tmp_path / "audit.jsonl").read_text().strip().split("\n")
       lines[2] = lines[2].replace("event-2", "TAMPERED")
       (tmp_path / "audit.jsonl").write_text("\n".join(lines) + "\n")
       result = validate_audit_chain(tmp_path / "audit.jsonl")
       assert not result.valid
       assert result.broken_at_line == 3
   ```

2. **GREEN:** Add `prev_hash` field to each log entry. Track `_last_line_hash` in logger state. Add `validate_audit_chain()` utility function.
3. **REFACTOR:** Ensure chain survives rotation (hash of last line before rotation carries to new file).

**Acceptance Criteria:**

- [ ] Every log line includes `prev_hash`
- [ ] Chain validates when untampered
- [ ] Tampered lines are detected with line number
- [ ] `validate_audit_chain()` is usable by audit script

---

## Task Group 5: Container & Network Hardening (FR-1, FR-2, NFR-2)

### 5.1 Harden Dockerfile

**Size:** S | **Type:** Infrastructure | **FR:** FR-1, NFR-2

**Steps:**

1. Pin base image with `@sha256:` digest in both stages
2. Add `RUN find / -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true` in runtime stage
3. Verify `USER 65534` is already present (no change)

**Acceptance Criteria:**

- [ ] Base image pinned by digest
- [ ] No SUID/SGID binaries in built image
- [ ] Image builds successfully

---

### 5.2 Add image hardening validation to install.sh

**Size:** S | **Type:** Infrastructure | **Dependencies:** 5.1 | **FR:** FR-1

**Steps:**

1. Add `validate_image_hardening()` function
2. Call it after `docker compose build`
3. Fail install if checks don't pass

**Acceptance Criteria:**

- [ ] Function checks non-root user, no SUID binaries
- [ ] Install fails if image is not hardened

---

### 5.3 Fix network isolation

**Size:** S | **Type:** Infrastructure | **FR:** FR-2

**Steps:**

1. Remove `ports: ["3000:3000"]` from `openclaw` service in `docker-compose.yml`
2. Pin egress Dockerfile base image by digest

**Acceptance Criteria:**

- [ ] OpenClaw is not accessible on host port 3000
- [ ] OpenClaw is reachable from proxy via internal network
- [ ] Egress Dockerfile base image is pinned

---

## Task Group 6: Security Audit Script (FR-6, NFR-1)

### 6.1 Create scripts/audit.py

**Size:** L | **Type:** Integration | **Dependencies:** 4.2, 5.1, 5.3 | **FR:** FR-6, NFR-1

**TDD Steps:**

1. **RED:** Tests in `tests/integration/test_audit_script.py`:

   ```python
   def test_audit_script_exits_zero_when_clean(healthy_stack):
       result = subprocess.run(["python", "scripts/audit.py"], capture_output=True)
       assert result.returncode == 0

   def test_audit_script_exits_nonzero_on_finding():
       result = subprocess.run(["python", "scripts/audit.py"], capture_output=True)
       assert result.returncode == 1

   def test_audit_json_output():
       result = subprocess.run(
           ["python", "scripts/audit.py", "--format", "json"],
           capture_output=True
       )
       findings = json.loads(result.stdout)
       assert isinstance(findings, list)

   def test_container_hardening_check():
       findings = container_hardening()
       for f in findings:
           assert f.check and f.severity and f.message and f.remediation
   ```

2. **GREEN:** Implement `scripts/audit.py` with check functions:
   - `container_hardening()` — inspect images for non-root, read-only, caps, SUID
   - `network_isolation()` — inspect compose for published ports, verify internal network
   - `secret_management()` — check `.env` not in git, no secrets in compose
   - `log_integrity()` — call `validate_audit_chain()`, check rotation config
   - `skill_security()` — verify scanner rules loaded, quarantine DB accessible
   - `documentation()` — check troubleshooting and network policy sections exist
   - `performance()` (NFR-1) — startup time and latency checks (informational)
3. **REFACTOR:** Extract `Finding` dataclass, `print_report()`, `--format` flag handling.

**Acceptance Criteria:**

- [ ] `scripts/audit.py` is executable
- [ ] Exit 0 = no findings, exit 1 = findings, exit 2 = prerequisite failure
- [ ] `--format json` outputs machine-parseable findings
- [ ] Covers: container hardening, network, secrets, logs, skills, docs, performance

---

## Task Group 7: Documentation (FR-2, NFR-2, NFR-3)

### 7.1 Update README and docs

**Size:** M | **Type:** Documentation | **Dependencies:** 5.3, 6.1 | **FR:** FR-2, NFR-2, NFR-3

**Steps:**

1. Add **Troubleshooting** section to README with common failure modes table
2. Add **Network Policy** section (or `docs/network-policy.md`) with topology, egress policy, port exposure rules
3. Add **Maintenance / Rebuild Strategy** section covering base image updates and `audit.py` usage
4. Update egress documentation to match actual CoreDNS config

**Acceptance Criteria:**

- [ ] Troubleshooting covers: startup, auth, DNS, certs, quarantine, audit logs
- [ ] Network policy documents all networks, ports, and egress rules
- [ ] Rebuild strategy is documented
- [ ] `audit.py` documentation check passes

---

## Summary

| Group | Tasks | Size | FR/NFR |
|-------|-------|------|--------|
| 1. Data Models | 1.1 | S | FR-3 |
| 2. Skill Pinning | 2.1, 2.2 | M, S | FR-3 |
| 3. Quarantine Enforcement | 3.1, 3.2, 3.3 | S, M, M | FR-4 |
| 4. Audit Log Hardening | 4.1, 4.2 | M, M | FR-5 |
| 5. Container & Network | 5.1, 5.2, 5.3 | S, S, S | FR-1, FR-2, NFR-2 |
| 6. Audit Script | 6.1 | L | FR-6, NFR-1 |
| 7. Documentation | 7.1 | M | FR-2, NFR-2, NFR-3 |

**Total:** 12 tasks (5S, 5M, 1L, 1 doc-only M)

## Definition of Done

- [ ] All unit tests pass (`pytest tests/unit/`)
- [ ] All integration tests pass (`pytest tests/integration/`)
- [ ] `ruff check` and `mypy` pass
- [ ] `scripts/audit.py` exits 0 against the built stack
- [ ] Every traceability matrix row reaches **Met**
- [ ] Code reviewed
