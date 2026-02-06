# Requirements Document — requirements-audit

## Introduction

Requirements derived from the traceability matrix gap analysis (`traceability-matrix.md`) and audit plan (`plan.md`). Each requirement traces to a specific gap identified during the security audit of the OpenClaw Secure Stack.

**Project**: OpenClaw Secure Stack
**Feature**: requirements-audit
**Date**: 2026-02-02

---

## Functional Requirements

### FR-1: Container Hardening

**Source Gap**: FR-1 Partial — proxy image uses `python:3.12-slim` with manual purge but no formal image-hardening validation.

**Requirements**:

1. The proxy container image SHALL use a minimal or distroless base image with no unnecessary packages installed. _(Ubiquitous)_
2. `install.sh` SHALL validate that the OpenClaw image meets hardening criteria (no shell in production, no SUID binaries, non-root user). _(Ubiquitous)_

**Acceptance Criteria**:

- [ ] Proxy Dockerfile uses a minimal base (e.g., `python:3.12-slim` with explicit package purge, or distroless)
- [ ] `install.sh` includes an image-hardening check that fails on violation
- [ ] No container runs as root in default configuration

---

### FR-2: Network Isolation

**Source Gap**: FR-2 Partial — openclaw service publishes port 3000:3000 to the host; egress policy documentation is incomplete.

**Requirements**:

1. No container SHALL publish ports to the host unless explicitly configured by the operator. _(Ubiquitous)_
2. WHEN egress restrictions change THEN the documentation (`README.md` or dedicated network doc) SHALL be updated to reflect the current policy. _(Event-Driven)_

**Acceptance Criteria**:

- [ ] `docker-compose.yml` removes `ports: ["3000:3000"]` from openclaw; only proxy (8080) and caddy (8443) are host-facing
- [ ] Egress policy is documented and matches the actual CoreDNS/firewall configuration
- [ ] Changing an egress rule without updating docs causes an audit script warning

---

### FR-3: Skill Pinning & Trust Score

**Source Gap**: FR-3 Partial — skills are scanned but not pinned by hash; trust score not persisted.

**Requirements**:

1. WHERE a skill pin file exists WHEN a skill is scanned THEN the scanner SHALL verify the skill's content hash against the pinned SHA-256 hash. _(Optional + Event-Driven)_
2. IF a pinned hash does not match THEN the scanner SHALL quarantine the skill immediately without further scanning. _(Unwanted Behavior)_
3. IF no pin file or no pin entry exists for a skill THEN the scanner SHALL log a warning and proceed with AST scanning (fail-open). _(Unwanted Behavior)_
4. The system SHALL persist a trust score for each skill in the quarantine database. _(Ubiquitous)_

**Acceptance Criteria**:

- [ ] `config/skill-pins.json` maps each skill name to a single SHA-256 hash computed over the skill directory contents
- [ ] Scanner rejects (quarantines) skills whose content hash does not match the pinned hash
- [ ] Missing pin file or missing entry for a skill results in an audit log warning, not a rejection
- [ ] Trust score is stored in the quarantine DB and queryable

---

### FR-4: Quarantine Runtime Enforcement

**Source Gap**: FR-4 Partial — quarantine DB exists but runtime enforcement is not verified.

**Requirements**:

1. WHILE a skill is quarantined THE system SHALL prevent its execution and return a clear rejection message. _(State-Driven)_

**Acceptance Criteria**:

- [ ] Attempting to invoke a quarantined skill returns an error indicating quarantine status
- [ ] No code path bypasses the quarantine check
- [ ] Integration test confirms quarantined skill cannot execute

---

### FR-5: Audit Log Hardening

**Source Gap**: FR-10 Partial — audit logging exists but lacks append-only enforcement and tamper detection.

**Requirements**:

1. Audit logs SHALL be append-only with configurable rotation and retention policies. _(Ubiquitous)_
2. Each audit log entry SHALL include a `prev_hash` field forming a SHA-256 hash chain for integrity verification. _(Ubiquitous)_
3. IF the audit script detects a broken hash chain THEN it SHALL report a `critical` finding. _(Unwanted Behavior)_

**Acceptance Criteria**:

- [ ] Log files are opened in append-only mode
- [ ] Rotation and retention are configurable via environment variables or config file
- [ ] Each log line includes `prev_hash` (null for the first entry)
- [ ] `scripts/audit.py` validates the hash chain and reports broken chains as `critical` findings
- [ ] Tamper detection is passive (audit-script-based); real-time alerting is out of scope for v0.1

---

### FR-6: Security Audit Script

**Source Gap**: NFR-2 Gap — no automated OWASP-aligned security validation exists.

**Requirements**:

1. `scripts/audit.py` SHALL exist and perform OWASP-aligned security checks against the running stack. _(Ubiquitous)_
2. The audit script SHALL exit with code 0 only when zero findings are reported. _(Ubiquitous)_

**Acceptance Criteria**:

- [ ] `scripts/audit.py` exists and is executable
- [ ] Script checks at minimum: container hardening, network isolation, secret management, log integrity
- [ ] Exit code 0 = pass (no findings); non-zero = fail
- [ ] Script output is human-readable and CI-friendly

---

## Non-Functional Requirements

### NFR-1: Performance Validation

**Source Gap**: NFR-1 Partial — no startup-time or latency benchmarks defined.

**Requirements**:

1. The stack SHALL start within a defined startup-time threshold (configurable, default 60s). _(Ubiquitous)_
2. WHEN the proxy receives a request THEN it SHALL respond within the configured latency threshold (default 500ms p95). _(Event-Driven)_

**Acceptance Criteria**:

- [ ] Startup time is measured by `scripts/audit.py` and compared against a configurable threshold
- [ ] Latency p95 is measured by `scripts/audit.py` via health-check requests
- [ ] Thresholds are configurable via environment variables
- [ ] Performance findings are informational (severity: `low`) unless thresholds are breached

---

### NFR-2: CI / Maintainability

**Source Gap**: NFR-4 Partial — no documented rebuild strategy; base images not pinned.

**Requirements**:

1. All Dockerfiles SHALL pin base image versions using digest or explicit tag. _(Ubiquitous)_
2. The rebuild strategy (when and how to rebuild images) SHALL be documented. _(Ubiquitous)_

**Acceptance Criteria**:

- [ ] No Dockerfile uses `:latest` without a pinned digest
- [ ] `README.md` or `MAINTENANCE.md` documents the rebuild strategy
- [ ] CI pipeline validates base image pinning

---

### NFR-3: Usability / Documentation

**Source Gap**: NFR-3 Partial — troubleshooting section incomplete.

**Requirements**:

1. The documentation SHALL include a troubleshooting section covering common failure modes. _(Ubiquitous)_

**Acceptance Criteria**:

- [ ] Troubleshooting section exists in README or dedicated doc
- [ ] Covers at minimum: startup failures, DNS resolution issues, certificate errors, quarantine behavior
- [ ] Each entry includes symptom, cause, and resolution

---

## Out of Scope

- GUI / web dashboard
- Multi-tenancy
- Kubernetes deployment
- Windows native support

## Success Criteria

Every row in the traceability matrix (`traceability-matrix.md`) reaches status **Met**.
