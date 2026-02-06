# Requirements Document Improvements - Complete Unified Version

Please replace the entire requirements document with this updated version:

---

# Requirements Document

## Project Description (Input)

### Original Description

A secure Docker-based deployment solution for OpenClaw AI agent (100k+ GitHub stars in 48 hours) that addresses critical security vulnerabilities discovered by Cisco, Vectra AI, and security researchers in January 2026. The solution provides: (1) Default Security via distroless images, least-privilege containers, and network isolation; (2) Skills Supply-Chain Protection with automatic scanning for malicious patterns in skills; (3) One-Click Deployment via install.sh that auto-generates strong tokens and runs with docker-compose up.

## Business Justification (Why)

OpenClaw is a popular AI agent (100k+ GitHub stars) with serious security issues: 26% of skills contain vulnerabilities, the top-ranked skill is malware, it is easily vulnerable to prompt-injection attacks, and its default configuration is unsafe with over-privileged tools and open network access. Users who self-host OpenClaw are exposed to these risks with no easy mitigation path.

Recent documented attacks include:

- "What Would Elon Do?" skill (4,000+ downloads) contained data exfiltration code
- Security researchers demonstrated private key extraction via malicious email in under 5 minutes  
- OWASP classifies prompt injection as the #1 LLM vulnerability with no industry-wide solution
- Cisco's Skill Scanner found 2 critical and 5 high-severity vulnerabilities in popular skills

This project provides a secure-by-default deployment that eliminates the most critical attack vectors without requiring security expertise from the user. One command (docker-compose up) gives users a hardened OpenClaw instance with supply-chain protection for skills.

## Target Users (Who)

**PRIMARY:** Developers and small teams (1-10 people) who want privacy via self-hosting but lack dedicated security expertise.

**SECONDARY:** Enterprise DevOps/SRE teams evaluating AI agents for internal deployment (need audit trails and compliance).

**TERTIARY:** Security researchers and hobbyists who want a reference implementation of "secure-by-default" AI agent architecture.

## Core Features (What)

Security requirements include: (1) Container security - distroless base image, non-root user, dropped capabilities, read-only filesystem where possible. (2) Network security - isolated Docker network, no unnecessary port exposure, egress filtering. (3) Supply-chain security - automatic scanning of OpenClaw skills for malicious patterns (dangerous dynamic code execution, network exfiltration, file system abuse). (4) Authentication - auto-generated strong API tokens via install.sh. (5) Prompt injection mitigation - input sanitization layer. (6) Secrets management - no hardcoded secrets, .env-based configuration.

## Success Criteria

1. Scanner achieves 100% detection rate on the "malicious skills test suite" (minimum 50 samples from real-world incidents)
2. Default deployment scores >= 90/100 on CIS Docker Benchmark automated scan
3. 95th percentile setup time under 3 minutes on 4-core, 8GB RAM machine
4. Zero findings on OWASP ZAP automated scan with "Medium" or higher severity
5. Community adoption: 100+ GitHub stars within first week, 1,000+ Docker pulls within first month
6. Security validation: Reviewed and endorsed by at least one security researcher or firm

## Key Decisions

- **Scanner action on flagged skills**: Quarantine with user force-override option (explicit acknowledgment required)
- **Database**: Self-contained (SQLite or file-based), no external database dependency
- **Egress policy**: Allowlist-only — all outbound traffic blocked except explicitly permitted LLM API endpoints

---

## Functional Requirements

### FR-1: Secure Container Runtime

WHEN the system is deployed via docker-compose
THEN the system SHALL run the OpenClaw container using a distroless base image, a non-root user, with all unnecessary Linux capabilities dropped, and a read-only root filesystem.

**Acceptance Criteria:**

1. Container runs as a non-root user (UID >= 1000)
2. `docker inspect` shows `no-new-privileges:true` and all capabilities dropped except those explicitly required
3. Root filesystem is mounted read-only; only designated volumes are writable
4. Base image contains no shell, package manager, or unnecessary binaries

### FR-2: Network Isolation

WHEN the system is deployed
THEN the system SHALL place all containers on an isolated Docker network with egress restricted to an allowlist of LLM API endpoint domains.

**Acceptance Criteria:**

1. Containers communicate only via an internal bridge network not exposed to the host network
2. Outbound traffic is blocked by default; only domains listed in the egress allowlist are reachable
3. No unnecessary ports are published to the host
4. DNS resolution is restricted to allowlisted domains

### FR-3: Skills Supply-Chain Scanner

WHEN a skill is loaded or installed
THEN the system SHALL scan the skill source code for malicious patterns including dangerous dynamic code APIs, network exfiltration attempts, and unauthorized filesystem access, and report the results.

**Acceptance Criteria:**

1. Scanner detects calls to dangerous dynamic code APIs (e.g., dynamic evaluation, process spawning, child process creation)
2. Scanner detects outbound network requests to non-allowlisted domains
3. Scanner detects filesystem writes outside designated directories
4. Scan results include the pattern matched, file path, and line number
5. Scanner completes within 5 seconds per skill
6. Scanner supports skill pinning: skills can be locked to a specific commit hash or checksum
7. Scanner provides a "trust score" based on: author reputation, download count, community reviews, last update date
8. Scanner integrates with VoltAgent/awesome-openclaw-skills allowlist (opt-in)

### FR-4: Skills Quarantine

WHEN the scanner flags a skill as potentially malicious
THEN the system SHALL quarantine the skill, preventing its execution, and provide the user an option to force-override with explicit acknowledgment of the risk.

**Acceptance Criteria:**

1. Flagged skills are moved to a quarantine directory and cannot be loaded or run
2. A clear warning message describes why the skill was flagged
3. Force-override requires the user to explicitly acknowledge the risk (e.g., `--force-allow` flag or confirmation prompt)
4. Override decisions are logged with timestamp and user identifier
5. Quarantined skills can be re-scanned after modification

### FR-5: One-Click Deployment

WHEN a user runs `install.sh`
THEN the system SHALL validate prerequisites (Docker, docker-compose), generate secure API tokens, create the `.env` file, and launch the stack via `docker-compose up`.

**Acceptance Criteria:**

1. Script checks for Docker >= 20.10 and docker-compose >= 2.0
2. Script generates a cryptographically random API token (minimum 32 bytes, base64-encoded)
3. Script creates `.env` from `.env.example` without overwriting existing `.env`
4. Script exits with clear error messages if prerequisites are missing
5. After successful run, the stack is running and accessible

### FR-6: Authentication

WHEN any request is made to the system's API endpoints
THEN the system SHALL require a valid API token in the `Authorization` header and reject unauthenticated requests with HTTP 401.

**Acceptance Criteria:**

1. All API endpoints require Bearer token authentication
2. Unauthenticated requests receive HTTP 401 with a generic error message (no information leakage)
3. Invalid tokens receive HTTP 403
4. Token is auto-generated during `install.sh` and stored in `.env`
5. Token comparison uses constant-time equality to prevent timing attacks

### FR-7: Secrets Management

The system SHALL store all secrets and configuration values in a `.env` file, never hardcode secrets in source code, and ensure `.env` is listed in `.gitignore`.

**Acceptance Criteria:**

1. No secrets (API keys, tokens, passwords) appear in any committed source file
2. `.env` is listed in `.gitignore`
3. `.env.example` provides documented placeholders for all required configuration
4. Application reads secrets exclusively from environment variables at runtime

### FR-8: Prompt Injection Mitigation

WHEN user-facing input is received by the system
THEN the system SHALL pass the input through a sanitization layer that detects and neutralizes common prompt injection patterns before forwarding to the LLM.

**Acceptance Criteria:**

1. Sanitizer detects known prompt injection patterns (e.g., "ignore previous instructions", delimiter injection, role-switching attempts)
2. Detected injections are logged and either stripped or rejected
3. Sanitization does not alter legitimate user input
4. Sanitization rules are configurable via a rules file

### FR-9: Egress Allowlist Management

The system SHALL provide a configurable allowlist file that defines permitted external domains for outbound network requests.

**Acceptance Criteria:**

1. Allowlist is stored in a human-readable configuration file (e.g., `egress-allowlist.conf`)
2. Default allowlist includes only necessary LLM API endpoints (e.g., `api.openai.com`, `api.anthropic.com`)
3. Changes to the allowlist take effect after container restart
4. Invalid entries in the allowlist are logged as warnings and ignored

### FR-10: Security Audit Logging

WHEN the system performs any security-sensitive operation (skill scan, quarantine, override, authentication failure)
THEN the system SHALL log the event with timestamp, user/source, action, and outcome in a tamper-evident format.

**Acceptance Criteria:**

1. Logs include: timestamp (ISO8601), event type, source IP/user, action, result, risk level
2. Logs are written to a structured format (JSON Lines) for SIEM integration
3. Logs are rotated and retained for minimum 90 days (configurable)
4. Audit log file is read-only to the application user
5. Log entries cannot be deleted or modified by the application

---

## Non-Functional Requirements

### NFR-1: Performance

The system SHALL start all containers within 60 seconds of `docker-compose up`, and the skills scanner SHALL complete analysis of a single skill within 5 seconds.

**Acceptance Criteria:**

1. Cold start (first `docker-compose up`) completes within 60 seconds on a standard development machine
2. Warm start (subsequent runs) completes within 30 seconds
3. Skills scanner processes one skill in under 5 seconds
4. Authentication middleware adds less than 5ms latency per request

### NFR-2: Security

The system SHALL address all applicable OWASP Top 10 attack vectors and use a base container image with zero known CVEs at time of release.

**Acceptance Criteria:**

1. Container image scan (e.g., Trivy) reports zero critical or high CVEs
2. Deployment configuration addresses: broken access control, cryptographic failures, injection, insecure design, security misconfiguration, vulnerable components, authentication failures, logging failures, and SSRF
3. Security configuration is documented and auditable
4. Provides automated security audit script (`scripts/audit.py`) that checks 34 OpenClaw official security items
5. Security configuration is version-controlled and can be diffed between releases
6. Includes penetration testing scenarios in `tests/security/`

### NFR-3: Usability

The system SHALL enable a user to go from `git clone` to a running secure instance in under 5 minutes, with clear error messages for any failures.

**Acceptance Criteria:**

1. Setup requires no manual configuration beyond running `install.sh`
2. Error messages include the problem description and suggested resolution
3. A README documents all configuration options and troubleshooting steps
4. `docker-compose logs` provides meaningful operational information

### NFR-4: Maintainability

The system SHALL support automated base image rebuilds and scanner rule updates without requiring changes to application code.

**Acceptance Criteria:**

1. Scanner rules are defined in a separate configuration file, not embedded in code
2. Dockerfile uses multi-stage builds to allow base image updates independently
3. CI pipeline can rebuild and re-scan images on a schedule
4. Dependency versions are pinned and documented

---

## Out of Scope (MVP)

1. Web-based GUI for skill management (CLI only in MVP)
2. Multi-tenancy support (single-user deployment only)
3. Kubernetes deployment (Docker Compose only)
4. Custom LLM integration beyond OpenAI/Anthropic (future enhancement)
5. Windows native deployment (WSL2 or Docker Desktop required)

## Constraints

1. Must run on Docker >= 20.10 and docker-compose >= 2.0
2. No external database dependency — all state is self-contained (SQLite or file-based)
3. Must work offline after initial image pull (except for LLM API calls)
4. Must not modify OpenClaw core source code — all security layers are additive
5. Must maintain <100MB total image size for fast deployment (excluding OpenClaw base image)
6. Must support ARM64 architecture for deployment on Apple Silicon and Raspberry Pi

## Assumptions

1. Users have Docker and docker-compose installed on their host
2. Users have internet access for initial setup (image pull, LLM API)
3. OpenClaw publishes a usable Docker image or Dockerfile
4. LLM API endpoints use HTTPS
5. Assumes OpenClaw project remains active and maintains backward compatibility
6. Assumes LLM providers do not block self-hosted agent traffic
7. Assumes users accept that "secure by default" may limit some OpenClaw features (documented in README)
