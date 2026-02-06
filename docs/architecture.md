# Architecture Documentation

## System Context Diagram

```mermaid
graph TB
    User["Client Application"]
    Admin["Admin / CLI User"]

    subgraph "OpenClaw Secure Stack"
        Proxy["Proxy<br/>(FastAPI)"]
        OCW["OpenClaw Gateway"]
        DNS["Egress DNS<br/>(CoreDNS)"]
        Caddy["Caddy<br/>(HTTPS)"]
    end

    LLM["LLM Provider<br/>(OpenAI / Anthropic)"]
    Telegram["Telegram API"]

    User -- "Bearer Token<br/>HTTP :8080" --> Proxy
    Admin -- "HTTPS :8443" --> Caddy
    Caddy --> OCW
    Proxy -- "Internal :3000" --> OCW
    OCW -- "DNS Query" --> DNS
    DNS -- "Filtered DNS" --> LLM
    OCW -- "API Calls<br/>(egress-filtered)" --> LLM
    OCW -. "Optional" .-> Telegram
```

## Component Diagram

```mermaid
graph TB
    subgraph "Proxy Service"
        Auth["AuthMiddleware<br/>hmac.compare_digest"]
        Sanitizer["PromptSanitizer<br/>strip / reject"]
        QCheck["Quarantine Check"]
        Forward["HTTP Forwarder<br/>httpx.AsyncClient"]
        RespScan["Response Scanner"]
    end

    subgraph "Scanner Service"
        Scanner["SkillScanner"]
        PinVerify["Pin Verification<br/>SHA-256"]
        AST["Tree-sitter Parser"]
        PatRule["PatternScanRule"]
        ASTRules["AST Rules<br/>DangerousAPI<br/>NetworkExfil<br/>FSAbuse"]
    end

    subgraph "Quarantine Service"
        QMgr["QuarantineManager"]
        QDB["QuarantineDB<br/>SQLite"]
    end

    subgraph "Governance Service"
        Classifier["IntentClassifier"]
        Planner["PlanGenerator"]
        Validator["PolicyValidator"]
        Approver["ApprovalGate"]
        Enforcer["GovernanceEnforcer"]
        SessMgr["SessionManager"]
        PlanStore["PlanStore<br/>HMAC tokens"]
        GovDB["GovernanceDB<br/>SQLite WAL"]
    end

    subgraph "Audit Service"
        AuditLog["AuditLogger<br/>JSONL + hash chain"]
    end

    Auth --> Sanitizer --> QCheck --> Forward --> RespScan
    QCheck --> QMgr
    QMgr --> QDB
    QMgr --> Scanner
    Scanner --> PinVerify
    Scanner --> AST
    AST --> PatRule
    AST --> ASTRules

    Classifier --> Planner --> Validator
    Validator --> Approver
    Validator --> PlanStore
    PlanStore --> GovDB
    Approver --> GovDB
    Enforcer --> PlanStore
    SessMgr --> GovDB

    Auth --> AuditLog
    Scanner --> AuditLog
    QMgr --> AuditLog
    Sanitizer --> AuditLog
    RespScan --> AuditLog
```

## Request Lifecycle Sequence

```mermaid
sequenceDiagram
    participant C as Client
    participant AM as AuthMiddleware
    participant S as PromptSanitizer
    participant Q as QuarantineManager
    participant P as Proxy Handler
    participant RS as Response Scanner
    participant OC as OpenClaw Gateway
    participant AL as AuditLogger

    C->>AM: POST /v1/chat/completions<br/>Authorization: Bearer <token>
    AM->>AM: hmac.compare_digest(token)
    alt Invalid token
        AM-->>C: 401 / 403
        AM->>AL: auth_failure event
    end
    AM->>AL: auth_success event
    AM->>S: Forward request

    S->>S: Recursive string sanitization
    alt Reject rule triggered
        S-->>C: 400 Policy violation
        S->>AL: prompt_injection event
    end

    S->>Q: Check quarantine (skills/* paths)
    alt Skill quarantined
        Q-->>C: 403 Skill quarantined
        Q->>AL: skill_quarantine blocked
    end

    Q->>P: Pass through
    P->>OC: Forward with gateway token

    OC-->>P: Response (streaming or full)

    P->>RS: Scan response body
    alt Injection detected
        RS->>AL: indirect_injection event
        RS-->>P: Set X-Prompt-Guard header
    end

    P-->>C: Response
```

## Governance Pipeline Sequence

```mermaid
sequenceDiagram
    participant R as Request
    participant MW as GovernanceMiddleware
    participant IC as IntentClassifier
    participant PG as PlanGenerator
    participant PV as PolicyValidator
    participant SM as SessionManager
    participant PS as PlanStore
    participant AG as ApprovalGate
    participant GE as GovernanceEnforcer

    R->>MW: evaluate(request_body, session_id, user_id)
    MW->>SM: get_or_create(session_id)
    SM-->>MW: Session

    MW->>IC: classify(request_body)
    IC->>IC: Extract tool calls
    IC->>IC: Categorize tools
    IC->>IC: Analyze arguments
    IC-->>MW: Intent

    MW->>PG: generate(intent, request_body, session_id)
    PG->>PG: Build PlannedActions
    PG->>PG: Extract resources
    PG->>PG: Assess risk
    PG-->>MW: ExecutionPlan

    MW->>PV: validate(plan, session)
    PV->>PV: Check action policies
    PV->>PV: Check resource policies
    PV->>PV: Check sequence policies
    PV->>PV: Check rate policies
    PV-->>MW: ValidationResult

    alt ALLOW
        MW->>PS: store(plan)
        PS-->>MW: plan_id + HMAC token
        MW->>SM: record_action(...)
    else REQUIRE_APPROVAL
        MW->>PS: store_pending(plan)
        MW->>AG: create_request(plan_id, violations)
        AG-->>MW: ApprovalRequest
    else BLOCK
        MW-->>R: Blocked with violations
    end

    Note over GE: At execution time
    R->>GE: enforce_action(plan_id, token, tool_call)
    GE->>PS: verify_token(plan_id, token)
    GE->>PS: lookup(plan_id)
    GE->>PS: get_current_sequence(plan_id)
    GE->>GE: Match tool call to plan
    GE-->>R: EnforcementResult
```

## Skill Scan Flow

```mermaid
flowchart TD
    Start([scan skill_path]) --> Checksum[Compute SHA-256 checksum]
    Checksum --> PinCheck{Pin file loaded?}

    PinCheck -- Yes --> VerifyPin{Pin entry exists?}
    PinCheck -- No --> FindFiles[Find JS/TS files]

    VerifyPin -- Yes --> PinMatch{SHA-256 matches?}
    VerifyPin -- No, unpinned --> FindFiles

    PinMatch -- Yes, verified --> FindFiles
    PinMatch -- No, mismatch --> CritFinding[CRITICAL: Pin mismatch]
    CritFinding --> AutoQuarantine[Auto-quarantine]
    AutoQuarantine --> Return([Return ScanReport])

    FindFiles --> ParseLoop[For each file]
    ParseLoop --> TreeSitter[Parse with tree-sitter]

    TreeSitter -- Parse error --> ParseFinding[HIGH: Unparseable file]
    TreeSitter -- Success --> RunRules[Run all rules]

    RunRules --> PatternRules[PatternScanRule<br/>String matching]
    RunRules --> DangerousAPI[DangerousAPIRule<br/>AST walk]
    RunRules --> NetworkExfil[NetworkExfilRule<br/>AST walk]
    RunRules --> FSAbuse[FSAbuseRule<br/>AST walk]

    PatternRules --> Collect[Collect findings]
    DangerousAPI --> Collect
    NetworkExfil --> Collect
    FSAbuse --> Collect
    ParseFinding --> Collect

    Collect --> HasMore{More files?}
    HasMore -- Yes --> ParseLoop
    HasMore -- No --> TrustScore[Compute trust score]
    TrustScore --> AuditLog[Log to audit]
    AuditLog --> Return
```

## Data Model Relationships

```mermaid
erDiagram
    AuditEvent {
        string timestamp
        string event_type
        string source_ip
        string user_id
        string action
        string result
        string risk_level
        json details
    }

    ScanReport {
        string skill_name
        string skill_path
        string checksum
        string scanned_at
        int duration_ms
    }

    ScanFinding {
        string rule_id
        string rule_name
        string severity
        string file
        int line
        int column
        string snippet
        string message
    }

    TrustScore {
        int overall
        int author_reputation
        int download_count
        int community_reviews
        int last_update_days
    }

    QuarantinedSkill {
        string name
        string original_path
        string quarantined_at
        string reason
        bool overridden
        string overridden_by
        string overridden_at
    }

    ExecutionPlan {
        string plan_id
        string session_id
        string request_hash
    }

    PlannedAction {
        int sequence
        string category
        int risk_score
    }

    RiskAssessment {
        int overall_score
        string level
    }

    PolicyRule {
        string id
        string name
        string type
        string effect
        int priority
    }

    ApprovalRequest {
        string approval_id
        string plan_id
        string requester_id
        string status
        string requested_at
        string expires_at
    }

    Session {
        string session_id
        string created_at
        string last_activity
        int action_count
        int risk_accumulator
    }

    ScanReport ||--o{ ScanFinding : contains
    ScanReport ||--o| TrustScore : has
    QuarantinedSkill ||--o{ ScanFinding : triggered_by
    ExecutionPlan ||--o{ PlannedAction : contains
    ExecutionPlan ||--|| RiskAssessment : has
    ExecutionPlan ||--o| ApprovalRequest : requires
    Session ||--o{ ExecutionPlan : tracks
    PolicyRule ||--o{ PlannedAction : evaluates
```

## Network Topology

```mermaid
graph LR
    subgraph Host
        HP["Host Port :8080"]
        HC["Host Port :8443"]
    end

    subgraph "internal network (172.28.0.0/16)"
        Proxy["proxy"]
        OCW["openclaw"]
        DNS["egress-dns<br/>172.28.0.10"]
        Caddy["caddy"]
    end

    subgraph "egress network"
        OCW2["openclaw"]
        DNS2["egress-dns"]
    end

    Internet["Internet<br/>(DNS-filtered)"]

    HP --> Proxy
    HC --> Caddy
    Proxy --> OCW
    Caddy --> OCW
    OCW --> DNS
    OCW2 --> DNS2
    DNS2 --> Internet

    style HP fill:#f96,stroke:#333
    style HC fill:#f96,stroke:#333
    style Internet fill:#9cf,stroke:#333
```

## Deployment Architecture

```mermaid
graph TB
    subgraph "Dockerfile (multi-stage)"
        B["Stage 1: Builder<br/>python:3.12-slim + uv"]
        R["Stage 2: Runtime<br/>distroless/python3:nonroot"]
        B --> R
    end

    subgraph "Container Hardening"
        H1["read_only: true"]
        H2["cap_drop: ALL"]
        H3["no-new-privileges"]
        H4["user: 65534 (nobody)"]
        H5["tmpfs with size limit"]
    end

    subgraph "Volumes"
        V1["audit-data<br/>(append-only logs)"]
        V2["openclaw-data<br/>(gateway config)"]
        V3["caddy-data<br/>(TLS certs)"]
    end

    R --> H1
    R --> H2
    R --> H3
    R --> H4
    R --> H5
```
