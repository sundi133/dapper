---
description: Reference guide for all Dapper agent skills, phases, and CLI commands
---

# Dapper Agent Skills Reference

## Overview

Dapper is an AI-powered penetration testing agent with a five-phase testing workflow orchestrated via Temporal. Each phase has specialized agents with distinct skills.

---

## Phase 1: Pre-Reconnaissance

### `pre-recon` — External Tool Scanning & Code Analysis
**Skills:**
- Run `nmap` port scans and service detection
- Run `subfinder` for subdomain enumeration
- Run `whatweb` for technology fingerprinting
- Static code analysis of target repository
- Identify attack surface from source code patterns

**Output:** `deliverables/pre_recon_deliverable.md`, `deliverables/code_analysis_deliverable.md`

### `threat-model` — Threat Modeling
**Skills:**
- Identify crown jewels and high-value targets
- Map attacker objectives and assumptions
- Define abuse cases prioritized by business impact
- Assess attack surface breadth

**Output:** `deliverables/threat_model_deliverable.md`

---

## Phase 2: Reconnaissance

### `recon` — Attack Surface Mapping
**Skills:**
- Endpoint discovery and API mapping
- Authentication flow analysis
- Input vector identification
- Technology stack confirmation via browser automation
- Session management behavior analysis

**Output:** `deliverables/recon_deliverable.md`

---

## Phase 3: Vulnerability Analysis (16 agents, parallel)

### `injection-vuln` — SQL/Command Injection Analysis
**Skills:**
- SQL injection point identification (UNION, blind, error-based)
- Command injection via user-controlled parameters
- NoSQL operator injection detection
- XXE and YAML injection analysis
- Local/Remote File Inclusion (LFI/RFI)

**Output:** `deliverables/injection_analysis_deliverable.md`, `deliverables/injection_exploitation_queue.json`

### `xss-vuln` — Cross-Site Scripting Analysis
**Skills:**
- Reflected XSS identification
- Stored XSS through persistent input vectors
- DOM-based XSS via client-side code review
- CSP bypass technique identification
- Context-aware payload generation

**Output:** `deliverables/xss_analysis_deliverable.md`, `deliverables/xss_exploitation_queue.json`

### `auth-vuln` — Authentication Vulnerability Analysis
**Skills:**
- Authentication bypass detection
- Credential handling weaknesses
- Token generation and validation flaws
- Multi-factor authentication bypasses
- Session fixation and hijacking vectors

**Output:** `deliverables/auth_analysis_deliverable.md`, `deliverables/auth_exploitation_queue.json`

### `authz-vuln` — Authorization Vulnerability Analysis
**Skills:**
- Horizontal privilege escalation (IDOR/BOLA)
- Vertical privilege escalation
- Missing function-level access control
- Object-level authorization bypass
- Context-dependent access control flaws

**Output:** `deliverables/authz_analysis_deliverable.md`, `deliverables/authz_exploitation_queue.json`

### `ssrf-vuln` — Server-Side Request Forgery Analysis
**Skills:**
- SSRF via URL parameters and file uploads
- Cloud metadata endpoint access
- Internal service enumeration
- Protocol smuggling techniques
- Bypass of SSRF protections (DNS rebinding, redirects)

**Output:** `deliverables/ssrf_analysis_deliverable.md`, `deliverables/ssrf_exploitation_queue.json`

### `web-attacks-vuln` — Web Attack Analysis
**Skills:**
- File upload vulnerability detection
- Path traversal identification
- HTTP request smuggling
- Host header injection
- Open redirect detection
- JWT/OAuth token manipulation

**Output:** `deliverables/web_attacks_analysis_deliverable.md`, `deliverables/web_attacks_exploitation_queue.json`

### `session-auth-vuln` — Session & Authentication Analysis
**Skills:**
- Session token entropy analysis
- Cookie security attribute validation
- Session fixation detection
- Concurrent session handling
- Logout and timeout behavior

**Output:** `deliverables/session_auth_analysis_deliverable.md`, `deliverables/session_auth_exploitation_queue.json`

### `business-logic-vuln` — Business Logic Analysis
**Skills:**
- Workflow bypass detection
- Race condition identification (TOCTOU)
- Rate limiting circumvention
- Payment/pricing logic manipulation
- Multi-step process abuse

**Output:** `deliverables/business_logic_analysis_deliverable.md`, `deliverables/business_logic_exploitation_queue.json`

### `client-side-vuln` — Client-Side Vulnerability Analysis
**Skills:**
- DOM manipulation vulnerabilities
- Client-side storage security
- Postmessage handler analysis
- WebSocket security analysis
- Browser extension interaction vectors

**Output:** `deliverables/client_side_analysis_deliverable.md`, `deliverables/client_side_exploitation_queue.json`

### `web-hardening` — Web Hardening Analysis
**Skills:**
- Security header analysis (HSTS, CSP, X-Frame-Options)
- TLS configuration assessment
- CORS policy validation
- Cookie security flags
- Server information disclosure

**Output:** `deliverables/web_hardening_analysis_deliverable.md`

### `info-gathering-vuln` — Information Gathering
**Skills:**
- Sensitive file/endpoint discovery
- Source code disclosure detection
- API specification exposure
- Backup file identification
- Version information leakage

**Output:** `deliverables/info_gathering_analysis_deliverable.md`, `deliverables/info_gathering_exploitation_queue.json`

### `config-deploy-vuln` — Configuration & Deployment Analysis
**Skills:**
- Default credential detection
- Admin interface exposure
- Debug mode identification
- Misconfigured services
- Environment file disclosure

**Output:** `deliverables/config_deploy_analysis_deliverable.md`, `deliverables/config_deploy_exploitation_queue.json`

### `session-mgmt-vuln` — Session Management Analysis
**Skills:**
- Token generation predictability
- Session invalidation testing
- Cross-site session manipulation
- MFA implementation gaps
- Session data exposure

**Output:** `deliverables/session_mgmt_analysis_deliverable.md`, `deliverables/session_mgmt_exploitation_queue.json`

### `error-handling-vuln` — Error Handling Analysis
**Skills:**
- Verbose error message detection
- Stack trace information leakage
- Database error disclosure
- Framework/version disclosure
- Exception handling gaps

**Output:** `deliverables/error_handling_analysis_deliverable.md`, `deliverables/error_handling_exploitation_queue.json`

### `crypto-vuln` — Cryptography Analysis
**Skills:**
- Weak hashing algorithm detection
- Hardcoded secret identification
- Key management weaknesses
- Insecure random number generation
- Encryption implementation flaws

**Output:** `deliverables/crypto_analysis_deliverable.md`, `deliverables/crypto_exploitation_queue.json`

### `api-testing-vuln` — API Security Analysis
**Skills:**
- API authentication testing
- Rate limiting validation
- Input validation gaps
- Mass assignment detection
- API versioning issues

**Output:** `deliverables/api_testing_analysis_deliverable.md`, `deliverables/api_testing_exploitation_queue.json`

---

## Phase 4: Exploitation (conditional, parallel)

Each exploitation agent only runs if its corresponding vulnerability analysis found exploitable issues.

### Exploitation Agent Skills (all types)
**Common capabilities across all exploit agents:**
- Craft and execute proof-of-concept exploits
- Document exploitation steps with exact requests/responses
- Classify results: `EXPLOITED` / `BLOCKED_BY_SECURITY` / `OUT_OF_SCOPE_INTERNAL` / `FALSE_POSITIVE`
- Browser automation via Playwright MCP for interactive exploitation
- Authentication handling (form, SSO, API, TOTP)
- Generate exploitation evidence with vulnerability IDs

**Exploitation agents:** `injection-exploit`, `xss-exploit`, `auth-exploit`, `ssrf-exploit`, `authz-exploit`, `web-attacks-exploit`, `session-auth-exploit`, `business-logic-exploit`, `client-side-exploit`, `info-gathering-exploit`, `config-deploy-exploit`, `session-mgmt-exploit`, `error-handling-exploit`, `crypto-exploit`, `api-testing-exploit`

**Output:** `deliverables/{type}_exploitation_evidence.md`

---

## Phase 5: Reporting

### `report` — Executive Report Generation
**Skills:**
- Assemble findings from all specialist agents
- Generate executive summary with severity breakdown
- Create threat model summary with top abuse cases
- Synthesize impact analysis (business consequences)
- Produce remediation guidance (priority-ordered)
- Extract network reconnaissance highlights
- Clean hallucinated content from raw agent outputs
- Inject model metadata

**Output:** `deliverables/comprehensive_security_assessment_report.md`

---

## Report Generation Script

### `export-findings-csv` — Structured Findings Export
**Usage:** `node scripts/export-findings-csv.js <deliverables-dir> [output.csv] [--model <model>] [--max-turns <n>] [--reuse-json]`

**Skills:**
- Agentic analysis of all deliverable files
- Cross-reference findings across multiple source files
- Structured JSON extraction with 40+ fields per finding
- CWE mapping and inference from vulnerability patterns
- Cyber Risk Quantification (CRQ): likelihood, impact, risk score, compliance mapping
- Attack chain identification across findings
- Developer verification step generation
- Generate **Developer Security Report** (technical, code-level remediations, attack chain diagrams, remediation checklist)
- Generate **Executive Security Report** (CRQ dashboard, risk matrix, compliance exposure, strategic remediation roadmap)
- CSV export with all structured fields

**Output:**
- `{deliverables}/findings.csv` — Flat CSV with all findings
- `{deliverables}/*_findings.json` — Structured JSON intermediate
- `{deliverables}/developer_security_report.md` — Developer-focused report
- `{deliverables}/executive_security_report.md` — Executive/leads report

---

## CLI Commands

| Command | Description |
|---------|-------------|
| `./dapper start URL=<url> REPO=<name>` | Start a pentest workflow |
| `./dapper logs` | View real-time worker logs |
| `./dapper query ID=<workflow-id>` | Query workflow progress |
| `./dapper stop` | Stop containers (preserves data) |
| `./dapper stop CLEAN=true` | Full cleanup including volumes |

### Options
| Option | Description |
|--------|-------------|
| `CONFIG=<file>` | YAML config for auth and test parameters |
| `OUTPUT=<path>` | Custom output directory for session |
| `PIPELINE_TESTING=true` | Fast mode with minimal prompts |
| `REBUILD=true` | Force Docker rebuild |
| `ROUTER=true` | Route through claude-code-router |

---

## Claude Code Slash Commands

| Command | Description |
|---------|-------------|
| `/debug` | Systematic error debugging with structured recovery |
| `/pr` | Create PR to main with conventional commit title |
| `/review` | Review code for Shannon-specific patterns and security |
| `/skills` | This reference guide |

---

## Shared Agent Capabilities

All agents share these cross-cutting skills via the Claude Agent SDK:

- **Browser Automation** — Playwright MCP with isolated sessions per agent
- **Authenticated Testing** — Form login, SSO, API keys, TOTP generation
- **Git Checkpoints** — Automatic save/rollback of workspace state
- **Crash-Safe Logging** — Append-only audit logs surviving kill -9
- **Retry Logic** — 3 attempts per agent with exponential backoff
- **Configuration Injection** — YAML config distributed per agent context
- **Working Directory Scoping** — Agents operate within target repository

---

## MCP Tools Available to Agents

| Tool | Description |
|------|-------------|
| `generate_totp` | Generate TOTP codes for MFA authentication flows |
| Playwright actions | Navigate, click, fill, screenshot, network interception |
| File system tools | Read, write, glob, grep within working directory |
| Shell execution | Run security tools (nmap, subfinder, whatweb) |
