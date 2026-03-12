# BRON MCP Gateway - Agentic Workflow Catalog

This document provides comprehensive documentation for all 11 agentic workflows designed for AI coding agents to leverage BRON cybersecurity intelligence for safer code development and execution.

## Overview

The BRON MCP Gateway provides specialized prompts designed for AI coding agents (Cline, Roo, LangChain, Kiro, etc.) to make security-informed decisions during code development and execution. These prompts guide agents through structured queries of the BRON knowledge graph to assess security risks before taking actions like executing generated code, installing dependencies, or committing changes.

### Design Philosophy

**Prevent, Don't Just Detect**: Agentic workflow prompts are designed to help agents make safer decisions proactively, not just report issues after the fact. Each prompt provides a decision framework that helps agents determine whether an action is safe to proceed.

**Code Execution Safety**: A primary use case is preventing execution of dynamically generated code that matches known vulnerability patterns. Before executing any generated code, agents can validate it against BRON to identify CWE patterns, related CVEs, and CAPEC attack vectors.

**Structured Guidance**: Rather than returning raw data, prompts provide step-by-step guidance for querying BRON and interpreting results in the context of the agent's current task.

### Integration Points

Prompts are designed to integrate with agent decision loops at key points:
- Before executing dynamically generated code (code execution safety validation)
- Before installing or updating dependencies (dependency vulnerability assessment)
- During code generation (to avoid vulnerable patterns)
- During code review (to identify security issues)
- Before committing changes (pre-commit security checks)
- During architecture design (threat modeling)
- When refactoring code (security regression detection)

## Table of Contents

1. [validate_code_execution_safety](#1-validate_code_execution_safety)
2. [assess_dependency_vulnerabilities](#2-assess_dependency_vulnerabilities)
3. [guide_secure_code_generation](#3-guide_secure_code_generation)
4. [analyze_attack_surface](#4-analyze_attack_surface)
5. [recognize_vulnerability_patterns](#5-recognize_vulnerability_patterns)
6. [discover_exploit_chains](#6-discover_exploit_chains)
7. [recommend_security_controls](#7-recommend_security_controls)
8. [assist_threat_modeling](#8-assist_threat_modeling)
9. [detect_security_regressions](#9-detect_security_regressions)
10. [map_compliance_standards](#10-map_compliance_standards)
11. [pre_commit_security_check](#11-pre_commit_security_check)

---

## 1. validate_code_execution_safety

### Purpose
Help agents decide whether dynamically generated code is safe to execute.

### Use Case
An agent generates code to solve a user's problem. Before executing it, the agent invokes this prompt to check if the code contains patterns matching known vulnerabilities.

### Input Schema
```json
{
  "code_snippet": "string (the generated code)",
  "language": "string (python, javascript, java, etc.)",
  "execution_context": "string (optional: where/how code will run)"
}
```

### Workflow Steps

1. **PATTERN ANALYSIS**: Identify code patterns that may match known CWE weaknesses
   - Use `search_bron` to find CWEs related to identified patterns
   - Focus on CWEs in categories: Input Validation, Memory Safety, Injection, Path Traversal

2. **RISK ASSESSMENT**: For each identified CWE
   - Use `query_cwe` to get detailed weakness information
   - Use `find_relationships` to discover related CVEs and CAPEC patterns
   - Assess severity: Are there recent CVEs exploiting this weakness?

3. **EXECUTION DECISION**
   - **HIGH RISK**: Code matches CWE patterns with active CVE exploitation → DO NOT EXECUTE
   - **MEDIUM RISK**: Code matches CWE patterns but no recent CVEs → WARN USER, request approval
   - **LOW RISK**: No CWE pattern matches or only theoretical weaknesses → SAFE TO EXECUTE

4. **MITIGATION**: If risks identified, suggest secure alternatives
   - Query related CWEs for secure coding patterns
   - Recommend input validation, sanitization, or safer APIs

### High-Risk Patterns to Check

- SQL query construction from user input (CWE-89: SQL Injection)
- File path operations with user input (CWE-22: Path Traversal)
- Command execution with user input (CWE-78: OS Command Injection)
- Deserialization of untrusted data (CWE-502: Deserialization of Untrusted Data)
- Memory operations without bounds checking (CWE-119: Buffer Overflow)

### Decision Framework

| Risk Level | Criteria | Action |
|------------|----------|--------|
| HIGH | Code matches CWE with CVSS ≥ 9.0 CVEs | BLOCK execution |
| MEDIUM | Code matches CWE with CVSS 7.0-8.9 CVEs | WARN user, request approval |
| LOW | No CWE matches or only theoretical | EXECUTE safely |

### Integration Example (Python/Cline)

```python
# Before executing generated code
prompt_result = await mcp_client.get_prompt(
    "validate_code_execution_safety",
    {"code_snippet": generated_code, "language": "python"}
)

# Agent uses prompt guidance to query BRON
decision = await agent.analyze_with_bron(prompt_result)

if decision == "BLOCK":
    return "Code execution blocked due to security risks"
elif decision == "WARN":
    user_approval = await ask_user("Code has potential risks. Execute anyway?")
    if not user_approval:
        return "Execution cancelled by user"
```

---

## 2. assess_dependency_vulnerabilities

### Purpose
Help agents evaluate dependencies for known vulnerabilities before installation.

### Use Case
User asks agent to install a package. Agent checks for CVEs before running `npm install` or `pip install`.

### Input Schema
```json
{
  "package_name": "string",
  "version": "string (optional, or 'latest')",
  "ecosystem": "string (npm, pypi, maven, etc.)"
}
```

### Workflow Steps

1. **CVE SEARCH**: Search for known vulnerabilities
   - Use `search_bron` with query: "{package_name}"
   - Filter results to CVE entity types
   - Look for CVEs mentioning the package name in descriptions

2. **VERSION ANALYSIS**: For each CVE found
   - Use `query_cve` to get detailed vulnerability information
   - Check if the CVE affects version specified
   - Note CVSS score and severity rating
   - Check published date (recent CVEs are higher priority)

3. **WEAKNESS ANALYSIS**: Understand vulnerability types
   - Use `find_relationships` to get related CWEs
   - Use `query_cwe` to understand weakness categories
   - Identify if vulnerabilities are remotely exploitable

4. **TRANSITIVE RISK**: Consider dependency chain
   - Note if package has many dependencies (larger attack surface)
   - Recommend checking transitive dependencies separately

5. **DECISION FRAMEWORK**
   - **CRITICAL CVEs** (CVSS ≥ 9.0) in target version → BLOCK installation
   - **HIGH CVEs** (CVSS ≥ 7.0) in target version → WARN, suggest patched version
   - **MEDIUM/LOW CVEs** or CVEs in older versions → INFORM user, safe to proceed
   - **No CVEs found** → SAFE to install

6. **RECOMMENDATIONS**
   - If CVEs found, identify safe version ranges
   - Suggest alternative packages if no safe version available
   - Recommend security monitoring for the dependency

### Decision Framework

| CVE Severity | CVSS Score | Action |
|--------------|------------|--------|
| CRITICAL | ≥ 9.0 | BLOCK installation |
| HIGH | 7.0-8.9 | WARN, suggest patched version |
| MEDIUM/LOW | < 7.0 | INFORM, safe to proceed |
| None | N/A | INSTALL safely |

### Integration Example (Python/Roo)

```python
# Before installing a package
async def check_dependency(package: str, version: str):
    prompt = await mcp.get_prompt("assess_dependency_vulnerabilities", {
        "package_name": package,
        "version": version,
        "ecosystem": "pypi"
    })
    
    cves = await query_bron_for_cves(package, version)
    if any(cve.cvss_score >= 9.0 for cve in cves):
        raise SecurityError(f"Critical CVEs found in {package}@{version}")
```

---

## 3. guide_secure_code_generation

### Purpose
Provide security guidance during code generation to avoid introducing vulnerabilities.

### Use Case
User requests code to implement a feature. Agent consults this prompt to understand security considerations before generating code.

### Input Schema
```json
{
  "feature_description": "string (what the code should do)",
  "language": "string",
  "context": "string (optional: existing codebase context)"
}
```

### Workflow Steps

1. **IDENTIFY SECURITY-RELEVANT OPERATIONS**
   - Does the feature involve: user input, file operations, network requests, authentication, data storage, cryptography?
   - List security-relevant operations

2. **QUERY RELEVANT CWES**: For each operation type
   - User input → `search_bron("input validation injection")`
   - File operations → `search_bron("path traversal file inclusion")`
   - Network requests → `search_bron("SSRF request forgery")`
   - Authentication → `search_bron("authentication bypass")`
   - Data storage → `search_bron("SQL injection XSS")`
   - Cryptography → `search_bron("weak cryptography")`

3. **UNDERSTAND VULNERABILITY PATTERNS**: For top CWEs found
   - Use `query_cwe` to understand the weakness
   - Use `find_relationships` to see real-world CVE examples
   - Note common mistake patterns that lead to the weakness

4. **APPLY SECURE CODING PATTERNS**
   - Input validation: Whitelist validation, type checking, length limits
   - Output encoding: Context-appropriate escaping (HTML, SQL, shell)
   - Authentication: Use established libraries, never roll your own crypto
   - File operations: Validate paths, use safe APIs, restrict permissions
   - Error handling: Don't leak sensitive information in error messages

5. **GENERATE CODE WITH SECURITY CONTROLS**
   - Include input validation before processing
   - Use parameterized queries for databases
   - Use safe APIs (e.g., subprocess with shell=False)
   - Add comments explaining security considerations

6. **DOCUMENT SECURITY ASSUMPTIONS**
   - Note what inputs are trusted vs untrusted
   - Document required security configurations
   - List security testing recommendations

### Secure Coding Patterns by Operation

| Operation | CWE to Avoid | Secure Pattern |
|-----------|--------------|----------------|
| User Input | CWE-89, CWE-78, CWE-79 | Whitelist validation, parameterized queries |
| File Operations | CWE-22, CWE-434 | Path validation, safe file APIs |
| Network Requests | CWE-918 | URL validation, allowlist domains |
| Authentication | CWE-287, CWE-798 | Use established libraries, no hardcoded secrets |
| Data Storage | CWE-89, CWE-79 | Parameterized queries, output encoding |
| Cryptography | CWE-327, CWE-330 | Use modern algorithms (AES-256, SHA-256) |

### Integration Example (TypeScript/Cline)

```typescript
// Before generating code
const guidance = await mcpClient.getPrompt("guide_secure_code_generation", {
  feature_description: "file upload endpoint",
  language: "python"
});

// Agent queries BRON for relevant CWEs
const cwes = await mcpClient.callTool("search_bron", {
  query: "file upload path traversal"
});

// Generate code with security controls
const secureCode = generateCodeWithValidation(cwes);
```

---

## 4. analyze_attack_surface

### Purpose
Help agents understand security implications of code changes.

### Use Case
Agent is about to make changes that add new functionality. This prompt helps assess how the changes affect the attack surface.

### Input Schema
```json
{
  "change_description": "string (what's being added/modified)",
  "code_diff": "string (optional: actual diff)",
  "exposed_interfaces": "array (APIs, endpoints, file operations, etc.)"
}
```

### Workflow Steps

1. **MAP TO ATT&CK TECHNIQUES**: For each exposed interface
   - API endpoints → `search_bron("API exploitation injection")`
   - File uploads → `search_bron("malicious file upload")`
   - User authentication → `search_bron("credential access")`
   - Data processing → `search_bron("code injection deserialization")`

2. **IDENTIFY ATTACK VECTORS**: For each ATT&CK technique found
   - Use `query_attack_technique` to understand attacker methods
   - Use `find_relationships` to discover related CAPEC patterns
   - Use `query_capec` to understand attack prerequisites

3. **ASSESS EXPLOITABILITY**
   - Are exposed interfaces accessible remotely or only locally?
   - Is authentication required?
   - What privileges are needed?
   - Rate: [CRITICAL / HIGH / MEDIUM / LOW] exploitability

4. **DISCOVER RELATED VULNERABILITIES**
   - Use `find_relationships` from CAPEC to CWE to CVE
   - Identify real-world examples of similar attack surfaces being exploited
   - Note CVSS scores and exploitation frequency

5. **RECOMMEND MITIGATIONS**
   - Input validation and sanitization requirements
   - Authentication and authorization controls
   - Rate limiting and abuse prevention
   - Logging and monitoring recommendations
   - Security testing requirements (fuzzing, penetration testing)

6. **QUANTIFY RISK**
   - Attack surface expansion: [SIGNIFICANT / MODERATE / MINIMAL]
   - Recommended security controls
   - Required security testing

### Exploitability Assessment

| Factor | High Risk | Medium Risk | Low Risk |
|--------|-----------|-------------|----------|
| Access | Remote, unauthenticated | Remote, authenticated | Local only |
| Privileges | None required | User privileges | Admin privileges |
| Complexity | Simple exploit | Moderate complexity | Complex exploit chain |

### Integration Example

```python
# Before adding new API endpoint
analysis = await mcp_client.get_prompt("analyze_attack_surface", {
    "change_description": "New REST API for file uploads",
    "exposed_interfaces": ["POST /api/upload", "file system write"]
})

# Query BRON for attack patterns
attack_techniques = await mcp_client.call_tool("search_bron", {
    "query": "file upload exploitation"
})

# Recommend mitigations based on findings
if has_high_risk_patterns(attack_techniques):
    recommend_controls(["input validation", "file type checking", "virus scanning"])
```

---

## 5. recognize_vulnerability_patterns

### Purpose
Help agents identify potential security issues during code review.

### Use Case
Agent is reviewing code (user's or its own) and needs to flag potential vulnerabilities.

### Input Schema
```json
{
  "code_snippet": "string",
  "language": "string",
  "review_context": "string (optional: what to focus on)"
}
```

### Workflow Steps

1. **PATTERN RECOGNITION**: Scan code for common vulnerability indicators
   - String concatenation in SQL/shell commands
   - User input flowing to sensitive sinks (eval, exec, system)
   - Missing input validation or sanitization
   - Hardcoded credentials or secrets
   - Unsafe deserialization
   - Missing authentication/authorization checks
   - Weak cryptographic algorithms
   - Race conditions in file operations

2. **MAP PATTERNS TO CWES**: For each identified pattern
   - Use `search_bron` to find matching CWE definitions
   - Use `query_cwe` to get detailed weakness information
   - Confirm the pattern matches the CWE description

3. **ASSESS SEVERITY**: For each confirmed CWE
   - Use `find_relationships` to find related CVEs
   - Check CVSS scores of related CVEs
   - Determine if the weakness is actively exploited
   - Rate severity: [CRITICAL / HIGH / MEDIUM / LOW / INFO]

4. **DISTINGUISH FALSE POSITIVES**
   - Check if mitigations are already in place
   - Consider if the code path is actually reachable
   - Assess if inputs are already validated elsewhere
   - Confidence level: [HIGH / MEDIUM / LOW]

5. **PROVIDE SPECIFIC FEEDBACK**: For each issue found
   - Line number and code excerpt
   - CWE reference and description
   - Explanation of why it's vulnerable
   - Specific remediation advice
   - Example of secure alternative

### Common Vulnerability Indicators

| Pattern | CWE | Severity |
|---------|-----|----------|
| `eval(user_input)` | CWE-95 | CRITICAL |
| `"SELECT * FROM users WHERE id=" + user_id` | CWE-89 | CRITICAL |
| `os.system(user_command)` | CWE-78 | CRITICAL |
| `pickle.loads(untrusted_data)` | CWE-502 | HIGH |
| `password = "hardcoded123"` | CWE-798 | HIGH |
| `open(user_path, 'r')` without validation | CWE-22 | HIGH |
| `md5(password)` | CWE-327 | MEDIUM |

### Integration Example

```python
# During code review
findings = await mcp_client.get_prompt("recognize_vulnerability_patterns", {
    "code_snippet": code_to_review,
    "language": "python"
})

# Query BRON for each identified pattern
for pattern in identified_patterns:
    cwes = await mcp_client.call_tool("search_bron", {"query": pattern})
    cve_details = await get_related_cves(cwes)
    
    if has_critical_severity(cve_details):
        flag_issue(pattern, cwes, cve_details)
```

---

## 6. discover_exploit_chains

### Purpose
Help agents understand how multiple vulnerabilities could be chained together.

### Use Case
Agent has identified multiple potential issues and wants to understand if they could be combined for greater impact.

### Input Schema
```json
{
  "vulnerability_ids": "array (CVE or CWE identifiers)",
  "system_context": "string (optional: system architecture)"
}
```

### Workflow Steps

1. **BUILD VULNERABILITY GRAPH**: For each vulnerability
   - Use `query_cve` or `query_cwe` to get details
   - Use `find_relationships` to discover connections
   - Map relationships: CVE → CWE → CAPEC → ATT&CK

2. **IDENTIFY ATTACK PATTERNS**
   - Use `query_capec` for each related CAPEC pattern
   - Look for patterns that chain multiple weaknesses
   - Note attack prerequisites and required conditions

3. **DISCOVER MULTI-STAGE ATTACKS**
   - Can one vulnerability provide access needed for another?
   - Example: Info disclosure (CWE-200) → enables authentication bypass (CWE-287)
   - Example: XSS (CWE-79) → enables CSRF (CWE-352)
   - Use `find_relationships` to traverse attack chains

4. **MAP TO ATT&CK TACTICS**
   - Initial Access → Execution → Persistence → Privilege Escalation
   - Use `query_attack_technique` to understand each stage
   - Identify which vulnerabilities enable which tactics

5. **ASSESS COMBINED IMPACT**
   - Individual vulnerability severity
   - Combined exploit chain severity: [CRITICAL / HIGH / MEDIUM / LOW]
   - Likelihood of successful exploitation: [HIGH / MEDIUM / LOW]

6. **PRIORITIZE REMEDIATION**
   - Which vulnerability breaks the most exploit chains if fixed?
   - Recommend fixing order based on maximum impact
   - Suggest defense-in-depth controls

### Example Exploit Chains

| Chain | Stage 1 | Stage 2 | Stage 3 | Impact |
|-------|---------|---------|---------|--------|
| Web App Takeover | CWE-79 (XSS) | CWE-352 (CSRF) | CWE-287 (Auth Bypass) | Account compromise |
| Data Exfiltration | CWE-200 (Info Disclosure) | CWE-287 (Weak Auth) | CWE-22 (Path Traversal) | Data breach |
| Privilege Escalation | CWE-89 (SQL Injection) | CWE-798 (Hardcoded Creds) | CWE-78 (Command Injection) | System compromise |

### Integration Example

```python
# Analyze multiple vulnerabilities
chain_analysis = await mcp_client.get_prompt("discover_exploit_chains", {
    "vulnerability_ids": ["CWE-200", "CWE-287", "CWE-22"]
})

# Build vulnerability graph
for vuln_id in vulnerability_ids:
    relationships = await mcp_client.call_tool("find_relationships", {
        "entity_id": vuln_id,
        "relationship_type": "all"
    })
    
    # Identify chaining opportunities
    chains = discover_attack_sequences(relationships)
    
# Prioritize fixes that break most chains
priority_fixes = prioritize_by_chain_impact(chains)
```

---

## 7. recommend_security_controls

### Purpose
Help agents suggest appropriate mitigations for identified risks.

### Use Case
Agent has identified a security issue and needs to recommend specific fixes.

### Input Schema
```json
{
  "weakness_ids": "array (CWE or CAPEC identifiers)",
  "context": "string (code context, architecture)"
}
```

### Workflow Steps

1. **UNDERSTAND THE WEAKNESS**: For each CWE
   - Use `query_cwe` to get detailed information
   - Note the weakness description and consequences
   - Identify the root cause of the weakness

2. **IDENTIFY DEFENSIVE TECHNIQUES**
   - Use `find_relationships` to discover related ATT&CK techniques
   - Use `query_attack_technique` to understand attack methods
   - Identify which defensive controls counter these techniques

3. **MAP TO MITIGATION STRATEGIES**: Common categories
   - Input validation and sanitization
   - Output encoding and escaping
   - Authentication and authorization
   - Cryptographic controls
   - Secure configuration
   - Error handling and logging
   - Rate limiting and resource controls

4. **PROVIDE CODE-LEVEL MITIGATIONS**
   - Specific API calls or libraries to use
   - Code patterns that prevent the weakness
   - Example implementations in the target language

5. **PROVIDE ARCHITECTURAL MITIGATIONS**
   - Network segmentation
   - Principle of least privilege
   - Defense in depth layers
   - Security monitoring and alerting

6. **PRIORITIZE CONTROLS**
   - Effectiveness: How well does it mitigate the risk?
   - Implementation cost: How difficult to implement?
   - Performance impact: Does it affect system performance?
   - Recommended priority: [HIGH / MEDIUM / LOW]

### Mitigation Strategies by CWE Category

| CWE Category | Code-Level Mitigation | Architectural Mitigation |
|--------------|----------------------|--------------------------|
| Injection (CWE-89, 78, 79) | Parameterized queries, input validation | WAF, input filtering gateway |
| Authentication (CWE-287) | Use OAuth/SAML libraries | MFA, SSO integration |
| Path Traversal (CWE-22) | Path canonicalization, allowlist | Chroot jails, containerization |
| Cryptography (CWE-327) | Use modern algorithms (AES-256) | HSM, key management service |
| Deserialization (CWE-502) | Avoid deserializing untrusted data | Network segmentation |

### Integration Example

```python
# Recommend controls for identified weakness
recommendations = await mcp_client.get_prompt("recommend_security_controls", {
    "weakness_ids": ["CWE-89"],
    "context": "Python web application with PostgreSQL"
})

# Query BRON for defensive techniques
cwe_details = await mcp_client.call_tool("query_cwe", {"cwe_id": "CWE-89"})
attack_techniques = await mcp_client.call_tool("find_relationships", {
    "entity_id": "CWE-89",
    "relationship_type": "cwe_to_capec"
})

# Generate specific recommendations
controls = generate_mitigations(cwe_details, attack_techniques, context="python")
# Returns: ["Use parameterized queries with psycopg2", "Implement input validation", ...]
```

---

## 8. assist_threat_modeling

### Purpose
Help agents identify security requirements early in development.

### Use Case
User describes a new feature or system. Agent uses this prompt to identify potential threats before implementation.

### Input Schema
```json
{
  "system_description": "string (architecture, components, data flows)",
  "assets": "array (what needs protection)",
  "trust_boundaries": "array (where untrusted data enters)"
}
```

### Workflow Steps

1. **IDENTIFY ATTACK VECTORS**: For each trust boundary
   - What untrusted data enters the system?
   - Use `search_bron` to find relevant attack patterns
   - Focus on: injection, authentication, authorization, data exposure

2. **MAP TO ATT&CK TACTICS**: For each system component
   - Use `search_bron` with component type (API, database, file system, etc.)
   - Identify relevant ATT&CK techniques
   - Use `query_attack_technique` for detailed attack methods

3. **DISCOVER APPLICABLE ATTACK PATTERNS**
   - Use `find_relationships` from ATT&CK to CAPEC
   - Use `query_capec` to understand attack prerequisites
   - Assess which patterns apply to your system architecture

4. **IDENTIFY RELEVANT WEAKNESSES**
   - Use `find_relationships` from CAPEC to CWE
   - Use `query_cwe` to understand weakness categories
   - Prioritize CWEs relevant to your technology stack

5. **GENERATE THREAT SCENARIOS**: For each identified threat
   - Threat description
   - Attack vector (how attacker gains access)
   - Exploited weakness (CWE reference)
   - Impact (what attacker achieves)
   - Likelihood: [HIGH / MEDIUM / LOW]
   - Risk: [CRITICAL / HIGH / MEDIUM / LOW]

6. **DEFINE SECURITY REQUIREMENTS**: For each threat
   - Required security control
   - Acceptance criteria for the control
   - Testing requirements

### STRIDE Threat Categories

| Category | Example Threats | Relevant CWEs |
|----------|----------------|---------------|
| Spoofing | Impersonation, credential theft | CWE-287, CWE-290 |
| Tampering | Data modification, injection | CWE-89, CWE-79, CWE-352 |
| Repudiation | Lack of audit logs | CWE-778 |
| Information Disclosure | Data leaks, exposure | CWE-200, CWE-311 |
| Denial of Service | Resource exhaustion | CWE-400, CWE-770 |
| Elevation of Privilege | Privilege escalation | CWE-269, CWE-863 |

### Integration Example

```python
# Threat modeling for new feature
threat_model = await mcp_client.get_prompt("assist_threat_modeling", {
    "system_description": "Payment processing API with credit card storage",
    "assets": ["credit card data", "user accounts", "transaction history"],
    "trust_boundaries": ["public API", "database", "payment gateway"]
})

# Identify threats for each boundary
for boundary in trust_boundaries:
    attack_techniques = await mcp_client.call_tool("search_bron", {
        "query": f"{boundary} exploitation"
    })
    
    # Map to CAPEC patterns
    for technique in attack_techniques:
        capec_patterns = await mcp_client.call_tool("find_relationships", {
            "entity_id": technique.id,
            "relationship_type": "attack_to_capec"
        })
        
        # Generate threat scenarios
        threats = generate_threat_scenarios(capec_patterns, assets)

# Define security requirements
requirements = derive_security_requirements(threats)
```

---

## 9. detect_security_regressions

### Purpose
Help agents prevent reintroduction of previously fixed vulnerabilities.

### Use Case
Agent is reviewing code changes and needs to check if they reintroduce old security issues.

### Input Schema
```json
{
  "code_changes": "string (diff or description)",
  "historical_fixes": "array (optional: previous CVE/CWE fixes)",
  "commit_history": "string (optional: relevant commit messages)"
}
```

### Workflow Steps

1. **IDENTIFY PREVIOUSLY FIXED WEAKNESSES**: For each historical fix
   - Use `query_cve` or `query_cwe` to understand the original vulnerability
   - Note the vulnerable code pattern that was fixed
   - Identify the secure pattern that replaced it

2. **ANALYZE CURRENT CHANGES**
   - Does the new code reintroduce the vulnerable pattern?
   - Are security controls being removed or weakened?
   - Is validated input becoming unvalidated?
   - Are safe APIs being replaced with unsafe ones?

3. **PATTERN MATCHING**
   - Use `search_bron` to find CWEs matching current code patterns
   - Compare against CWEs from historical fixes
   - Flag matches as potential regressions

4. **ASSESS REGRESSION RISK**: For each potential regression
   - Confidence: [HIGH / MEDIUM / LOW] that it's a true regression
   - Severity: [CRITICAL / HIGH / MEDIUM / LOW] if it is a regression
   - Affected functionality

5. **PROVIDE EVIDENCE**
   - Original vulnerable code pattern
   - Fixed code pattern
   - Current code pattern
   - Explanation of why it's a regression

6. **RECOMMEND ACTIONS**
   - Block commit if high-confidence critical regression
   - Require security review if medium confidence
   - Add regression test to prevent future reintroduction

### Regression Detection Patterns

| Change Type | Regression Indicator | Confidence |
|-------------|---------------------|------------|
| Removing input validation | Previously validated input now unvalidated | HIGH |
| Replacing safe API with unsafe | `subprocess.run()` → `os.system()` | HIGH |
| Removing authentication check | Protected endpoint now unprotected | HIGH |
| Weakening crypto | AES-256 → DES | HIGH |
| Removing output encoding | HTML escaping removed | MEDIUM |
| Changing error handling | Detailed errors now exposed | MEDIUM |

### Integration Example

```python
# Check for security regressions in PR
regression_check = await mcp_client.get_prompt("detect_security_regressions", {
    "code_changes": git_diff,
    "historical_fixes": ["CVE-2023-1234", "CWE-89"],
    "commit_history": get_security_commits()
})

# Analyze historical fixes
for fix_id in historical_fixes:
    original_vuln = await mcp_client.call_tool("query_cve", {"cve_id": fix_id})
    related_cwes = await mcp_client.call_tool("find_relationships", {
        "entity_id": fix_id,
        "relationship_type": "cve_to_cwe"
    })
    
    # Check if current changes match old vulnerable patterns
    if matches_vulnerable_pattern(code_changes, related_cwes):
        flag_regression(fix_id, related_cwes, confidence="HIGH")

# Decision
if has_high_confidence_regressions():
    return "BLOCK: Security regression detected"
```

---

## 10. map_compliance_standards

### Purpose
Help agents map vulnerabilities to compliance requirements.

### Use Case
Organization has compliance requirements (PCI-DSS, HIPAA, SOC2). Agent needs to explain how security issues relate to compliance.

### Input Schema
```json
{
  "vulnerability_ids": "array (CVE or CWE identifiers)",
  "compliance_frameworks": "array (optional: specific frameworks to check)"
}
```

### Workflow Steps

1. **UNDERSTAND THE VULNERABILITIES**: For each vulnerability
   - Use `query_cve` or `query_cwe` to get details
   - Note the weakness category and impact
   - Identify affected security properties (confidentiality, integrity, availability)

2. **MAP TO COMMON STANDARDS**: Check against major frameworks
   - OWASP Top 10: Use `search_bron` to find if CWE is in current Top 10
   - CWE Top 25: Check if CWE is in Most Dangerous Software Weaknesses
   - SANS Top 25: Check for inclusion in SANS list
   - PCI-DSS: Requirements 6.5.x (secure coding), 6.6 (vulnerability management)
   - HIPAA: Security Rule requirements for data protection
   - SOC 2: Trust Services Criteria (Security, Availability, Confidentiality)

3. **IDENTIFY SPECIFIC REQUIREMENTS**: For each framework
   - Which specific requirement does the vulnerability violate?
   - What evidence is needed to demonstrate compliance?
   - What remediation is required for compliance?

4. **ASSESS COMPLIANCE IMPACT**
   - Does this vulnerability cause non-compliance?
   - Severity of compliance violation: [CRITICAL / HIGH / MEDIUM / LOW]
   - Potential penalties or audit findings

5. **PRIORITIZE REMEDIATION**
   - Compliance-driven priority: [URGENT / HIGH / MEDIUM / LOW]
   - Deadline considerations (audit dates, certification renewals)
   - Dependencies (what else must be fixed together)

6. **GENERATE COMPLIANCE REPORT**
   - Vulnerability summary with CWE/CVE references
   - Affected compliance requirements
   - Required remediation actions
   - Evidence needed to demonstrate fix
   - Recommended timeline

### Compliance Framework Mappings

| Framework | Relevant Requirements | Common CWEs |
|-----------|----------------------|-------------|
| OWASP Top 10 2021 | A03: Injection | CWE-89, CWE-78, CWE-79 |
| | A01: Broken Access Control | CWE-287, CWE-863 |
| | A02: Cryptographic Failures | CWE-327, CWE-311 |
| PCI-DSS 4.0 | Req 6.5.1: Injection flaws | CWE-89, CWE-78 |
| | Req 6.5.3: Insecure cryptography | CWE-327, CWE-330 |
| | Req 6.5.10: Broken authentication | CWE-287, CWE-798 |
| HIPAA Security Rule | §164.312(a)(2)(i): Access control | CWE-287, CWE-863 |
| | §164.312(e)(2)(i): Encryption | CWE-311, CWE-327 |
| SOC 2 | CC6.1: Logical access controls | CWE-287, CWE-863 |
| | CC6.7: Encryption | CWE-311, CWE-327 |

### Integration Example

```python
# Map vulnerabilities to compliance
compliance_mapping = await mcp_client.get_prompt("map_compliance_standards", {
    "vulnerability_ids": ["CWE-89", "CWE-287"],
    "compliance_frameworks": ["PCI-DSS", "SOC2"]
})

# Query BRON for vulnerability details
for vuln_id in vulnerability_ids:
    vuln_details = await mcp_client.call_tool("query_cwe", {"cwe_id": vuln_id})
    
    # Map to compliance requirements
    mappings = map_to_frameworks(vuln_details, ["PCI-DSS", "SOC2"])
    
    # Generate compliance report
    report = {
        "vulnerability": vuln_id,
        "description": vuln_details.description,
        "frameworks": {
            "PCI-DSS": {
                "requirements": ["6.5.1"],
                "severity": "CRITICAL",
                "deadline": "Next audit (Q2 2026)"
            },
            "SOC2": {
                "criteria": ["CC6.1"],
                "severity": "HIGH",
                "deadline": "Annual assessment"
            }
        },
        "remediation": "Implement parameterized queries",
        "evidence": "Code review, penetration test results"
    }
```

---

## 11. pre_commit_security_check

### Purpose
Comprehensive security check before committing code changes.

### Use Case
Agent is about to commit code. This prompt provides a final security gate.

### Input Schema
```json
{
  "staged_changes": "string (git diff or file list)",
  "commit_message": "string",
  "changed_files": "array (file paths)"
}
```

### Workflow Steps

1. **VULNERABILITY PATTERN SCAN**
   - Use `recognize_vulnerability_patterns` prompt for each changed file
   - Identify any CWE patterns in the code
   - Flag high-severity issues

2. **DEPENDENCY CHECK**
   - If package files changed (package.json, requirements.txt, pom.xml)
   - Use `assess_dependency_vulnerabilities` for new/updated dependencies
   - Block commit if critical CVEs found

3. **ATTACK SURFACE ANALYSIS**
   - If new APIs, endpoints, or interfaces added
   - Use `analyze_attack_surface` prompt
   - Assess if security controls are adequate

4. **REGRESSION CHECK**
   - Use `detect_security_regressions` prompt
   - Check if changes reintroduce old vulnerabilities
   - Review commit history for related security fixes

5. **SECRETS DETECTION**
   - Scan for hardcoded credentials, API keys, tokens
   - Flag any potential secrets in code or config files
   - Recommend using environment variables or secret management

6. **SECURITY TEST COVERAGE**
   - Are security tests included for new functionality?
   - Are edge cases and error conditions tested?
   - Recommend additional security tests if needed

7. **COMMIT DECISION**
   - **BLOCK**: Critical security issues found → must fix before commit
   - **WARN**: Medium issues found → recommend fix but allow commit with acknowledgment
   - **PASS**: No significant security issues → safe to commit

### Pre-Commit Checklist

| Check | Tool/Method | Block Criteria |
|-------|-------------|----------------|
| Vulnerability patterns | `recognize_vulnerability_patterns` | CRITICAL severity CWE |
| Dependencies | `assess_dependency_vulnerabilities` | CVSS ≥ 9.0 |
| Attack surface | `analyze_attack_surface` | Unauthenticated remote access |
| Regressions | `detect_security_regressions` | High confidence regression |
| Secrets | Pattern matching | Any hardcoded credentials |
| Test coverage | Code analysis | No tests for security-critical code |

### Integration Example

```python
# Pre-commit hook
async def pre_commit_security_check(staged_files, commit_msg):
    check_result = await mcp_client.get_prompt("pre_commit_security_check", {
        "staged_changes": get_git_diff(),
        "commit_message": commit_msg,
        "changed_files": staged_files
    })
    
    issues = {
        "blocking": [],
        "warnings": [],
        "info": []
    }
    
    # 1. Scan for vulnerability patterns
    for file in staged_files:
        if is_code_file(file):
            patterns = await mcp_client.get_prompt("recognize_vulnerability_patterns", {
                "code_snippet": read_file(file),
                "language": detect_language(file)
            })
            
            critical_issues = [p for p in patterns if p.severity == "CRITICAL"]
            if critical_issues:
                issues["blocking"].extend(critical_issues)
    
    # 2. Check dependencies
    if any(is_package_file(f) for f in staged_files):
        new_deps = extract_new_dependencies(staged_files)
        for dep in new_deps:
            vuln_check = await mcp_client.get_prompt("assess_dependency_vulnerabilities", {
                "package_name": dep.name,
                "version": dep.version,
                "ecosystem": dep.ecosystem
            })
            
            if has_critical_cves(vuln_check):
                issues["blocking"].append(f"Critical CVE in {dep.name}@{dep.version}")
    
    # 3. Attack surface analysis
    if has_new_interfaces(staged_files):
        attack_surface = await mcp_client.get_prompt("analyze_attack_surface", {
            "change_description": commit_msg,
            "exposed_interfaces": extract_interfaces(staged_files)
        })
        
        if attack_surface.risk == "CRITICAL":
            issues["warnings"].append("Significant attack surface expansion")
    
    # 4. Regression check
    historical_fixes = get_security_fixes_from_history()
    if historical_fixes:
        regression_check = await mcp_client.get_prompt("detect_security_regressions", {
            "code_changes": get_git_diff(),
            "historical_fixes": historical_fixes
        })
        
        if regression_check.confidence == "HIGH":
            issues["blocking"].append("Security regression detected")
    
    # 5. Secrets detection
    secrets = scan_for_secrets(staged_files)
    if secrets:
        issues["blocking"].extend([f"Hardcoded secret in {s.file}" for s in secrets])
    
    # Decision
    if issues["blocking"]:
        print("❌ COMMIT BLOCKED - Critical security issues found:")
        for issue in issues["blocking"]:
            print(f"  - {issue}")
        return False
    
    if issues["warnings"]:
        print("⚠️  WARNING - Security concerns detected:")
        for warning in issues["warnings"]:
            print(f"  - {warning}")
        
        if not confirm("Proceed with commit?"):
            return False
    
    print("✅ COMMIT APPROVED - No critical security issues")
    return True
```

---

## Integration Patterns

### Cline Integration

```typescript
// Cline agent with BRON security checks
class ClineWithBRON {
  async executeCode(code: string, language: string): Promise<ExecutionResult> {
    // Security validation before execution
    const safetyCheck = await this.mcpClient.getPrompt(
      "validate_code_execution_safety",
      { code_snippet: code, language }
    );
    
    const risk = await this.assessRisk(safetyCheck);
    
    if (risk === "HIGH") {
      return {
        executed: false,
        reason: "Execution blocked due to security risks",
        details: safetyCheck
      };
    }
    
    // Safe to execute
    return await this.runCode(code);
  }
}
```

### Roo Integration

```python
# Roo agent with BRON dependency checks
class RooWithBRON:
    async def install_package(self, package: str, version: str):
        # Check for vulnerabilities before installation
        vuln_check = await self.mcp_client.get_prompt(
            "assess_dependency_vulnerabilities",
            {
                "package_name": package,
                "version": version,
                "ecosystem": "pypi"
            }
        )
        
        cves = await self.query_bron_cves(package, version)
        critical_cves = [c for c in cves if c.cvss_score >= 9.0]
        
        if critical_cves:
            safe_versions = self.find_safe_versions(package, cves)
            raise SecurityError(
                f"Critical CVEs in {package}@{version}. "
                f"Safe versions: {safe_versions}"
            )
        
        # Safe to install
        await self.run_pip_install(package, version)
```

### LangChain Integration

```python
# LangChain agent with BRON security tool
from langchain.agents import Tool, initialize_agent

async def bron_security_check(code: str) -> str:
    """Security check using BRON MCP gateway."""
    prompt = await mcp_client.get_prompt(
        "recognize_vulnerability_patterns",
        {"code_snippet": code, "language": "python"}
    )
    
    findings = await analyze_with_bron(code, prompt)
    
    if findings["critical_issues"]:
        return f"SECURITY RISK: {findings['critical_issues']}"
    return "Code appears safe"

security_tool = Tool(
    name="SecurityCheck",
    func=bron_security_check,
    description="Check code for vulnerabilities using BRON"
)

agent = initialize_agent(
    tools=[security_tool],
    llm=llm,
    agent="zero-shot-react-description"
)
```

---

## Best Practices

### For AI Agent Developers

1. **Always validate before execution**: Use `validate_code_execution_safety` before running any dynamically generated code
2. **Check dependencies proactively**: Use `assess_dependency_vulnerabilities` before installing packages
3. **Generate secure code from the start**: Use `guide_secure_code_generation` during code generation
4. **Implement pre-commit hooks**: Use `pre_commit_security_check` as a final gate
5. **Learn from findings**: When BRON identifies issues, use the CWE/CVE details to improve future code generation

### For Security Teams

1. **Customize workflows**: Adapt prompts to your organization's specific security requirements
2. **Integrate with CI/CD**: Run BRON checks automatically in your pipeline
3. **Track metrics**: Monitor how often agents block/warn on security issues
4. **Update regularly**: Keep BRON data current to catch latest vulnerabilities
5. **Provide feedback**: Help agents learn by providing feedback on false positives/negatives

### For Developers

1. **Understand the guidance**: Read the BRON query results to learn about vulnerabilities
2. **Don't bypass warnings**: If an agent warns about security risks, investigate before proceeding
3. **Add security tests**: When BRON identifies risks, add tests to prevent regressions
4. **Document security decisions**: Record why certain patterns were chosen or avoided
5. **Stay informed**: Use BRON to learn about emerging threats in your technology stack

---

## Conclusion

These 11 agentic workflows provide comprehensive security guidance for AI coding agents, enabling them to make informed decisions about code execution, dependency management, and security throughout the development lifecycle. By leveraging BRON's extensive cybersecurity knowledge graph, agents can prevent vulnerabilities before they're introduced, making AI-generated code safer and more secure.

For implementation details, see the [Design Document](../design.md) and [Requirements Document](../requirements.md).
