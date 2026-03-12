# Requirements Document

## Introduction

This document specifies the requirements for an MCP (Model Context Protocol) server that provides gateway access to the BRON (Bridging Reconnaissance and Operational Nexus) cybersecurity framework. BRON is a knowledge graph that connects various cybersecurity datasets including CVEs, CWEs, ATT&CK techniques, and CAPEC attack patterns. The MCP server will expose BRON's capabilities through standardized MCP tools, resources, and prompts, enabling AI assistants to query and analyze cybersecurity threat intelligence.

## Glossary

- **MCP_Server**: The Model Context Protocol server implementation that exposes BRON capabilities
- **BRON**: Bridging Reconnaissance and Operational Nexus - a cybersecurity knowledge graph framework
- **Tool**: An MCP capability that performs an action or query (e.g., searching for CVEs)
- **Resource**: An MCP capability that provides access to data (e.g., a specific CVE record)
- **Prompt**: An MCP capability that provides pre-defined interaction templates
- **Client**: An MCP client application (e.g., Claude Desktop, AI assistant) that connects to the MCP_Server
- **CVE**: Common Vulnerabilities and Exposures identifier
- **CWE**: Common Weakness Enumeration identifier
- **ATT&CK**: MITRE ATT&CK framework technique identifier
- **CAPEC**: Common Attack Pattern Enumeration and Classification identifier
- **Knowledge_Graph**: The underlying BRON data structure connecting cybersecurity entities
- **ArangoDB**: The graph database backend used by BRON to store the Knowledge_Graph
- **Docker_Container**: A containerized deployment package containing the MCP_Server and dependencies
- **Isolated_Network**: A network environment with no internet connectivity (also called non-internet connected networks)
- **Data_Export**: A serialized snapshot of the Knowledge_Graph for transfer between environments
- **Agentic_Workflow**: A structured security analysis process designed for AI coding agents to query BRON and make informed decisions
- **AI_Coding_Agent**: An autonomous AI system that generates, reviews, or executes code (e.g., Cline, Roo, LangChain, Kiro)
- **Code_Execution_Safety**: The practice of validating generated code against known vulnerability patterns before execution
- **Vulnerability_Pattern**: A code structure or practice that matches a known CWE weakness definition
- **Quickstart_Guide**: Documentation that enables rapid deployment and initial use of the MCP_Server

## Requirements

### Requirement 1: MCP Server Initialization

**User Story:** As a system administrator, I want the MCP server to initialize properly, so that clients can connect and use BRON capabilities.

#### Acceptance Criteria

1. WHEN the MCP_Server starts, THE MCP_Server SHALL load the BRON Knowledge_Graph data
2. WHEN the MCP_Server starts, THE MCP_Server SHALL expose server capabilities via the MCP protocol
3. IF the BRON Knowledge_Graph data fails to load, THEN THE MCP_Server SHALL return a descriptive error message
4. THE MCP_Server SHALL accept connections from MCP-compatible Clients

### Requirement 2: CVE Query Tool

**User Story:** As a security analyst, I want to query CVE information, so that I can understand specific vulnerabilities.

#### Acceptance Criteria

1. THE MCP_Server SHALL expose a tool named "query_cve" that accepts CVE identifiers
2. WHEN a valid CVE identifier is provided, THE MCP_Server SHALL return vulnerability details from the Knowledge_Graph
3. WHEN an invalid CVE identifier is provided, THE MCP_Server SHALL return an error indicating the CVE was not found
4. THE MCP_Server SHALL return CVE data including description, severity, related CWEs, and related ATT&CK techniques

### Requirement 3: CWE Query Tool

**User Story:** As a security analyst, I want to query CWE information, so that I can understand weakness patterns.

#### Acceptance Criteria

1. THE MCP_Server SHALL expose a tool named "query_cwe" that accepts CWE identifiers
2. WHEN a valid CWE identifier is provided, THE MCP_Server SHALL return weakness details from the Knowledge_Graph
3. WHEN an invalid CWE identifier is provided, THE MCP_Server SHALL return an error indicating the CWE was not found
4. THE MCP_Server SHALL return CWE data including description, related CVEs, and related CAPEC patterns

### Requirement 4: ATT&CK Technique Query Tool

**User Story:** As a threat intelligence analyst, I want to query ATT&CK techniques, so that I can understand adversary tactics.

#### Acceptance Criteria

1. THE MCP_Server SHALL expose a tool named "query_attack_technique" that accepts ATT&CK technique identifiers
2. WHEN a valid ATT&CK identifier is provided, THE MCP_Server SHALL return technique details from the Knowledge_Graph
3. WHEN an invalid ATT&CK identifier is provided, THE MCP_Server SHALL return an error indicating the technique was not found
4. THE MCP_Server SHALL return ATT&CK data including description, tactics, and related CVEs

### Requirement 5: CAPEC Query Tool

**User Story:** As a security researcher, I want to query CAPEC attack patterns, so that I can understand attack methodologies.

#### Acceptance Criteria

1. THE MCP_Server SHALL expose a tool named "query_capec" that accepts CAPEC identifiers
2. WHEN a valid CAPEC identifier is provided, THE MCP_Server SHALL return attack pattern details from the Knowledge_Graph
3. WHEN an invalid CAPEC identifier is provided, THE MCP_Server SHALL return an error indicating the CAPEC was not found
4. THE MCP_Server SHALL return CAPEC data including description, prerequisites, and related CWEs

### Requirement 6: Relationship Traversal Tool

**User Story:** As a security analyst, I want to discover relationships between cybersecurity entities, so that I can understand attack chains and vulnerability connections.

#### Acceptance Criteria

1. THE MCP_Server SHALL expose a tool named "find_relationships" that accepts an entity identifier and relationship type
2. WHEN a valid entity identifier is provided, THE MCP_Server SHALL return all connected entities of the specified relationship type
3. THE MCP_Server SHALL support relationship queries between CVEs, CWEs, ATT&CK techniques, and CAPEC patterns
4. WHEN no relationships exist for the specified criteria, THE MCP_Server SHALL return an empty result set

### Requirement 7: Search Tool

**User Story:** As a security analyst, I want to search across all BRON entities, so that I can find relevant cybersecurity information by keyword.

#### Acceptance Criteria

1. THE MCP_Server SHALL expose a tool named "search_bron" that accepts search terms
2. WHEN search terms are provided, THE MCP_Server SHALL return matching entities from the Knowledge_Graph
3. THE MCP_Server SHALL search across CVE descriptions, CWE names, ATT&CK technique names, and CAPEC pattern names
4. THE MCP_Server SHALL return search results with entity type, identifier, and relevance score

### Requirement 8: Resource Access for Entities

**User Story:** As an AI assistant, I want to access BRON entities as MCP resources, so that I can provide contextual information to users.

#### Acceptance Criteria

1. THE MCP_Server SHALL expose resources with URIs in the format "bron://cve/{id}", "bron://cwe/{id}", "bron://attack/{id}", and "bron://capec/{id}"
2. WHEN a Client requests a resource URI, THE MCP_Server SHALL return the entity data in a structured format
3. WHEN a Client requests an invalid resource URI, THE MCP_Server SHALL return an error indicating the resource was not found
4. THE MCP_Server SHALL support resource listing for each entity type

### Requirement 9: Threat Analysis Prompt

**User Story:** As an AI assistant user, I want pre-defined prompts for threat analysis, so that I can quickly analyze vulnerabilities and attack patterns.

#### Acceptance Criteria

1. THE MCP_Server SHALL expose a prompt named "analyze_threat" that accepts a CVE or vulnerability description
2. WHEN the prompt is invoked, THE MCP_Server SHALL provide a template for comprehensive threat analysis
3. THE MCP_Server SHALL include guidance for analyzing related CWEs, ATT&CK techniques, and potential mitigations
4. THE MCP_Server SHALL structure the prompt to encourage exploration of the Knowledge_Graph relationships

### Requirement 10: Attack Path Discovery Prompt

**User Story:** As a security analyst, I want to discover potential attack paths, so that I can understand how vulnerabilities might be exploited.

#### Acceptance Criteria

1. THE MCP_Server SHALL expose a prompt named "discover_attack_path" that accepts a starting entity identifier
2. WHEN the prompt is invoked, THE MCP_Server SHALL provide a template for exploring attack chains through the Knowledge_Graph
3. THE MCP_Server SHALL include guidance for traversing from CVEs through CWEs to CAPEC patterns and ATT&CK techniques
4. THE MCP_Server SHALL structure the prompt to identify potential exploitation sequences

### Requirement 11: Error Handling and Logging

**User Story:** As a system administrator, I want comprehensive error handling and logging, so that I can troubleshoot issues and monitor server health.

#### Acceptance Criteria

1. WHEN an error occurs during tool execution, THE MCP_Server SHALL return a structured error response to the Client
2. THE MCP_Server SHALL log all tool invocations with timestamps and parameters
3. THE MCP_Server SHALL log all errors with stack traces and context information
4. WHEN the Knowledge_Graph is unavailable, THE MCP_Server SHALL return an error indicating the service is temporarily unavailable

### Requirement 12: Configuration Management

**User Story:** As a system administrator, I want to configure the MCP server, so that I can customize its behavior for different environments.

#### Acceptance Criteria

1. THE MCP_Server SHALL load configuration from a configuration file at startup
2. THE MCP_Server SHALL support configuration of the BRON Knowledge_Graph data source location
3. THE MCP_Server SHALL support configuration of logging levels and output destinations
4. WHEN the configuration file is invalid, THE MCP_Server SHALL return a descriptive error and fail to start

### Requirement 13: MCP Protocol Compliance

**User Story:** As an MCP client developer, I want the server to comply with the MCP specification, so that it works with standard MCP clients.

#### Acceptance Criteria

1. THE MCP_Server SHALL implement the MCP protocol version 1.0 or later
2. THE MCP_Server SHALL respond to the "initialize" request with server capabilities
3. THE MCP_Server SHALL respond to "tools/list", "resources/list", and "prompts/list" requests
4. THE MCP_Server SHALL handle "tools/call", "resources/read", and "prompts/get" requests according to the MCP specification

### Requirement 14: Data Freshness and Updates

**User Story:** As a security analyst, I want access to current BRON data, so that my analysis reflects the latest threat intelligence.

#### Acceptance Criteria

1. THE MCP_Server SHALL expose a tool named "get_data_version" that returns the Knowledge_Graph version and last update timestamp
2. WHERE a data update mechanism is configured, THE MCP_Server SHALL support reloading the Knowledge_Graph without restart
3. WHEN the Knowledge_Graph is reloaded, THE MCP_Server SHALL log the update event with version information
4. THE MCP_Server SHALL continue serving requests during Knowledge_Graph reload operations

### Requirement 15: Performance and Scalability

**User Story:** As a system administrator, I want the server to handle multiple concurrent requests efficiently, so that it can support multiple clients.

#### Acceptance Criteria

1. WHEN multiple Clients connect simultaneously, THE MCP_Server SHALL handle requests concurrently
2. THE MCP_Server SHALL respond to simple query requests within 500 milliseconds under normal load
3. THE MCP_Server SHALL respond to complex relationship traversal requests within 2 seconds under normal load
4. WHEN the server is under heavy load, THE MCP_Server SHALL queue requests rather than rejecting them

### Requirement 16: Docker-Based Deployment

**User Story:** As a system administrator, I want to deploy the MCP server using Docker, so that I can quickly set up BRON in any environment.

#### Acceptance Criteria

1. THE MCP_Server SHALL provide a Docker_Container image that includes all required dependencies
2. THE Docker_Container SHALL include ArangoDB configured for BRON data storage
3. WHEN the Docker_Container starts, THE MCP_Server SHALL initialize the Knowledge_Graph from included data
4. THE Docker_Container SHALL expose the MCP server port for client connections
5. THE Docker_Container SHALL support volume mounting for persistent Knowledge_Graph storage

### Requirement 17: Cloud and On-Premises Deployment Support

**User Story:** As a system administrator, I want to deploy BRON in cloud or on-premises environments, so that I can choose the deployment model that fits my organization's needs.

#### Acceptance Criteria

1. THE MCP_Server SHALL support deployment on cloud platforms with internet connectivity
2. THE MCP_Server SHALL support deployment on on-premises infrastructure with internet connectivity
3. THE MCP_Server SHALL support deployment in Isolated_Networks without internet connectivity
4. WHERE internet connectivity is available, THE MCP_Server SHALL support automated data updates from upstream BRON sources
5. WHERE internet connectivity is not available, THE MCP_Server SHALL operate using locally stored Knowledge_Graph data

### Requirement 18: Isolated Network Deployment Support

**User Story:** As a security administrator in a restricted environment, I want to deploy BRON without internet access, so that I can use threat intelligence in non-internet connected networks.

#### Acceptance Criteria

1. THE MCP_Server SHALL support initialization with a --no_download flag that prevents internet access attempts
2. WHEN deployed in an Isolated_Network, THE MCP_Server SHALL build the Knowledge_Graph from pre-downloaded data files
3. THE MCP_Server SHALL provide a Data_Export tool that serializes the Knowledge_Graph for transfer
4. WHEN a Data_Export is provided, THE MCP_Server SHALL import and load the Knowledge_Graph data
5. THE MCP_Server SHALL document all data files required for isolated network deployment

### Requirement 19: Data Synchronization for Internet-Connected Environments

**User Story:** As a system administrator, I want to keep BRON data current in internet-connected environments, so that my threat intelligence remains up-to-date.

#### Acceptance Criteria

1. WHERE internet connectivity is available, THE MCP_Server SHALL expose a tool named "update_knowledge_graph" that downloads latest threat intelligence data
2. WHEN the update tool is invoked, THE MCP_Server SHALL download CVE, CWE, ATT&CK, and CAPEC data from upstream sources
3. WHEN data download completes, THE MCP_Server SHALL rebuild the Knowledge_Graph with updated data
4. WHEN data download fails, THE MCP_Server SHALL log the error and continue using existing Knowledge_Graph data
5. THE MCP_Server SHALL support scheduled automatic updates via configuration

### Requirement 20: Data Export and Import for Isolated Network Synchronization

**User Story:** As a system administrator managing isolated network deployments, I want to export and import BRON data, so that I can update threat intelligence in non-internet connected environments.

#### Acceptance Criteria

1. THE MCP_Server SHALL expose a tool named "export_knowledge_graph" that creates a Data_Export file
2. WHEN the export tool is invoked, THE MCP_Server SHALL serialize the complete Knowledge_Graph to a portable format
3. THE Data_Export SHALL include version metadata and timestamp information
4. THE MCP_Server SHALL expose a tool named "import_knowledge_graph" that accepts a Data_Export file
5. WHEN the import tool is invoked with a valid Data_Export, THE MCP_Server SHALL replace the current Knowledge_Graph with imported data
6. WHEN the import tool is invoked with an invalid Data_Export, THE MCP_Server SHALL return an error and preserve existing data

### Requirement 21: Quickstart Documentation

**User Story:** As a new user, I want comprehensive quickstart guides, so that I can rapidly deploy and begin using BRON with MCP.

#### Acceptance Criteria

1. THE MCP_Server SHALL provide a Quickstart_Guide for Docker-based deployment
2. THE MCP_Server SHALL provide a Quickstart_Guide for cloud deployment with automated data updates
3. THE MCP_Server SHALL provide a Quickstart_Guide for isolated network deployment with manual data import
4. EACH Quickstart_Guide SHALL include step-by-step instructions from installation to first query
5. EACH Quickstart_Guide SHALL include example MCP client configuration for connecting to the MCP_Server
6. EACH Quickstart_Guide SHALL include verification steps to confirm successful deployment

### Requirement 22: Database Configuration and Management

**User Story:** As a system administrator, I want to configure ArangoDB settings, so that I can optimize BRON for my environment.

#### Acceptance Criteria

1. THE MCP_Server SHALL support configuration of ArangoDB connection parameters including host, port, and credentials
2. WHERE ArangoDB is not running, THE MCP_Server SHALL return a descriptive error indicating database unavailability
3. THE MCP_Server SHALL support configuration of ArangoDB memory limits and performance settings
4. THE MCP_Server SHALL validate ArangoDB connectivity during startup
5. WHEN ArangoDB connection fails, THE MCP_Server SHALL log connection details and fail gracefully

### Requirement 23: Initial Data Build Process

**User Story:** As a system administrator performing first-time setup, I want to build the initial BRON knowledge graph, so that the MCP server has data to serve.

#### Acceptance Criteria

1. THE MCP_Server SHALL provide a build tool that downloads threat intelligence data from public sources
2. WHEN the build tool is invoked, THE MCP_Server SHALL download CVE, CWE, ATT&CK, and CAPEC datasets
3. WHEN the build tool is invoked with --no_download flag, THE MCP_Server SHALL build from locally available data files
4. WHEN data download or build fails, THE MCP_Server SHALL return descriptive error messages indicating which step failed
5. THE MCP_Server SHALL log build progress including dataset sizes and processing time
6. WHEN the build completes successfully, THE MCP_Server SHALL store the Knowledge_Graph in ArangoDB

### Requirement 24: Agentic Workflow Prompts

**User Story:** As an AI coding agent, I want pre-defined security-aware workflow prompts, so that I can make safer decisions about code execution and development.

#### Acceptance Criteria

1. THE MCP_Server SHALL expose at least 11 Agentic_Workflow prompts designed for AI_Coding_Agents
2. EACH Agentic_Workflow prompt SHALL include a description of its security purpose and expected usage
3. EACH Agentic_Workflow prompt SHALL specify the sequence of BRON tools to invoke for the workflow
4. THE MCP_Server SHALL expose prompts for Code_Execution_Safety validation, dependency vulnerability scanning, secure code generation guidance, attack pattern detection, threat modeling, security regression detection, and compliance mapping
5. WHEN an Agentic_Workflow prompt is invoked, THE MCP_Server SHALL provide structured guidance that helps AI_Coding_Agents query BRON data to inform security decisions
6. EACH Agentic_Workflow prompt SHALL include a decision framework with risk levels and recommended actions
7. EACH Agentic_Workflow prompt SHALL include examples of high-risk patterns or scenarios relevant to the workflow

### Requirement 25: Code Execution Safety Validation

**User Story:** As an AI coding agent, I want to validate dynamically generated code before execution, so that I can prevent execution of code with known Vulnerability_Patterns.

#### Acceptance Criteria

1. THE MCP_Server SHALL expose a prompt named "validate_code_execution_safety" that accepts code snippets and language identifiers
2. WHEN the prompt is invoked, THE MCP_Server SHALL provide guidance for identifying Vulnerability_Patterns that match CWE definitions
3. THE MCP_Server SHALL include guidance for checking if code patterns match known CAPEC attack vectors
4. THE MCP_Server SHALL structure the prompt to help AI_Coding_Agents decide whether code execution is safe, requires user approval, or should be blocked
5. THE MCP_Server SHALL provide examples of high-risk patterns including SQL injection, command injection, path traversal, deserialization, and buffer overflow patterns
6. THE MCP_Server SHALL include guidance for using search_bron, query_cwe, find_relationships, and query_cve tools to assess execution risk
7. THE MCP_Server SHALL provide a decision framework with three risk levels: HIGH RISK (block execution), MEDIUM RISK (warn user), LOW RISK (safe to execute)

### Requirement 26: Dependency Vulnerability Assessment

**User Story:** As an AI coding agent, I want to assess dependencies for known vulnerabilities, so that I can warn users before adding vulnerable packages.

#### Acceptance Criteria

1. THE MCP_Server SHALL expose a prompt named "assess_dependency_vulnerabilities" that accepts package names, version ranges, and ecosystem identifiers
2. WHEN the prompt is invoked, THE MCP_Server SHALL provide guidance for searching CVEs related to the dependency using search_bron
3. THE MCP_Server SHALL include guidance for evaluating CVE severity using CVSS scores and checking version applicability
4. THE MCP_Server SHALL structure the prompt to help AI_Coding_Agents recommend safe version ranges or alternative packages
5. THE MCP_Server SHALL provide guidance for identifying transitive dependency risks and checking dependency chains
6. THE MCP_Server SHALL include a decision framework: BLOCK for critical CVEs (CVSS >= 9.0), WARN for high CVEs (CVSS >= 7.0), INFORM for medium/low CVEs
7. THE MCP_Server SHALL provide guidance for using query_cve, find_relationships, and query_cwe tools to understand vulnerability types

### Requirement 27: Secure Code Generation Guidance

**User Story:** As an AI coding agent, I want security guidance during code generation, so that I can avoid introducing Vulnerability_Patterns.

#### Acceptance Criteria

1. THE MCP_Server SHALL expose a prompt named "guide_secure_code_generation" that accepts feature descriptions, language identifiers, and optional code context
2. WHEN the prompt is invoked, THE MCP_Server SHALL provide guidance for identifying security-relevant operations including user input handling, file operations, network requests, authentication, data storage, and cryptography
3. THE MCP_Server SHALL include guidance for querying relevant CWEs using search_bron based on operation types
4. THE MCP_Server SHALL structure the prompt to help AI_Coding_Agents generate code that avoids common vulnerability classes by applying secure coding patterns
5. THE MCP_Server SHALL provide examples of secure coding patterns including input validation, output encoding, parameterized queries, and safe API usage
6. THE MCP_Server SHALL include guidance for using query_cwe and find_relationships to understand real-world CVE examples of vulnerabilities
7. THE MCP_Server SHALL provide guidance for documenting security assumptions and required security configurations in generated code

### Requirement 28: Attack Surface Analysis

**User Story:** As an AI coding agent, I want to analyze the attack surface of code changes, so that I can inform users about security implications.

#### Acceptance Criteria

1. THE MCP_Server SHALL expose a prompt named "analyze_attack_surface" that accepts change descriptions, optional code diffs, and lists of exposed interfaces
2. WHEN the prompt is invoked, THE MCP_Server SHALL provide guidance for mapping exposed interfaces to ATT&CK techniques using search_bron
3. THE MCP_Server SHALL include guidance for identifying attack vectors and using query_attack_technique and query_capec to understand attack methods
4. THE MCP_Server SHALL structure the prompt to help AI_Coding_Agents assess exploitability based on remote accessibility, authentication requirements, and required privileges
5. THE MCP_Server SHALL provide guidance for discovering related vulnerabilities using find_relationships to traverse from CAPEC to CWE to CVE
6. THE MCP_Server SHALL include guidance for recommending specific mitigations including input validation, authentication controls, rate limiting, and security testing
7. THE MCP_Server SHALL provide a framework for quantifying attack surface changes as SIGNIFICANT, MODERATE, or MINIMAL

### Requirement 29: Vulnerability Pattern Recognition

**User Story:** As an AI coding agent, I want to recognize Vulnerability_Patterns in code, so that I can flag potential security issues during code review.

#### Acceptance Criteria

1. THE MCP_Server SHALL expose a prompt named "recognize_vulnerability_patterns" that accepts code snippets, language identifiers, and optional review context
2. WHEN the prompt is invoked, THE MCP_Server SHALL provide guidance for scanning code for common vulnerability indicators including string concatenation in SQL/shell commands, user input flowing to sensitive sinks, missing input validation, hardcoded credentials, unsafe deserialization, and weak cryptography
3. THE MCP_Server SHALL include guidance for mapping identified patterns to CWE definitions using search_bron and query_cwe
4. THE MCP_Server SHALL structure the prompt to help AI_Coding_Agents assess severity using find_relationships to discover related CVEs and their CVSS scores
5. THE MCP_Server SHALL provide guidance for distinguishing false positives by checking for existing mitigations and assessing code path reachability
6. THE MCP_Server SHALL include guidance for providing specific feedback with line numbers, CWE references, vulnerability explanations, and remediation advice
7. THE MCP_Server SHALL provide a severity rating framework: CRITICAL, HIGH, MEDIUM, LOW, INFO with confidence levels

### Requirement 30: Exploit Chain Discovery

**User Story:** As an AI coding agent, I want to discover potential exploit chains, so that I can understand how multiple vulnerabilities could be combined.

#### Acceptance Criteria

1. THE MCP_Server SHALL expose a prompt named "discover_exploit_chains" that accepts arrays of CVE or CWE identifiers and optional system context
2. WHEN the prompt is invoked, THE MCP_Server SHALL provide guidance for building vulnerability graphs using query_cve, query_cwe, and find_relationships
3. THE MCP_Server SHALL include guidance for identifying CAPEC patterns that chain multiple weaknesses using query_capec
4. THE MCP_Server SHALL structure the prompt to help AI_Coding_Agents discover multi-stage attacks where one vulnerability provides access needed for another
5. THE MCP_Server SHALL provide guidance for mapping exploit chains to ATT&CK tactics using query_attack_technique
6. THE MCP_Server SHALL include guidance for assessing combined impact and likelihood of successful exploitation
7. THE MCP_Server SHALL provide guidance for prioritizing remediation by identifying which vulnerability fixes break the most exploit chains

### Requirement 31: Security Control Recommendation

**User Story:** As an AI coding agent, I want security control recommendations, so that I can suggest appropriate mitigations for identified risks.

#### Acceptance Criteria

1. THE MCP_Server SHALL expose a prompt named "recommend_security_controls" that accepts arrays of CWE or CAPEC identifiers and optional context
2. WHEN the prompt is invoked, THE MCP_Server SHALL provide guidance for understanding weaknesses using query_cwe and identifying root causes
3. THE MCP_Server SHALL include guidance for identifying defensive techniques using find_relationships to discover related ATT&CK techniques and query_attack_technique to understand attack methods
4. THE MCP_Server SHALL structure the prompt to help AI_Coding_Agents map weaknesses to mitigation strategies including input validation, output encoding, authentication, cryptographic controls, and secure configuration
5. THE MCP_Server SHALL provide guidance for suggesting specific code-level mitigations with API calls, libraries, and code patterns
6. THE MCP_Server SHALL include guidance for recommending architectural mitigations including network segmentation, least privilege, and defense in depth
7. THE MCP_Server SHALL provide a prioritization framework based on effectiveness, implementation cost, and performance impact

### Requirement 32: Threat Modeling Assistance

**User Story:** As an AI coding agent, I want threat modeling assistance, so that I can help developers identify security requirements early in development.

#### Acceptance Criteria

1. THE MCP_Server SHALL expose a prompt named "assist_threat_modeling" that accepts system descriptions, lists of assets to protect, and trust boundaries
2. WHEN the prompt is invoked, THE MCP_Server SHALL provide guidance for identifying attack vectors at trust boundaries using search_bron
3. THE MCP_Server SHALL include guidance for mapping system components to ATT&CK techniques using query_attack_technique
4. THE MCP_Server SHALL structure the prompt to help AI_Coding_Agents discover applicable CAPEC attack patterns using find_relationships and query_capec
5. THE MCP_Server SHALL provide guidance for identifying relevant CWEs for the technology stack using query_cwe
6. THE MCP_Server SHALL include guidance for generating threat scenarios with attack vectors, exploited weaknesses, impacts, and likelihood ratings
7. THE MCP_Server SHALL provide guidance for defining testable security requirements and acceptance criteria for each identified threat

### Requirement 33: Security Regression Detection

**User Story:** As an AI coding agent, I want to detect security regressions, so that I can prevent reintroduction of previously fixed vulnerabilities.

#### Acceptance Criteria

1. THE MCP_Server SHALL expose a prompt named "detect_security_regressions" that accepts code changes, optional historical fixes, and optional commit history
2. WHEN the prompt is invoked, THE MCP_Server SHALL provide guidance for identifying previously fixed weaknesses using query_cve and query_cwe
3. THE MCP_Server SHALL include guidance for analyzing current changes to detect reintroduction of Vulnerability_Patterns including removed security controls, unvalidated inputs, and unsafe API replacements
4. THE MCP_Server SHALL structure the prompt to help AI_Coding_Agents use search_bron to find CWEs matching current code patterns and compare against historical fixes
5. THE MCP_Server SHALL provide guidance for assessing regression risk with confidence levels (HIGH, MEDIUM, LOW) and severity ratings
6. THE MCP_Server SHALL include guidance for providing evidence through code comparisons showing original vulnerable pattern, fixed pattern, and current pattern
7. THE MCP_Server SHALL provide a decision framework: BLOCK for high-confidence critical regressions, REVIEW for medium confidence, WARN for low confidence, PASS for no regressions

### Requirement 34: Compliance and Standards Mapping

**User Story:** As an AI coding agent, I want to map vulnerabilities to compliance standards, so that I can help organizations meet regulatory requirements.

#### Acceptance Criteria

1. THE MCP_Server SHALL expose a prompt named "map_compliance_standards" that accepts arrays of CVE or CWE identifiers and optional compliance framework specifications
2. WHEN the prompt is invoked, THE MCP_Server SHALL provide guidance for understanding vulnerabilities using query_cve and query_cwe
3. THE MCP_Server SHALL include guidance for mapping to common standards including OWASP Top 10, CWE Top 25, SANS Top 25, PCI-DSS, HIPAA, and SOC 2
4. THE MCP_Server SHALL structure the prompt to help AI_Coding_Agents identify specific violated requirements and required evidence for compliance
5. THE MCP_Server SHALL provide guidance for assessing compliance impact severity and potential penalties
6. THE MCP_Server SHALL include guidance for prioritizing remediation based on compliance deadlines and audit schedules
7. THE MCP_Server SHALL provide guidance for generating compliance reports with vulnerability summaries, affected requirements, remediation actions, and audit evidence

### Requirement 35: Pre-Commit Security Check

**User Story:** As an AI coding agent, I want comprehensive pre-commit security checks, so that I can prevent insecure code from being committed to version control.

#### Acceptance Criteria

1. THE MCP_Server SHALL expose a prompt named "pre_commit_security_check" that accepts staged changes, commit messages, and lists of changed files
2. WHEN the prompt is invoked, THE MCP_Server SHALL provide guidance for performing Vulnerability_Pattern scans using recognize_vulnerability_patterns for each changed file
3. THE MCP_Server SHALL include guidance for dependency checks when package files change, using assess_dependency_vulnerabilities to detect critical CVEs
4. THE MCP_Server SHALL structure the prompt to help AI_Coding_Agents perform attack surface analysis for new APIs or interfaces using analyze_attack_surface
5. THE MCP_Server SHALL provide guidance for regression checks using detect_security_regressions to prevent reintroduction of old vulnerabilities
6. THE MCP_Server SHALL include guidance for secrets detection to identify hardcoded credentials, API keys, or tokens
7. THE MCP_Server SHALL provide a decision framework: BLOCK for critical security issues that must be fixed before commit, WARN for medium issues that allow commit with acknowledgment, PASS for no significant security issues
